#!/usr/bin/env python3
"""
Проверки резервной копии состояния ноды (shaperctl export / import).

Запускать из песочницы, не на рабочей ноде. Каталоги подменяются через
переменные окружения до загрузки модуля, поэтому /etc и /var не трогаются.
"""
import argparse
import importlib.util
import io
import json
import os
import re
import stat
import sys
import tempfile

SRC = os.environ.get("SHAPE_SRC") or os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))

TMP = tempfile.mkdtemp(prefix="shape-export-")
ETC = os.path.join(TMP, "etc"); os.makedirs(ETC)
VAR = os.path.join(TMP, "var"); os.makedirs(VAR)
BIN = os.path.join(TMP, "bin"); os.makedirs(BIN)
PIN = os.path.join(TMP, "maps"); os.makedirs(PIN)

# Подставной bpftool: запоминает вызовы, ничего не делает. Нужен там, где
# импорт доводит восстановленное до ядра.
with open(os.path.join(BIN, "bpftool"), "w") as f:
    f.write('#!/bin/sh\nprintf "%s\\n" "$*" >> "$BPFTOOL_LOG"\n'
            'case "$*" in *dump*) echo "[]";; esac\nexit 0\n')
os.chmod(os.path.join(BIN, "bpftool"), 0o755)

os.environ["PATH"] = BIN + ":" + os.environ["PATH"]
os.environ["SHAPER_PIN_DIR"] = PIN
os.environ["BPFTOOL_LOG"] = os.path.join(TMP, "bpftool.log")
os.environ["SHAPE_ETC_DIR"] = ETC
os.environ["SHAPE_VAR_DIR"] = VAR

spec = importlib.util.spec_from_file_location("S", os.path.join(SRC, "shaperctl.py"))
S = importlib.util.module_from_spec(spec); spec.loader.exec_module(S)

ok = fail = 0


def check(name, cond, extra=""):
    global ok, fail
    if cond:
        ok += 1
        print(f"  \033[32m✓\033[0m {name}")
    else:
        fail += 1
        print(f"  \033[31m✗ {name}\033[0m {extra}")


def dies(fn, *a, **kw):
    try:
        fn(*a, **kw)
        return False
    except SystemExit:
        return True


def quiet(fn, *a, **kw):
    """Гасит печать команды: в наборе важен результат, а не вывод."""
    keep = sys.stdout
    sys.stdout = io.StringIO()
    try:
        return fn(*a, **kw)
    finally:
        sys.stdout = keep


def ns_export(**kw):
    d = dict(out=None, with_secrets=False)
    d.update(kw)
    return argparse.Namespace(**d)


def ns_import(file, **kw):
    d = dict(file=file, dry_run=False, only=None, replace=False)
    d.update(kw)
    return argparse.Namespace(**d)


TOKEN = ("123456789:" + "AABBccddeeFFgghhiijjkkllmmnnoopp")
PROXY = "socks5://user:secretpass@1.2.3.4:1080"


def seed():
    """Кладёт в песочницу заведомо известное состояние."""
    for p in (S.WL_FILE, S.PEN_FILE, S.OWNERS_FILE, S.HISTORY_FILE, S.CONFIG_FILE):
        try:
            os.remove(p)
        except OSError:
            pass
    S.save_config({
        "speed_mbps": 25, "ports": [443, 8443],
        "guard": dict(S.GUARD_DEFAULT, enabled=True, penalty_mbps=2),
        "telegram": dict(S.TG_DEFAULT, enabled=True, token=TOKEN,
                         chat_id="-1001234567890", proxy=PROXY,
                         digest_at="21:30"),
    })
    with open(S.WL_FILE, "w") as f:
        f.write("# белый список\n10.0.0.1\n10.0.0.2\n")
    S.save_penalties({
        "1.2.3.4": {"mbps": 5.0, "until": 9.9e10, "kind": "personal",
                    "source": "manual"},
        "5.6.7.8": {"mbps": 1.0, "until": 9.9e10, "source": "guard"},
    })
    S.save_owners({"1.2.3.4": {"label": "Александр", "user_id": "42",
                               "updated": 1755000000}})
    with open(S.HISTORY_FILE, "w") as f:
        f.write(json.dumps({"day": "2026-08-12", "down": 1, "up": 2, "ips": 3,
                            "limited": 0, "top": []}) + "\n")
        f.write(json.dumps({"day": "2026-08-13", "down": 4, "up": 5, "ips": 6,
                            "limited": 1, "top": []}) + "\n")


def wipe_state():
    """Стирает всё, кроме конфига: нода как будто новая, но бот настроен."""
    for p in (S.WL_FILE, S.PEN_FILE, S.OWNERS_FILE, S.HISTORY_FILE):
        try:
            os.remove(p)
        except OSError:
            pass


def semantic(state):
    """Состояние без плавающих значений — для сравнения до и после."""
    return json.dumps({
        "config": state["config"],
        "whitelist": sorted(state["whitelist"]),
        "penalties": {ip: {"mbps": float(p["mbps"]), "until": float(p["until"])}
                      for ip, p in state["penalties"].items()},
        "owners": state["owners"],
        "history": state["history"],
    }, sort_keys=True, ensure_ascii=False)


# ────────────────────────────────────────────────────────────────────
print("\n\033[1m1. Формат выгрузки\033[0m")
seed()
d = S.build_export()
check("метка kind = shape-node-state", d.get("kind") == "shape-node-state")
check("указана версия формата", d.get("schema") == S.EXPORT_SCHEMA)
check("указана версия Shape", bool(d.get("shape_version")))
check("указано имя ноды", bool(d.get("node")))
check("есть отметка времени в двух видах",
      isinstance(d.get("exported_at"), int) and "T" in str(d.get("exported_at_iso")))
check("все пять разделов на месте",
      sorted(d["state"]) == sorted(S.EXPORT_SECTIONS),
      str(sorted(d["state"])))
check("журнал событий в выгрузку не попал", "events" not in d["state"])
check("метрики в выгрузку не попали", "metrics" not in d["state"])

print("\n\033[1m2. Секреты не утекают в файл по умолчанию\033[0m")
plain = json.dumps(S.build_export(with_secrets=False), ensure_ascii=False)
check("токена бота в выгрузке нет", TOKEN not in plain)
check("пароля прокси в выгрузке нет", "secretpass" not in plain)
check("флаг secrets_included = false",
      S.build_export(with_secrets=False)["secrets_included"] is False)
noprod = S.build_export(with_secrets=False)["state"]["config"]["telegram"]
check("chat_id при этом сохранён", noprod["chat_id"] == "-1001234567890")
check("время сводки сохранено", noprod["digest_at"] == "21:30")
check("сам признак включённости сохранён", noprod["enabled"] is True)

full = S.build_export(with_secrets=True)
check("с --with-secrets токен присутствует",
      full["state"]["config"]["telegram"]["token"] == TOKEN)
check("с --with-secrets прокси присутствует",
      full["state"]["config"]["telegram"]["proxy"] == PROXY)
check("флаг secrets_included = true", full["secrets_included"] is True)

print("\n\033[1m3. Файл выгрузки не читается посторонними\033[0m")
path = os.path.join(TMP, "dump.json")
quiet(S.cmd_export, ns_export(out=path, with_secrets=True))
mode = stat.S_IMODE(os.stat(path).st_mode)
check("права на файле 600", mode == 0o600, oct(mode))
check("файл читается как JSON", isinstance(json.load(open(path)), dict))

print("\n\033[1m4. Круговой тест: выгрузили, стёрли, восстановили\033[0m")
seed()
before = semantic(S.build_export(with_secrets=True)["state"])
dump = S.build_export(with_secrets=True)
wipe_state()
check("состояние действительно стёрто",
      not S.whitelist_ips() and not S.load_penalties() and not S.load_owners())
state, problems = S.validate_export(dump)
check("чистая выгрузка проходит проверку без замечаний", problems == [], str(problems))
done = S.apply_import(state, keep_secrets=False)
after = semantic(S.build_export(with_secrets=True)["state"])
check("состояние совпадает с исходным", before == after)
check("все пять разделов применены",
      sorted(done) == sorted(S.EXPORT_SECTIONS), str(sorted(done)))

print("\n\033[1m5. Повторный импорт ничего не меняет\033[0m")
one = semantic(S.build_export(with_secrets=True)["state"])
S.apply_import(S.validate_export(S.build_export(with_secrets=True))[0],
               keep_secrets=False)
two = semantic(S.build_export(with_secrets=True)["state"])
check("импорт идемпотентен", one == two)

print("\n\033[1m6. Токен ноды не затирается выгрузкой без секретов\033[0m")
seed()
dump_plain = S.build_export(with_secrets=False)
S.save_config({"telegram": dict(S.TG_DEFAULT, token="999:LOCALTOKEN",
                                proxy="socks5://local:1080")})
state, _ = S.validate_export(dump_plain)
S.apply_import(state, keep_secrets=True)
cfg = S.load_config()
check("токен, настроенный на ноде, остался", cfg["telegram"]["token"] == "999:LOCALTOKEN")
check("прокси ноды остался", cfg["telegram"]["proxy"] == "socks5://local:1080")
check("остальные поля пришли из выгрузки",
      cfg["telegram"]["chat_id"] == "-1001234567890")
check("скорость пришла из выгрузки", cfg["speed_mbps"] == 25)

print("\n\033[1m7. Выгрузка с секретами перезаписывает токен\033[0m")
seed()
S.save_config({"telegram": dict(S.TG_DEFAULT, token="999:LOCALTOKEN")})
dump_full = dict(json.loads(json.dumps(full)))
state, _ = S.validate_export(dump_full)
S.apply_import(state, keep_secrets=False)
check("токен из выгрузки применён", S.load_config()["telegram"]["token"] == TOKEN)

print("\n\033[1m8. Чужие и битые файлы отвергаются целиком\033[0m")
check("не объект", dies(S.validate_export, "строка"))
check("список вместо объекта", dies(S.validate_export, [1, 2]))
check("нет метки kind", dies(S.validate_export, {"schema": 1, "state": {}}))
check("чужая метка kind",
      dies(S.validate_export, {"kind": "backup", "schema": 1, "state": {}}))
check("нет версии формата",
      dies(S.validate_export, {"kind": "shape-node-state", "state": {}}))
check("версия формата нечисловая",
      dies(S.validate_export, {"kind": "shape-node-state", "schema": "x", "state": {}}))
check("формат новее нашего",
      dies(S.validate_export,
           {"kind": "shape-node-state", "schema": S.EXPORT_SCHEMA + 1, "state": {}}))
check("нет раздела state",
      dies(S.validate_export, {"kind": "shape-node-state", "schema": 1}))
check("state не объект",
      dies(S.validate_export,
           {"kind": "shape-node-state", "schema": 1, "state": []}))

bad_json = os.path.join(TMP, "broken.json")
with open(bad_json, "w") as f:
    f.write("{это не json")
check("битый JSON отвергается", dies(quiet, S.cmd_import, ns_import(bad_json)))
check("отсутствующий файл отвергается",
      dies(quiet, S.cmd_import, ns_import(os.path.join(TMP, "нет-такого.json"))))
check("неизвестный раздел в --only отвергается",
      dies(quiet, S.cmd_import, ns_import(path, only="config,выдумка")))


def wrap(state_dict):
    return {"kind": "shape-node-state", "schema": 1, "state": state_dict}


print("\n\033[1m9. Мусор внутри разделов отбрасывается, а не ломает импорт\033[0m")
st, pr = S.validate_export(wrap({
    "config": {"speed_mbps": float("nan"),
               "ports": [443, 70000, "x", True, -1],
               "guard": {"enabled": "да", "penalty_mbps": 3, "чужое": 1},
               "telegram": {"token": 5, "chat_id": "ok"}},
    "whitelist": ["10.0.0.1", "не адрес", "10.0.0.1", 42],
    "penalties": {"1.2.3.4": {"mbps": -5, "until": 1},
                  "2.2.2.2": {"mbps": 0, "until": 9e9},
                  "3.3.3.3": {"mbps": float("inf"), "until": 9e9},
                  "плохой": {}, "5.6.7.8": {"mbps": 3, "until": 9e9}},
    "owners": {"9.9.9.9": {"label": "A" * 500, "мусор": 1},
               "нет-адреса": {"label": "x"}},
    "history": [{"day": "2026-01-01"}, {"day": "вчера"}, "строка", 5],
}))
check("скорость nan отброшена", "speed_mbps" not in st["config"])
check("остался только годный порт", st["config"]["ports"] == [443],
      str(st["config"]["ports"]))
check("строка вместо булева в guard отброшена", "enabled" not in st["config"]["guard"])
check("годное число в guard осталось", st["config"]["guard"]["penalty_mbps"] == 3)
check("незнакомый ключ в guard отброшен", "чужое" not in st["config"]["guard"])
check("число вместо строки в telegram отброшено", "token" not in st["config"]["telegram"])
check("годная строка в telegram осталась", st["config"]["telegram"]["chat_id"] == "ok")
check("в белом списке только адреса", st["whitelist"] == ["10.0.0.1"],
      str(st["whitelist"]))
check("отрицательная, нулевая и бесконечная скорости отброшены",
      list(st["penalties"]) == ["5.6.7.8"], str(list(st["penalties"])))
check("длинный ярлык владельца обрезан",
      len(st["owners"]["9.9.9.9"]["label"]) == 200)
check("незнакомое поле владельца отброшено", "мусор" not in st["owners"]["9.9.9.9"])
check("владелец без адреса отброшен", list(st["owners"]) == ["9.9.9.9"])
check("в истории остались только записи с датой",
      [r["day"] for r in st["history"]] == ["2026-01-01"])
check("на каждую отброшенную запись есть замечание", len(pr) >= 10, str(len(pr)))

st, pr = S.validate_export(wrap({"config": {"ports": list(range(1000, 1000 + S.MAX_PORTS + 5))}}))
check(f"портов не больше {S.MAX_PORTS}", len(st["config"]["ports"]) == S.MAX_PORTS)
check("про лишние порты есть замечание", any("MAX" in p or str(S.MAX_PORTS) in p for p in pr))

st, pr = S.validate_export(wrap({}))
check("пустой state не ломает разбор", st == {} and pr == [])
st, pr = S.validate_export(wrap({"config": "строка", "whitelist": 5,
                                 "penalties": [], "owners": 1, "history": {}}))
check("испорченные разделы отбрасываются целиком", st == {}, str(st))
check("на каждый испорченный раздел есть замечание", len(pr) == 5, str(pr))

print("\n\033[1m10. Проверка без записи ничего не меняет\033[0m")
seed()
snapshot = semantic(S.build_export(with_secrets=True)["state"])
other = os.path.join(TMP, "other.json")
with open(other, "w") as f:
    json.dump(wrap({"config": {"speed_mbps": 999}, "whitelist": ["8.8.8.8"],
                    "penalties": {}, "owners": {}, "history": []}), f)
quiet(S.cmd_import, ns_import(other, dry_run=True))
check("после --dry-run состояние прежнее",
      semantic(S.build_export(with_secrets=True)["state"]) == snapshot)
check("чужой адрес в белый список не попал", "8.8.8.8" not in S.whitelist_ips())

print("\n\033[1m11. Выборочное восстановление\033[0m")
seed()
quiet(S.cmd_import, ns_import(other, only="whitelist"))
check("указанный раздел применён", "8.8.8.8" in S.whitelist_ips())
check("не указанный раздел не тронут", S.load_config()["speed_mbps"] == 25)
check("владельцы не тронуты", "1.2.3.4" in S.load_owners())

print("\n\033[1m12. Белый список: дополнить или заменить\033[0m")
seed()
quiet(S.cmd_import, ns_import(other, only="whitelist"))
check("без --replace список дополняется",
      {"8.8.8.8", "10.0.0.1", "10.0.0.2"} <= S.whitelist_ips())
seed()
quiet(S.cmd_import, ns_import(other, only="whitelist", replace=True))
check("с --replace список заменяется", S.whitelist_ips() == {"8.8.8.8"},
      str(S.whitelist_ips()))
check("шапка файла сохранена",
      open(S.WL_FILE).read().lstrip().startswith("#"))

print("\n\033[1m13. Просроченные ограничения не воскресают\033[0m")
seed()
stale = wrap({"penalties": {"7.7.7.7": {"mbps": 2, "until": 1000000000},
                            "8.8.8.8": {"mbps": 2, "until": 9.9e10}}})
state, _ = S.validate_export(stale)
S.apply_import(state, only=["penalties"])
live = S.load_penalties()
check("истёкший штраф не вернулся", "7.7.7.7" not in live)
check("действующий штраф вернулся", "8.8.8.8" in live)

print("\n\033[1m14. История сливается по суткам, без задвоения\033[0m")
seed()
extra = wrap({"history": [
    {"day": "2026-08-13", "down": 999, "up": 0, "ips": 1, "limited": 0, "top": []},
    {"day": "2026-08-14", "down": 7, "up": 0, "ips": 1, "limited": 0, "top": []},
]})
state, _ = S.validate_export(extra)
S.apply_import(state, only=["history"])
rows = S.read_history(limit=400)
days = [r["day"] for r in rows]
check("сутки не задвоились", len(days) == len(set(days)), str(days))
check("прежние сутки на месте", "2026-08-12" in days)
check("новые сутки добавились", "2026-08-14" in days)
check("совпавшие сутки перезаписаны",
      next(r for r in rows if r["day"] == "2026-08-13")["down"] == 999)
check("порядок по возрастанию дат", days == sorted(days))

print("\n\033[1m15. Доведение до ядра\033[0m")
seed()
open(os.path.join(PIN, "config_map"), "w").close()
open(os.environ["BPFTOOL_LOG"], "w").close()
state, _ = S.validate_export(S.build_export(with_secrets=True))
done = S.apply_import(state, keep_secrets=False)
live = S.import_to_kernel(done)
log = open(os.environ["BPFTOOL_LOG"]).read()
check("движок распознан как загруженный", live is True)
check("скорость залита в config_map", "config_map" in log)
check("порты залиты в port_map", "port_map" in log)
check("белый список залит в whitelist_map", "whitelist_map" in log)

os.remove(os.path.join(PIN, "config_map"))
open(os.environ["BPFTOOL_LOG"], "w").close()
check("без движка импорт не падает и в ядро не лезет",
      S.import_to_kernel(done) is False
      and os.path.getsize(os.environ["BPFTOOL_LOG"]) == 0)

print("\n\033[1m16. Импорт записывает событие в журнал\033[0m")
seed()
try:
    os.remove(S.EVENT_FILE)
except OSError:
    pass
quiet(S.cmd_import, ns_import(other, only="whitelist"))
events, _more = S.read_events(limit=10)
check("событие о восстановлении записано",
      any("import" in str(e.get("message", "")) for e in events), str(events))
check("в событии перечислены восстановленные разделы",
      any("whitelist" in str(e.get("message", "")) for e in events))

print("\n\033[1m17. Строки интерфейса переведены на оба языка\033[0m")
keys = set(re.findall(r'\bt\("([a-z0-9_]+)"', open(os.path.join(SRC, "shaperctl.py"),
                                                   encoding="utf-8").read()))
new_keys = {k for k in keys if k.startswith(("imp_", "exp_", "sec_", "h_exp", "h_imp"))
            } | {"h_export", "h_import"}
missing_ru = sorted(k for k in new_keys if k not in S.MSG["ru"])
missing_en = sorted(k for k in new_keys if k not in S.MSG["en"])
check("все новые ключи есть по-русски", not missing_ru, str(missing_ru))
check("все новые ключи есть по-английски", not missing_en, str(missing_en))
check("русский и английский наборы совпадают по размеру",
      len(S.MSG["ru"]) == len(S.MSG["en"]),
      f"ru={len(S.MSG['ru'])} en={len(S.MSG['en'])}")

print(f"\n\033[1mИтог: {ok} пройдено, {fail} провалено\033[0m")
sys.exit(1 if fail else 0)
