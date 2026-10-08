#!/usr/bin/env python3
"""
Немобильный лимит: конфиг, синхронизация карты mobile_lpm с кешем сетей,
предохранитель, CLI on/off/status, значение config_map в ядре, монитор.

Без root и без ядра: bpftool подменён скриптом, который хранит карты в
файлах каталога закрепления и понимает update / delete / dump / batch.
"""
import argparse
import contextlib
import importlib.util
import io
import json
import os
import struct
import sys
import tempfile
import time

SRC = os.environ.get("SHAPE_SRC") or os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))

TMP = tempfile.mkdtemp(prefix="shape-nonmobile-")
VAR = os.path.join(TMP, "var")
ETC = os.path.join(TMP, "etc")
PIN = os.path.join(TMP, "maps")
BIN = os.path.join(TMP, "bin")
for d in (VAR, ETC, PIN, BIN):
    os.makedirs(d)
os.environ["SHAPE_VAR_DIR"] = VAR
os.environ["SHAPE_ETC_DIR"] = ETC
os.environ["SHAPER_PIN_DIR"] = PIN
os.environ["BPFTOOL_LOG"] = os.path.join(TMP, "bpftool.log")

# Подставной bpftool с состоянием: карта = JSON-файл {hex ключа: hex значения}.
FAKE = r'''#!/usr/bin/env python3
import json, os, sys
log = os.environ["BPFTOOL_LOG"]

def note(s):
    with open(log, "a") as f:
        f.write(s + "\n")

def hexes(args, word):
    i = args.index(word)
    out = []
    for a in args[i + 2:]:
        if a in ("value", "key"):
            break
        out.append(a)
    return "".join(out)

def run(args):
    # args: map update|delete|dump pinned PATH ...
    if args[0] != "map":
        return 0
    verb, path = args[1], args[3]
    if os.environ.get("FAKE_FAIL_MAP") and os.path.basename(path) == os.environ["FAKE_FAIL_MAP"]:
        return 1
    if not os.path.exists(path):
        return 1
    try:
        st = json.load(open(path))
    except Exception:
        st = {}
    if verb == "update":
        st[hexes(args, "key")] = hexes(args, "value")
        note("update " + os.path.basename(path))
    elif verb == "delete":
        k = hexes(args, "key")
        if k not in st:
            return 1
        del st[k]
        note("delete " + os.path.basename(path))
    elif verb == "dump":
        rows = [{"key": ["0x" + k[i:i + 2] for i in range(0, len(k), 2)],
                 "value": ["0x" + v[i:i + 2] for i in range(0, len(v), 2)]}
                for k, v in st.items()]
        print(json.dumps(rows))
        return 0
    json.dump(st, open(path, "w"))
    return 0

a = sys.argv[1:]
if a[:2] == ["batch", "file"]:
    note("batch")
    if os.environ.get("FAKE_FAIL_BATCH"):
        sys.exit(254)
    for line in open(a[2]):
        line = line.split()
        if line and run(line) != 0:
            sys.exit(254)
    sys.exit(0)
sys.exit(run(a))
'''
with open(os.path.join(BIN, "bpftool"), "w") as f:
    f.write(FAKE)
os.chmod(os.path.join(BIN, "bpftool"), 0o755)
os.environ["PATH"] = BIN + ":" + os.environ["PATH"]

spec = importlib.util.spec_from_file_location("S", os.path.join(SRC, "shaperctl.py"))
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)

ok = fail = 0


def check(name, cond, extra=""):
    global ok, fail
    if cond:
        ok += 1
        print(f"  \033[32m✓\033[0m {name}")
    else:
        fail += 1
        print(f"  \033[31m✗ {name}\033[0m {extra}")


def run(fn, *args):
    buf, code = io.StringIO(), None
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        try:
            fn(*args)
        except SystemExit as e:
            code = e.code
    return code, buf.getvalue()


ANSI = S.re.compile(r"\033\[[0-9;?]*[A-Za-z]")


def plain(s):
    return ANSI.sub("", s)


def pin(name):
    return os.path.join(PIN, name)


def make_maps(lpm=True):
    for n in ("config_map", "mobile_lpm", "port_map", "penalty_map"):
        if os.path.exists(pin(n)):
            os.remove(pin(n))
    json.dump({}, open(pin("config_map"), "w"))
    json.dump({}, open(pin("port_map"), "w"))
    json.dump({}, open(pin("penalty_map"), "w"))
    if lpm:
        json.dump({}, open(pin("mobile_lpm"), "w"))


def kernel_cfg():
    st = json.load(open(pin("config_map")))
    raw = bytes.fromhex(st["00000000"])
    return raw, struct.unpack("<2Q", raw)


def lpm_keys():
    return {bytes.fromhex(k) for k in json.load(open(pin("mobile_lpm")))}


def write_cache(nets, updated=None):
    os.makedirs(VAR, exist_ok=True)
    with open(S.MOBILE_FILE, "w") as f:
        json.dump({"updated": time.time() if updated is None else updated,
                   "nets": nets}, f)
    S._MOBILE_IDX = None


def drop_cache():
    if os.path.exists(S.MOBILE_FILE):
        os.remove(S.MOBILE_FILE)
    S._MOBILE_IDX = None


def reset_log():
    open(os.environ["BPFTOOL_LOG"], "w").close()


def log_lines():
    return open(os.environ["BPFTOOL_LOG"]).read().split()


def key4(addr, plen):
    return struct.pack("<II", 32 + plen, 4) + bytes(map(int, addr.split("."))) + b"\0" * 12


def key6(addr, plen):
    import ipaddress
    return struct.pack("<II", 32 + plen, 6) + ipaddress.IPv6Address(addr).packed


def ns(action, speed=None):
    return argparse.Namespace(action=action, speed=speed)


def reset_cfg(nm=None):
    cfg = {"ports": [443], "speed_mbps": 10.0}
    if nm is not None:
        cfg["nonmobile_mbps"] = nm
    if os.path.exists(S.CONFIG_FILE):
        os.remove(S.CONFIG_FILE)
    S.save_config(cfg)


print("\n\033[1m1. Конфиг и размер значения в ядре\033[0m")
reset_cfg()
check("config_map: struct config — 16 байт (два u64)",
      struct.calcsize(S.CONFIG_FMT) == 16, S.CONFIG_FMT)
check("по умолчанию nonmobile_mbps = 0", S.load_config()["nonmobile_mbps"] == 0)
reset_cfg(2.5)
check("nonmobile_mbps читается из файла", S.load_config()["nonmobile_mbps"] == 2.5)
cfg = S.load_config()
cfg["speed_mbps"] = 7
S.save_config(cfg)
check("save_config сохраняет nonmobile_mbps",
      json.load(open(S.CONFIG_FILE))["nonmobile_mbps"] == 2.5)

make_maps()
write_cache([["185.1.0.0/24", "МТС"]])
S.write_to_kernel(S.load_config())
raw, (g, nm) = kernel_cfg()
check("в ядро уходит значение ровно 16 байт", len(raw) == 16, len(raw))
check("общий лимит 7 Мбит/с, немобильный 2.5 Мбит/с",
      (g, nm) == (7 * 125000, int(2.5 * 125000)), (g, nm))

reset_cfg(0)
S.write_to_kernel(S.load_config())
raw, (g, nm) = kernel_cfg()
check("режим выключен: в ядре 0, значение всё равно 16 байт",
      (g, nm, len(raw)) == (10 * 125000, 0, 16), (g, nm, len(raw)))

print("\n\033[1m2. Синхронизация карты mobile_lpm\033[0m")
make_maps()
reset_cfg(1)
write_cache([["185.1.0.0/24", "МТС"], ["10.0.0.0/8", "Билайн"],
             ["2001:db8::/32", "T2"], ["185.1.0.0/24", "дубль"]])
reset_log()
n = S.mobile_sync()
check("sync вернул число уникальных префиксов", n == 3, n)
check("ключи: prefixlen = 32 + длина, family первым словом, v4 в addr[0]",
      lpm_keys() == {key4("185.1.0.0", 24), key4("10.0.0.0", 8),
                     key6("2001:db8::", 32)})
log = log_lines()
check("одной пачкой: один вызов batch, без вызовов по записи",
      log.count("batch") == 1, log)

write_cache([["185.1.0.0/24", "МТС"], ["10.0.0.0/8", "Билайн"],
             ["20.0.0.0/16", "T2"], ["2001:db8::/32", "T2"]])
reset_log()
S.mobile_sync()
check("новые добавлены, ушедших нет — набор совпал с кешем",
      lpm_keys() == {key4("185.1.0.0", 24), key4("10.0.0.0", 8),
                     key4("20.0.0.0", 16), key6("2001:db8::", 32)})

write_cache([["185.1.0.0/24", "МТС"], ["30.0.0.0/16", "T2"]])
reset_log()
S.mobile_sync()
ops = [x for x in log_lines() if x in ("update", "delete")]
check("ушедшие префиксы удалены", lpm_keys() == {key4("185.1.0.0", 24), key4("30.0.0.0", 16)})
check("сначала добавления, потом удаления (карта не пустеет)",
      ops == sorted(ops, key=lambda x: x == "delete") and "delete" in ops, ops)
check("существующие записи не переписываются",
      ops.count("update") == 1 and ops.count("delete") == 3, ops)

reset_log()
S.mobile_sync()
check("кеш не менялся — карта не трогается вовсе",
      "update" not in log_lines() and "delete" not in log_lines()
      and "batch" not in log_lines(), log_lines())

big = [[f"{a}.{b}.0.0/16", "X"] for a in range(1, 100) for b in range(0, 256)]
write_cache(big)
before = lpm_keys()
try:
    S.mobile_sync()
    raised = False
except RuntimeError:
    raised = True
check("кеш больше карты (16384) — отказ, а не молчаливая обрезка",
      raised and lpm_keys() == before)

print("\n\033[1m3. Предохранитель: в ядро 0, если карта не заполнена\033[0m")
reset_cfg(1)
for label, setup in (
        ("нет кеша", lambda: (make_maps(), drop_cache())),
        ("кеш без сетей", lambda: (make_maps(), write_cache([]))),
        ("кеш из одного мусора", lambda: (make_maps(), write_cache([["мусор", "X"]]))),
        ("нет карты mobile_lpm (старый движок)",
         lambda: (make_maps(lpm=False), write_cache([["185.1.0.0/24", "МТС"]]))),
):
    setup()
    code, out = run(S.write_to_kernel, S.load_config())
    raw, (g, nm) = kernel_cfg()
    check(f"{label}: немобильный = 0, общий лимит записан",
          (nm, g) == (0, 10 * 125000) and code is None, (nm, g, code, out))
    check(f"{label}: предупреждение выведено", "mobile update" in out or "⚠" in out, out)
    check(f"{label}: желаемое значение осталось в конфиге",
          S.load_config()["nonmobile_mbps"] == 1)

make_maps()
write_cache([["185.1.0.0/24", "МТС"]])
os.environ["FAKE_FAIL_MAP"] = "mobile_lpm"
code, out = run(S.write_to_kernel, S.load_config())
del os.environ["FAKE_FAIL_MAP"]
raw, (g, nm) = kernel_cfg()
check("синхронизация упала (bpftool вернул ошибку): немобильный = 0",
      nm == 0 and code is None, (nm, code, out))
code, out = run(S.write_to_kernel, S.load_config())
raw, (g, nm) = kernel_cfg()
check("следующая успешная синхронизация включает режим", nm == 125000, nm)

print("\n\033[1m4. CLI nonmobile on / off / status\033[0m")
make_maps()
write_cache([["185.1.0.0/24", "МТС"]])
reset_cfg()
code, out = run(S.cmd_nonmobile, ns("on"))
check("on без --speed при первом включении — отказ", code not in (None, 0), out)
check("отказ ничего не записал", S.load_config()["nonmobile_mbps"] == 0)
for bad in (0, -1, float("nan"), float("inf"), S.MAX_MBPS + 1):
    code, out = run(S.cmd_nonmobile, ns("on", bad))
    check(f"on --speed {bad}: отказ", code not in (None, 0) and S.load_config()["nonmobile_mbps"] == 0, out)
code, out = run(S.cmd_nonmobile, ns("on", 1.0))
raw, (g, nm) = kernel_cfg()
check("on --speed 1: конфиг и ядро", code is None and S.load_config()["nonmobile_mbps"] == 1.0
      and nm == 125000, (code, nm, out))
check("on: карта заполнена", lpm_keys() == {key4("185.1.0.0", 24)})
check("on не трогает общую скорость", S.load_config()["speed_mbps"] == 10.0 and g == 10 * 125000)
code, out = run(S.cmd_nonmobile, ns("on", 3))
check("повторное on --speed 3 меняет значение",
      S.load_config()["nonmobile_mbps"] == 3.0 and kernel_cfg()[1][1] == 375000)
code, out = run(S.cmd_nonmobile, ns("on"))
check("on без --speed при уже заданной скорости — берёт сохранённую",
      code is None and S.load_config()["nonmobile_mbps"] == 3.0)

code, out = run(S.cmd_nonmobile, ns("status"))
p = plain(out)
check("status: желаемое значение", "3 Mbit/s" in p, p)
check("status: активно в ядре", ("активен" in p or "active" in p.lower()) and "не активен" not in p, p)
check("status: число префиксов в карте", "1" in p and "префикс" in p.lower(), p)
check("status: дата кеша", time.strftime("%Y-%m-%d") in p, p)
print("      --- пример вывода status ---")
for line in p.strip().splitlines():
    print("      " + line)

code, out = run(S.cmd_nonmobile, ns("off"))
raw, (g, nm) = kernel_cfg()
check("off: конфиг 0 и в ядре 0, общий лимит цел",
      code is None and S.load_config()["nonmobile_mbps"] == 0 and nm == 0 and g == 10 * 125000, out)
code, out = run(S.cmd_nonmobile, ns("status"))
check("status после off: режим выключен", "выкл" in plain(out), plain(out))

drop_cache()
make_maps()
reset_cfg()
code, out = run(S.cmd_nonmobile, ns("on", 1))
raw, (g, nm) = kernel_cfg()
check("on без кеша: значение сохранено, в ядре 0, понятное сообщение",
      code is None and S.load_config()["nonmobile_mbps"] == 1 and nm == 0
      and "mobile update" in out, (code, nm, out))
code, out = run(S.cmd_nonmobile, ns("status"))
check("status без кеша: не активен, кеша нет",
      "не активен" in plain(out) and "mobile update" in plain(out), plain(out))

shutil_pin = pin("config_map")
os.remove(shutil_pin)
reset_cfg()
code, out = run(S.cmd_nonmobile, ns("on", 2))
check("движок не запущен: настройка сохраняется, без падения",
      code is None and S.load_config()["nonmobile_mbps"] == 2, (code, out))
make_maps()

print("\n\033[1m5. Обновление кеша включает режим (CLI и сторож)\033[0m")
drop_cache()
make_maps()
reset_cfg(1)
S.mobile_fetch_asn = lambda asn: ["185.9.0.0/24"] if asn == 8359 else []
code, out = run(S.cmd_mobile, argparse.Namespace(action="update", ip=None))
raw, (g, nm) = kernel_cfg()
check("mobile update: карта синхронизирована, режим включён в ядре",
      lpm_keys() == {key4("185.9.0.0", 24)} and nm == 125000, (nm, out))

drop_cache()
make_maps()
S._MOBILE_RETRY_AT = 0
S._MOBILE_THREAD = None
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    S.mobile_due()
    S._MOBILE_THREAD.join(5)
raw, (g, nm) = kernel_cfg()
check("фоновое обновление из watch: карта и режим в ядре",
      lpm_keys() == {key4("185.9.0.0", 24)} and nm == 125000, (nm, buf.getvalue()))

reset_cfg(0)
make_maps()
drop_cache()
S._MOBILE_RETRY_AT = 0
S._MOBILE_THREAD = None
reset_log()
with contextlib.redirect_stdout(io.StringIO()):
    S.mobile_due()
    S._MOBILE_THREAD.join(5)
check("режим выключен: обновление кеша карту mobile_lpm не трогает",
      lpm_keys() == set() and "batch" not in log_lines())

print("\n\033[1m6. show и монитор\033[0m")
make_maps()
write_cache([["185.1.0.0/24", "МТС"]])
reset_cfg(1)
S.write_to_kernel(S.load_config())
S.edt_ready = lambda iface=None: (True, "")
code, out = run(S.cmd_show, argparse.Namespace())
p = plain(out)
check("show: строка про режим со скоростью", "1 Mbit/s" in p and "Немобиль" in p, p)
reset_cfg(0)
code, out = run(S.cmd_show, argparse.Namespace())
check("show: режим выключен — строка тоже есть", "Немобиль" in plain(out), plain(out))

S.require_engine = lambda: None
S.read_port_stats = lambda: {}
S.load_penalties = lambda: {"9.9.9.9": {"until": 1, "mbps": 0.5}}
S.whitelist_ips = lambda: {"7.7.7.7"}
USERS = {"185.1.0.7": {"down": 5_000_000, "up": 1_000, "up_pkts": 10, "seen": 0},
         "8.8.4.4": {"down": 5_000_000, "up": 1_000, "up_pkts": 10, "seen": 0},
         "9.9.9.9": {"down": 5_000_000, "up": 1_000, "up_pkts": 10, "seen": 0},
         "7.7.7.7": {"down": 5_000_000, "up": 1_000, "up_pkts": 10, "seen": 0},
         "127.0.0.1": {"down": 5_000_000, "up": 1_000, "up_pkts": 10, "seen": 0}}


def mon_out():
    state = {"n": 0}
    cur = {k: dict(v) for k, v in USERS.items()}
    for v in cur.values():
        v["down"] += 12_500        # монитор меряет за 0.1 с: это 1 Мбит/с
        v["up_pkts"] += 100
    seq = iter([dict(USERS), cur])

    def users():
        try:
            return next(seq)
        except StopIteration:
            return cur

    def sleep(_):
        state["n"] += 1
        if state["n"] > 1:
            raise KeyboardInterrupt
    S.read_users = users
    real = S.time.sleep
    S.time.sleep = sleep
    try:
        return plain(run(S.cmd_monitor, argparse.Namespace(interval=1, top=10))[1])
    finally:
        S.time.sleep = real


def pct_of(out, ip):
    for l in out.splitlines():
        if ip in l.split() and "%" in l:
            return l.rsplit("%", 1)[0].split()[-1]
    return "нет строки"


reset_cfg(1)
S.write_to_kernel(S.load_config())
# общий лимит 10 Мбит/с, немобильный 1: скорость 1 Мбит/с — 100% от немобильного
out = mon_out()
check("monitor: немобильный адрес — доля от немобильной скорости (100%)",
      pct_of(out, "8.8.4.4") == "100", out)
check("monitor: мобильный адрес — доля от общего лимита (10%)",
      pct_of(out, "185.1.0.7") == "10", out)
check("monitor: адрес со штрафом — как раньше, от общего лимита",
      pct_of(out, "9.9.9.9") == "10", out)
check("monitor: белый список — от общего лимита", pct_of(out, "7.7.7.7") == "10", out)
check("monitor: loopback — от общего лимита", pct_of(out, "127.0.0.1") == "10", out)
reset_cfg(0)
S.write_to_kernel(S.load_config())
out = mon_out()
check("monitor: режим выключен — все от общего лимита",
      pct_of(out, "8.8.4.4") == "10", out)


print("\n\033[1m7. Частичный отказ обновления не стирает сети оператора\033[0m")
import urllib.error
make_maps()
reset_cfg(1)
write_cache([["185.1.0.0/24", "МТС"], ["85.2.0.0/16", "Билайн"]])
S.write_to_kernel(S.load_config())
check("старый кеш в карте: МТС и Билайн",
      lpm_keys() == {key4("185.1.0.0", 24), key4("85.2.0.0", 16)})


def fake_fetch(table):
    def f(asn):
        v = table.get(asn, [])
        if isinstance(v, Exception):
            raise v
        return v
    return f


S.mobile_fetch_asn = fake_fetch({8359: urllib.error.URLError("нет ответа"),
                                 3216: ["85.2.0.0/16", "85.3.0.0/16"]})
code, out = run(S.cmd_mobile, argparse.Namespace(action="update", ip=None))
nets = {tuple(n) for n in json.load(open(S.MOBILE_FILE))["nets"]}
check("AS МТС не ответил — МТС остался в кеше", ("185.1.0.0/24", "МТС") in nets, nets)
check("новые сети Билайна добавлены", ("85.3.0.0/16", "Билайн") in nets)
check("в кеше нет дублей",
      len(json.load(open(S.MOBILE_FILE))["nets"]) == len(nets), nets)
check("МТС остался и в карте ядра, режим включён",
      key4("185.1.0.0", 24) in lpm_keys() and key4("85.3.0.0", 16) in lpm_keys()
      and kernel_cfg()[1][1] == 125000, lpm_keys())

# сеть пропала посреди обновления: после MOBILE_MAX_FAILS отказов остальные ASN пропущены
only_first = {8359: ["185.7.0.0/24"]}
S.mobile_fetch_asn = fake_fetch({**only_first, **{a: urllib.error.URLError("x")
                                                  for v in S.MOBILE_ASNS.values() for a in v
                                                  if a != 8359}})
run(S.cmd_mobile, argparse.Namespace(action="update", ip=None))
nets = {tuple(n) for n in json.load(open(S.MOBILE_FILE))["nets"]}
check("отказ по большинству AS: прежние сети сохранены",
      ("85.2.0.0/16", "Билайн") in nets and ("185.7.0.0/24", "МТС") in nets, nets)
check("и в карте ядра ничего не пропало", key4("85.2.0.0", 16) in lpm_keys())

S.mobile_fetch_asn = fake_fetch({8359: ["185.7.0.0/24"]})     # остальные ответили пусто
run(S.cmd_mobile, argparse.Namespace(action="update", ip=None))
nets = {tuple(n) for n in json.load(open(S.MOBILE_FILE))["nets"]}
check("полностью успешное обновление заменяет кеш (старые сети уходят)",
      nets == {("185.7.0.0/24", "МТС")}, nets)
check("и только теперь префиксы удалены из карты",
      lpm_keys() == {key4("185.7.0.0", 24)}, lpm_keys())

print("\n\033[1m8. Сбой синхронизации не выключает уже работающий режим\033[0m")
make_maps()
reset_cfg(1)
write_cache([["185.1.0.0/24", "МТС"]])
S.write_to_kernel(S.load_config())
write_cache([["185.1.0.0/24", "МТС"], ["20.0.0.0/16", "T2"]])
os.environ["FAKE_FAIL_BATCH"] = "1"
code, out = run(S.write_to_kernel, S.load_config())
del os.environ["FAKE_FAIL_BATCH"]
check("карта была заполнена, batch упал — немобильный лимит остаётся",
      kernel_cfg()[1][1] == 125000 and code is None, (kernel_cfg(), code, out))
check("при этом предупреждение выведено", "⚠" in out, out)
make_maps()
os.environ["FAKE_FAIL_BATCH"] = "1"
run(S.write_to_kernel, S.load_config())
del os.environ["FAKE_FAIL_BATCH"]
check("карта пуста и batch падает — в ядре 0", kernel_cfg()[1][1] == 0)
make_maps()
write_cache([["185.1.0.0/24", "МТС"]])
S.write_to_kernel(S.load_config())
drop_cache()
code, out = run(S.write_to_kernel, S.load_config())
check("карта заполнена, кеш пропал — режим держится",
      kernel_cfg()[1][1] == 125000, kernel_cfg())

print("\n\033[1m9. Фоновое обновление не пишет по устаревшему конфигу\033[0m")
make_maps()
reset_cfg(1)
write_cache([["185.1.0.0/24", "МТС"]])
real_sync = S.mobile_sync


def sync_and_change():
    n = real_sync()
    c = S.load_config()
    c["nonmobile_mbps"] = 0.0          # пока шла синхронизация, режим выключили
    c["speed_mbps"] = 20.0
    S.save_config(c)
    return n


S.mobile_sync = sync_and_change
S.nonmobile_refresh()
S.mobile_sync = real_sync
raw, (g, nm) = kernel_cfg()
check("в ядро попал свежий конфиг: режим выключен, скорость 20",
      (g, nm) == (20 * 125000, 0), (g, nm))

print("\n\033[1m10. Мусор в nonmobile_mbps не роняет restore\033[0m")
for label, raw_val in (("Infinity", "Infinity"), ("1e30", "1e30"), ("-5", "-5"),
                       ("NaN", "NaN"), ('"abc"', '"abc"'), ("null", "null"),
                       ("true", "true")):
    make_maps()
    write_cache([["185.1.0.0/24", "МТС"]])
    with open(S.CONFIG_FILE, "w") as f:
        f.write('{"ports": [443], "speed_mbps": 10, "nonmobile_mbps": %s}' % raw_val)
    check(f"{label}: load_config даёт 0", S.load_config()["nonmobile_mbps"] == 0)
    code, out = run(S.cmd_restore, argparse.Namespace())
    raw, (g, nm) = kernel_cfg()
    check(f"{label}: restore проходит, в ядре 0, общий лимит цел",
          code is None and nm == 0 and g == 10 * 125000, (code, out, g, nm))
with open(S.CONFIG_FILE, "w") as f:
    f.write('{"ports": [443], "speed_mbps": 10, "nonmobile_mbps": 2}')
check("нормальное значение читается", S.load_config()["nonmobile_mbps"] == 2)

print(f"\n\033[1mИтог: {ok} пройдено, {fail} провалено\033[0m")
sys.exit(1 if fail else 0)
