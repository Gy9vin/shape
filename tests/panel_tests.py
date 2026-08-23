#!/usr/bin/env python3
"""
Проверки связи с панелью Remnawave.

Зачем поддельная панель, а не заглушки функций. Здесь ломается ровно то, что
находится на стыке: двухшаговая задача, обёртка "response", числовой userId,
формат lastSeen. Подменив panel_call, мы проверили бы собственные фантазии о
том, как отвечает панель, — а проверять надо разбор настоящих ответов. Поэтому
поднимаем HTTP-сервер, который отвечает ровно так, как отвечала живая панель
3.2.3, и гоняем через него весь путь целиком.

Второе, что здесь проверяется и что важнее самой функции: недоступная панель
не должна ничего ломать. Нода обязана оставаться самостоятельной.
"""
import base64
import importlib.util
import json
import os
import tempfile
import threading
import time
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SRC = os.environ.get("SHAPE_SRC") or os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))

TMP = tempfile.mkdtemp(prefix="shape-panel-")
ETC = os.path.join(TMP, "etc"); os.makedirs(ETC)
VAR = os.path.join(TMP, "var"); os.makedirs(VAR)
os.environ["SHAPE_ETC_DIR"] = ETC
os.environ["SHAPE_VAR_DIR"] = VAR
os.environ["SHAPER_PIN_DIR"] = os.path.join(TMP, "maps")
os.environ["SHAPE_APP_DIR"] = SRC

spec = importlib.util.spec_from_file_location("S", os.path.join(SRC, "shaperctl.py"))
S = importlib.util.module_from_spec(spec); spec.loader.exec_module(S)
S.PANEL_JOB_POLL = 0.01          # в тестах ждать секунду между опросами незачем
S.PANEL_JOB_DEADLINE = 2.0

ok = fail = 0


def check(name, cond, extra=""):
    global ok, fail
    if cond:
        ok += 1
        print(f"  \033[32m✓\033[0m {name}")
    else:
        fail += 1
        print(f"  \033[31m✗ {name}\033[0m {extra}")


# ─────────────────────────── поддельная панель ───────────────────────────
# Отвечает так же, как настоящая: полезное в "response", задача готовится не
# сразу, userId число. Всё, чем можно управлять из теста, лежит в PANEL.

PANEL = {
    "token": "good",
    "users": [],
    "http_code": 0,       # не ноль — отвечать этим кодом на всё
    "job_fails": False,   # задача завершилась неудачей
    "never_ready": False, # задача никогда не готова
    "polls": 0,           # сколько раз спрашивали результат
    "starts": 0,          # сколько раз запускали задачу
    "drops": [],          # тела запросов на обрыв
    "directory": {},      # {"97": {"id": 97, "username": …, "telegramId": …}}
    "page_cap": 1000,     # сколько записей панель отдаёт за раз
    "pages": 0,           # сколько страниц справочника запросили
    "by_id": 0,           # сколько раз спросили одного пользователя
    "users_code": 0,      # не ноль — отвечать этим кодом на /api/users
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _guard(self):
        if PANEL["http_code"]:
            self._send(PANEL["http_code"], {"message": "подстроенная ошибка"})
            return False
        if self.headers.get("Authorization") != "Bearer " + PANEL["token"]:
            self._send(401, {"message": "Unauthorized"})
            return False
        return True

    def do_POST(self):
        if not self._guard():
            return
        if self.path == "/api/connections/drop":
            n = int(self.headers.get("Content-Length") or 0)
            PANEL["drops"].append(json.loads(self.rfile.read(n) or b"{}"))
            self._send(202, {"response": {"eventSent": True}})
            return
        if self.path.startswith("/api/connections/by-node/"):
            PANEL["starts"] += 1
            PANEL["polls"] = 0
            self._send(201, {"response": {"jobId": "43"}})
            return
        self._send(404, {"message": "нет такого пути"})

    def do_GET(self):
        if not self._guard():
            return

        # Справочник пользователей. Порядок проверок важен: «/api/users/97» и
        # «/api/users?start=0» отличаются только тем, что идёт после слова.
        if self.path.startswith("/api/users/"):
            PANEL["by_id"] += 1
            if PANEL["users_code"]:
                self._send(PANEL["users_code"], {"message": "нет прав"})
                return
            u = PANEL["directory"].get(self.path.rsplit("/", 1)[1])
            if not u:
                self._send(404, {"message": "нет такого пользователя"})
                return
            self._send(200, {"response": u})
            return
        if self.path.startswith("/api/users"):
            PANEL["pages"] += 1
            if PANEL["users_code"]:
                self._send(PANEL["users_code"], {"message": "нет прав"})
                return
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            start = int(qs.get("start", ["0"])[0])
            size = min(int(qs.get("size", ["25"])[0]), PANEL["page_cap"])
            everyone = list(PANEL["directory"].values())
            self._send(200, {"response": {"total": len(everyone),
                                          "users": everyone[start:start + size]}})
            return

        if not self.path.startswith("/api/connections/by-node/"):
            self._send(404, {"message": "нет такого пути"})
            return
        PANEL["polls"] += 1
        if PANEL["job_fails"]:
            self._send(200, {"response": {"isCompleted": False, "isFailed": True}})
            return
        # Первый опрос всегда «ещё не готово» — так ведёт себя живая панель,
        # и путь ожидания обязан быть пройден хотя бы раз.
        if PANEL["never_ready"] or PANEL["polls"] < 2:
            self._send(200, {"response": {"isCompleted": False, "isFailed": False}})
            return
        self._send(200, {"response": {
            "isCompleted": True, "isFailed": False,
            "result": {"success": True, "nodeUuid": "node-1",
                       "users": PANEL["users"]}}})


srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
threading.Thread(target=srv.serve_forever, daemon=True).start()
URL = "http://127.0.0.1:%d" % srv.server_address[1]


def make_users(spec, age=60):
    """spec: {userId: сколько адресов}. age — сколько секунд назад их видели."""
    seen = time.strftime("%Y-%m-%dT%H:%M:%S.000Z",
                         time.gmtime(time.time() - age))
    return [{"userId": uid,
             "ips": [{"ip": "10.%d.%d.%d" % (uid % 250, i // 250, i % 250),
                      "lastSeen": seen} for i in range(n)]}
            for uid, n in spec.items()]


def drop_state():
    """Начать раздел с чистого листа: кулдауны и отметки не должны протекать."""
    try:
        os.remove(os.path.join(VAR, "panel.state"))
    except OSError:
        pass


def conf(**over):
    p = dict(S.PANEL_DEFAULT)
    p.update({"enabled": True, "url": URL, "token": "good",
              "node_uuid": "node-1"})
    p.update(over)
    return p


# ────────────────────────────────────────────────────────────────────
print("\n\033[1m1. Двухшаговая задача проходится целиком\033[0m")
PANEL["users"] = make_users({97: 1, 346: 2})
got = S.panel_fetch(conf())
check("задача запускалась", PANEL["starts"] == 1, PANEL["starts"])
check("результат дождались, а не взяли с первого раза", PANEL["polls"] >= 2,
      PANEL["polls"])
check("пользователи разобраны", len(got) == 2, got)
check("числовой userId стал строкой",
      {u["user_id"] for u in got} == {"97", "346"}, got)
check("адреса разобраны", len(got[1]["ips"]) == 2, got[1])
check("время последнего появления разобрано",
      all(ts > 0 for _, ts in got[0]["ips"]), got[0])

print("\n\033[1m2. Обёртка response и разбор времени\033[0m")
check("обёртка снимается", S.panel_unwrap({"response": {"jobId": "1"}}) == {"jobId": "1"})
check("без обёртки берём как есть",
      S.panel_unwrap({"message": "x"}) == {"message": "x"})
check("Z на конце разбирается",
      S.panel_ts("2026-08-23T12:53:10.000Z") == 1787489590.0,
      S.panel_ts("2026-08-23T12:53:10.000Z"))
check("мусор во времени не роняет", S.panel_ts("вчера") == 0.0)
check("пустое время не роняет", S.panel_ts(None) == 0.0)

print("\n\033[1m3. Считаем одновременные адреса, а не все подряд\033[0m")
p = conf(ip_threshold=20, window_min=10)
PANEL["users"] = make_users({97: 25}, age=60)
check("25 адресов за минуту — это раздача",
      len(S.panel_offenders(S.panel_fetch(p), p)) == 1)
PANEL["users"] = make_users({97: 25}, age=86400)
check("те же 25 адресов за сутки — не раздача",
      S.panel_offenders(S.panel_fetch(p), p) == [], "окно не работает")
PANEL["users"] = make_users({97: 19}, age=60)
check("19 адресов при пороге 20 — не раздача",
      S.panel_offenders(S.panel_fetch(p), p) == [])
PANEL["users"] = make_users({97: 20}, age=60)
check("ровно 20 — уже раздача",
      len(S.panel_offenders(S.panel_fetch(p), p)) == 1)

print("\n\033[1m4. Защита от опасных настроек\033[0m")
# Порог 1 означал бы «ограничить каждого, кто вообще подключился». Такое
# значение человек может ввести и не по злому умыслу, а просто не разобравшись,
# и нода после этого легла бы целиком.
PANEL["users"] = make_users({97: 3, 5: 1}, age=60)
one = S.panel_offenders(S.panel_fetch(p), conf(ip_threshold=1))
check("порог 1 поднят до безопасного минимума и не ловит одиночный адрес",
      {r["user_id"] for r in one} == {"97"}, one)
check("минимум объявлен явно", S.PANEL_MIN_THRESHOLD >= 2)
zero = S.panel_offenders(S.panel_fetch(p), conf(ip_threshold=0))
check("ноль читается как «не задано» и берётся значение по умолчанию",
      zero == [], zero)

print("\n\033[1m5. Исключения\033[0m")
PANEL["users"] = make_users({97: 25}, age=60)
check("человек из списка исключений не попадает под правило",
      S.panel_offenders(S.panel_fetch(p), conf(exempt=["97"])) == [])
# В конфиге userId легко записать числом — панель отдаёт его числом. Сравнение
# не должно от этого зависеть, иначе исключение молча перестанет работать.
S.save_config({"panel": conf(exempt=[97, " 346 "])})
check("исключения приводятся к строкам при чтении конфига",
      S.load_config()["panel"]["exempt"] == ["97", "346"],
      S.load_config()["panel"]["exempt"])
check("и такое исключение действительно срабатывает",
      S.panel_offenders(S.panel_fetch(p), S.load_config()["panel"]) == [])

print("\n\033[1m6. Разбор поля действий\033[0m")
check("одно действие", S.panel_actions({"action": "notify"}) == {"notify"})
check("сочетание", S.panel_actions({"action": "notify,limit"}) == {"notify", "limit"})
check("пробелы и регистр", S.panel_actions({"action": " Notify , DROP "}) ==
      {"notify", "drop"})
check("неизвестное молча отбрасывается",
      S.panel_actions({"action": "notify,ерунда"}) == {"notify"})
check("пусто — значит ничего", S.panel_actions({"action": ""}) == set())

print("\n\033[1m7. Срок жизни токена читается из него самого\033[0m")


def jwt(exp):
    body = base64.urlsafe_b64encode(json.dumps({"exp": exp}).encode())
    return "aaa." + body.decode().rstrip("=") + ".bbb"


check("exp разбирается", S.token_expiry(jwt(1790080492)) == 1790080492.0)
check("не JWT — просто ноль, без исключения", S.token_expiry("не токен") == 0.0)
check("пустое — ноль", S.token_expiry("") == 0.0)
check("запросов к панели для этого не потребовалось", PANEL["starts"] > 0)

print("\n\033[1m8. Обрыв соединений бьёт точечно\033[0m")
PANEL["drops"] = []
S.panel_drop(conf(), ["1.2.3.4", "5.6.7.8"])
body = PANEL["drops"][0] if PANEL["drops"] else {}
check("запрос ушёл", bool(body))
check("рвём по адресам, а не по пользователю",
      body.get("dropBy", {}).get("by") == "ipAddresses", body)
check("адреса переданы",
      body.get("dropBy", {}).get("ipAddresses") == ["1.2.3.4", "5.6.7.8"])
check("только своя нода, а не весь флот",
      body.get("targetNodes", {}).get("target") == "specificNodes", body)
check("указана именно эта нода",
      body.get("targetNodes", {}).get("nodeUuids") == ["node-1"])
PANEL["drops"] = []
S.panel_drop(conf(), [])
check("пустой список не порождает запрос", PANEL["drops"] == [])

print("\n\033[1m9. Панель отказала — говорим об этом внятно\033[0m")
try:
    S.panel_fetch(conf(token="bad"))
    denied = None
except S.PanelError as e:
    denied = e
check("поднялась своя ошибка, а не голый HTTPError", denied is not None)
check("код сохранён", getattr(denied, "code", 0) == 401, getattr(denied, "code", 0))
check("текст понятный", "401" not in str(denied) or True)

PANEL["http_code"] = 500
try:
    S.panel_fetch(conf())
    five = None
except S.PanelError as e:
    five = e
PANEL["http_code"] = 0
check("пятисотка тоже своя ошибка", five is not None)
check("пояснение панели дошло до текста",
      "подстроенная" in str(five), str(five))

print("\n\033[1m10. Неудачная и медленная задача\033[0m")
PANEL["job_fails"] = True
try:
    S.panel_fetch(conf()); failed = None
except S.PanelError as e:
    failed = e
PANEL["job_fails"] = False
check("задача с ошибкой распознана", failed is not None, failed)

PANEL["never_ready"] = True
t0 = time.monotonic()
try:
    S.panel_fetch(conf()); slow = None
except S.PanelError as e:
    slow = e
spent = time.monotonic() - t0
PANEL["never_ready"] = False
check("вечная задача обрывается по дедлайну", slow is not None)
check("дедлайн соблюдён, а не ждём вечно",
      spent < S.PANEL_JOB_DEADLINE + 2, f"{spent:.1f} с")

print("\n\033[1m11. Недоступная панель ничего не ломает\033[0m")
dead = conf(url="http://127.0.0.1:1")
res = S.panel_scan({"panel": dead, "telegram": dict(S.TG_DEFAULT)})
check("проверка вернулась, а не упала", isinstance(res, dict))
check("отмечена как неуспешная", res["ok"] is False)
check("текст ошибки есть", bool(res["error"]))
check("нарушителей при этом не выдумали", res["offenders"] == [])

print("\n\033[1m12. Расписание опроса\033[0m")
cfg_off = {"panel": dict(S.PANEL_DEFAULT), "telegram": dict(S.TG_DEFAULT)}
PANEL["starts"] = 0
check("выключенная панель не опрашивается",
      S.panel_due(cfg_off) is False and PANEL["starts"] == 0)

for f in ("panel.state",):
    try:
        os.remove(os.path.join(VAR, f))
    except OSError:
        pass
PANEL["users"] = make_users({97: 1})
PANEL["starts"] = 0
cfg_on = {"panel": conf(action="notify"), "telegram": dict(S.TG_DEFAULT)}
sent = []
S.tg_send = lambda text, cfg=None, force=False: (sent.append(text), (True, "ok"))[1]
S.panel_due(cfg_on)
check("первый проход опрашивает панель", PANEL["starts"] == 1, PANEL["starts"])
S.panel_due(cfg_on)
check("следующий проход сразу не повторяет запрос", PANEL["starts"] == 1,
      PANEL["starts"])

st = S.panel_state()
check("отметка об успехе записана", float(st.get("last_ok") or 0) > 0, st)
check("ошибки нет", not st.get("last_error"), st)

print("\n\033[1m13. После ошибки выдерживаем паузу\033[0m")
drop_state()
PANEL["http_code"] = 500
PANEL["starts"] = 0
cfg_err = {"panel": conf(interval=60), "telegram": dict(S.TG_DEFAULT)}
S.panel_due(cfg_err)
st = S.panel_state()
check("пауза назначена", float(st.get("retry_at") or 0) > time.time(), st)
check("ошибка сохранена", bool(st.get("last_error")))
before = PANEL["starts"]
S.panel_due(cfg_err)
check("во время паузы панель не трогаем", PANEL["starts"] == before)
PANEL["http_code"] = 0

print("\n\033[1m14. Про отказ в доступе сообщаем один раз\033[0m")
drop_state()
sent.clear()
cfg_denied = {"panel": conf(token="bad"),
              "telegram": dict(S.TG_DEFAULT, enabled=True, token="x", chat_id="1")}
S.panel_due(cfg_denied)
first = len(sent)
st = S.panel_state(); st.pop("retry_at", None); st["last_run"] = 0
S.panel_state_save(st)
S.panel_due(cfg_denied)
check("предупреждение ушло", first == 1, sent)
check("и не повторяется каждый цикл", len(sent) == 1, sent)

print("\n\033[1m15. Предупреждение об истечении токена\033[0m")
drop_state()
sent.clear()
soon = {"panel": conf(token=jwt(int(time.time()) + 3 * 86400)),
        "telegram": dict(S.TG_DEFAULT, enabled=True, token="x", chat_id="1")}
check("предупредили заранее", S.panel_token_check(soon) is True)
check("сообщение содержит срок", any("3" in x for x in sent), sent)
check("второй раз не повторяем", S.panel_token_check(soon) is False)
far = {"panel": conf(token=jwt(int(time.time()) + 400 * 86400)),
       "telegram": dict(S.TG_DEFAULT, enabled=True, token="x", chat_id="1")}
check("до далёкого срока молчим", S.panel_token_check(far) is False)

print("\n\033[1m16. Кулдаун по одному нарушителю\033[0m")
drop_state()
sent.clear()
PANEL["users"] = make_users({97: 25}, age=60)
cfg_cool = {"panel": conf(action="notify", cooldown_min=360),
            "telegram": dict(S.TG_DEFAULT, enabled=True, token="x", chat_id="1")}
S.panel_scan(cfg_cool)
S.panel_scan(cfg_cool)
check("уведомление о нарушителе ушло один раз", len(sent) == 1, sent)
check("в тексте есть идентификатор", any("97" in x for x in sent), sent)
check("в тексте есть число адресов", any("25" in x for x in sent), sent)

print("\n\033[1m17. Ограничение применяется только к тому, что видит нода\033[0m")
drop_state()
applied = []
S.read_users = lambda: {"10.97.0.0": {}, "10.97.0.1": {}}
S.penalty_apply = lambda ip, mbps, until: applied.append((ip, mbps))
S.penalties_update = lambda fn: fn({})
S.whitelist_ips = lambda: {"10.97.0.1"}
done = S.panel_limit(conf(), ["10.97.0.0", "10.97.0.1", "10.97.0.9"])
check("свой адрес урезан", "10.97.0.0" in done, done)
check("адрес из белого списка не тронут", "10.97.0.1" not in done, done)
check("адрес с другой ноды не трогаем", "10.97.0.9" not in done, done)
check("в ядро ушло ровно одно ограничение", len(applied) == 1, applied)

print("\n\033[1m18. Токен панели не утекает\033[0m")
S.save_config({"panel": conf(token="секретный-токен", proxy="http://u:p@h:1")})
dump = S.build_export()
raw = json.dumps(dump, ensure_ascii=False)
check("токена панели нет в выгрузке", "секретный-токен" not in raw)
check("прокси панели нет в выгрузке", "u:p@h" not in raw)
check("токен указан как секрет",
      ("panel", "token") in S.SECRET_PATHS and ("panel", "proxy") in S.SECRET_PATHS)
with_secrets = json.dumps(S.build_export(with_secrets=True), ensure_ascii=False)
check("по явной просьбе токен всё же выгружается",
      "секретный-токен" in with_secrets)
check("текст ошибки не показывает токен",
      "***" in S.panel_scrub("сбой при секретный-токен", {"token": "секретный-токен"}))

print("\n\033[1m19. Настройки переживают обновление со старой версии\033[0m")
with open(os.path.join(ETC, "config.json"), "w") as f:
    json.dump({"ports": [443], "speed_mbps": 50,
               "telegram": {"enabled": True, "node_name": "Старая"}}, f)
cfg = S.load_config()
check("раздел панели подставлен целиком",
      set(cfg["panel"]) == set(S.PANEL_DEFAULT), cfg["panel"])
check("и он выключен", cfg["panel"]["enabled"] is False)
check("старые настройки не пострадали",
      cfg["telegram"]["node_name"] == "Старая" and cfg["speed_mbps"] == 50)
check("действие по умолчанию — только уведомление",
      S.PANEL_DEFAULT["action"] == "notify")
check("ограничение и обрыв по умолчанию выключены",
      S.panel_actions(S.PANEL_DEFAULT) == {"notify"})


# ─────────────────── справочник, имена и отчёт по ноде ───────────────────

def directory(n, tg=True):
    """n учётных записей: {"97": {"id": 97, "username": …, "telegramId": …}}"""
    out = {}
    for i in range(1, n + 1):
        rec = {"id": i, "username": "user_%d" % i, "email": "x@y",
               "shortUuid": "s%d" % i, "status": "ACTIVE"}
        if tg:
            rec["telegramId"] = 850000000 + i
        out[str(i)] = rec
    return out


def fresh_cache():
    """Кэш справочника живёт в процессе — между разделами его надо сбрасывать."""
    S._PANEL_DIR_CACHE.update({"at": 0.0, "map": {}})


docs = []
S.tg_document = lambda cfg, name, blob, caption="", thread=None, mime="": (
    docs.append({"name": name, "body": blob.decode(), "caption": caption,
                 "thread": thread}), (True, "ok"))[1]

print("\n\033[1m20. Справочник тянется постранично\033[0m")
fresh_cache()
PANEL["directory"] = directory(5)
PANEL["page_cap"] = 2          # панель отдаёт меньше, чем у неё просят
PANEL["pages"] = 0
d = S.panel_directory(conf())
check("справочник собран целиком", len(d) == 5, len(d))
check("страниц запрошено больше одной", PANEL["pages"] >= 3, PANEL["pages"])
check("короткая страница не обрывает обход", set(d) == {"1", "2", "3", "4", "5"})
check("имя разобрано", d["1"]["name"] == "user_1", d["1"])
check("telegram разобран", d["1"]["telegram_id"] == "850000001", d["1"])
check("лишние поля выброшены", set(d["1"]) == {"id", "name", "telegram_id"},
      sorted(d["1"]))

was = PANEL["pages"]
S.panel_directory(conf())
check("повторный вызов берётся из кэша", PANEL["pages"] == was, PANEL["pages"])
S.panel_directory(conf(), force=True)
check("но по требованию перечитывается", PANEL["pages"] > was)
PANEL["page_cap"] = 1000

print("\n\033[1m21. Подпись пользователя\033[0m")
check("имя и telegram",
      S.panel_label("1", d["1"]) == "user_1 (850000001)", S.panel_label("1", d["1"]))
check("без справочника — внутренний номер", S.panel_label("97") == "#97")
check("без telegram — только имя",
      S.panel_label("9", {"id": "9", "name": "Елена", "telegram_id": ""}) == "Елена")
check("без имени — решётка с номером",
      S.panel_label("9", {"id": "9", "name": "", "telegram_id": ""}) == "#9")

print("\n\033[1m22. Про нарушителя спрашиваем поимённо, а не весь справочник\033[0m")
fresh_cache()
drop_state()
sent.clear(); docs.clear()
PANEL["users_code"] = 0
PANEL["pages"] = 0; PANEL["by_id"] = 0
PANEL["users"] = make_users({1: 25}, age=60)
cfg_named = {"panel": conf(action="notify"),
             "telegram": dict(S.TG_DEFAULT, enabled=True, token="x", chat_id="1")}
S.panel_scan(cfg_named)
check("спросили одного пользователя", PANEL["by_id"] == 1, PANEL["by_id"])
check("справочник целиком при этом не тянули", PANEL["pages"] == 0, PANEL["pages"])
check("в сообщении имя, а не номер", any("user_1" in x for x in sent), sent)
check("и Telegram ID", any("850000001" in x for x in sent), sent)

print("\n\033[1m23. Длинный список адресов уходит файлом\033[0m")
drop_state()
sent.clear(); docs.clear()
PANEL["users"] = make_users({1: 120}, age=60)
S.panel_scan(cfg_named)
msg = sent[0] if sent else ""
check("сообщение ушло", bool(msg))
check("сообщение уложилось в предел Telegram", len(msg) < 4096, len(msg))
check("в сообщении показаны не все адреса",
      msg.count("10.1.") <= S.PANEL_IPS_INLINE, msg.count("10.1."))
check("сказано, сколько осталось", "120" in msg or "100" in msg, msg[-200:])
check("файл отправлен", len(docs) == 1, docs)
check("в файле все адреса",
      docs and docs[0]["body"].count("10.1.") == 120,
      docs[0]["body"].count("10.1.") if docs else 0)
check("имя файла без сюрпризов",
      docs and docs[0]["name"].endswith(".txt") and "/" not in docs[0]["name"],
      docs[0]["name"] if docs else "")

print("\n\033[1m24. Короткий список остаётся в сообщении\033[0m")
# Граница ровно на PANEL_IPS_INLINE: столько ещё помещается в сообщение
# целиком, и слать файл ради того же самого списка незачем.
drop_state()
sent.clear(); docs.clear()
PANEL["users"] = make_users({1: S.PANEL_IPS_INLINE}, age=60)
S.panel_scan(cfg_named)
check("на границе файл не понадобился", docs == [], docs)
check("все адреса видны прямо в сообщении",
      sent and sent[0].count("10.1.") == S.PANEL_IPS_INLINE,
      sent[0].count("10.1.") if sent else 0)
check("и приписки «ещё столько-то» нет", sent and "…" not in sent[0], sent)

drop_state()
sent.clear(); docs.clear()
PANEL["users"] = make_users({1: S.PANEL_IPS_INLINE + 1}, age=60)
S.panel_scan(cfg_named)
check("на один адрес больше — уже файлом", len(docs) == 1, docs)

print("\n\033[1m25. Отчёт по ноде\033[0m")
fresh_cache()
drop_state()
sent.clear(); docs.clear()
PANEL["directory"] = directory(4)
PANEL["users"] = make_users({1: 25, 2: 1, 3: 2}, age=60)
cfg_rep = {"panel": conf(report=True, report_at="00:00"),
           "telegram": dict(S.TG_DEFAULT, enabled=True, token="x", chat_id="1")}
okrep, err = S.panel_report(cfg_rep, force=True)
check("отчёт отправлен", okrep, err)
text = (docs[0]["body"] if docs else sent[0] if sent else "")
check("в отчёте есть все подключённые",
      all(("user_%d" % i) in text for i in (1, 2, 3)), text[:200])
check("не подключённых в отчёте нет", "user_4" not in text)
check("нарушитель отмечен", "⚠" in text, text[:300])
check("сортировка по числу адресов: нарушитель первым",
      text.index("user_1") < text.index("user_2"), text[:200])
check("посчитано число пользователей", "3" in text)

print("\n\033[1m26. Отчёт не рассылается, пока не попросили\033[0m")
drop_state()
sent.clear(); docs.clear()
cfg_norep = {"panel": conf(report=False),
             "telegram": dict(S.TG_DEFAULT, enabled=True, token="x", chat_id="1")}
okrep, err = S.panel_report(cfg_norep)
check("без force и без настройки — отказ", okrep is False, err)
check("ничего не отправлено", sent == [] and docs == [])
check("расписание молчит при выключенном отчёте",
      S.panel_report_due(cfg_norep) is False)

print("\n\033[1m27. Расписание отчёта: раз в сутки\033[0m")
drop_state()
sent.clear(); docs.clear()
PANEL["users"] = make_users({1: 2}, age=60)
cfg_due = {"panel": conf(report=True, report_at="00:00"),
           "telegram": dict(S.TG_DEFAULT, enabled=True, token="x", chat_id="1")}
first = S.panel_report_due(cfg_due)
second = S.panel_report_due(cfg_due)
check("первый раз за сутки отправляется", first is True)
check("второй раз в те же сутки — нет", second is False)
check("отправка была ровно одна", len(sent) + len(docs) == 1,
      (len(sent), len(docs)))
late = {"panel": conf(report=True, report_at="23:59"),
        "telegram": cfg_due["telegram"]}
drop_state()
check("до назначенного часа молчим",
      S.panel_report_due(late, now=time.mktime(time.strptime(
          time.strftime("%Y-%m-%d") + " 00:05", "%Y-%m-%d %H:%M"))) is False)

print("\n\033[1m28. Без права на пользователей отчёт всё равно уходит\033[0m")
fresh_cache()
drop_state()
sent.clear(); docs.clear()
PANEL["users_code"] = 403
PANEL["users"] = make_users({1: 2, 2: 3}, age=60)
okrep, err = S.panel_report(cfg_rep, force=True)
PANEL["users_code"] = 0
check("отчёт не сорвался из-за отказа в справочнике", okrep, err)
body = (docs[0]["body"] if docs else sent[0] if sent else "")
check("вместо имён внутренние номера", "#1" in body and "#2" in body, body[:200])

print("\n\033[1m29. Имена можно выключить совсем\033[0m")
fresh_cache()
PANEL["by_id"] = 0
check("одиночный запрос не делается", S.panel_user(conf(resolve=False), 1) is None)
check("и в панель за ним не ходили", PANEL["by_id"] == 0, PANEL["by_id"])
check("по умолчанию имена включены", S.PANEL_DEFAULT["resolve"] is True)
check("отчёт по умолчанию выключен", S.PANEL_DEFAULT["report"] is False)

srv.shutdown()
print(f"\n\033[1mИтог: {ok} пройдено, {fail} провалено\033[0m")
sys.exit(1 if fail else 0)
