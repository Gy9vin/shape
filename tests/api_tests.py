#!/usr/bin/env python3
"""
Тесты Shape Node API. Поднимают настоящий сервер в песочнице:
подставные bpftool и systemctl, свой /etc/shaper, свои карты.
"""
import importlib.util
import json
import os
import socket
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

import os as _os
# Корень проекта: каталог над tests/. Так набор работает и локально, и в CI.
SRC = _os.environ.get("SHAPE_SRC") or _os.path.dirname(_os.path.dirname(
    _os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix="shape-api-test-")
ETC = os.path.join(TMP, "etc"); os.makedirs(ETC)
VAR = os.path.join(TMP, "var"); os.makedirs(VAR)
BIN = os.path.join(TMP, "bin"); os.makedirs(BIN)
PIN = os.path.join(TMP, "maps"); os.makedirs(PIN)

# карты «существуют» — движок считается запущенным
for m in ("config_map", "port_map", "whitelist_map", "penalty_map",
          "user_state_map_down", "user_state_map_up"):
    open(os.path.join(PIN, m), "w").close()

# подставной bpftool: записывает вызовы, на dump отдаёт пустой список
with open(os.path.join(BIN, "bpftool"), "w") as f:
    f.write('#!/bin/sh\nprintf "%s\\n" "$*" >> "$BPFTOOL_LOG"\n'
            'case "$*" in *dump*) echo "[]";; esac\nexit 0\n')
with open(os.path.join(BIN, "systemctl"), "w") as f:
    f.write('#!/bin/sh\n[ "$1" = "is-active" ] && echo active\nexit 0\n')
with open(os.path.join(BIN, "ip"), "w") as f:
    f.write('#!/bin/sh\necho "2: eth0    inet 203.0.113.5/24 scope global eth0"\n')
for name in ("bpftool", "systemctl", "ip"):
    os.chmod(os.path.join(BIN, name), 0o755)

os.environ["PATH"] = BIN + ":" + os.environ["PATH"]
os.environ["BPFTOOL_LOG"] = os.path.join(TMP, "bpftool.log")
os.environ["SHAPER_PIN_DIR"] = PIN
os.environ["SHAPE_APP_DIR"] = SRC
os.environ["SHAPE_ETC_DIR"] = ETC

spec = importlib.util.spec_from_file_location("apisrv", os.path.join(SRC, "api", "server.py"))
api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(api)

# перенаправляем состояние Shape в песочницу
S = api.S
S.ETC_DIR = ETC
S.CONFIG_FILE = os.path.join(ETC, "config.json")
S.PEN_FILE = os.path.join(ETC, "penalties.json")
S.DAILY_FILE = os.path.join(ETC, "daily.json")
S.DIGEST_FILE = os.path.join(ETC, "digest.json")
S.WL_FILE = os.path.join(ETC, "whitelist.txt")
S.VAR_DIR = VAR
S.EVENT_FILE = os.path.join(VAR, "events.jsonl")
S.EVENT_SEQ = os.path.join(VAR, "events.seq")
S.OWNERS_FILE = os.path.join(VAR, "owners.json")
S.HISTORY_FILE = os.path.join(VAR, "history.jsonl")
S.save_config({"ports": [443], "speed_mbps": 15,
               "guard": dict(S.GUARD_DEFAULT),
               "telegram": dict(S.TG_DEFAULT, token="123456789:SECRET-TOKEN-VALUE",
                                chat_id="-100500", enabled=True)})
S.save_penalties({})
open(S.WL_FILE, "w").write("198.51.100.7\n")

# конфиг API: высокие пределы, чтобы тесты не упирались в rate limit
PORT = 18765
API_CONF = os.path.join(ETC, "api.json")
BASE_CFG = {"bind_address": "127.0.0.1", "port": PORT, "allowed_ips": [],
            "rate_read_per_min": 100000, "rate_write_per_min": 100000,
            "auth_fail_per_min": 100000, "expose_docs": True,
            "tokens": {"read": "READ-" + "r" * 30, "write": "WRITE-" + "w" * 30}}


def write_cfg(**over):
    cfg = dict(BASE_CFG); cfg.update(over)
    with open(API_CONF, "w") as f:
        json.dump(cfg, f)
    os.chmod(API_CONF, 0o600)


write_cfg()
READ, WRITE = BASE_CFG["tokens"]["read"], BASE_CFG["tokens"]["write"]

# журнал сервера пишется в stdout — перехватываем, чтобы проверить утечки
LOGBUF = []
api.log = lambda **f: LOGBUF.append(json.dumps(f, ensure_ascii=False))

api.Server.address_family = socket.AF_INET
srv = api.Server(("127.0.0.1", PORT), api.Handler)
threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.1},
                 daemon=True).start()
time.sleep(0.4)

ok = fail = 0


def check(name, cond, extra=""):
    global ok, fail
    if cond:
        ok += 1
        print(f"  \033[32m✓\033[0m {name}")
    else:
        fail += 1
        print(f"  \033[31m✗ {name}\033[0m {extra}")


def call(method, path, token=None, body=None, raw=None, headers=None, timeout=10):
    url = f"http://127.0.0.1:{PORT}{path}"
    data = raw if raw is not None else (
        json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(url, data=data, method=method)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            payload = r.read()
            try:
                return r.status, json.loads(payload)
            except ValueError:
                return r.status, payload.decode(errors="replace")
    except urllib.error.HTTPError as e:
        payload = e.read()
        try:
            return e.code, json.loads(payload)
        except ValueError:
            return e.code, payload.decode(errors="replace")
    except Exception as e:
        return 0, str(e)


print("\n\033[1m1. Health и документация\033[0m")
st, body = call("GET", "/api/v1/health")
check("health без токена → 200", st == 200 and body == {"status": "ok"}, body)
check("health не раскрывает ничего лишнего", set(body) == {"status"})
st, body = call("GET", "/api/v1/openapi.json")
check("openapi.json отдаётся", st == 200 and body.get("openapi", "").startswith("3."))
check("в openapi описан bearer",
      "bearerAuth" in body.get("components", {}).get("securitySchemes", {}))
check("в openapi есть все ключевые пути",
      all(p in body["paths"] for p in
          ("/health", "/status", "/node", "/limits", "/limits/{ip}",
           "/limits/{ip}/temporary", "/stats", "/events", "/config", "/bpf/status")))

print("\n\033[1m2. Аутентификация и права\033[0m")
st, body = call("GET", "/api/v1/status")
check("без токена → 401", st == 401 and body["error"]["code"] == "UNAUTHORIZED")
st, _ = call("GET", "/api/v1/status", token="wrong-token-value")
check("неверный токен → 401", st == 401)
st, _ = call("GET", "/api/v1/status", token=READ[:-1])
check("токен без последнего символа → 401", st == 401)
st, _ = call("GET", "/api/v1/status", token=READ)
check("токен чтения на чтении → 200", st == 200)
st, _ = call("GET", "/api/v1/status", token=WRITE)
check("токен записи тоже читает → 200", st == 200)
st, body = call("POST", "/api/v1/limits", token=READ,
                body={"ip": "1.2.3.4", "download_mbps": 1})
check("токен чтения на записи → 403", st == 403 and body["error"]["code"] == "FORBIDDEN")
st, _ = call("GET", "/api/v1/status", headers={"Authorization": "Basic " + READ})
check("схема Basic не принимается", st == 401)

print("\n\033[1m3. Статус, нода, BPF\033[0m")
st, body = call("GET", "/api/v1/status", token=READ)
check("статус отдаёт версии и состояние",
      st == 200 and body["versions"]["shape"] and body["shape"]["engine_loaded"] is True)
check("в статусе нет секретов", "token" not in json.dumps(body).lower())
st, body = call("GET", "/api/v1/node", token=READ)
check("нода отдаёт hostname, ядро, архитектуру",
      st == 200 and body["hostname"] and body["kernel"] and body["architecture"])
check("нода не отдаёт секретов",
      not any(k in json.dumps(body) for k in ("SECRET-TOKEN", "tokens", "private")))
st, body = call("GET", "/api/v1/bpf/status", token=READ)
check("bpf/status перечисляет карты",
      st == 200 and body["loaded"] and len(body["maps"]) == 6)

print("\n\033[1m4. Создание и снятие ограничений\033[0m")
st, body = call("POST", "/api/v1/limits", token=WRITE,
                body={"ip": "203.0.113.10", "download_mbps": 1, "upload_mbps": 1,
                      "duration": 43200, "reason": "torrent"})
check("создание → 201", st == 201, body)
check("в ответе все обещанные поля",
      st == 201 and all(k in body for k in
                        ("ip", "family", "download_mbps", "upload_mbps", "created_at",
                         "expires_at", "remaining_seconds", "reason", "source", "type")),
      body)
check("source=api, type=temporary",
      st == 201 and body["source"] == "api" and body["type"] == "temporary")
check("остаток времени близок к 43200",
      st == 201 and 43190 <= body["remaining_seconds"] <= 43200)
check("ограничение записано в общий файл Shape",
      "203.0.113.10" in S.load_penalties())
check("правило доехало до карты ядра",
      "penalty_map" in open(os.environ["BPFTOOL_LOG"]).read())

st, body = call("GET", "/api/v1/limits/203.0.113.10", token=READ)
check("чтение конкретного адреса → 200", st == 200 and body["ip"] == "203.0.113.10")
st, body = call("GET", "/api/v1/limits", token=READ)
check("список содержит адрес", st == 200 and body["count"] == 1)
st, body = call("GET", "/api/v1/limits/198.51.100.99", token=READ)
check("несуществующий адрес → 404",
      st == 404 and body["error"]["code"] == "LIMIT_NOT_FOUND")

st, body = call("POST", "/api/v1/limits/203.0.113.11/temporary", token=WRITE,
                body={"download_mbps": 2, "duration": 600, "reason": "manual check"})
check("временное ограничение через путь → 201", st == 201 and body["ip"] == "203.0.113.11")
st, body = call("DELETE", "/api/v1/limits/203.0.113.11/temporary", token=WRITE)
check("снятие временного → 200", st == 200)
check("запись убрана из файла", "203.0.113.11" not in S.load_penalties())
st, body = call("DELETE", "/api/v1/limits/203.0.113.10", token=WRITE)
check("удаление → 200", st == 200)
st, body = call("DELETE", "/api/v1/limits/203.0.113.10", token=WRITE)
check("повторное удаление → 404", st == 404)

st, body = call("POST", "/api/v1/limits", token=WRITE,
                body={"ip": "198.51.100.7", "download_mbps": 1})
check("адрес из белого списка → 409",
      st == 409 and body["error"]["code"] == "IP_WHITELISTED", body)

print("\n\033[1m5. Валидация входа\033[0m")
BAD_IPS = ["1.2.3.4; id", "$(id)", "`id`", "1.2.3.4 && rm -rf /", "999.1.1.1",
           "../../etc/passwd", "1.2.3.4/24", "", "  ", "gggg::1", "1.2.3.4\n5.6.7.8",
           "%2e%2e%2f", "0x7f000001", "a" * 60]
for bad in BAD_IPS:
    st, body = call("POST", "/api/v1/limits", token=WRITE,
                    body={"ip": bad, "download_mbps": 1})
    check(f"IP отвергнут: {bad[:24]!r}",
          st == 422 and body["error"]["code"] == "INVALID_IP", f"{st} {body}")
st, body = call("POST", "/api/v1/limits", token=WRITE,
                body={"ip": "2001:db8::1", "download_mbps": 1, "duration": 60})
check("корректный IPv6 принят", st == 201 and body["family"] == "ipv6", body)
call("DELETE", "/api/v1/limits/2001:db8::1", token=WRITE)

for bad in [0, -1, "1", None, 1e9, float("nan"), float("inf"), True, [1], {"a": 1}]:
    st, body = call("POST", "/api/v1/limits", token=WRITE,
                    body={"ip": "203.0.113.20", "download_mbps": bad})
    check(f"скорость отвергнута: {bad!r}", st == 422, f"{st} {body}")
for bad in [0, -100, 1, 10 ** 9, "3600", 3.5, True]:
    st, body = call("POST", "/api/v1/limits", token=WRITE,
                    body={"ip": "203.0.113.20", "download_mbps": 1, "duration": bad})
    check(f"длительность отвергнута: {bad!r}", st == 422, f"{st} {body}")
for bad in ["a" * 100, "reason\nInjected: header", "$(touch /tmp/api_pwned)",
            "`id`", "x;id", 42]:
    st, body = call("POST", "/api/v1/limits", token=WRITE,
                    body={"ip": "203.0.113.20", "download_mbps": 1, "reason": bad})
    check(f"причина отвергнута: {str(bad)[:24]!r}", st == 422, f"{st} {body}")
st, body = call("POST", "/api/v1/limits", token=WRITE,
                body={"ip": "203.0.113.20", "download_mbps": 5, "upload_mbps": 1})
check("разные скорости вверх и вниз → 422 с объяснением",
      st == 422 and body["error"]["code"] == "ASYMMETRIC_NOT_SUPPORTED", body)

print("\n\033[1m6. Некорректные запросы\033[0m")
st, body = call("POST", "/api/v1/limits", token=WRITE, raw="{не json".encode())
check("битый JSON → 400", st == 400 and body["error"]["code"] == "INVALID_JSON")
st, body = call("POST", "/api/v1/limits", token=WRITE, raw='"строка"'.encode())
check("JSON не объект → 400", st == 400)
st, body = call("POST", "/api/v1/limits", token=WRITE, raw=b"x" * (200 * 1024))
check("тело 200 КБ → 413", st == 413 and body["error"]["code"] == "BODY_TOO_LARGE")
st, body = call("GET", "/api/v1/nope", token=READ)
check("неизвестный путь → 404", st == 404)
st, body = call("PUT", "/api/v1/limits", token=WRITE, body={})
check("метод не поддержан → 405", st == 405, f"{st} {body}")
st, body = call("GET", "/api/v1/../../etc/passwd", token=READ)
check("обход каталога в пути → 404", st in (400, 404), st)
st, body = call("GET", "/api/v1/limits/%3B%20id", token=READ)
check("экранированный «; id» в пути → 422/404", st in (404, 422), st)
st, body = call("GET", "/api/v1/events?type=../../etc", token=READ)
check("мусор в query → 400", st == 400)

print("\n\033[1m7. Конфигурация\033[0m")
st, body = call("GET", "/api/v1/config", token=READ)
check("конфиг отдаётся", st == 200 and "guard" in body)
check("токен Telegram в конфиг не попал",
      "SECRET-TOKEN" not in json.dumps(body) and "telegram" not in body)
check("токены API не отдаются", "tokens" not in json.dumps(body))
st, body = call("PATCH", "/api/v1/config", token=WRITE, body={"penalty_min": 120})
check("разрешённое поле меняется", st == 200 and body["changed"]["penalty_min"] == 120)
check("значение сохранено в конфиге Shape",
      S.load_config()["guard"]["penalty_min"] == 120)
check("раздел telegram пережил правку через API",
      S.load_config()["telegram"]["token"] == "123456789:SECRET-TOKEN-VALUE")
for bad_key in ("engine_path", "bpf_object", "command", "../../etc/passwd",
                "telegram_token", "bind_address"):
    st, body = call("PATCH", "/api/v1/config", token=WRITE, body={bad_key: "x"})
    check(f"поле не даёт себя менять: {bad_key}",
          st == 422 and body["error"]["code"] == "FIELD_NOT_WRITABLE", st)
st, body = call("PATCH", "/api/v1/config", token=WRITE, body={"penalty_min": 999999})
check("значение вне диапазона → 422", st == 422)
st, body = call("PATCH", "/api/v1/config", token=READ, body={"penalty_min": 60})
check("правка конфига токеном чтения → 403", st == 403)

print("\n\033[1m8. Статистика и события\033[0m")
st, body = call("GET", "/api/v1/stats", token=READ)
check("статистика отдаётся", st == 200 and "traffic" in body and "ips" in body)
check("в статистике видно белый список", body["ips"]["whitelisted"] == 1)
st, body = call("GET", "/api/v1/events", token=READ)
check("события пишутся", st == 200 and body["count"] > 0)
types = {e["type"] for e in body["items"]}
check("есть события создания и снятия ограничения",
      {"limit_applied", "limit_released"} <= types, types)
check("у событий есть id и request_id",
      all("id" in e for e in body["items"]) and
      any("request_id" in e for e in body["items"]))
st, body = call("GET", "/api/v1/events?type=limit_applied&limit=2", token=READ)
check("фильтр по типу работает",
      st == 200 and all(e["type"] == "limit_applied" for e in body["items"]))
check("limit ограничивает выдачу", len(body["items"]) <= 2)
st, body = call("GET", "/api/v1/events?ip=203.0.113.10", token=READ)
check("фильтр по IP работает",
      st == 200 and all(e.get("ip") == "203.0.113.10" for e in body["items"]))
st, all_ev = call("GET", "/api/v1/events?limit=1000", token=READ)
first_id = min(e["id"] for e in all_ev["items"])
st, body = call("GET", f"/api/v1/events?cursor={first_id}", token=READ)
check("курсор отсекает старые события",
      st == 200 and all(e["id"] > first_id for e in body["items"]))
check("в событиях нет токенов",
      "SECRET-TOKEN" not in json.dumps(all_ev) and READ not in json.dumps(all_ev))

print("\n\033[1m9. Частота запросов\033[0m")
write_cfg(rate_read_per_min=5)
codes = [call("GET", "/api/v1/status", token=READ)[0] for _ in range(12)]
check("после превышения приходит 429", 429 in codes, codes)
st, body = call("GET", "/api/v1/status", token=READ)
check("429 объясняет причину структурно",
      st == 429 and body["error"]["code"] == "RATE_LIMITED")
check("health не режется чужим лимитом чтения",
      call("GET", "/api/v1/health")[0] == 200)
write_cfg(auth_fail_per_min=3)
codes = [call("GET", "/api/v1/status", token="bad-token")[0] for _ in range(10)]
check("перебор токена упирается в 429", codes.count(429) > 0, codes)
write_cfg()

print("\n\033[1m10. Параллельные запросы\033[0m")
with ThreadPoolExecutor(max_workers=24) as pool:
    res = list(pool.map(lambda i: call("GET", "/api/v1/status", token=READ)[0],
                        range(60)))
check("60 параллельных чтений обслужены", all(c in (200, 429, 503) for c in res)
      and res.count(200) > 0, f"{sorted(set(res))}")

def hammer(i):
    return call("POST", "/api/v1/limits", token=WRITE,
                body={"ip": f"198.51.100.{i}", "download_mbps": 1, "duration": 60})[0]

with ThreadPoolExecutor(max_workers=16) as pool:
    res = list(pool.map(hammer, range(20, 40)))
created = res.count(201)
pens = S.load_penalties()
check("параллельные записи не теряются под замком",
      created == len([ip for ip in pens if ip.startswith("198.51.100.")]),
      f"создано {created}, в файле {len([ip for ip in pens if ip.startswith('198.51.100.')])}")
call("DELETE", "/api/v1/limits/198.51.100.20", token=WRITE)

print("\n\033[1m11. Попытки выполнить команду\033[0m")
MARK = "/tmp/api_pwned_marker"
if os.path.exists(MARK):
    os.remove(MARK)
INJECTIONS = [
    ("POST", "/api/v1/limits", {"ip": f"1.2.3.4; touch {MARK}", "download_mbps": 1}),
    ("POST", "/api/v1/limits", {"ip": f"$(touch {MARK})", "download_mbps": 1}),
    ("POST", "/api/v1/limits", {"ip": "1.2.3.4", "download_mbps": 1,
                                "reason": f"; touch {MARK}"}),
    ("POST", "/api/v1/limits", {"ip": "1.2.3.4", "download_mbps": f"1; touch {MARK}"}),
    ("PATCH", "/api/v1/config", {"penalty_min": f"120; touch {MARK}"}),
    ("PATCH", "/api/v1/config", {f"penalty_min; touch {MARK}": 1}),
]
for method, path, payload in INJECTIONS:
    st, _ = call(method, path, token=WRITE, body=payload)
    check(f"{method} {path} с инъекцией отвергнут: {st}", st in (400, 422), st)
st, _ = call("DELETE", f"/api/v1/limits/1.2.3.4;touch{MARK}", token=WRITE)
check("инъекция в пути отвергнута", st in (404, 422), st)
st, _ = call("GET", f"/api/v1/events?ip=1.2.3.4;touch{MARK}", token=READ)
check("инъекция в query отвергнута", st == 422, st)
time.sleep(0.3)
check("файл-маркер не создан — команда не выполнилась", not os.path.exists(MARK))
log_text = open(os.environ["BPFTOOL_LOG"]).read()
check("в вызовы bpftool не просочилась подстрока touch", "touch" not in log_text)

print("\n\033[1m12. Журнал сервера\033[0m")
joined = "\n".join(LOGBUF)
check("токены в журнал не попадают",
      READ not in joined and WRITE not in joined and "SECRET-TOKEN" not in joined)
check("в журнале есть request_id, метод, статус",
      all(k in joined for k in ("request_id", "method", "status", "client")))
check("трассировки клиенту не уходят",
      not any("Traceback" in str(x) for x in LOGBUF if "detail" not in str(x)))

print("\n\033[1m12b. Кривые HTTP-запросы на сыром сокете\033[0m")


def raw_send(payload, read=True):
    try:
        c = socket.create_connection(("127.0.0.1", PORT), timeout=5)
        c.sendall(payload)
        data = c.recv(4096) if read else b""
        c.close()
        return data.decode(errors="replace")
    except Exception as e:
        return "ERR " + str(e)


cases = {
    "не-ASCII в заголовке токена":
        "GET /api/v1/status HTTP/1.1\r\nHost: x\r\n"
        "Authorization: Bearer токен\r\n\r\n".encode("utf-8"),
    "перевод строки в пути":
        b"GET /api/v1/status HTTP/1.1\r\nHost: x\r\nX-A: 1\r\n\r\n",
    "мусор вместо запроса": b"\x00\x01\x02 GARBAGE\r\n\r\n",
    "Content-Length больше тела":
        b"POST /api/v1/limits HTTP/1.1\r\nHost: x\r\nContent-Length: 999\r\n\r\n{}",
    "отрицательный Content-Length":
        b"POST /api/v1/limits HTTP/1.1\r\nHost: x\r\nContent-Length: -5\r\n\r\n",
}
for name, payload in cases.items():
    resp = raw_send(payload)
    check(f"сервер выжил: {name}", "ERR" not in resp[:3] or "timed out" in resp,
          resp[:60])
check("после кривых запросов API отвечает",
      call("GET", "/api/v1/health")[0] == 200)

print("\n\033[1m13. Ограничение по адресу источника\033[0m")
write_cfg(allowed_ips=["10.99.0.0/24"])
st, body = call("GET", "/api/v1/health")
check("чужой адрес отсекается даже на health",
      st == 403 and body["error"]["code"] == "FORBIDDEN", st)
write_cfg(allowed_ips=["127.0.0.1/32"])
check("свой адрес проходит", call("GET", "/api/v1/health")[0] == 200)
write_cfg()

print("\n\033[1m14. Движок остановлен\033[0m")
os.rename(os.path.join(PIN, "config_map"), os.path.join(PIN, "config_map.off"))
st, body = call("POST", "/api/v1/limits", token=WRITE,
                body={"ip": "203.0.113.30", "download_mbps": 1})
check("создание ограничения без движка → 503",
      st == 503 and body["error"]["code"] == "ENGINE_NOT_RUNNING", st)
st, body = call("GET", "/api/v1/status", token=READ)
check("статус продолжает отвечать и говорит правду",
      st == 200 and body["shape"]["engine_loaded"] is False)
check("health продолжает отвечать", call("GET", "/api/v1/health")[0] == 200)
os.rename(os.path.join(PIN, "config_map.off"), os.path.join(PIN, "config_map"))

print("\n\033[1m15. Права на файлы\033[0m")
check("api.json — 600", oct(os.stat(API_CONF).st_mode)[-3:] == "600")
check("config.json — 600", oct(os.stat(S.CONFIG_FILE).st_mode)[-3:] == "600")
check("журнал событий не для всех",
      oct(os.stat(S.EVENT_FILE).st_mode)[-3:] in ("600", "640"))


print("\n\033[1m16. Метрики Prometheus\033[0m")
st, body = call("GET", "/metrics")
check("метрики без токена → 401", st == 401, st)
st, body = call("GET", "/metrics", token=READ)
check("метрики с токеном чтения → 200", st == 200, st)
check("формат Prometheus, а не JSON",
      isinstance(body, str) and body.startswith("# HELP"), str(body)[:60])
for metric in ("shape_up", "shape_info", "shape_engine_loaded",
               "shape_speed_limit_mbps", "shape_traffic_bytes_total",
               "shape_ips_limited", "shape_ips_personal", "shape_ips_whitelisted",
               "shape_owners_known", "shape_events_24h", "shape_uptime_seconds",
               "shape_guard_enabled", "shape_watchdog_active"):
    check(f"есть метрика {metric}", metric in body)
check("у каждой метрики есть HELP и TYPE",
      body.count("# HELP") == body.count("# TYPE"))
check("в метриках нет токенов",
      READ not in body and WRITE not in body and "SECRET-TOKEN" not in body)
st, body2 = call("GET", "/api/v1/metrics", token=READ)
check("длинный путь /api/v1/metrics тоже работает", st == 200)
lines = [x for x in body.splitlines() if x and not x.startswith("#")]
check("значения метрик числовые",
      all(x.rsplit(" ", 1)[1].replace(".", "", 1).replace("-", "", 1).isdigit()
          for x in lines), lines[:3])
write_cfg(metrics_public=True)
check("metrics_public открывает метрики без токена",
      call("GET", "/metrics")[0] == 200)
check("остальное остаётся закрытым", call("GET", "/api/v1/status")[0] == 401)
write_cfg()

print("\n\033[1m17. Владельцы адресов\033[0m")
st, body = call("PUT", "/api/v1/owners", token=WRITE, body={"items": {
    "203.0.113.10": {"label": "Александр", "telegram_id": 123456789,
                     "user_id": "42"},
    "203.0.113.11": {"label": "Мария", "telegram_id": 987654321,
                     "shared": True}}})
check("карта владельцев загружена", st == 200 and body["updated"] == 2, body)
st, body = call("GET", "/api/v1/owners", token=READ)
check("владельцы читаются", st == 200 and body["count"] == 2)
check("telegram_id сохранён числом",
      any(i.get("telegram_id") == 123456789 for i in body["items"]))
st, body = call("PUT", "/api/v1/owners", token=READ, body={"items": {}})
check("загрузка карты токеном чтения → 403", st == 403)
for bad_rec in ({"label": "x" * 100}, {"label": "<b>hack</b>"},
                {"telegram_id": "abc"}, {"telegram_id": -5},
                {"user_id": "a b; id"}, {}, {"shared": "yes"}):
    st, _ = call("PUT", "/api/v1/owners", token=WRITE,
                 body={"items": {"203.0.113.30": bad_rec}})
    check(f"запись отвергнута: {str(bad_rec)[:32]}", st == 422, st)
st, _ = call("PUT", "/api/v1/owners", token=WRITE,
             body={"items": {"1.2.3.4; id": {"label": "x"}}})
check("мусор вместо адреса отвергнут", st == 422)
st, body = call("DELETE", "/api/v1/owners/203.0.113.11", token=WRITE)
check("владелец удаляется", st == 200)
check("повторное удаление → 404",
      call("DELETE", "/api/v1/owners/203.0.113.11", token=WRITE)[0] == 404)

print("\n\033[1m18. Ярлык попадает в ограничение и событие\033[0m")
st, body = call("POST", "/api/v1/limits", token=WRITE,
                body={"ip": "203.0.113.10", "download_mbps": 1, "duration": 600,
                      "reason": "torrent"})
check("ограничение создано", st == 201, body)
st, body = call("GET", "/api/v1/limits/203.0.113.10", token=READ)
check("в ограничении есть поле subject", "subject" in body, body)
S.penalties_update(lambda p: None)
who = S.owner_of("203.0.113.10")
check("владелец адреса известен ядру Shape",
      who is not None and who.get("label") == "Александр", who)
check("подпись для Telegram содержит ссылку по telegram_id",
      'tg://user?id=123456789' in S.subject_text(who, "203.0.113.10"),
      S.subject_text(who, "203.0.113.10"))
check("подпись экранирует HTML",
      "&lt;" in S.subject_text({"label": "<b>x</b>"}, "1.2.3.4"))
call("DELETE", "/api/v1/limits/203.0.113.10", token=WRITE)

print("\n\033[1m19. Персональные скорости\033[0m")
st, body = call("PUT", "/api/v1/personal/203.0.113.50", token=WRITE,
                body={"mbps": 25, "note": "bitrix"})
check("персональная скорость назначена",
      st == 200 and body["mbps"] == 25 and body["kind"] == "personal", body)
st, body = call("GET", "/api/v1/personal", token=READ)
check("персональные читаются списком", st == 200 and body["count"] == 1)
st, body = call("GET", "/api/v1/limits", token=READ)
check("в списке ограничений персональных нет",
      all(i["type"] != "personal" for i in body["items"]), body)
check("ядро Shape тоже их разделяет",
      "203.0.113.50" in S.personal_list())
for bad_val in (0, -1, "25", None, float("nan"), 1e9):
    st, _ = call("PUT", "/api/v1/personal/203.0.113.51", token=WRITE,
                 body={"mbps": bad_val})
    check(f"скорость отвергнута: {bad_val!r}", st == 422, st)
st, _ = call("PUT", "/api/v1/personal/198.51.100.7", token=WRITE, body={"mbps": 5})
check("адрес из белого списка → 409", st == 409, st)
call("POST", "/api/v1/limits", token=WRITE,
     body={"ip": "203.0.113.60", "download_mbps": 1, "duration": 600})
st, _ = call("PUT", "/api/v1/personal/203.0.113.60", token=WRITE, body={"mbps": 5})
check("поверх действующего ограничения → 409", st == 409, st)
call("DELETE", "/api/v1/limits/203.0.113.60", token=WRITE)
st, _ = call("DELETE", "/api/v1/personal/203.0.113.50", token=WRITE)
check("персональная скорость снимается", st == 200)
check("повторное снятие → 404",
      call("DELETE", "/api/v1/personal/203.0.113.50", token=WRITE)[0] == 404)
st, _ = call("PUT", "/api/v1/personal/203.0.113.50", token=READ, body={"mbps": 5})
check("назначение токеном чтения → 403", st == 403)

print("\n\033[1m20. История по суткам\033[0m")
S.history_append("2026-08-10", {"203.0.113.10": {"down": 24.8e9, "up": 1e9},
                                "203.0.113.11": {"down": 5e9, "up": 2e8}}, limited=3)
S.history_append("2026-08-11", {"203.0.113.10": {"down": 12e9, "up": 5e8}}, limited=1)
st, body = call("GET", "/api/v1/history", token=READ)
check("история отдаётся", st == 200 and body["count"] == 2, body)
check("суммы посчитаны", body["totals"]["download_bytes"] > 40e9)
check("в топе есть ярлык владельца",
      any(t.get("label") == "Александр" for t in body["items"][0]["top"]),
      body["items"][0]["top"])
st, body = call("GET", "/api/v1/history?days=1", token=READ)
check("days ограничивает выдачу", body["count"] == 1)
st, _ = call("GET", "/api/v1/history?days=abc", token=READ)
check("мусор в days → 400", st == 400)
S.history_append("2026-08-11", {"203.0.113.10": {"down": 99e9, "up": 1}}, limited=0)
st, body = call("GET", "/api/v1/history", token=READ)
check("повторная запись за те же сутки заменяет прежнюю",
      body["count"] == 2 and body["items"][-1]["down"] == 99e9, body["items"][-1])

print("\n\033[1m21. Плавная смена токенов\033[0m")
NEW_READ = "NEWREAD-" + "n" * 28
write_cfg(tokens={"read": NEW_READ, "write": BASE_CFG["tokens"]["write"],
                  "read_previous": READ, "write_previous": "",
                  "previous_until": time.time() + 3600})
check("новый токен работает", call("GET", "/api/v1/status", token=NEW_READ)[0] == 200)
check("прежний токен ещё принимается",
      call("GET", "/api/v1/status", token=READ)[0] == 200)
write_cfg(tokens={"read": NEW_READ, "write": BASE_CFG["tokens"]["write"],
                  "read_previous": READ, "write_previous": "",
                  "previous_until": time.time() - 1})
check("после истечения срока прежний отвергается",
      call("GET", "/api/v1/status", token=READ)[0] == 401)
check("новый продолжает работать",
      call("GET", "/api/v1/status", token=NEW_READ)[0] == 200)
write_cfg()

print("\n\033[1m22. OpenAPI описывает новое\033[0m")
st, spec = call("GET", "/api/v1/openapi.json")
for path in ("/history", "/owners", "/owners/{ip}", "/personal",
             "/personal/{ip}", "/metrics"):
    check(f"в схеме описан {path}", path in spec["paths"], list(spec["paths"]))

srv.shutdown()
print(f"\n\033[1mИтог: {ok} пройдено, {fail} провалено\033[0m")
sys.exit(1 if fail else 0)
