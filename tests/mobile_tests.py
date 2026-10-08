#!/usr/bin/env python3
"""
Метка «сеть мобильного оператора»: кеш префиксов, поиск, обновление, вывод.

Без root, без сети и без ядра: urllib подменён заглушкой, карты BPF заменены
готовыми словарями, состояние живёт во временном каталоге.
"""
import argparse
import contextlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import time
import urllib.error

SRC = os.environ.get("SHAPE_SRC") or os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))

TMP = tempfile.mkdtemp(prefix="shape-mobile-")
VAR = os.path.join(TMP, "var")
os.environ["SHAPE_VAR_DIR"] = VAR
os.environ["SHAPE_ETC_DIR"] = os.path.join(TMP, "etc")
os.environ["SHAPER_PIN_DIR"] = os.path.join(TMP, "maps")

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


CACHE = S.MOBILE_FILE


def write_cache(nets, updated=None):
    os.makedirs(VAR, exist_ok=True)
    with open(CACHE, "w") as f:
        json.dump({"updated": time.time() if updated is None else updated,
                   "nets": nets}, f)
    S._MOBILE_IDX = None


def drop_cache():
    if os.path.exists(CACHE):
        os.remove(CACHE)
    S._MOBILE_IDX = None


def run(fn, *args):
    """-> (код выхода или None, stdout+stderr)"""
    buf, code = io.StringIO(), None
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        try:
            fn(*args)
        except SystemExit as e:
            code = e.code
    return code, buf.getvalue()


# ───────────────────── заглушка RIPEstat ─────────────────────
class FakeResp:
    def __init__(self, payload):
        self.raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()

    def read(self):
        return self.raw

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def ripe(prefixes):
    return {"data": {"prefixes": [{"prefix": p} for p in prefixes]}}


REQUESTED = []


def install_ripe(table):
    """table: {asn: список префиксов | Exception | bytes}"""
    def fake(req, timeout=None, **kw):
        url = getattr(req, "full_url", req)
        REQUESTED.append((url, timeout))
        asn = int(url.split("resource=AS")[1].split("&")[0])
        v = table.get(asn, [])
        if isinstance(v, Exception):
            raise v
        if isinstance(v, bytes):
            return FakeResp(v)
        return FakeResp(ripe(v))
    S.urllib.request.urlopen = fake


_real_urlopen = S.urllib.request.urlopen

print("\n\033[1m1. Константа ASN\033[0m")
allasn = [a for v in S.MOBILE_ASNS.values() for a in v]
check("МТС — 8359", S.MOBILE_ASNS.get("МТС") == [8359])
check("Ростелеком 12389 не включён", 12389 not in allasn)
check("ASN не повторяются между операторами", len(allasn) == len(set(allasn)))
check("Win Mobile = 203451, Волна = 203561",
      S.MOBILE_ASNS.get("Win Mobile") == [203451]
      and S.MOBILE_ASNS.get("Волна") == [203561])
check("47203 — Миранда, 59833 — Севтелеком",
      47203 in S.MOBILE_ASNS["Миранда"] and S.MOBILE_ASNS["Севтелеком"] == [59833])

print("\n\033[1m2. Поиск адреса\033[0m")
write_cache([["10.0.0.0/24", "МТС"], ["2001:db8::/32", "Билайн"]])
check("IPv4 внутри префикса", S.mobile_of("10.0.0.77") == "МТС")
check("первый адрес префикса", S.mobile_of("10.0.0.0") == "МТС")
check("последний адрес префикса", S.mobile_of("10.0.0.255") == "МТС")
check("адрес перед префиксом — нет", S.mobile_of("9.255.255.255") is None)
check("адрес после префикса — нет", S.mobile_of("10.0.1.0") is None)
check("IPv6 внутри", S.mobile_of("2001:db8:ffff::1") == "Билайн")
check("IPv6 последний адрес", S.mobile_of("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff") == "Билайн")
check("IPv6 вне", S.mobile_of("2001:db9::1") is None)
check("IPv4-in-IPv6 попадает в v4-сети", S.mobile_of("::ffff:10.0.0.5") == "МТС")
check("v4 не путается с v6", S.mobile_of("0.0.0.1") is None)
check("мусор -> None, без исключения",
      S.mobile_of("не адрес") is None and S.mobile_of(None) is None
      and S.mobile_of("") is None)

print("\n\033[1m3. Вложенные и пересекающиеся префиксы\033[0m")
write_cache([["10.0.0.0/8", "МТС"], ["10.1.0.0/16", "МТС"],
             ["10.1.2.0/24", "МТС"], ["20.0.0.0/16", "T2"], ["20.0.128.0/17", "T2"]])
check("адрес в широкой сети после узкой", S.mobile_of("10.2.0.1") == "МТС")
check("адрес в самой узкой", S.mobile_of("10.1.2.3") == "МТС")
check("адрес за широкой сетью — нет", S.mobile_of("11.0.0.1") is None)
check("узкая внутри широкой, адрес между", S.mobile_of("20.0.5.5") == "T2")
check("за широкой — нет", S.mobile_of("20.1.0.0") is None)
write_cache([["30.0.0.0/16", "A"], ["30.0.0.0/24", "B"]])
check("одинаковый старт: находится покрывающий", S.mobile_of("30.0.9.9") == "A")

print("\n\033[1m4. Нет кеша и битый кеш\033[0m")
drop_cache()
check("нет файла -> None", S.mobile_of("10.0.0.1") is None)
for label, raw in (("не JSON", "{{{"), ("не словарь", "[1,2]"),
                   ("nets не список", '{"updated":1,"nets":5}'),
                   ("пустой файл", "")):
    os.makedirs(VAR, exist_ok=True)
    with open(CACHE, "w") as f:
        f.write(raw)
    S._MOBILE_IDX = None
    check(f"битый кеш ({label}) -> None", S.mobile_of("10.0.0.1") is None)
write_cache([["10.0.0.0/24", "МТС"], ["мусор", "X"], [1, 2], ["10.5.0.0/24"]])
check("битые записи пропускаются, годные работают",
      S.mobile_of("10.0.0.1") == "МТС")
write_cache([["10.0.0.0/24", "МТС"]])
S.mobile_of("10.0.0.1")
os.remove(CACHE)
check("кеш грузится один раз на процесс", S.mobile_of("10.0.0.1") == "МТС")

print("\n\033[1m5. Разбор ответа RIPEstat\033[0m")
REQUESTED.clear()
install_ripe({8359: ["185.0.0.0/24", "2a00:1::/32", "мусор", "10.0.0.0/33"]})
got = S.mobile_fetch_asn(8359)
check("префиксы v4 и v6 разобраны, мусор отброшен",
      got == ["185.0.0.0/24", "2a00:1::/32"], got)
check("запрос на stat.ripe.net с нужным AS и таймаутом",
      REQUESTED and "stat.ripe.net/data/announced-prefixes/data.json?resource=AS8359"
      in REQUESTED[0][0] and REQUESTED[0][1])
install_ripe({1: b"<html>"})
try:
    S.mobile_fetch_asn(1)
    raised = False
except Exception:
    raised = True
check("не-JSON в ответе — исключение (вызывающий посчитает отказом)", raised)
install_ripe({2: b'{"data": {}}'})
check("ответ без prefixes — пусто", S.mobile_fetch_asn(2) == [])

print("\n\033[1m6. Обновление: частичный и полный отказ\033[0m")
drop_cache()
table = {a: [] for a in allasn}
table[8359] = ["185.1.0.0/24"]
table[3216] = ["85.2.0.0/16"]
for a in allasn:
    if a not in (8359, 3216):
        table[a] = urllib.error.URLError("нет сети")
install_ripe(table)
S._MOBILE_RETRY_AT = 0
code, out = run(S.cmd_mobile, argparse.Namespace(action="update", ip=None))
data = json.load(open(CACHE)) if os.path.exists(CACHE) else {}
nets = {tuple(n) for n in data.get("nets", [])}
check("часть ASN ответила — кеш записан с тем, что есть",
      nets == {("185.1.0.0/24", "МТС"), ("85.2.0.0/16", "Билайн")}, nets)
check("в кеше есть метка времени", isinstance(data.get("updated"), (int, float)))
check("после обновления поиск видит новые сети",
      S.mobile_of("185.1.0.9") == "МТС" and S.mobile_of("85.2.1.1") == "Билайн")
check("частичный отказ не ошибка выхода", code in (None, 0), code)
check("временного файла не осталось", not os.path.exists(CACHE + ".tmp"))

before = open(CACHE).read()
install_ripe({a: urllib.error.URLError("нет сети") for a in allasn})
n_before = len(REQUESTED)
code, out = run(S.cmd_mobile, argparse.Namespace(action="update", ip=None))
check("полный отказ — выход с ошибкой", code not in (None, 0), code)
check("при мёртвой сети не ждём все ASN",
      0 < len(REQUESTED) - n_before < len(allasn), len(REQUESTED) - n_before)
check("полный отказ не затирает старый кеш", open(CACHE).read() == before)
check("после отказа поиск по-прежнему работает", S.mobile_of("185.1.0.9") == "МТС")

install_ripe({a: [] for a in allasn})
code, out = run(S.cmd_mobile, argparse.Namespace(action="update", ip=None))
check("все ответили, но пусто — тоже не затираем",
      code not in (None, 0) and open(CACHE).read() == before)

print("\n\033[1m7. mobile status / lookup\033[0m")
write_cache([["185.1.0.0/24", "МТС"], ["185.2.0.0/24", "МТС"],
             ["85.2.0.0/16", "Билайн"]], updated=1_700_000_000)
code, out = run(S.cmd_mobile, argparse.Namespace(action="status", ip=None))
check("status: даты и числа по операторам",
      "МТС" in out and "Билайн" in out and "2023" in out, out)
drop_cache()
code, out = run(S.cmd_mobile, argparse.Namespace(action="status", ip=None))
check("status без кеша не падает", code in (None, 0) and out.strip())
write_cache([["185.1.0.0/24", "МТС"]])
code, out = run(S.cmd_mobile, argparse.Namespace(action="lookup", ip="185.1.0.5"))
check("lookup: оператор в выводе", "МТС" in out and code in (None, 0), out)
code, out = run(S.cmd_mobile, argparse.Namespace(action="lookup", ip="8.8.8.8"))
check("lookup: вне сетей — не оператор", "МТС" not in out and out.strip())
code, out = run(S.cmd_mobile, argparse.Namespace(action="lookup", ip="ерунда"))
check("lookup: плохой адрес — ошибка", code not in (None, 0))

print("\n\033[1m8. Автообновление в сторожe\033[0m")
S.urllib.request.urlopen = _real_urlopen
calls = []
S.mobile_update = lambda: calls.append(1) or (1, [])
drop_cache()
S._MOBILE_RETRY_AT = 0
S.mobile_due(now=1000.0)
for th in list(getattr(S, "_MOBILE_THREAD", None) and [S._MOBILE_THREAD] or []):
    th.join(2)
check("нет кеша — обновление запускается", len(calls) == 1, calls)
write_cache([["10.0.0.0/24", "МТС"]], updated=time.time())
S._MOBILE_RETRY_AT = 0
S.mobile_due()
if getattr(S, "_MOBILE_THREAD", None):
    S._MOBILE_THREAD.join(2)
check("свежий кеш — не трогаем", len(calls) == 1, calls)
write_cache([["10.0.0.0/24", "МТС"]], updated=time.time() - 90000)
S._MOBILE_RETRY_AT = 0
S.mobile_due()
if getattr(S, "_MOBILE_THREAD", None):
    S._MOBILE_THREAD.join(2)
check("кеш старше суток — обновляем", len(calls) == 2, calls)
S._MOBILE_RETRY_AT = 0
S.mobile_update = lambda: (_ for _ in ()).throw(RuntimeError("сеть упала"))
write_cache([["10.0.0.0/24", "МТС"]], updated=0)
try:
    S.mobile_due()
    if getattr(S, "_MOBILE_THREAD", None):
        S._MOBILE_THREAD.join(2)
    survived = True
except Exception:
    survived = False
check("ошибка обновления не роняет сторожа", survived)
n = len(calls)
S.mobile_update = lambda: calls.append(1) or (1, [])
S.mobile_due()
check("после ошибки повтор не чаще раза в час", len(calls) == n, (len(calls), n))

print("\n\033[1m9. Метка в status и monitor\033[0m")
write_cache([["185.1.0.0/24", "МТС"]])
USERS = {"185.1.0.7": {"down": 5_000_000, "up": 1_000_000, "up_pkts": 10, "seen": 0},
         "8.8.4.4": {"down": 2_000_000, "up": 500_000, "up_pkts": 5, "seen": 0}}
S.require_engine = lambda: None
S.read_users = lambda: dict(USERS)
S.read_port_stats = lambda: {}
S.mono_ns = lambda: 0
S.load_penalties = lambda: {}
S.whitelist_ips = lambda: set()
S.load_config = lambda: {"ports": [443], "speed_mbps": 0, "guard": {},
                         "telegram": {}, "panel": {}}


def st_args(**kw):
    d = dict(live=False, interval=1, json=False, full=True, top=20)
    d.update(kw)
    return argparse.Namespace(**d)


code, out = run(S.cmd_status, st_args(json=True))
rows = {r["ip"]: r for r in json.loads(out)}
check("JSON status: mobile = оператор", rows["185.1.0.7"]["mobile"] == "МТС", rows)
check("JSON status: mobile = null вне сетей",
      "mobile" in rows["8.8.4.4"] and rows["8.8.4.4"]["mobile"] is None)
code, out = run(S.cmd_status, st_args())
l1 = [l for l in out.splitlines() if "185.1.0.7" in l]
l2 = [l for l in out.splitlines() if "8.8.4.4" in l]
ANSI = S.re.compile(r"\033\[[0-9;?]*[A-Za-z]")
check("status: метка рядом с IP мобильного",
      bool(l1) and "МТС" in l1[0] and l1[0].index("185.1.0.7") < l1[0].index("МТС"), l1)
check("status: у обычного адреса метки нет", bool(l2) and "МТС" not in l2[0], l2)
check("status: колонки скачано/отдано не поехали",
      bool(l1 and l2) and len(ANSI.sub("", l1[0])) == len(ANSI.sub("", l2[0])),
      (l1, l2))


def mon_out(lo_down=None):
    state = {"n": 0}
    snaps = [dict(USERS)]
    cur = {k: dict(v) for k, v in USERS.items()}
    for v in cur.values():
        v["down"] += 12_500_000
        v["up"] += 2_500_000
        v["up_pkts"] += 100
    if lo_down is not None and "127.0.0.1" in cur:
        cur["127.0.0.1"]["down"] = USERS["127.0.0.1"]["down"] + lo_down
        cur["127.0.0.1"]["up"] = USERS["127.0.0.1"]["up"]
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
    real_sleep, S.time.sleep = S.time.sleep, sleep
    try:
        return run(S.cmd_monitor, argparse.Namespace(interval=1, top=10))[1]
    finally:
        S.time.sleep = real_sleep
        S.read_users = lambda: dict(USERS)


out = mon_out()
plain = S.re.sub(r"\033\[[0-9;?]*[A-Za-z]", "", out)
m1 = [l for l in plain.splitlines() if "185.1.0.7" in l]
m2 = [l for l in plain.splitlines() if "8.8.4.4" in l]
check("monitor: метка у мобильного адреса", m1 and "МТС" in m1[0], plain)
check("monitor: у обычного метки нет", m2 and "МТС" not in m2[0])

print("\n\033[1m10. Сводка «мобильных: K из N»\033[0m")
write_cache([["185.1.0.0/24", "МТС"], ["185.2.0.0/24", "Билайн"]])
mob, tot, ops = S.mobile_summary(["185.1.0.7", "185.1.0.8", "185.2.0.1", "8.8.4.4",
                                  "127.0.0.1", "::1", "127.9.9.9"])
check("сводка: loopback не считается ни в K, ни в N", (mob, tot) == (3, 4), (mob, tot))
check("сводка: разбивка по операторам", dict(ops) == {"МТС": 2, "Билайн": 1}, ops)
check("сводка: пустой список", S.mobile_summary([]) [:2] == (0, 0))

rows_sp = [("185.1.0.7", 10.0, 1.0, 0, 0, 0), ("185.2.0.1", 5.5, 0.5, 0, 0, 0),
           ("8.8.4.4", 3.0, 0.25, 0, 0, 0), ("1.1.1.1", 0.0, 0.0, 0, 0, 0),
           ("127.0.0.1", 99.0, 99.0, 0, 0, 0), ("::1", 99.0, 99.0, 0, 0, 0)]
(m_dl, m_ul), (o_dl, o_ul), (l_dl, l_ul) = S.mobile_speed(rows_sp)
check("скорость: сумма по мобильным", (m_dl, m_ul) == (15.5, 1.5), (m_dl, m_ul))
check("скорость: сумма по остальным, loopback не в счёт",
      (o_dl, o_ul) == (3.0, 0.25), (o_dl, o_ul))
check("скорость: суммы по loopback (127.0.0.1 и ::1) возвращаются отдельно",
      (l_dl, l_ul) == (198.0, 198.0), (l_dl, l_ul))
check("скорость: пустой список — нули",
      S.mobile_speed([]) == ((0.0, 0.0), (0.0, 0.0), (0.0, 0.0)))

plain_st = ANSI.sub("", run(S.cmd_status, st_args())[1])
head = plain_st.splitlines()[1]
check("status: в шапке «мобильных: 1 из 2 (50%)»",
      "всего IP: 2" in head and "мобильных: 1 из 2 (50%)" in head, head)
check("status: счётчик идёт после «активных за минуту»",
      head.index("активных за минуту") < head.index("мобильных"), head)
check("JSON status: по-прежнему список без сводки",
      isinstance(json.loads(run(S.cmd_status, st_args(json=True))[1]), list))

USERS["127.0.0.1"] = {"down": 9_000_000, "up": 9_000_000, "up_pkts": 9, "seen": 0}
head = ANSI.sub("", run(S.cmd_status, st_args())[1]).splitlines()[1]
check("status: loopback не попадает в мобильных/N, но есть в «всего IP»",
      "всего IP: 3" in head and "мобильных: 1 из 2 (50%)" in head, head)
del USERS["127.0.0.1"]

drop_cache()
head = ANSI.sub("", run(S.cmd_status, st_args())[1]).splitlines()[1]
check("status без кеша: части про мобильных нет", "мобильных" not in head, head)
write_cache([["185.1.0.0/24", "МТС"]])

plain = ANSI.sub("", mon_out())
check("monitor: «мобильных: 1 из 2 (50%)» в шапке",
      any("мобильных: 1 из 2 (50%)" in l for l in plain.splitlines()), plain)
check("monitor: разбивка по операторам одной строкой",
      any("МТС 1" in l and "мобильных" not in l and "185.1.0.7" not in l
          for l in plain.splitlines()), plain)
sp_ln = [l for l in plain.splitlines() if "мобильные ↓" in l]
check("monitor: строка скорости мобильных и остальных",
      bool(sp_ln) and "остальные ↓" in sp_ln[0] and "Mbit/s" in sp_ln[0], plain)
check("monitor: без трафика 127.0.0.1 третьей части нет",
      bool(sp_ln) and "без адреса" not in sp_ln[0] and not any("HAProxy" in l for l in plain.splitlines()), plain)

USERS["127.0.0.1"] = {"down": 9_000_000, "up": 1_000_000, "up_pkts": 9, "seen": 0}
plain = ANSI.sub("", mon_out())
sp_ln = [l for l in plain.splitlines() if "мобильные ↓" in l]
check("monitor: при трафике 127.0.0.1 в строке скорости есть «без адреса (127.0.0.1) ↓ … ↑ …»",
      bool(sp_ln) and "· без адреса (127.0.0.1) ↓ 1000.0 ↑ 200.0" in sp_ln[0], sp_ln)
check("monitor: при 127.0.0.1 ≥ 1 Mbit/s есть подсказка перезапустить HAProxy",
      any("systemctl restart haproxy" in l and l.strip().startswith("↳") for l in plain.splitlines()), plain)
plain = ANSI.sub("", mon_out(lo_down=25_000))   # 2 Mbit/s (монитор меряет за 0.1 с)
plain_lo = ANSI.sub("", mon_out(lo_down=6_250))   # 0.5 Mbit/s: часть есть, подсказки нет
sp_lo = [l for l in plain_lo.splitlines() if "мобильные ↓" in l]
check("monitor: 127.0.0.1 < 1 Mbit/s — третья часть есть, подсказки нет",
      bool(sp_lo) and "без адреса" in sp_lo[0] and "systemctl restart haproxy" not in plain_lo, plain_lo)
check("monitor: 127.0.0.1 = 2 Mbit/s — подсказка есть",
      "systemctl restart haproxy" in plain, plain)
del USERS["127.0.0.1"]

drop_cache()
plain = ANSI.sub("", mon_out())
check("monitor без кеша: строк про мобильных нет", "мобильных" not in plain, plain)
write_cache([["185.1.0.0/24", "МТС"]])

saved_users = dict(USERS)
USERS.clear()
for i in range(1, 8):
    for k in range(8 - i):          # Оп1 — 7 адресов, Оп2 — 6, ... Оп7 — 1
        USERS[f"10.{i}.0.{k + 1}"] = {"down": 1_000_000, "up": 1_000, "up_pkts": 1, "seen": 0}
USERS["8.8.4.4"] = {"down": 1_000_000, "up": 1_000, "up_pkts": 1, "seen": 0}
write_cache([[f"10.{i}.0.0/16", f"Оп{i}"] for i in range(1, 8)])
plain = ANSI.sub("", mon_out())
ops_ln = [l.strip() for l in plain.splitlines() if "Оп1 7" in l and "10.1.0" not in l]
check("разбивка: не больше 5 операторов, по убыванию",
      bool(ops_ln) and ops_ln[0] == "Оп1 7 · Оп2 6 · Оп3 5 · Оп4 4 · Оп5 3", ops_ln)
check("разбивка: счётчик учитывает всех, а не только показанных",
      any("мобильных: 28 из 29" in l for l in plain.splitlines()), plain)
USERS.clear()
USERS.update(saved_users)

print(f"\n\033[1mИтог: {ok} пройдено, {fail} провалено\033[0m")
sys.exit(1 if fail else 0)
