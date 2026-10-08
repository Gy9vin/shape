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
    n = 0
    for line in open(a[2]):
        line = line.split()
        if line and run(line) != 0:
            sys.exit(254)
        if line:
            n += 1
            if os.environ.get("FAKE_PARTIAL") and n >= int(os.environ["FAKE_PARTIAL"]):
                sys.exit(254)       # часть записей уже применена
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
REAL_READ_USERS = S.read_users

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
    """(сырые байты, (общий лимит, немобильный лимит)); блок — kernel_block()."""
    st = json.load(open(pin("config_map")))
    raw = bytes.fromhex(st["00000000"])
    return raw, struct.unpack("<3Q", raw)[:2]


def kernel_block():
    st = json.load(open(pin("config_map")))
    return struct.unpack("<3Q", bytes.fromhex(st["00000000"]))[2]


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


def ns(action, speed=None, arg=None):
    return argparse.Namespace(action=action, speed=speed, arg=arg)


def reset_cfg(nm=None, block=None, extra=None):
    cfg = {"ports": [443], "speed_mbps": 10.0}
    if nm is not None:
        cfg["nonmobile_mbps"] = nm
    if block is not None:
        cfg["nonmobile_block"] = block
    if extra is not None:
        cfg["mobile_extra"] = extra
    if os.path.exists(S.CONFIG_FILE):
        os.remove(S.CONFIG_FILE)
    S.save_config(cfg)


print("\n\033[1m1. Конфиг и размер значения в ядре\033[0m")
reset_cfg()
check("config_map: struct config — 24 байта (три u64)",
      struct.calcsize(S.CONFIG_FMT) == 24, S.CONFIG_FMT)
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
check("в ядро уходит значение ровно 24 байта", len(raw) == 24, len(raw))
check("общий лимит 7 Мбит/с, немобильный 2.5 Мбит/с",
      (g, nm) == (7 * 125000, int(2.5 * 125000)), (g, nm))

reset_cfg(0)
S.write_to_kernel(S.load_config())
raw, (g, nm) = kernel_cfg()
check("режим выключен: в ядре 0, значение всё равно 24 байта",
      (g, nm, len(raw)) == (10 * 125000, 0, 24), (g, nm, len(raw)))

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


print("\n\033[1m11. Блокировка немобильных: конфиг, ядро, CLI\033[0m")
reset_cfg()
check("по умолчанию nonmobile_block выключен", S.load_config()["nonmobile_block"] is False)
reset_cfg(block=True)
check("nonmobile_block читается из файла", S.load_config()["nonmobile_block"] is True)
cfg = S.load_config()
cfg["speed_mbps"] = 7
S.save_config(cfg)
check("save_config сохраняет nonmobile_block",
      json.load(open(S.CONFIG_FILE))["nonmobile_block"] is True)

make_maps()
write_cache([["185.1.0.0/24", "МТС"]])
reset_cfg()
code, out = run(S.cmd_nonmobile, ns("block", arg="on"))
raw, (g, nm) = kernel_cfg()
check("block on: конфиг и ядро (24 байта, блок = 1)",
      code is None and S.load_config()["nonmobile_block"] is True
      and kernel_block() == 1 and len(raw) == 24, (code, out))
check("block on: общий лимит и немобильный не тронуты", (g, nm) == (10 * 125000, 0))
check("block on: карта mobile_lpm заполнена", lpm_keys() == {key4("185.1.0.0", 24)})
code, out = run(S.cmd_nonmobile, ns("on", 2.0))
raw, (g, nm) = kernel_cfg()
check("лимит поверх блока: оба в ядре, независимы",
      nm == 250000 and kernel_block() == 1 and S.load_config()["nonmobile_block"] is True)
code, out = run(S.cmd_nonmobile, ns("off"))
check("nonmobile off блок не снимает", kernel_cfg()[1][1] == 0 and kernel_block() == 1)
code, out = run(S.cmd_nonmobile, ns("on", 2.0))
code, out = run(S.cmd_nonmobile, ns("block", arg="off"))
check("block off: блок снят, лимит цел",
      code is None and kernel_block() == 0 and kernel_cfg()[1][1] == 250000
      and S.load_config()["nonmobile_block"] is False, out)
code, out = run(S.cmd_nonmobile, ns("off"))
for bad in (None, "maybe", "ON "):
    code, out = run(S.cmd_nonmobile, ns("block", arg=bad))
    check(f"block {bad!r}: отказ, конфиг цел",
          code not in (None, 0) and S.load_config()["nonmobile_block"] is False, out)

code, out = run(S.cmd_nonmobile, ns("block", arg="on"))
code, out = run(S.cmd_nonmobile, ns("status"))
p = plain(out)
check("status: блокировка задана и активна в ядре",
      "Блокировка" in p and "включена" in p and "активна" in p and "не активна" not in p, p)
print("      --- пример вывода status с блокировкой ---")
for line in p.strip().splitlines():
    print("      " + line)
code, out = run(S.cmd_nonmobile, ns("block", arg="off"))
code, out = run(S.cmd_nonmobile, ns("status"))
check("status: блокировка выкл", "Блокировка" in plain(out) and "выкл" in plain(out), plain(out))

print("\n\033[1m12. Блокировка: предохранитель и сохранение режима\033[0m")
reset_cfg(block=True)
for label, setup in (
        ("нет кеша", lambda: (make_maps(), drop_cache())),
        ("кеш без сетей", lambda: (make_maps(), write_cache([]))),
        ("нет карты mobile_lpm", lambda: (make_maps(lpm=False),
                                          write_cache([["185.1.0.0/24", "МТС"]]))),
):
    setup()
    code, out = run(S.write_to_kernel, S.load_config())
    raw, (g, nm) = kernel_cfg()
    check(f"{label}: блок в ядре 0, общий лимит записан",
          kernel_block() == 0 and g == 10 * 125000 and code is None, (code, out))
    check(f"{label}: предупреждение выведено", "⚠" in out, out)
    check(f"{label}: желаемое осталось в конфиге", S.load_config()["nonmobile_block"] is True)

make_maps()
write_cache([["185.1.0.0/24", "МТС"]])
os.environ["FAKE_FAIL_MAP"] = "mobile_lpm"
code, out = run(S.write_to_kernel, S.load_config())
del os.environ["FAKE_FAIL_MAP"]
check("синхронизация упала: блок = 0", kernel_block() == 0 and code is None, out)
code, out = run(S.write_to_kernel, S.load_config())
check("следующая успешная синхронизация включает блок", kernel_block() == 1)

write_cache([["185.1.0.0/24", "МТС"], ["20.0.0.0/16", "T2"]])
os.environ["FAKE_FAIL_BATCH"] = "1"
code, out = run(S.write_to_kernel, S.load_config())
del os.environ["FAKE_FAIL_BATCH"]
check("карта была заполнена, batch упал: блок остаётся", kernel_block() == 1 and "⚠" in out, out)
make_maps()
os.environ["FAKE_FAIL_BATCH"] = "1"
run(S.write_to_kernel, S.load_config())
del os.environ["FAKE_FAIL_BATCH"]
check("карта пуста и batch падает: блок = 0", kernel_block() == 0)
make_maps()
write_cache([["185.1.0.0/24", "МТС"]])
S.write_to_kernel(S.load_config())
drop_cache()
run(S.write_to_kernel, S.load_config())
check("карта заполнена, кеш пропал: блок держится", kernel_block() == 1)

reset_cfg(0, block=False)
make_maps()
write_cache([["185.1.0.0/24", "МТС"]])
reset_log()
S.write_to_kernel(S.load_config())
check("ни лимита, ни блока: карта mobile_lpm не трогается",
      "batch" not in log_lines() and lpm_keys() == set() and kernel_block() == 0)

# mobile update включает только блок (лимита нет)
drop_cache()
make_maps()
reset_cfg(0, block=True)
S.mobile_fetch_asn = lambda asn: ["185.9.0.0/24"] if asn == 8359 else []
code, out = run(S.cmd_mobile, argparse.Namespace(action="update", ip=None))
check("mobile update при одном блоке: карта и блок в ядре",
      lpm_keys() == {key4("185.9.0.0", 24)} and kernel_block() == 1, out)

for label, raw_val in (('"yes"', '"yes"'), ("1", "1"), ('"true"', '"true"'),
                       ("null", "null"), ("[]", "[]")):
    make_maps()
    write_cache([["185.1.0.0/24", "МТС"]])
    with open(S.CONFIG_FILE, "w") as f:
        f.write('{"ports": [443], "speed_mbps": 10, "nonmobile_block": %s}' % raw_val)
    check(f"nonmobile_block={label}: load_config даёт False",
          S.load_config()["nonmobile_block"] is False)
    code, out = run(S.cmd_restore, argparse.Namespace())
    check(f"nonmobile_block={label}: restore проходит, блок = 0",
          code is None and kernel_block() == 0, (code, out))

print("\n\033[1m13. Блокировка: show и монитор\033[0m")
make_maps()
write_cache([["185.1.0.0/24", "МТС"]])
reset_cfg(0, block=True)
S.write_to_kernel(S.load_config())
code, out = run(S.cmd_show, argparse.Namespace())
check("show: строка про блокировку (включена, активна)",
      "Блок" in plain(out) and "включена" in plain(out), plain(out))
reset_cfg(0, block=False)
S.write_to_kernel(S.load_config())
code, out = run(S.cmd_show, argparse.Namespace())
check("show: блокировка выкл — строка тоже есть", "Блок" in plain(out), plain(out))

print("\n\033[1m14. Учёт: user_state 48 байт, отброшенное отдельно\033[0m")
check("USER_SIZE = 48", S.USER_SIZE == 48 and struct.calcsize(S.USER_FMT) == 48)
raw48 = struct.pack("<6Q", 5, 1000, 77, 10, 4000, 4)
st = S.parse_user_state(list(raw48))
check("parse_user_state: пропущенное и отброшенное раздельно",
      (st["total"], st["pkts"], st["seen"], st["dropped"], st["dpkts"])
      == (1000, 10, 77, 4000, 4), st)
raw32 = struct.pack("<4Q", 5, 1000, 77, 10)
st = S.parse_user_state(list(raw32))
check("старые 32 байта читаются, отброшенного нет",
      (st["total"], st["dropped"], st["dpkts"]) == (1000, 0, 0), st)
st = S.parse_user_state({"total_bytes": 9, "packets": 2, "last_seen_ns": 3,
                         "dropped_bytes": 70, "dropped_packets": 7})
check("структурный вид (BTF): отброшенное читается",
      (st["total"], st["dropped"], st["dpkts"]) == (9, 70, 7), st)


def ukey(ip):
    return list(bytes(map(int, ip.split("."))) + b"\0" * 12)


def fake_dump(rows_down, rows_up):
    def dump(name):
        rows = rows_down if name.endswith("down") else rows_up
        return [(ukey(ip), list(struct.pack("<6Q", 0, *vals))) for ip, vals in rows.items()
                if name.startswith("user_state")]
    return dump


real_dump = S.map_dump
S.map_dump = fake_dump({"1.1.1.1": (1000, 5, 4, 2000, 2)}, {"1.1.1.1": (300, 6, 3, 90, 1)})
us = REAL_READ_USERS()
S.map_dump = real_dump
check("read_users: down/up — пропущенное, drop — отброшенное",
      us["1.1.1.1"]["down"] == 1000 and us["1.1.1.1"]["up"] == 300
      and us["1.1.1.1"]["up_pkts"] == 3 and us["1.1.1.1"]["down_drop"] == 2000
      and us["1.1.1.1"]["up_drop"] == 90, us)

dr = S.drop_rates({"1.1.1.1": {"down_drop": 0, "up_drop": 0}},
                  {"1.1.1.1": {"down_drop": 125000, "up_drop": 12500},
                   "2.2.2.2": {}}, 1.0)
check("drop_rates: Мбит/с по отброшенному, нет ключей — нули",
      abs(dr["1.1.1.1"][0] - 1.0) < 1e-9 and abs(dr["1.1.1.1"][1] - 0.1) < 1e-9
      and dr["2.2.2.2"] == (0.0, 0.0), dr)

smp = S.traffic_sample(
    {"1.1.1.1": {"down": 0, "up": 0, "up_pkts": 0, "down_drop": 0, "up_drop": 0}},
    {"1.1.1.1": {"down": 1_250_000, "up": 100_000, "up_pkts": 100,
                 "down_drop": 50_000_000, "up_drop": 9_000_000}}, 10.0)
check("сторож (traffic_sample): скорость и средний пакет — по пропущенному, срезанное не мешает",
      abs(smp["1.1.1.1"]["dl"] - 1.0) < 1e-9 and smp["1.1.1.1"]["up_pkt"] == 1000
      and smp["1.1.1.1"]["dl_bytes"] == 1_250_000, smp)

print("      --- монитор: блок и срезанное ---")
make_maps()
write_cache([["185.1.0.0/24", "МТС"]])
reset_cfg(1, block=True)
S.write_to_kernel(S.load_config())
S.load_penalties = lambda: {}
S.whitelist_ips = lambda: set()
USERS = {"185.1.0.7": {"down": 5_000_000, "up": 1_000, "up_pkts": 10, "seen": 0,
                       "down_drop": 0, "up_drop": 0},
         "8.8.4.4": {"down": 0, "up": 0, "up_pkts": 0, "seen": 0,
                     "down_drop": 100_000, "up_drop": 0},
         "9.9.9.9": {"down": 0, "up": 0, "up_pkts": 0, "seen": 0,
                     "down_drop": 100_000, "up_drop": 0}}


def mon_out2(grow):
    state = {"n": 0}
    cur = {k: dict(v) for k, v in USERS.items()}
    for ip, v in cur.items():
        for key, inc in grow.get(ip, {}).items():
            v[key] += inc
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


out = mon_out2({"185.1.0.7": {"down": 12_500}, "8.8.4.4": {"down_drop": 125_000}})
for l in out.splitlines():
    if "ЗАБЛОКИРОВАН" in l or "8.8.4.4" in l or "185.1.0.7" in l or "✂" in l:
        print("      " + l)
check("шапка монитора: блокировка активна", "ЗАБЛОКИРОВАН" in out, out)
check("заблокированный адрес виден в списке, не исчезает",
      any("8.8.4.4" in l for l in out.splitlines()), out)
l884 = [l for l in out.splitlines() if "8.8.4.4" in l][0]
check("у него маркер блокировки и срезанная скорость (125000 Б за 0.1 с = 10.0)",
      "✗" in l884 and "✂" in l884 and l884.split("✂")[1].split()[0] == "10.0", l884)
l185 = [l for l in out.splitlines() if "185.1.0.7" in l][0]
check("мобильный: идёт по пропущенному, без маркера срезанного",
      "✂" not in l185 and "✗" not in l185, l185)
check("адрес без роста отброшенного не показывается как активный",
      not any("9.9.9.9" in l for l in out.splitlines()), out)

reset_cfg(1, block=False)
S.write_to_kernel(S.load_config())
out = mon_out2({"185.1.0.7": {"down": 12_500}})
check("блок выключен: строки в шапке нет", "ЗАБЛОКИРОВАН" not in out, out)

print("\n\033[1m15. Свои сети: mobile_extra, add / del / list\033[0m")
P = S.mobile_extra_parse
check("ASN: AS12345 и as12345 → AS12345", P("AS12345") == "AS12345" and P("as12345") == "AS12345")
check("ASN: границы 1 и 4294967295", P("AS1") == "AS1" and P("AS4294967295") == "AS4294967295")
for bad in ("AS0", "AS4294967296", "AS", "ASx", "AS-1", "AS 5", "12345", "",
            "AS١٢٣", "AS1;rm", "0.0.0.0/0", "::/0", "1.2.3.0/33", "1.2.3.256",
            "evil", "None", None, 5):
    check(f"невалидный ввод {bad!r} отвергается", P(bad) is None, P(bad))
check("CIDR: хост без маски → /32, host bits обнуляются",
      P("1.2.3.4") == "1.2.3.4/32" and P("10.0.0.1/8") == "10.0.0.0/8")
check("CIDR v6", P("2001:db8::1/32") == "2001:db8::/32")
check("пробелы по краям отрезаются", P("  AS5 ") == "AS5" and P(" 10.0.0.0/8 ") == "10.0.0.0/8")

reset_cfg(extra=["AS1", "мусор", "10.0.0.1/8", "AS1", "AS0", 5, "10.0.0.0/8", "as7"])
check("load_config: mobile_extra нормализован, мусор и дубли убраны",
      S.load_config()["mobile_extra"] == ["AS1", "10.0.0.0/8", "AS7"], S.load_config()["mobile_extra"])
with open(S.CONFIG_FILE, "w") as f:
    f.write('{"ports": [443], "speed_mbps": 10, "mobile_extra": "AS5"}')
check("mobile_extra не список → пусто", S.load_config()["mobile_extra"] == [])


def nsm(action, ip=""):
    return argparse.Namespace(action=action, ip=ip)


make_maps()
write_cache([["185.1.0.0/24", "МТС"]])
reset_cfg(1)
S.write_to_kernel(S.load_config())
code, out = run(S.cmd_mobile, nsm("add", "10.5.0.0/16"))
check("add CIDR: сохранён в конфиге", code is None
      and S.load_config()["mobile_extra"] == ["10.5.0.0/16"], (code, out))
check("add CIDR: карта синхронизирована сразу",
      lpm_keys() == {key4("185.1.0.0", 24), key4("10.5.0.0", 16)}, lpm_keys())
check("метка в мониторе — «свои»", S.mobile_of("10.5.1.1") == "свои", S.mobile_of("10.5.1.1"))
check("кеш оператора не затронут", json.load(open(S.MOBILE_FILE))["nets"] == [["185.1.0.0/24", "МТС"]])
code, out = run(S.cmd_mobile, nsm("add", "10.5.0.0/16"))
check("повторный add — без ошибки, без дублей",
      code is None and S.load_config()["mobile_extra"] == ["10.5.0.0/16"], (code, out))
code, out = run(S.cmd_mobile, nsm("add", "10.6.0.9"))
check("add без маски → /32", "10.6.0.9/32" in S.load_config()["mobile_extra"])
before = list(S.load_config()["mobile_extra"])
for bad in ("AS0", "junk", "0.0.0.0/0", "AS99999999999", "1.1.1.1/40", ""):
    code, out = run(S.cmd_mobile, nsm("add", bad))
    check(f"add {bad!r}: отказ, конфиг цел",
          code not in (None, 0) and S.load_config()["mobile_extra"] == before, out)
code, out = run(S.cmd_mobile, nsm("list"))
p = plain(out)
check("list: показывает свои сети", "10.5.0.0/16" in p and "10.6.0.9/32" in p, p)
print("      --- пример mobile list ---")
for line in p.strip().splitlines():
    print("      " + line)
code, out = run(S.cmd_mobile, nsm("del", "10.5.0.0/16"))
check("del CIDR: убран из конфига и из карты",
      "10.5.0.0/16" not in S.load_config()["mobile_extra"]
      and key4("10.5.0.0", 16) not in lpm_keys()
      and key4("185.1.0.0", 24) in lpm_keys(), (code, out))
check("метка исчезла", S.mobile_of("10.5.1.1") is None)
code, out = run(S.cmd_mobile, nsm("del", "10.5.0.0/16"))
check("del несуществующего — ошибка", code not in (None, 0), out)
code, out = run(S.cmd_mobile, nsm("del", "10.6.0.9"))
check("del принимает ввод в любой форме записи (без маски)",
      S.load_config()["mobile_extra"] == [], (code, out))
code, out = run(S.cmd_mobile, nsm("list"))
check("list пустого — понятное сообщение", code is None and plain(out).strip() != "", out)

# ASN: запрашивается вместе со встроенными и метится «свои»
asked = []


def fetch_log(asn):
    asked.append(asn)
    return {8359: ["185.9.0.0/24"], 64500: ["100.64.0.0/24", "100.64.1.0/24"]}.get(asn, [])


S.mobile_fetch_asn = fetch_log
make_maps()
write_cache([["185.1.0.0/24", "МТС"]])
reset_cfg(1)
S.write_to_kernel(S.load_config())
code, out = run(S.cmd_mobile, nsm("add", "AS64500"))
nets = {tuple(n) for n in json.load(open(S.MOBILE_FILE))["nets"]}
check("add ASN: сохранён, запрошен вместе со встроенными",
      S.load_config()["mobile_extra"] == ["AS64500"] and 64500 in asked and 8359 in asked, (asked, out))
check("сети ASN в кеше с меткой «свои»",
      ("100.64.0.0/24", "свои") in nets and ("185.9.0.0/24", "МТС") in nets, nets)
check("и в карте ядра сразу",
      key4("100.64.0.0", 24) in lpm_keys() and key4("100.64.1.0", 24) in lpm_keys())
check("метка по адресу из ASN — «свои»", S.mobile_of("100.64.1.5") == "свои")
code, out = run(S.cmd_mobile, nsm("list"))
check("list показывает ASN", "AS64500" in plain(out), plain(out))
code, out = run(S.cmd_mobile, nsm("del", "AS64500"))
nets = {tuple(n) for n in json.load(open(S.MOBILE_FILE))["nets"]}
check("del ASN: из конфига убран, сети уходят из кеша и карты после обновления",
      S.load_config()["mobile_extra"] == [] and ("100.64.0.0/24", "свои") not in nets
      and key4("100.64.0.0", 24) not in lpm_keys(), (nets, out))

# ASN-обновление недоступно: add не падает, подсказывает mobile update
S.mobile_fetch_asn = lambda asn: (_ for _ in ()).throw(OSError("нет сети"))
code, out = run(S.cmd_mobile, nsm("add", "AS64501"))
check("add ASN при недоступной сети: сохранено, подсказка mobile update",
      code is None and S.load_config()["mobile_extra"] == ["AS64501"]
      and "mobile update" in plain(out), (code, out))

# предохранитель: свои CIDR не заменяют кеш операторов
make_maps()
drop_cache()
reset_cfg(1, extra=["10.5.0.0/16"])
code, out = run(S.write_to_kernel, S.load_config())
check("кеша операторов нет, есть только свои CIDR: немобильный лимит не включается",
      kernel_cfg()[1][1] == 0 and lpm_keys() == set(), (kernel_cfg(), lpm_keys()))
check("но метка «свои» работает и без кеша", S.mobile_of("10.5.9.9") == "свои")
reset_cfg(1, extra=["10.5.0.0/16"])
write_cache([["185.1.0.0/24", "МТС"]])
S.mobile_sync()
check("с кешем: свои CIDR в карте вместе с операторами",
      lpm_keys() == {key4("185.1.0.0", 24), key4("10.5.0.0", 16)})
reset_cfg(1, extra=["10.5.0.0/16", "2001:db8:5::/48"])
S.mobile_sync()
check("свой v6 тоже", key6("2001:db8:5::", 48) in lpm_keys())

# частичный отказ: свои сети кеша остаются как у остальных
reset_cfg(1, extra=["AS64502"])
write_cache([["185.1.0.0/24", "МТС"], ["77.0.0.0/16", "свои"]])
S.mobile_fetch_asn = lambda asn: (_ for _ in ()).throw(OSError("x")) if asn == 64502 \
    else (["185.9.0.0/24"] if asn == 8359 else [])
run(S.cmd_mobile, argparse.Namespace(action="update", ip=None))
nets = {tuple(n) for n in json.load(open(S.MOBILE_FILE))["nets"]}
check("AS из extra не ответил: его прежние сети остались в кеше", ("77.0.0.0/16", "свои") in nets, nets)


print("\n\033[1m16. Блок несовместим с правилом «все порты» (порт 0)\033[0m")
make_maps()
write_cache([["185.1.0.0/24", "МТС"]])
for ports in ([0], [443, 0]):
    reset_cfg()
    c = S.load_config(); c["ports"] = ports; S.save_config(c)
    code, out = run(S.cmd_nonmobile, ns("block", arg="on"))
    check(f"ports={ports}: block on отказывает с понятным сообщением",
          code not in (None, 0) and "порт" in plain(out).lower()
          and S.load_config()["nonmobile_block"] is False, (code, out))
c = S.load_config(); c["ports"] = [0]; c["nonmobile_block"] = True; S.save_config(c)
S.write_to_kernel(S.load_config())
check("block=true в конфиге при портах с 0: в ядро пишется 0, общий лимит цел",
      kernel_block() == 0 and kernel_cfg()[1][0] == 10 * 125000, (kernel_block(), kernel_cfg()))
code, out = run(S.cmd_nonmobile, ns("status"))
check("status показывает блок как включённый, но не активный",
      "не активна" in plain(out), plain(out))
c = S.load_config(); c["ports"] = [443]; S.save_config(c)
S.write_to_kernel(S.load_config())
check("порты без 0: блок снова уходит в ядро", kernel_block() == 1)
code, out = run(S.cmd_apply, argparse.Namespace(ports="0", speed=None, quiet=True))
check("apply --ports 0 при включённом блоке отказывает, порты не тронуты",
      code not in (None, 0) and S.load_config()["ports"] == [443]
      and "порт" in plain(out).lower(), (code, out))
code, out = run(S.cmd_apply, argparse.Namespace(ports="443,0", speed=None, quiet=True))
check("и со списком, где есть 0", code not in (None, 0) and S.load_config()["ports"] == [443], out)
code, out = run(S.cmd_apply, argparse.Namespace(ports="8443", speed=None, quiet=True))
check("apply другого порта при блоке проходит",
      code is None and S.load_config()["ports"] == [8443], (code, out))
code, out = run(S.cmd_nonmobile, ns("block", arg="off"))
code, out = run(S.cmd_apply, argparse.Namespace(ports="0", speed=None, quiet=True))
check("блок выключен: apply --ports 0 работает как раньше",
      code is None and S.load_config()["ports"] == [0], (code, out))

print("\n\033[1m17. Порядок старта: штрафы и белый список раньше блока\033[0m")
calls = []
real_wk, real_rp = S.write_to_kernel, S.restore_penalties
S.write_to_kernel = lambda cfg: calls.append("config")
S.restore_penalties = lambda: calls.append("penalties") or 0
reset_cfg(block=True)
run(S.cmd_restore, argparse.Namespace())
S.write_to_kernel, S.restore_penalties = real_wk, real_rp
check("cmd_restore: restore_penalties раньше записи config_map",
      calls == ["penalties", "config"], calls)

print("\n\033[1m18. Сбой batch посреди синхронизации на свежей карте\033[0m")
make_maps()
reset_cfg(1, block=True)
write_cache([["185.1.0.0/24", "МТС"], ["10.0.0.0/8", "Билайн"], ["20.0.0.0/16", "T2"]])
os.environ["FAKE_PARTIAL"] = "1"
code, out = run(S.write_to_kernel, S.load_config())
del os.environ["FAKE_PARTIAL"]
check("batch применил часть записей на пустой карте", 0 < len(lpm_keys()) < 3, len(lpm_keys()))
check("неполный список не включает ни блок, ни немобильный лимит",
      kernel_block() == 0 and kernel_cfg()[1][1] == 0 and kernel_cfg()[1][0] == 10 * 125000,
      (kernel_block(), kernel_cfg()))
check("предупреждение выведено", "⚠" in out, out)
S.write_to_kernel(S.load_config())
check("следующая полная синхронизация включает режим", kernel_block() == 1 and kernel_cfg()[1][1] == 125000)
write_cache([["185.1.0.0/24", "МТС"], ["10.0.0.0/8", "Билайн"], ["20.0.0.0/16", "T2"],
             ["30.0.0.0/16", "T2"]])
os.environ["FAKE_PARTIAL"] = "1"
run(S.write_to_kernel, S.load_config())
del os.environ["FAKE_PARTIAL"]
check("карта была заполнена до сбоя: режим держится", kernel_block() == 1 and kernel_cfg()[1][1] == 125000)

print("\n\033[1m19. Срезанное не делает адрес активным\033[0m")
S.require_engine = lambda: None
now_ns = S.mono_ns()
S.read_users = lambda: {
    "6.6.6.6": {"down": 0, "up": 0, "up_pkts": 0, "seen": 0, "down_drop": 9000, "up_drop": 0},
    "7.7.7.7": {"down": 100, "up": 0, "up_pkts": 0, "seen": now_ns, "down_drop": 0, "up_drop": 0}}
S.read_port_stats = lambda: {}
reset_cfg(0)
code, out = run(S.cmd_status, argparse.Namespace(live=False, interval=1, json=True, top=10, full=False))
rows = {r["ip"]: r for r in json.loads(out)}
check("status: адрес без пропущенного трафика и с seen=0 не активен (idle >= 60)",
      rows["6.6.6.6"]["idle_sec"] >= 60 and rows["7.7.7.7"]["idle_sec"] < 60, rows)
code, out = run(S.cmd_status, argparse.Namespace(live=False, interval=1, json=False, top=10, full=False))
check("status: в «активных за минуту» только 7.7.7.7",
      S.re.search(r"(?:активных|active)[^:]*:\s*1\b", plain(out)) is not None, plain(out)[:300])

print("\n\033[1m20. Монитор: заблокированный с прежним трафиком не пропадает\033[0m")
make_maps()
write_cache([["185.1.0.0/24", "МТС"]])
reset_cfg(1, block=True)
S.write_to_kernel(S.load_config())
USERS = {"185.1.0.7": {"down": 5_000_000, "up": 1_000, "up_pkts": 10, "seen": 0,
                       "down_drop": 0, "up_drop": 0},
         "4.4.4.4": {"down": 5_000_000, "up": 1_000, "up_pkts": 10, "seen": 0,
                     "down_drop": 100_000, "up_drop": 0}}
out = mon_out2({"185.1.0.7": {"down": 12_500}, "4.4.4.4": {"down_drop": 125_000}})
l444 = [l for l in out.splitlines() if "4.4.4.4" in l]
check("клиент с накопленным трафиком, но без пропущенного за интервал, виден с ✗ и ✂",
      l444 and "✗" in l444[0] and "✂" in l444[0], out)
out = mon_out2({"185.1.0.7": {"down": 12_500}})
check("и пропадает, когда срезание прекратилось",
      not any("4.4.4.4" in l for l in out.splitlines()), out)

print("\n\033[1m21. mobile_extra_parse: IPv4-mapped и зоны\033[0m")
for bad in ("::ffff:1.2.3.4", "::ffff:1.2.3.0/120", "::ffff:0:0/96", "fe80::1%eth0",
            "fe80::/64%eth0", "1.2.3.4%eth0", "::ffff:102:304"):
    check(f"{bad!r} отвергается", S.mobile_extra_parse(bad) is None, S.mobile_extra_parse(bad))
check("обычный IPv6 принимается", S.mobile_extra_parse("2a02::/16") == "2a02::/16")

print("\n\033[1m22. mobile del ASN при частичном отказе RIPEstat — честное сообщение\033[0m")
import urllib.error as _ue
make_maps()
reset_cfg(1, extra=["AS64500"])
write_cache([["185.1.0.0/24", "МТС"], ["100.64.0.0/24", "свои"]])
S.write_to_kernel(S.load_config())


def partial_fetch(asn):
    if asn == 8359:
        raise _ue.URLError("нет ответа")
    return ["85.2.0.0/16"] if asn == 3216 else []


S.mobile_fetch_asn = partial_fetch
code, out = run(S.cmd_mobile, nsm("del", "AS64500"))
p = plain(out)
nets = {tuple(n) for n in json.load(open(S.MOBILE_FILE))["nets"]}
check("сети удалённого ASN остались в кеше из-за слияния со старым",
      ("100.64.0.0/24", "свои") in nets and S.load_config()["mobile_extra"] == [], nets)
check("сообщение честное: уйдут при следующем полном обновлении, без «убрано из списка мобильных»",
      "полном обновлении" in p and "убрано из списка мобильных" not in p, p)
S.mobile_fetch_asn = lambda asn: []  # все ответили пусто, но кеш непустой — mob_none
S.mobile_fetch_asn = lambda asn: ["85.2.0.0/16"] if asn == 3216 else []
code, out = run(S.cmd_mobile, nsm("add", "AS64501"))
code, out = run(S.cmd_mobile, nsm("del", "AS64501"))
check("полностью успешное обновление: прежнее сообщение «убрано»",
      "убрано из списка мобильных" in plain(out) and "полном обновлении" not in plain(out), plain(out))

print(f"\n\033[1mИтог: {ok} пройдено, {fail} провалено\033[0m")
sys.exit(1 if fail else 0)
