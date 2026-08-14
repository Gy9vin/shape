#!/usr/bin/env python3
"""Проверки после аудита Shape. Запускать из песочницы, не на ноде."""
import json, os, subprocess, sys, tempfile, time, importlib.util

import os as _os
# Корень проекта: каталог над tests/. Так набор работает и локально, и в CI.
SRC = _os.environ.get("SHAPE_SRC") or _os.path.dirname(_os.path.dirname(
    _os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix="shape-audit-")
ETC = os.path.join(TMP, "etc"); os.makedirs(ETC)
BIN = os.path.join(TMP, "bin"); os.makedirs(BIN)
PIN = os.path.join(TMP, "maps"); os.makedirs(PIN)
open(os.path.join(PIN, "config_map"), "w").close()

# Подставной bpftool: пишет вызовы в файл, ничего не делает.
with open(os.path.join(BIN, "bpftool"), "w") as f:
    f.write('#!/bin/sh\nprintf "%s\\n" "$*" >> "$BPFTOOL_LOG"\n'
            'case "$*" in *dump*) echo "[]";; esac\nexit 0\n')
os.chmod(os.path.join(BIN, "bpftool"), 0o755)
os.environ["PATH"] = BIN + ":" + os.environ["PATH"]
os.environ["SHAPER_PIN_DIR"] = PIN
os.environ["BPFTOOL_LOG"] = os.path.join(TMP, "bpftool.log")

spec = importlib.util.spec_from_file_location("S", os.path.join(SRC, "shaperctl.py"))
S = importlib.util.module_from_spec(spec); spec.loader.exec_module(S)
S.ETC_DIR = ETC
S.CONFIG_FILE = os.path.join(ETC, "config.json")
S.PEN_FILE = os.path.join(ETC, "penalties.json")
S.DAILY_FILE = os.path.join(ETC, "daily.json")
S.DIGEST_FILE = os.path.join(ETC, "digest.json")
S.WL_FILE = os.path.join(ETC, "whitelist.txt")

import argparse
ok = fail = 0
def check(name, cond, extra=""):
    global ok, fail
    if cond: ok += 1; print(f"  \033[32m✓\033[0m {name}")
    else:    fail += 1; print(f"  \033[31m✗ {name}\033[0m {extra}")

def dies(fn, *a, **kw):
    try: fn(*a, **kw); return False
    except SystemExit: return True

def guard(**kw):
    d = dict(enable=False, disable=False, score=None, both_min=None, both_dl=None,
             both_ul=None, percent=None, sustain=None, penalty_mbps=None,
             penalty_min=None, hours=None, upload_gb=None, download_gb=None,
             download_gbh=None, interval=None, packet=None, quiet=True)
    d.update(kw); return argparse.Namespace(**d)

def tg(**kw):
    d = dict(action="set", at=None, token=None, chat=None, thread=None, name=None,
             proxy=None, enable=False, disable=False, events=None, daily=None,
             quiet=True)
    d.update(kw); return argparse.Namespace(**d)

print("\n\033[1m1. Регрессия: правка автоограничения стирала настройки Telegram\033[0m")
S.save_config({"ports": [443], "speed_mbps": 15, "guard": dict(S.GUARD_DEFAULT),
               "telegram": dict(S.TG_DEFAULT, token=("123456789:" + "AABBccddeeFFgghhiijjkkllmmnnoopp"),
                                chat_id="-1001234567890", enabled=True, digest_at="21:30")})
S.cmd_guard(guard(score=4))
after = json.load(open(S.CONFIG_FILE))
check("токен на месте после смены баллов",
      after.get("telegram", {}).get("token", "").startswith("123456789:"))
check("время сводки не сброшено", after.get("telegram", {}).get("digest_at") == "21:30")
check("новое значение записано", after["guard"]["score_needed"] == 4)

print("\n\033[1m2. Конфиг: чужие разделы и права\033[0m")
raw = json.load(open(S.CONFIG_FILE)); raw["future_section"] = {"x": 1}
open(S.CONFIG_FILE, "w").write(json.dumps(raw))
S.cmd_guard(guard(penalty_min=30))
check("незнакомый раздел пережил запись",
      "future_section" in json.load(open(S.CONFIG_FILE)))
check("права config.json = 600", oct(os.stat(S.CONFIG_FILE).st_mode)[-3:] == "600",
      oct(os.stat(S.CONFIG_FILE).st_mode))

print("\n\033[1m3. Валидация IP\033[0m")
for good in ("1.2.3.4", "203.0.113.10", "2001:db8::1", "::1"):
    check(f"принят {good}", S.valid_ip(good) is not None)
for bad in ("1.2.3.4; rm -rf /", "$(id)", "`id`", "999.1.1.1", "1.2.3.4/24",
            "../../etc/passwd", "", "   ", "1.2.3.4\n5.6.7.8", "0x7f000001"):
    check(f"отвергнут {bad!r}", S.valid_ip(bad) is None)
check("release с мусором не падает трассировкой",
      dies(S.cmd_release, argparse.Namespace(ip="1.2.3.4; id", all=False)))
check("whitelist add с мусором не падает трассировкой",
      dies(S.cmd_whitelist, argparse.Namespace(action="add", ip="$(touch /tmp/pwned)")))
check("файл /tmp/pwned не создан", not os.path.exists("/tmp/pwned"))

print("\n\033[1m4. Валидация портов и скорости\033[0m")
check("443,80 разобраны", S.parse_ports("443,80") == [443, 80])
for bad in ("443; rm -rf /", "-1", "99999", "443,$(id)", "port"):
    check(f"порт {bad!r} отвергнут", dies(S.parse_ports, bad))
check("дубликаты схлопнуты", S.parse_ports("443,443,80") == [443, 80])
for bad in (float("nan"), float("inf"), -1.0, 1e9):
    check(f"скорость {bad} отвергнута",
          dies(S.cmd_apply, argparse.Namespace(ports=None, speed=bad, quiet=True)))

print("\n\033[1m5. Валидация Telegram\033[0m")
for bad in ("abc", "123:short", "123456789:aa/../../botOTHER", "токен",
            "123456789:AABB ccdd", "123456789:AA\nBB"):
    check(f"токен {bad!r} отвергнут", dies(S.cmd_telegram, tg(token=bad)))
check("нормальный токен принят",
      not dies(S.cmd_telegram, tg(token=("987654321:" + "AABBccddeeFFgghhiijjkkllmmnnoopp"))))
for bad in ("chat; id", "abc", "@x"):
    check(f"chat_id {bad!r} отвергнут", dies(S.cmd_telegram, tg(chat=bad)))
check("chat_id -100... принят", not dies(S.cmd_telegram, tg(chat="-1001234567890")))
for bad in ("2; id", "-5", "abc"):
    check(f"тема {bad!r} отвергнута", dies(S.cmd_telegram, tg(thread=bad)))
for bad in ("socks5://", "socks5://host:99999", "https://t.me/proxy?secret=ee11",
            "javascript:alert(1)", "socks4://1.2.3.4:1080"):
    check(f"прокси {bad!r} отвергнут", dies(S.cmd_telegram, tg(proxy=bad)))
check("socks5://127.0.0.1:1080 принят",
      not dies(S.cmd_telegram, tg(proxy="socks5://127.0.0.1:1080")))
for bad in ("25:00", "9", "abc", "-1:00", "12:99"):
    check(f"время {bad!r} отвергнуто", dies(S.cmd_telegram, tg(at=bad)))
check("21:07 принято", not dies(S.cmd_telegram, tg(at="21:07")))
check("подпись длиной 200 символов отвергнута", dies(S.cmd_telegram, tg(name="x" * 200)))

print("\n\033[1m6. Утечка токена и HTML в сообщениях\033[0m")
tok = ("123456789:" + "AABBccddeeFFgghhiijjkkllmmnnoopp")
leak = f"<urlopen error https://api.telegram.org/bot{tok}/sendMessage failed>"
check("токен вычищен из текста ошибки", tok not in S.scrub(leak, {"telegram": {"token": tok}}))
check("токен вычищен и без знания конфига", tok not in S.scrub(leak))
check("подпись ноды экранируется",
      S.node_label({"node_name": "<b>RU</b> & Co"}) == "&lt;b&gt;RU&lt;/b&gt; &amp; Co")

print("\n\033[1m7. Повреждённые файлы состояния\033[0m")
for junk in ('{"1.2.3.4": {"until": "завтра", "mbps": 1}}',
             '[1,2,3]', 'не json вовсе', '{"$(id)": {"until": 99999999999, "mbps": 1}}',
             '{"1.2.3.4": {"until": 99999999999}}'):
    open(S.PEN_FILE, "w").write(junk)
    try:
        S.load_penalties(); good = True
    except Exception as e:
        good = False; err = e
    check(f"штрафы: пережит мусор {junk[:28]!r}", good)
open(S.PEN_FILE, "w").write(json.dumps(
    {"1.2.3.4": {"until": time.time() + 600, "mbps": 1, "since": time.time()}}))
check("живой штраф прочитан", "1.2.3.4" in S.load_penalties())

print("\n\033[1m8. Внешние команды выполняются без оболочки\033[0m")
S.map_dump("config_map; touch /tmp/injected")
check("подставленное имя карты не выполнилось", not os.path.exists("/tmp/injected"))
out, rc = S.run(["echo", "$(id)", "&&", "touch", "/tmp/injected2"])
check("метасимволы переданы как текст", out == "$(id) && touch /tmp/injected2")
check("файл /tmp/injected2 не создан", not os.path.exists("/tmp/injected2"))

print("\n\033[1m9. Сводка: расписание\033[0m")
S.digest_stash("2026-08-12", {"1.1.1.1": {"down": 9e10, "up": 2e9, "active": 3600}})
sent = []
S.tg_send = lambda text, cfg=None, force=False: (sent.append(text), (True, "ok"))[1]
cfg = {"telegram": {"enabled": True, "daily": True, "digest_at": "09:00", "node_name": "n"}}
base = time.mktime(time.strptime("2026-08-13", "%Y-%m-%d"))
real_time = time.time
for label, now in (("00:10", base + 600), ("08:59", base + 8 * 3600 + 3540),
                   ("09:00", base + 9 * 3600), ("09:00 повтор", base + 9 * 3600 + 30)):
    S.time.time = lambda n=now: n
    S.digest_due(cfg)
    check(f"{label}: отправлено {len(sent)}",
          len(sent) == (0 if label in ("00:10", "08:59") else 1))
S.time.time = real_time

print("\n\033[1m10. Расчёт задержки в ядре (модель eBPF)\033[0m")
def edt(limit_mbps, packets, flows=1, horizon_ns=2_000_000_000):
    """Повторяет арифметику process_packet: EDT на скачивание."""
    rate = int(limit_mbps * 125_000)
    dep = [0] * flows
    now, passed, dropped = 0, 0, 0
    for i, size in enumerate(packets):
        f = i % flows
        d = max(max(dep), now)
        delay = size * 1_000_000_000 // rate
        d += delay
        if d - now > horizon_ns:
            dropped += 1
            continue
        for k in range(flows):
            dep[k] = d
        passed += size
    span = max(dep) / 1e9 or 1e-9
    return passed * 8 / 1e6 / span, dropped

for flows in (1, 4, 64):
    mbps, drop = edt(10, [1500] * 4000, flows=flows)
    check(f"{flows:>2} потоков: {mbps:.2f} Мбит/с при лимите 10", 9.0 <= mbps <= 11.0,
          f"получено {mbps:.2f}")

print(f"\n\033[1mИтог: {ok} пройдено, {fail} провалено\033[0m")
sys.exit(1 if fail else 0)
