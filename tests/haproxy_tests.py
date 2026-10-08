#!/usr/bin/env python3
"""
Режим HAProxy: шейпер на списке интерфейсов («eth0 lo»).

Режим — это слово «lo» в IFACE плюс внутренний порт xray в списке портов.
Проверяется то, что можно проверить без root и без ядра: запись shaper.conf,
порты, перезапуск сервиса, чтение списка интерфейсов шейпером и сторожем.
`ip` и `systemctl` подменены заглушками, состояние живёт во временном каталоге.
"""
import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import argparse

SRC = os.environ.get("SHAPE_SRC") or os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))

TMP = tempfile.mkdtemp(prefix="shape-haproxy-")
ETC = os.path.join(TMP, "etc"); os.makedirs(ETC)
BIN = os.path.join(TMP, "bin"); os.makedirs(BIN)
PIN = os.path.join(TMP, "maps"); os.makedirs(PIN)
CALLS = os.path.join(TMP, "calls.log")

with open(os.path.join(BIN, "ip"), "w") as f:
    f.write('#!/bin/sh\necho "1.1.1.1 via 10.0.0.1 dev ens3 src 10.0.0.2 uid 0"\n')
with open(os.path.join(BIN, "systemctl"), "w") as f:
    f.write('#!/bin/sh\nprintf "systemctl %s\\n" "$*" >> "$CALLS_LOG"\n'
            '[ -f "$SYSTEMCTL_FAIL" ] && exit 1\nexit 0\n')
for n in ("ip", "systemctl"):
    os.chmod(os.path.join(BIN, n), 0o755)
os.environ["PATH"] = BIN + ":" + os.environ["PATH"]
os.environ["CALLS_LOG"] = CALLS
os.environ["SYSTEMCTL_FAIL"] = os.path.join(TMP, "fail")
os.environ["SHAPER_PIN_DIR"] = PIN
os.environ["SHAPE_ETC_DIR"] = ETC
os.environ["SHAPE_VAR_DIR"] = os.path.join(TMP, "var")
open(os.path.join(PIN, "config_map"), "w").close()

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


CONF = os.path.join(ETC, "shaper.conf")
CFG = os.path.join(ETC, "config.json")


def reset(conf, ports, speed=15):
    with open(CONF, "w") as f:
        f.write(conf)
    with open(CFG, "w") as f:
        json.dump({"ports": ports, "speed_mbps": speed}, f)
    open(CALLS, "w").close()
    if os.path.exists(os.environ["SYSTEMCTL_FAIL"]):
        os.remove(os.environ["SYSTEMCTL_FAIL"])


def conf_iface():
    last = None
    for line in open(CONF):
        if line.startswith("IFACE="):
            last = line.strip()
    return last


def ports():
    return json.load(open(CFG))["ports"]


def calls():
    return open(CALLS).read()


def ns(action, **kw):
    d = dict(action=action, port=None, drop_port=None, no_restart=False)
    d.update(kw)
    return argparse.Namespace(**d)


def run(action, **kw):
    """-> (завершилось ли выходом, вывод)"""
    buf = io.StringIO()
    exited = False
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        try:
            S.cmd_haproxy(ns(action, **kw))
        except SystemExit:
            exited = True
    return exited, buf.getvalue()


print("\n\033[1m1. Включение режима\033[0m")
reset('# комментарий\nIFACE=""\nUI_LANG="ru"\n', [443])
ex, out = run("on", port="1443")
check("пустой IFACE: внешний интерфейс определён по маршруту, lo добавлен",
      conf_iface() == 'IFACE="ens3 lo"', conf_iface())
check("внутренний порт добавлен к существующим", ports() == [443, 1443], ports())
check("остальные строки shaper.conf целы",
      '# комментарий' in open(CONF).read() and 'UI_LANG="ru"' in open(CONF).read())
check("сервис перезапущен", "systemctl restart shaper" in calls(), calls())
check("права на shaper.conf 600", oct(os.stat(CONF).st_mode & 0o777) == "0o600")

ex, out = run("on", port="1443")
check("повторное включение не плодит lo и порт",
      conf_iface() == 'IFACE="ens3 lo"' and ports() == [443, 1443])
ex, out = run("on", port="2443")
check("второй внутренний порт дописывается",
      ports() == [443, 1443, 2443] and conf_iface() == 'IFACE="ens3 lo"')

reset('IFACE="eth0"\n', [443])
run("on", port="1443")
check("явный внешний интерфейс сохраняется", conf_iface() == 'IFACE="eth0 lo"',
      conf_iface())

reset('UI_LANG="en"\n', [443])
run("on", port="1443")
check("IFACE не было вовсе — строка дописана",
      conf_iface() == 'IFACE="ens3 lo"' and 'UI_LANG="en"' in open(CONF).read())

reset('IFACE="eth0"\nIFACE="eth1"\n', [443])
run("on", port="1443")
check("дубли IFACE схлопнуты в одну строку (в bash побеждала бы последняя)",
      open(CONF).read().count("IFACE=") == 1 and conf_iface() == 'IFACE="eth1 lo"',
      open(CONF).read())

reset('IFACE="eth0"\n', [443])
run("on", port="1443", no_restart=True)
check("--no-restart не трогает сервис", "systemctl" not in calls(), calls())

print("\n\033[1m2. Плохой ввод не меняет ничего\033[0m")
for bad in (None, "0", "65536", "-1", "abc", "443; id", "", "1e3"):
    reset('IFACE="eth0"\n', [443])
    ex, out = run("on", port=bad)
    check(f"порт {bad!r} отвергнут, файлы не тронуты",
          ex and conf_iface() == 'IFACE="eth0"' and ports() == [443]
          and calls() == "", out)

reset('IFACE="eth0 bad;name"\n', [443])
ex, out = run("on", port="1443")
check("мусор в IFACE: отказ, а не запись", ex and ports() == [443], out)

reset('IFACE="eth0"\n', list(range(1, S.MAX_PORTS + 1)))
ex, out = run("on", port="9999")
check("лимит числа портов соблюдается", ex and 9999 not in ports(), out)

print("\n\033[1m3. Порт 0 («все порты») рядом с lo\033[0m")
reset('IFACE="eth0"\n', [0])
ex, out = run("on", port="1443")
check("0 в списке допустим, но пользователя предупреждают, что на lo он не работает",
      ports() == [0, 1443] and "0" in out and "lo" in out and not ex, out)

print("\n\033[1m4. Выключение режима\033[0m")
reset('IFACE="eth0 lo"\n', [443, 1443])
run("off")
check("lo снят, внешний интерфейс остался", conf_iface() == 'IFACE="eth0"',
      conf_iface())
check("порты не тронуты без --drop-port", ports() == [443, 1443])
check("сервис перезапущен", "systemctl restart shaper" in calls())

reset('IFACE="eth0 lo"\n', [443, 1443])
run("off", drop_port="1443")
check("--drop-port убирает внутренний порт", ports() == [443], ports())

reset('IFACE="lo"\n', [1443])
ex, out = run("off", drop_port="1443")
check("последний порт из списка не убирается", ports() == [1443], out)
check("IFACE из одного lo становится пустым (автоопределение)",
      conf_iface() == 'IFACE=""', conf_iface())

reset('IFACE="eth0"\n', [443])
run("off")
check("выключение без lo ничего не ломает", conf_iface() == 'IFACE="eth0"')

reset('IFACE="eth0 lo"\n', [443, 1443])
ex, out = run("off", drop_port="abc")
check("нечисловой --drop-port отвергнут", ex, out)

print("\n\033[1m5. Сервис не перезапустился\033[0m")
reset('IFACE="eth0"\n', [443])
open(os.environ["SYSTEMCTL_FAIL"], "w").close()
ex, out = run("on", port="1443")
check("ошибка systemctl не роняет команду и не откатывает настройку",
      not ex and conf_iface() == 'IFACE="eth0 lo"' and 1443 in ports(), out)
check("и пользователю говорят, что делать", "systemctl restart shaper" in out, out)

print("\n\033[1m6. Статус\033[0m")
reset('IFACE="eth0 lo"\n', [443])
ex, out = run("status")
check("статус: режим включён", "eth0 lo" in out and "lo" in out and not ex, out)
check("статус ничего не пишет", conf_iface() == 'IFACE="eth0 lo"' and calls() == "")
reset('IFACE="eth0"\n', [443])
ex, out2 = run("status")
check("статус: режим выключен, текст отличается", out2 != out, out2)

print("\n\033[1m7. Список интерфейсов читают шейпер и сторож\033[0m")
AI = os.path.join(ETC, ".active_iface")
with open(AI, "w") as f:
    f.write('IFACE="eth0 lo"\n')
check("active_ifaces: оба интерфейса", S.active_ifaces() == ["eth0", "lo"],
      S.active_ifaces())
check("active_iface: основной — внешний, а не lo", S.active_iface() == "eth0")
with open(AI, "w") as f:
    f.write('IFACE="lo eth0"\n')
check("порядок в файле не важен: основной всё равно внешний",
      S.active_iface() == "eth0")
with open(AI, "w") as f:
    f.write('IFACE="ens3"\n')
check("старый формат с одним интерфейсом читается", S.active_ifaces() == ["ens3"]
      and S.active_iface() == "ens3")
with open(AI, "w") as f:
    f.write('IFACE="lo"\n')
check("только lo: основной — lo", S.active_iface() == "lo")
with open(AI, "w") as f:
    f.write('IFACE="eth0 ba;d $(id)"\n')
check("мусор в списке отбрасывается", S.active_ifaces() == ["eth0"] or
      S.active_ifaces() == [], S.active_ifaces())
os.remove(AI)
check("файла нет — интерфейсов нет", S.active_ifaces() == []
      and S.active_iface() is None)

print("\n\033[1m8. Проверка fq идёт по каждому интерфейсу\033[0m")
with open(AI, "w") as f:
    f.write('IFACE="eth0 lo"\n')
_real_run = subprocess.run


class _R:
    def __init__(self, out, code=0):
        self.stdout, self.returncode = out, code


def _tc(by_dev):
    def fake(cmd, *a, **kw):
        if cmd[:3] == ["tc", "qdisc", "show"]:
            return _R(by_dev.get(cmd[4], ""))
        return _real_run(cmd, *a, **kw)
    return fake


FQ = "qdisc fq 8001: root refcnt 2\nqdisc clsact ffff: parent ffff:fff1\n"
CODEL = "qdisc fq_codel 0: root refcnt 2\nqdisc clsact ffff: parent ffff:fff1\n"
NOQ = "qdisc noqueue 0: root refcnt 2\n"
subprocess.run = _tc({"eth0": FQ, "lo": FQ})
check("fq на обоих — готово", S.edt_ready() == (True, ""))
subprocess.run = _tc({"eth0": FQ, "lo": CODEL})
r, bad = S.edt_ready()
check("плохой qdisc на lo замечен, хотя внешний в порядке",
      r is False and bad == "fq_codel", (r, bad))
subprocess.run = _tc({"eth0": FQ, "lo": NOQ})
check("noqueue на lo — не беда", S.edt_ready() == (True, ""))
subprocess.run = _tc({"eth0": CODEL, "lo": FQ})
check("явный интерфейс проверяется только он сам",
      S.edt_ready("lo") == (True, ""))
subprocess.run = _real_run

print(f"\n\033[1mИтог: {ok} пройдено, {fail} провалено\033[0m")
sys.exit(1 if fail else 0)
