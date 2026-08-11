#!/usr/bin/env python3
"""
shaperctl — управление eBPF-шейпером через pinned BPF-карты.

Одна настройка: порты и скорость в Мбит/с на каждого пользователя.
Только стандартная библиотека и bpftool.
"""

import argparse
import ipaddress
import json
import os
import struct
import subprocess
import sys
import time

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

PIN_DIR     = os.environ.get("SHAPER_PIN_DIR", "/sys/fs/bpf/shaper/maps")
ETC_DIR     = "/etc/shaper"
CONFIG_FILE = os.path.join(ETC_DIR, "config.json")
WL_FILE     = os.path.join(ETC_DIR, "whitelist.txt")
PEN_FILE    = os.path.join(ETC_DIR, "penalties.json")
DAILY_FILE  = os.path.join(ETC_DIR, "daily.json")

NS = 1_000_000_000
# Мбит/с -> байт/с. Мегабит десятичный: 1 Мбит = 1 000 000 бит = 125 000 байт.
BYTES_PER_MBPS = 125_000
MAX_MBPS = 100_000          # 100 Гбит/с — заведомо выше любого разумного канала
MAX_PORTS = 64              # должно совпадать с max_entries port_map в shaper.bpf.c

CONFIG_FMT = "<Q"           # struct config, 8 байт
PEN_FMT = "<2Q"             # struct penalty: rate_bytes_per_sec, until_ns
USER_FMT, USER_SIZE = "<4Q", 32   # struct user_state

C = {
    "r": "\033[0m", "b": "\033[1m",
    "red": "\033[31m", "grn": "\033[32m", "yel": "\033[33m", "gry": "\033[90m",
}


# ─────────────────────────── языки ───────────────────────────
# Язык берётся из UI_LANG в /etc/shaper/shaper.conf, его пишет меню.

MSG = {
    "ru": {
        "root": "нужны права root",
        "lim_why": "за что",
        "lim_when": "с",
        "lim_total": "всего ограничено",
        "lim_speed": "скорость нарушителя",
        "h_score": "баллов для штрафа (1-6)",
        "h_both_min": "минут одновременной нагрузки в обе стороны",
        "h_both_dl": "порог скачивания для двусторонней нагрузки, %",
        "h_both_ul": "порог отдачи для двусторонней нагрузки, %",
        "h_hours": "часов активности за сутки",
        "h_upload_gb": "гигабайт отдачи за сутки",
        "h_download_gb": "гигабайт скачивания за сутки, 0 = выкл",
        "h_watch_iv": "период опроса карт, сек (больше = легче процессору)",
        "why_download": "выкачал десятки гигабайт за сутки",
        "h_packet": "средний размер пакета в отдаче, байт",
        "guard_both": "Обе стороны сразу",
        "guard_score": "Баллов для штрафа",
        "why_packet": "отдаёт данные, а не подтверждения",
        "why_peak": "держит потолок скачивания",
        "why_hours": "часами не отпускает канал",
        "why_upload": "много отдал за сутки",
        "h_guard": "автоограничение нарушителей",
        "h_percent": "порог, % от лимита",
        "h_sustain": "сколько минут держать нагрузку до штрафа",
        "h_pen_mbps": "скорость нарушителя, Мбит/с",
        "h_pen_min": "на сколько минут ограничивать",
        "h_watch": "демон слежения (запускается сервисом)",
        "h_limited": "кто сейчас ограничен",
        "h_release": "снять ограничение с IP",
        "guard_state": "Автоограничение",
        "guard_on": "включено", "guard_off": "выключено",
        "guard_trigger": "Порог", "guard_of_limit": "от лимита",
        "guard_during": "непрерывно", "guard_penalty": "Штраф",
        "guard_for": "на", "guard_range": "{k}: допустимо от {lo} до {hi}",
        "lim_title": "Ограниченные пользователи",
        "lim_none": "ограниченных нет",
        "lim_left": "осталось",
        "rel_one": "ограничение с {ip} снято",
        "rel_all": "снято ограничений: {n}",
        "rel_need_ip": "укажи IP или --all",
        "restored_pen": "восстановлено штрафов: {n}",
        "watch_start": "сторож запущен",
        "watch_hit": "{ip} ограничен до {mbps:g} Мбит/с на {m} мин",
        "units": ["Б", "КБ", "МБ", "ГБ", "ТБ", "ПБ"],
        "sec": "с", "min": "мин", "hour": "ч",
        "measuring": "замер скорости {i} с…",
        "desc": "eBPF-шейпер: лимит скорости на пользователя. Всё в Мбит/с.",
        "h_apply": "задать порты и скорость",
        "h_ports": "через запятую, 0 = все порты",
        "h_speed": "Мбит/с на пользователя, 0 = снять ограничение",
        "h_show": "показать текущие настройки",
        "h_restore": "залить настройки в карты",
        "h_monitor": "кто грузит канал прямо сейчас",
        "h_interval": "период обновления, сек",
        "h_status": "статистика по IP",
        "h_live": "замерить текущую скорость",
        "h_full": "показать все IP",
        "h_json": "вывод в JSON",
        "h_whitelist": "белый список IP",
        "no_engine": "движок не запущен — карты не найдены в {d}\n  запусти: systemctl start shaper",
        "cmd_fail": "команда не выполнилась: {c}\n  {e}",
        "port_nan": "порт «{p}» не число",
        "port_range": "порт {p} вне диапазона 0..65535",
        "too_many_ports": "портов не больше {n}",
        "no_ports": "не указан ни один порт (0 = все порты)",
        "neg_speed": "скорость не может быть отрицательной",
        "too_fast": "{v} Мбит/с — это больше 100 Гбит/с, проверь значение",
        "speed": "Скорость", "ports": "Порты", "all_ports": "ВСЕ ПОРТЫ",
        "per_user": "на каждого пользователя, в обе стороны",
        "unlimited": "не ограничена",
        "restored": "лимит {s:g} Мбит/с на портах {p}",
        "limit": "Лимит", "no_limit": "не ограничено",
        "total_ips": "всего IP", "active_min": "активных за минуту",
        "no_traffic": "трафика через шейпер ещё не было",
        "downloaded": "скачал", "uploaded": "отдал", "now": "сейчас",
        "more_ips": "… ещё {n} IP, полный список: shaperctl status --full",
        "idle_note": "· — нет трафика больше 5 минут",
        "wl_added": "{ip} добавлен в белый список",
        "wl_removed": "{ip} убран из белого списка",
        "wl_loaded": "загружено в белый список: {n}",
        "wl_bad": "пропущен неверный адрес: {ip}",
        "wl_empty": "белый список пуст",
        "mon_title": "Монитор", "mon_hint": "· обновление каждые {i} с · Ctrl+C — выход",
        "mon_channel": "Канал сейчас", "mon_limit": "Лимит {s:g} Мбит/с на пользователя",
        "mon_nolimit": "Лимит не задан", "mon_loading": "нагружают канал",
        "mon_of": "из", "mon_idle": "сейчас никто не качает",
        "mon_up": "отдача", "mon_avg": "мин.средн", "mon_hold": "держит",
        "mon_bar": "загрузка", "mon_more": "… ещё {n} активных",
        "mon_legend": "жёлтым — держит нагрузку больше 30 с, красным — упёрся в лимит",
    },
    "en": {
        "root": "root privileges required",
        "lim_why": "why",
        "lim_when": "since",
        "lim_total": "limited total",
        "lim_speed": "offender speed",
        "h_score": "score needed for a penalty (1-6)",
        "h_both_min": "minutes of simultaneous two-way load",
        "h_both_dl": "download floor for two-way load, %",
        "h_both_ul": "upload floor for two-way load, %",
        "h_hours": "hours of activity per day",
        "h_upload_gb": "gigabytes uploaded per day",
        "h_download_gb": "gigabytes downloaded per day, 0 = off",
        "h_watch_iv": "map polling period, sec (higher = lighter on CPU)",
        "why_download": "downloaded tens of gigabytes in 24h",
        "h_packet": "average upload packet size, bytes",
        "guard_both": "Both ways at once",
        "guard_score": "Score needed",
        "why_packet": "sends real data, not just ACKs",
        "why_peak": "holds the download ceiling",
        "why_upload": "uploaded a lot in 24h",
        "why_hours": "keeps the channel busy for hours",
        "h_guard": "automatic limiting of heavy users",
        "h_percent": "threshold, % of the limit",
        "h_sustain": "minutes of sustained load before the penalty",
        "h_pen_mbps": "offender speed, Mbit/s",
        "h_pen_min": "penalty duration, minutes",
        "h_watch": "watchdog daemon (started by the service)",
        "h_limited": "who is currently limited",
        "h_release": "release an IP",
        "guard_state": "Auto-limit",
        "guard_on": "enabled", "guard_off": "disabled",
        "guard_trigger": "Threshold", "guard_of_limit": "of the limit",
        "guard_during": "sustained for", "guard_penalty": "Penalty",
        "guard_for": "for", "guard_range": "{k}: allowed from {lo} to {hi}",
        "lim_title": "Limited users",
        "lim_none": "nobody is limited",
        "lim_left": "left",
        "rel_one": "{ip} released",
        "rel_all": "released: {n}",
        "rel_need_ip": "specify an IP or --all",
        "restored_pen": "penalties restored: {n}",
        "watch_start": "watchdog started",
        "watch_hit": "{ip} limited to {mbps:g} Mbit/s for {m} min",
        "units": ["B", "KB", "MB", "GB", "TB", "PB"],
        "sec": "s", "min": "min", "hour": "h",
        "measuring": "measuring speed for {i} s…",
        "desc": "eBPF shaper: per-user speed limit. Everything in Mbit/s.",
        "h_apply": "set ports and speed",
        "h_ports": "comma separated, 0 = all ports",
        "h_speed": "Mbit/s per user, 0 = remove the limit",
        "h_show": "show current settings",
        "h_restore": "push settings into the maps",
        "h_monitor": "who is loading the channel right now",
        "h_interval": "refresh period, seconds",
        "h_status": "per-IP statistics",
        "h_live": "measure current speed",
        "h_full": "show all IPs",
        "h_json": "JSON output",
        "h_whitelist": "IP whitelist",
        "no_engine": "engine is not running — no maps in {d}\n  start it: systemctl start shaper",
        "cmd_fail": "command failed: {c}\n  {e}",
        "port_nan": "port \u00ab{p}\u00bb is not a number",
        "port_range": "port {p} is out of range 0..65535",
        "too_many_ports": "no more than {n} ports",
        "no_ports": "no ports given (0 = all ports)",
        "neg_speed": "speed cannot be negative",
        "too_fast": "{v} Mbit/s is over 100 Gbit/s, check the value",
        "speed": "Speed", "ports": "Ports", "all_ports": "ALL PORTS",
        "per_user": "per user, both directions",
        "unlimited": "unlimited",
        "restored": "limit {s:g} Mbit/s on ports {p}",
        "limit": "Limit", "no_limit": "unlimited",
        "total_ips": "total IPs", "active_min": "active in the last minute",
        "no_traffic": "no traffic through the shaper yet",
        "downloaded": "down", "uploaded": "up", "now": "now",
        "more_ips": "… {n} more IPs, full list: shaperctl status --full",
        "idle_note": "· — no traffic for over 5 minutes",
        "wl_added": "{ip} added to the whitelist",
        "wl_removed": "{ip} removed from the whitelist",
        "wl_loaded": "loaded into the whitelist: {n}",
        "wl_bad": "skipped invalid address: {ip}",
        "wl_empty": "whitelist is empty",
        "mon_title": "Monitor", "mon_hint": "· refresh every {i} s · Ctrl+C to exit",
        "mon_channel": "Channel now", "mon_limit": "Limit {s:g} Mbit/s per user",
        "mon_nolimit": "No limit set", "mon_loading": "loading the channel",
        "mon_of": "of", "mon_idle": "nobody is downloading right now",
        "mon_up": "upload", "mon_avg": "1-min avg", "mon_hold": "holding",
        "mon_bar": "load", "mon_more": "… {n} more active",
        "mon_legend": "yellow — holding load over 30 s, red — hitting the limit",
    },
}


def _detect_lang():
    try:
        for line in open(os.path.join(ETC_DIR, "shaper.conf")):
            if line.strip().startswith("UI_LANG"):
                v = line.split("=", 1)[1].strip().strip('"').strip("'")
                if v in MSG:
                    return v
    except Exception:
        pass
    return "ru"


LANG = _detect_lang()


def t(key, **kw):
    s = MSG.get(LANG, MSG["ru"]).get(key, key)
    return s.format(**kw) if kw else s


# ────────────────────────────── утилиты ──────────────────────────────

def die(msg, code=1):
    print(f"{C['red']}✗ {msg}{C['r']}", file=sys.stderr)
    sys.exit(code)


def run(cmd, check=True):
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and p.returncode != 0:
        die(t("cmd_fail", c=cmd, e=p.stderr.strip()))
    return p.stdout.strip(), p.returncode


def hexs(data):
    return " ".join(f"{b:02x}" for b in data)


def map_path(name):
    return os.path.join(PIN_DIR, name)


def require_engine():
    if not os.path.exists(map_path("config_map")):
        die(t("no_engine", d=PIN_DIR))


def map_update(name, key, value):
    require_engine()
    run(f"bpftool map update pinned {map_path(name)} "
        f"key hex {hexs(key)} value hex {hexs(value)}")


def map_delete(name, key):
    run(f"bpftool map delete pinned {map_path(name)} key hex {hexs(key)}", check=False)


def map_dump(name):
    """
    Пары (key, value) как их отдал bpftool. Формат зависит от наличия BTF:
    с BTF — словари с именами полей, без BTF — списки байтов. Разборщики
    ниже понимают оба варианта.
    """
    path = map_path(name)
    if not os.path.exists(path):
        return []
    out, rc = run(f"bpftool map dump pinned {path} -j", check=False)
    if rc != 0 or not out:
        return []
    try:
        raw = json.loads(out)
    except json.JSONDecodeError:
        return []
    return [(e["key"], e.get("value")) for e in raw
            if isinstance(e, dict) and "key" in e]


def _int(x):
    if isinstance(x, int):
        return x
    if isinstance(x, str):
        return int(x, 16) if x.startswith("0x") else int(x)
    return 0


def _raw(x):
    """Список байтов -> bytes. Для структурного вида возвращает None."""
    if isinstance(x, list) and (not x or not isinstance(x[0], (dict, list))):
        try:
            return bytes(_int(v) & 0xFF for v in x)
        except (ValueError, TypeError):
            return None
    return None


def parse_u32(x):
    b = _raw(x)
    if b is not None and len(b) >= 4:
        return struct.unpack("<I", b[:4])[0]
    if isinstance(x, dict):
        return _int(next(iter(x.values()), 0))
    return _int(x)


def parse_ip_key(k):
    """struct ip_key -> (адрес строкой, 16 байт ключа)."""
    b = _raw(k)
    if b is not None and len(b) >= 16:
        words = struct.unpack("<4I", b[:16])
    elif isinstance(k, dict):
        words = tuple((list(map(_int, k.get("addr", []))) + [0, 0, 0, 0])[:4])
    else:
        return None, None
    kb = struct.pack("<4I", *words)
    if words[1] == 0 and words[2] == 0 and words[3] == 0:
        return str(ipaddress.IPv4Address(kb[:4])), kb
    return str(ipaddress.IPv6Address(kb)), kb


def parse_user_state(v):
    b = _raw(v)
    if b is not None and len(b) >= USER_SIZE:
        _dep, total, seen, pkts = struct.unpack(USER_FMT, b[:USER_SIZE])
        return {"total": total, "seen": seen, "pkts": pkts}
    if isinstance(v, dict):
        return {"total": _int(v.get("total_bytes", 0)),
                "seen":  _int(v.get("last_seen_ns", 0)),
                "pkts":  _int(v.get("packets", 0))}
    return {"total": 0, "seen": 0, "pkts": 0}


def fmt_bytes(n):
    n = float(n)
    units = t("units")
    for u in units[:-1]:
        if n < 1024:
            return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} {units[-1]}"


def mono_ns():
    return int(time.clock_gettime(time.CLOCK_MONOTONIC) * NS)


# ───────────────────────────── конфигурация ─────────────────────────────
# config.json:  {"ports": [443], "speed_mbps": 15}
# speed_mbps = 0 означает «ограничение выключено», трафик проходит свободно.

# Настройки сторожа. Порог в процентах от лимита: YouTube 1080p выдаёт
# в среднем 30-40% от канала в 10 Мбит/с, торрент и закачка — все 100%.
GUARD_DEFAULT = {
    "enabled": False,
    "score_needed": 3,        # баллов для штрафа
    "penalty_mbps": 1,        # хватает на переписку и звонок в мессенджере
    "penalty_min": 60,

    # Обязательное условие. Торрент — почти единственное бытовое занятие,
    # которое часами тянет данные ВНИЗ И ВВЕРХ одновременно. Стриминг молчит
    # вверх, облачный бэкап молчит вниз — оба не проходят это условие вообще.
    # Пороги разные: торрент забирает ВСЁ скачивание, а видеозвонок держит
    # скромный битрейт. Верхний порог низкий — у мобильных операторов отдача
    # всего 3-20 Мбит, и при лимите 10 сидирование даёт лишь треть канала.
    "both_dl_percent": 50,    # % от лимита вниз
    "both_ul_percent": 15,    # % от лимита вверх
    "both_ways_min": 10,      # минут одновременной нагрузки

    # Признаки, за которые начисляются баллы
    "packet_bytes": 600,      # +2 средний размер пакета в отдаче
    "trigger_percent": 80,    # +1 держит потолок скачивания
    "sustain_min": 5,
    "hours_per_day": 4,       # +2 часов активности за сутки
    "upload_gb_per_day": 2,   # +1 гигабайт отдачи за сутки

    # Отдельный путь к штрафу, в обход обязательного условия. Торрент с
    # выключенной раздачей с точки зрения сети неотличим от обычной тяжёлой
    # закачки — выдаёт его только объём за сутки. 0 = признак выключен.
    "download_gb_per_day": 50,

    # Период опроса карт. Каждый цикл — два дампа bpftool и разбор JSON;
    # на одноядерных VPS есть смысл поднять до 20-30 секунд, детект от этого
    # почти не страдает, потому что счётчики считаются в замерах, а не в секундах.
    "watch_interval": 10,
}

# Веса признаков. Размер пакета — самый надёжный: он не зависит от скорости
# канала, а у мобильных операторов отдача гуляет от 3 до 20 Мбит.
SIGNAL_WEIGHTS = {"packet": 2, "peak": 1, "hours": 2, "upload": 1,
                  "download": 3}

# Веса признаков. Одной нагрузки (3) не хватает — нужен второй признак.
# Так разовая большая закачка проходит мимо, а торрент набирает 7 из 7.
SCORE_LOAD, SCORE_RATIO, SCORE_PACKETS = 3, 2, 2
# Окно усреднения для соотношения и размера пакета.
SCORE_WINDOW_SEC = 60


def load_config():
    try:
        with open(CONFIG_FILE) as f:
            cfg = json.load(f)
    except Exception:
        cfg = {}
    guard = dict(GUARD_DEFAULT)
    guard.update(cfg.get("guard", {}))
    return {"ports": cfg.get("ports", [443]),
            "speed_mbps": float(cfg.get("speed_mbps", 0)),
            "guard": guard}


def save_config(cfg):
    os.makedirs(ETC_DIR, exist_ok=True)
    tmp = CONFIG_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, CONFIG_FILE)


def parse_ports(s):
    out = []
    for part in str(s).split(","):
        part = part.strip()
        if not part:
            continue
        if not part.isdigit():
            die(t("port_nan", p=part))
        p = int(part)
        if not 0 <= p <= 65535:
            die(t("port_range", p=p))
        if p not in out:
            out.append(p)
    if len(out) > MAX_PORTS:
        die(t("too_many_ports", n=MAX_PORTS))
    return out


def write_to_kernel(cfg):
    """Заливает скорость и список портов в BPF-карты."""
    require_engine()
    bps = int(cfg["speed_mbps"] * BYTES_PER_MBPS)
    map_update("config_map", struct.pack("<I", 0), struct.pack(CONFIG_FMT, bps))

    live = {parse_u32(k) for k, _ in map_dump("port_map")}
    for p in live - set(cfg["ports"]):
        map_delete("port_map", struct.pack("<I", p))
    for p in cfg["ports"]:
        map_update("port_map", struct.pack("<I", p), b"\x01")


def cmd_apply(a):
    cfg = load_config()
    if a.ports is not None:
        ports = parse_ports(a.ports)
        if not ports:
            die(t("no_ports"))
        cfg["ports"] = ports
    if a.speed is not None:
        if a.speed < 0:
            die(t("neg_speed"))
        if a.speed > MAX_MBPS:
            die(t("too_fast", v=a.speed))
        cfg["speed_mbps"] = a.speed

    write_to_kernel(cfg)
    save_config(cfg)
    if not a.quiet:
        cmd_show(a)


def cmd_show(a):
    cfg = load_config()
    ports = ", ".join(map(str, cfg["ports"])) if cfg["ports"] != [0] else t("all_ports")
    print()
    if cfg["speed_mbps"] > 0:
        print(f"  {t('speed'):<9}: {C['b']}{cfg['speed_mbps']:g} Mbit/s{C['r']} "
              f"{t('per_user')}")
    else:
        print(f"  {t('speed'):<9}: {C['yel']}{t('unlimited')}{C['r']}")
    print(f"  {t('ports'):<9}: {ports}")
    cmd_guard_show(cfg["speed_mbps"], cfg["guard"])


def cmd_restore(a):
    """Вызывается сервисом при старте: заливает config.json в свежие карты."""
    cfg = load_config()
    write_to_kernel(cfg)
    n = restore_penalties()
    print(t("restored", s=cfg["speed_mbps"], p=",".join(map(str, cfg["ports"]))))
    if n:
        print(t("restored_pen", n=n))


# ───────────────────────────── статистика ─────────────────────────────

def read_users():
    """{ip: {"down": байт, "up": байт, "up_pkts": шт, "seen": нс}}"""
    users = {}
    for map_name, direction in (("user_state_map_down", "down"),
                                ("user_state_map_up", "up")):
        for k, v in map_dump(map_name):
            ip, _ = parse_ip_key(k)
            if ip is None:
                continue
            st = parse_user_state(v)
            e = users.setdefault(ip, {"down": 0, "up": 0, "up_pkts": 0, "seen": 0})
            e[direction] = st["total"]
            if direction == "up":
                e["up_pkts"] = st["pkts"]
            e["seen"] = max(e["seen"], st["seen"])
    return users


def cmd_status(a):
    require_engine()
    cfg = load_config()

    first = read_users()
    if a.live:
        print(f"{C['gry']}  {t('measuring', i=a.interval)}{C['r']}")
        time.sleep(a.interval)
        second = read_users()
    else:
        second = first

    now = mono_ns()
    rows = []
    for ip, cur in second.items():
        prev = first.get(ip, {"down": 0, "up": 0})
        # байты за интервал -> Мбит/с
        dl = max(0, cur["down"] - prev["down"]) * 8 / 1e6 / a.interval if a.live else None
        ul = max(0, cur["up"] - prev["up"]) * 8 / 1e6 / a.interval if a.live else None
        idle = (now - cur["seen"]) / NS if cur["seen"] else 0
        rows.append((ip, cur, dl, ul, idle))

    if a.json:
        print(json.dumps([
            {"ip": ip, "downloaded_bytes": c["down"], "uploaded_bytes": c["up"],
             "download_mbps": dl, "upload_mbps": ul, "idle_sec": round(idle, 1)}
            for ip, c, dl, ul, idle in rows], indent=2))
        return

    rows.sort(key=(lambda x: (x[2] or 0) + (x[3] or 0)) if a.live
              else (lambda x: x[1]["down"] + x[1]["up"]), reverse=True)
    active = [x for x in rows if x[4] < 60]

    limit = (f"{cfg['speed_mbps']:g} Mbit/s" if cfg["speed_mbps"] > 0
             else t("no_limit"))
    ports = ", ".join(map(str, cfg["ports"])) if cfg["ports"] != [0] else t("all_ports")
    print(f"\n  {t('limit')} {C['b']}{limit}{C['r']} · {t('ports').lower()} {ports} · "
          f"{t('total_ips')}: {len(rows)} · {t('active_min')}: {len(active)}")
    print("  " + "─" * 70)

    if not rows:
        print(f"  {C['gry']}{t('no_traffic')}{C['r']}\n")
        return

    head = f"  {'IP':<30}{t('downloaded'):>12}{t('uploaded'):>12}"
    head += f"{t('now'):>14}" if a.live else ""
    print(f"{C['gry']}{head}{C['r']}")

    shown = rows if a.full else rows[:a.top]
    for ip, c, dl, ul, idle in shown:
        mark = f"{C['gry']}·{C['r']}" if idle > 300 else " "
        line = f" {mark}{ip:<30}{fmt_bytes(c['down']):>12}{fmt_bytes(c['up']):>12}"
        if a.live:
            line += f"{dl:>9.1f} Mbit/s"
        print(line)

    if not a.full and len(rows) > a.top:
        print(f"  {C['gry']}{t('more_ips', n=len(rows) - a.top)}{C['r']}")
    print(f"  {C['gry']}{t('idle_note')}{C['r']}\n")


# ────────────────────────────── монитор ──────────────────────────────

def rates(prev, cur, dt):
    """Скорости по каждому IP за прошедший интервал, Мбит/с."""
    out = {}
    for ip, c in cur.items():
        p = prev.get(ip, {"down": 0, "up": 0})
        out[ip] = (max(0, c["down"] - p["down"]) * 8 / 1e6 / dt,
                   max(0, c["up"] - p["up"]) * 8 / 1e6 / dt)
    return out


def fmt_hold(sec):
    """Сколько времени подряд IP держит нагрузку."""
    if sec < 1:
        return "—"
    if sec < 60:
        return f"{int(sec)} {t('sec')}"
    if sec < 3600:
        return f"{int(sec // 60)} {t('min')}"
    return f"{sec / 3600:.1f} {t('hour')}"


def bar(value, scale, width=14):
    if scale <= 0:
        return ""
    filled = min(width, int(round(value / scale * width)))
    return "█" * filled + "·" * (width - filled)


def cmd_monitor(a):
    require_engine()
    cfg = load_config()
    limit = cfg["speed_mbps"]
    # «Держит нагрузку» — выше половины лимита. Без лимита берём 5 Мбит/с.
    busy_at = max(1.0, limit * 0.5) if limit > 0 else 5.0
    keep = max(3, int(60 / a.interval))     # усреднение примерно за минуту

    history, since = {}, {}
    prev, prev_t = read_users(), time.monotonic()

    print("\033[?25l", end="", flush=True)   # спрятать курсор
    try:
        while True:
            time.sleep(a.interval)
            cur = read_users()
            now_t = time.monotonic()
            dt = max(0.1, now_t - prev_t)
            rt = rates(prev, cur, dt)
            prev, prev_t = cur, now_t

            rows = []
            for ip, (dl, ul) in rt.items():
                h = history.setdefault(ip, [])
                h.append(dl)
                del h[:-keep]
                if dl >= busy_at:
                    since.setdefault(ip, now_t)
                else:
                    since.pop(ip, None)
                rows.append((ip, dl, ul, sum(h) / len(h),
                             now_t - since[ip] if ip in since else 0))

            active = [r for r in rows if r[1] + r[2] > 0.05]
            active.sort(key=lambda r: r[1] + r[2], reverse=True)
            total_dl = sum(r[1] for r in rows)
            total_ul = sum(r[2] for r in rows)
            scale = limit if limit > 0 else max([r[1] for r in active] + [10])

            head = (t("mon_limit", s=limit) if limit > 0 else t("mon_nolimit"))
            print("\033[H\033[2J", end="")
            print(f"\n  {C['b']}{t('mon_title')}{C['r']} "
                  f"{C['gry']}{t('mon_hint', i=a.interval)}{C['r']}\n")
            print(f"  {t('mon_channel')} : {C['b']}↓ {total_dl:.1f}{C['r']} · "
                  f"↑ {total_ul:.1f} Mbit/s")
            print(f"  {head} · {t('mon_loading')}: {C['b']}{len(active)}{C['r']} "
                  f"{t('mon_of')} {len(rows)}\n")
            print(f"{C['gry']}  {'IP':<24}{t('now'):>9}{t('mon_up'):>9}"
                  f"{t('mon_avg'):>11}{t('mon_hold'):>9}   {t('mon_bar')}{C['r']}")
            print("  " + "─" * 76)

            if not active:
                print(f"  {C['gry']}{t('mon_idle')}{C['r']}")
            for ip, dl, ul, avg, hold in active[:a.top]:
                # красным — те, кто уткнулся в лимит и держит его долго
                hot = limit > 0 and dl >= limit * 0.9 and hold >= 30
                color = C["red"] if hot else (C["yel"] if hold >= 30 else "")
                print(f"  {color}{ip:<24}{dl:>9.1f}{ul:>9.1f}{avg:>11.1f}"
                      f"{fmt_hold(hold):>9}{C['r']}   {bar(dl, scale)}")

            if len(active) > a.top:
                print(f"  {C['gry']}{t('mon_more', n=len(active) - a.top)}{C['r']}")
            print(f"\n  {C['gry']}{t('mon_legend')}{C['r']}")
    except KeyboardInterrupt:
        pass
    finally:
        print("\033[?25h", end="", flush=True)   # вернуть курсор
        print()


# ─────────────────────── штрафы и сторож ───────────────────────
# Сторож раз в WATCH_INTERVAL секунд смотрит скорость каждого IP. Если она
# держится выше порога дольше заданного времени — это не стриминг, а закачка,
# и адрес получает персональный лимит на время.
#
# Счётчик с допуском: замер выше порога прибавляет очко, ниже — отнимает.
# Короткие провалы (буферизация, смена сегмента) штраф не отменяют, а вот
# нормальный сёрфинг с паузами очков не накопит.

WATCH_INTERVAL = 10          # значение по умолчанию, живое берётся из конфига


def load_penalties():
    """{ip: {"until": epoch, "mbps": float}} — только живые записи."""
    try:
        with open(PEN_FILE) as f:
            data = json.load(f)
    except Exception:
        return {}
    now = time.time()
    return {ip: p for ip, p in data.items()
            if isinstance(p, dict) and p.get("until", 0) > now}


def save_penalties(pens):
    tmp = PEN_FILE + ".tmp"
    os.makedirs(ETC_DIR, exist_ok=True)
    with open(tmp, "w") as f:
        json.dump(pens, f, indent=2)
    os.replace(tmp, PEN_FILE)


def penalty_apply(ip, mbps, until_epoch):
    """Пишет штраф в BPF-карту. until пересчитывается в шкалу ядра."""
    left = max(1.0, until_epoch - time.time())
    until_ns = mono_ns() + int(left * NS)
    map_update("penalty_map", ip_key(ip),
               struct.pack(PEN_FMT, int(mbps * BYTES_PER_MBPS), until_ns))


def penalty_clear(ip):
    map_delete("penalty_map", ip_key(ip))


def restore_penalties():
    """Перезаливает живые штрафы в карту — после рестарта движка."""
    pens = load_penalties()
    for ip, p in pens.items():
        try:
            penalty_apply(ip, p["mbps"], p["until"])
        except Exception:
            pass
    save_penalties(pens)
    return len(pens)


def cmd_limited(a):
    pens = load_penalties()
    if a.json:
        print(json.dumps([{"ip": ip, "mbps": p["mbps"],
                           "since": p.get("since"),
                           "seconds_left": round(p["until"] - time.time()),
                           "score": p.get("score"),
                           "reasons": p.get("reasons", [])}
                          for ip, p in pens.items()], indent=2))
        return
    if not pens:
        print(f"\n  {C['gry']}{t('lim_none')}{C['r']}\n")
        return

    print(f"\n{C['gry']}  {'IP':<24}{t('lim_when'):>8}{t('lim_left'):>12}"
          f"   {t('lim_why')}{C['r']}")
    print("  " + "─" * 68)
    # свежие сверху: интереснее всего то, что произошло только что
    for ip, p in sorted(pens.items(), key=lambda x: -x[1].get("since", 0)):
        since = p.get("since")
        when = time.strftime("%H:%M", time.localtime(since)) if since else "—"
        why = ", ".join(t("why_" + r) for r in p.get("reasons") or []) or "—"
        print(f"  {C['red']}{ip:<24}{C['r']}{when:>8}"
              f"{fmt_hold(p['until'] - time.time()):>12}   {C['gry']}{why}{C['r']}")
    print(f"\n  {C['gry']}{t('lim_total')}: {len(pens)} · "
          f"{t('lim_speed')} {next(iter(pens.values()))['mbps']:g} Mbit/s{C['r']}\n")


def cmd_release(a):
    pens = load_penalties()
    if a.all:
        for ip in list(pens):
            penalty_clear(ip)
        save_penalties({})
        print(f"{C['grn']}✓ {t('rel_all', n=len(pens))}{C['r']}")
        return
    if not a.ip:
        die(t("rel_need_ip"))
    penalty_clear(a.ip)
    pens.pop(a.ip, None)
    save_penalties(pens)
    print(f"{C['grn']}✓ {t('rel_one', ip=a.ip)}{C['r']}")


def cmd_guard(a):
    cfg = load_config()
    g = cfg["guard"]
    if a.enable:
        g["enabled"] = True
    if a.disable:
        g["enabled"] = False

    limits = (
        (a.score,      "score_needed",      1, 6),
        (a.both_min,   "both_ways_min",     1, 120),
        (a.both_dl,    "both_dl_percent",   10, 100),
        (a.both_ul,    "both_ul_percent",   5, 100),
        (a.percent,    "trigger_percent",   10, 100),
        (a.sustain,    "sustain_min",       1, 1440),
        (a.penalty_mbps, "penalty_mbps",    0.1, 1000),
        (a.penalty_min,  "penalty_min",     1, 10080),
        (a.hours,      "hours_per_day",     1, 24),
        (a.upload_gb,  "upload_gb_per_day", 0.1, 1000),
        (a.download_gb, "download_gb_per_day", 0, 10000),
        (a.interval,   "watch_interval",     5, 60),
        (a.packet,     "packet_bytes",      100, 1500),
    )
    for val, key, lo, hi in limits:
        if val is not None:
            if not lo <= val <= hi:
                die(t("guard_range", k=key, lo=lo, hi=hi))
            g[key] = val

    save_config({"ports": cfg["ports"], "speed_mbps": cfg["speed_mbps"], "guard": g})
    if not a.quiet:
        cmd_guard_show(cfg["speed_mbps"], g)


def cmd_guard_show(speed, g):
    print()
    state = f"{C['grn']}{t('guard_on')}{C['r']}" if g["enabled"] \
        else f"{C['gry']}{t('guard_off')}{C['r']}"
    print(f"  {t('guard_state')}: {state}")
    if speed > 0:
        print(f"  {t('guard_both')}: ↓{speed * g['both_dl_percent'] / 100:g} "
              f"↑{speed * g['both_ul_percent'] / 100:g} Mbit/s "
              f"{t('guard_during')} {g['both_ways_min']} {t('min')}")
        print(f"  {t('guard_score')}: {g['score_needed']}")
    print(f"  {t('guard_penalty')}: {g['penalty_mbps']:g} Mbit/s "
          f"{t('guard_for')} {g['penalty_min']} {t('min')}")
    print()


def traffic_sample(prev, cur, dt):
    """
    Замер за интервал по каждому IP:
      dl, ul   — Мбит/с
      up_pkt   — средний размер пакета в отдаче, байт
      up_bytes — сколько отдано за интервал
    """
    out = {}
    for ip, c in cur.items():
        p = prev.get(ip, {"down": 0, "up": 0, "up_pkts": 0})
        d_bytes = max(0, c["down"] - p["down"])
        u_bytes = max(0, c["up"] - p["up"])
        u_pkts = max(0, c["up_pkts"] - p["up_pkts"])
        out[ip] = {
            "dl": d_bytes * 8 / 1e6 / dt,
            "ul": u_bytes * 8 / 1e6 / dt,
            "up_pkt": (u_bytes / u_pkts) if u_pkts else 0,
            "up_bytes": u_bytes,
            "dl_bytes": d_bytes,
        }
    return out


def load_daily():
    """Суточные счётчики: секунды активности и объём отдачи. Сброс в полночь."""
    try:
        with open(DAILY_FILE) as f:
            data = json.load(f)
    except Exception:
        return {}
    if data.get("day") != time.strftime("%Y-%m-%d"):
        return {}
    return data.get("ips", {})


def save_daily(ips):
    tmp = DAILY_FILE + ".tmp"
    os.makedirs(ETC_DIR, exist_ok=True)
    with open(tmp, "w") as f:
        json.dump({"day": time.strftime("%Y-%m-%d"), "ips": ips}, f)
    os.replace(tmp, DAILY_FILE)


def evaluate(ip, s, g, cap, both_streak, peak_streak, daily):
    """
    Решает, нарушитель ли это. Возвращает (баллы, сработавшие признаки).

    Обязательное условие — трафик в обе стороны одновременно. Без него ноль
    баллов, каким бы тяжёлым трафик ни был: так из-под удара выходят стриминг
    (молчит вверх) и облачный бэкап (молчит вниз).
    """
    day = daily.get(ip, {"active": 0, "up": 0, "down": 0})

    # Независимый путь: качает десятками гигабайт в сутки. Отдача не важна —
    # торрент с выключенной раздачей выглядит как обычная тяжёлая закачка,
    # и единственное, что его выдаёт, это объём.
    gb = g.get("download_gb_per_day", 0)
    if gb and day.get("down", 0) >= gb * 1e9:
        return max(g["score_needed"], SIGNAL_WEIGHTS["download"]), ["download"]

    iv = g.get("watch_interval", WATCH_INTERVAL)
    if both_streak < max(1, int(g["both_ways_min"] * 60 / iv)):
        return 0, []

    reasons = []

    # Крупные пакеты вверх = клиент отдаёт данные, а не подтверждения.
    # Нижний порог по отдаче нужен, чтобы редкие пакеты не давали случайных
    # средних. Признак не зависит от скорости канала — это его главная ценность.
    if s["up_pkt"] >= g["packet_bytes"] and s["ul"] >= 0.3:
        reasons.append("packet")
    if peak_streak >= max(1, int(g["sustain_min"] * 60 / iv)):
        reasons.append("peak")
    if day["active"] >= g["hours_per_day"] * 3600:
        reasons.append("hours")
    if day["up"] >= g["upload_gb_per_day"] * 1e9:
        reasons.append("upload")

    return sum(SIGNAL_WEIGHTS[r] for r in reasons), reasons


def cmd_watch(a):
    """Демон: следит за нагрузкой и выдаёт штрафы. Запускается сервисом."""
    require_engine()
    print(t("watch_start"), flush=True)
    restore_penalties()

    both_streak, peak_streak = {}, {}
    daily = load_daily()
    prev, prev_t = read_users(), time.monotonic()
    last_daily_save = time.time()
    interval = load_config()["guard"].get("watch_interval", WATCH_INTERVAL)

    while True:
        time.sleep(interval)
        try:
            cfg = load_config()
            g = cfg["guard"]
            interval = g.get("watch_interval", WATCH_INTERVAL)
            cap = cfg["speed_mbps"]

            cur = read_users()
            now_t = time.monotonic()
            dt = max(1.0, now_t - prev_t)
            sample = traffic_sample(prev, cur, dt)
            prev, prev_t = cur, now_t

            # забываем тех, кто отвалился
            for d in (both_streak, peak_streak):
                for ip in [i for i in d if i not in cur]:
                    d.pop(ip, None)

            # снимаем истёкшие штрафы из карты ядра
            pens = load_penalties()
            in_map = {ip for ip, _ in
                      [(parse_ip_key(k)[0], v) for k, v in map_dump("penalty_map")]}
            for ip in in_map - set(pens):
                penalty_clear(ip)

            if not g["enabled"] or cap <= 0:
                both_streak.clear()
                peak_streak.clear()
                continue

            dl_floor = cap * g["both_dl_percent"] / 100
            ul_floor = cap * g["both_ul_percent"] / 100
            peak_floor = cap * g["trigger_percent"] / 100
            active_floor = cap * 0.25
            need_score = g["score_needed"]
            wl = whitelist_ips()

            for ip, s in sample.items():
                # суточные счётчики ведём для всех, даже для уже наказанных
                d = daily.setdefault(ip, {"active": 0, "up": 0, "down": 0})
                d.setdefault("down", 0)
                if max(s["dl"], s["ul"]) >= active_floor:
                    d["active"] += interval
                d["up"] += s["up_bytes"]
                d["down"] += s["dl_bytes"]

                if ip in pens or ip in wl:
                    continue

                # счётчики с допуском: короткий провал не обнуляет наблюдение
                both = s["dl"] >= dl_floor and s["ul"] >= ul_floor
                both_streak[ip] = (both_streak.get(ip, 0) + 1) if both \
                    else max(0, both_streak.get(ip, 0) - 1)
                peak = s["dl"] >= peak_floor
                peak_streak[ip] = (peak_streak.get(ip, 0) + 1) if peak \
                    else max(0, peak_streak.get(ip, 0) - 1)

                score, reasons = evaluate(ip, s, g, cap,
                                          both_streak[ip], peak_streak[ip], daily)
                if score >= need_score:
                    until = time.time() + g["penalty_min"] * 60
                    penalty_apply(ip, g["penalty_mbps"], until)
                    pens[ip] = {"until": until, "mbps": g["penalty_mbps"],
                                "since": time.time(),
                                "score": score, "reasons": reasons}
                    save_penalties(pens)
                    both_streak[ip] = peak_streak[ip] = 0
                    print(t("watch_hit", ip=ip, mbps=g["penalty_mbps"],
                            m=g["penalty_min"]) +
                          f" [{score}: {','.join(reasons)}]", flush=True)

            if time.time() - last_daily_save > 60:
                # чистим тех, кто за сутки не набрал ничего заметного
                daily = {k: v for k, v in daily.items()
                         if v["active"] > 0 or v["up"] > 1e6 or v.get("down", 0) > 1e6}
                save_daily(daily)
                last_daily_save = time.time()
        except Exception as e:
            print(f"watch: {e}", flush=True)


def whitelist_ips():
    out = set()
    try:
        for line in open(WL_FILE):
            s = line.split("#")[0].strip()
            if s:
                out.add(s)
    except Exception:
        pass
    return out


# ────────────────────────────── whitelist ──────────────────────────────

def ip_key(ip_str):
    ip = ipaddress.ip_address(ip_str)
    return ip.packed + b"\x00" * 12 if ip.version == 4 else ip.packed


def cmd_whitelist(a):
    require_engine()

    if a.action == "add":
        ip_key(a.ip)                      # проверка адреса до записи в файл
        with open(WL_FILE, "a") as f:
            f.write(a.ip + "\n")
        map_update("whitelist_map", ip_key(a.ip), b"\x01")
        print(f"{C['grn']}✓ {t('wl_added', ip=a.ip)}{C['r']}")

    elif a.action == "del":
        if os.path.exists(WL_FILE):
            kept = [l for l in open(WL_FILE) if l.strip() != a.ip]
            open(WL_FILE, "w").writelines(kept)
        map_delete("whitelist_map", ip_key(a.ip))
        print(f"{C['grn']}✓ {t('wl_removed', ip=a.ip)}{C['r']}")

    elif a.action == "sync":
        for k, _ in map_dump("whitelist_map"):
            _ip, kb = parse_ip_key(k)
            if kb:
                map_delete("whitelist_map", kb)
        n = 0
        if os.path.exists(WL_FILE):
            for line in open(WL_FILE):
                s = line.split("#")[0].strip()
                if not s:
                    continue
                try:
                    map_update("whitelist_map", ip_key(s), b"\x01")
                    n += 1
                except ValueError:
                    print(f"{C['yel']}⚠ {t('wl_bad', ip=s)}{C['r']}")
        print(t("wl_loaded", n=n))

    elif a.action == "list":
        found = False
        if os.path.exists(WL_FILE):
            for line in open(WL_FILE):
                if line.strip() and not line.startswith("#"):
                    print("  " + line.strip())
                    found = True
        if not found:
            print(f"  {C['gry']}{t('wl_empty')}{C['r']}")


# ──────────────────────────────── CLI ────────────────────────────────

def build_parser():
    p = argparse.ArgumentParser(
        prog="shaperctl",
        description=t("desc"))
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("apply", help=t("h_apply"))
    a.add_argument("--ports", default=None, help=t("h_ports"))
    a.add_argument("--speed", type=float, default=None,
                   help=t("h_speed"))
    a.add_argument("--quiet", action="store_true")
    a.set_defaults(func=cmd_apply)

    sub.add_parser("show", help=t("h_show")).set_defaults(func=cmd_show)
    sub.add_parser("restore", help=t("h_restore")).set_defaults(func=cmd_restore)

    m = sub.add_parser("monitor", help=t("h_monitor"))
    m.add_argument("--interval", type=int, default=2, help=t("h_interval"))
    m.add_argument("--top", type=int, default=20)
    m.set_defaults(func=cmd_monitor)

    st = sub.add_parser("status", help=t("h_status"))
    st.add_argument("--live", action="store_true", help=t("h_live"))
    st.add_argument("--interval", type=int, default=3)
    st.add_argument("--top", type=int, default=20)
    st.add_argument("--full", action="store_true", help=t("h_full"))
    st.add_argument("--json", action="store_true", help=t("h_json"))
    st.set_defaults(func=cmd_status)

    g = sub.add_parser("guard", help=t("h_guard"))
    g.add_argument("--enable", action="store_true")
    g.add_argument("--disable", action="store_true")
    g.add_argument("--score", type=int, default=None, help=t("h_score"))
    g.add_argument("--both-min", type=int, default=None, help=t("h_both_min"))
    g.add_argument("--both-dl", type=float, default=None, help=t("h_both_dl"))
    g.add_argument("--both-ul", type=float, default=None, help=t("h_both_ul"))
    g.add_argument("--percent", type=float, default=None, help=t("h_percent"))
    g.add_argument("--sustain", type=int, default=None, help=t("h_sustain"))
    g.add_argument("--penalty-mbps", type=float, default=None, help=t("h_pen_mbps"))
    g.add_argument("--penalty-min", type=int, default=None, help=t("h_pen_min"))
    g.add_argument("--hours", type=float, default=None, help=t("h_hours"))
    g.add_argument("--upload-gb", type=float, default=None, help=t("h_upload_gb"))
    g.add_argument("--download-gb", type=float, default=None, help=t("h_download_gb"))
    g.add_argument("--interval", type=int, default=None, help=t("h_watch_iv"))
    g.add_argument("--packet", type=int, default=None, help=t("h_packet"))
    g.add_argument("--quiet", action="store_true")
    g.set_defaults(func=cmd_guard)

    sub.add_parser("watch", help=t("h_watch")).set_defaults(func=cmd_watch)

    li = sub.add_parser("limited", help=t("h_limited"))
    li.add_argument("--json", action="store_true", help=t("h_json"))
    li.set_defaults(func=cmd_limited)

    rl = sub.add_parser("release", help=t("h_release"))
    rl.add_argument("ip", nargs="?", default="")
    rl.add_argument("--all", action="store_true")
    rl.set_defaults(func=cmd_release)

    w = sub.add_parser("whitelist", help=t("h_whitelist"))
    w.add_argument("action", choices=["add", "del", "sync", "list"])
    w.add_argument("ip", nargs="?", default="")
    w.set_defaults(func=cmd_whitelist)

    return p


def main():
    if os.geteuid() != 0:
        die(t("root"))
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
