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

NS = 1_000_000_000
# Мбит/с -> байт/с. Мегабит десятичный: 1 Мбит = 1 000 000 бит = 125 000 байт.
BYTES_PER_MBPS = 125_000
MAX_MBPS = 100_000          # 100 Гбит/с — заведомо выше любого разумного канала
MAX_PORTS = 64              # должно совпадать с max_entries port_map в shaper.bpf.c

CONFIG_FMT = "<Q"           # struct config, 8 байт
USER_FMT, USER_SIZE = "<3Q", 24   # struct user_state

C = {
    "r": "\033[0m", "b": "\033[1m",
    "red": "\033[31m", "grn": "\033[32m", "yel": "\033[33m", "gry": "\033[90m",
}


# ─────────────────────────── языки ───────────────────────────
# Язык берётся из UI_LANG в /etc/shaper/shaper.conf, его пишет меню.

MSG = {
    "ru": {
        "root": "нужны права root",
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
        _dep, total, seen = struct.unpack(USER_FMT, b[:USER_SIZE])
        return {"total": total, "seen": seen}
    if isinstance(v, dict):
        return {"total": _int(v.get("total_bytes", 0)),
                "seen":  _int(v.get("last_seen_ns", 0))}
    return {"total": 0, "seen": 0}


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

def load_config():
    try:
        with open(CONFIG_FILE) as f:
            cfg = json.load(f)
        return {"ports": cfg.get("ports", [443]),
                "speed_mbps": float(cfg.get("speed_mbps", 0))}
    except Exception:
        return {"ports": [443], "speed_mbps": 0}


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
    print()


def cmd_restore(a):
    """Вызывается сервисом при старте: заливает config.json в свежие карты."""
    cfg = load_config()
    write_to_kernel(cfg)
    print(t("restored", s=cfg["speed_mbps"], p=",".join(map(str, cfg["ports"]))))


# ───────────────────────────── статистика ─────────────────────────────

def read_users():
    """{ip: {"down": байт, "up": байт, "seen": нс}}"""
    users = {}
    for map_name, direction in (("user_state_map_down", "down"),
                                ("user_state_map_up", "up")):
        for k, v in map_dump(map_name):
            ip, _ = parse_ip_key(k)
            if ip is None:
                continue
            st = parse_user_state(v)
            e = users.setdefault(ip, {"down": 0, "up": 0, "seen": 0})
            e[direction] = st["total"]
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
