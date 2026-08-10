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


# ────────────────────────────── утилиты ──────────────────────────────

def die(msg, code=1):
    print(f"{C['red']}✗ {msg}{C['r']}", file=sys.stderr)
    sys.exit(code)


def run(cmd, check=True):
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and p.returncode != 0:
        die(f"команда не выполнилась: {cmd}\n  {p.stderr.strip()}")
    return p.stdout.strip(), p.returncode


def hexs(data):
    return " ".join(f"{b:02x}" for b in data)


def map_path(name):
    return os.path.join(PIN_DIR, name)


def require_engine():
    if not os.path.exists(map_path("config_map")):
        die(f"движок не запущен — карты не найдены в {PIN_DIR}\n"
            "  запусти: systemctl start shaper")


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
    for u in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if n < 1024:
            return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} ПБ"


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
            die(f"порт «{part}» не число")
        p = int(part)
        if not 0 <= p <= 65535:
            die(f"порт {p} вне диапазона 0..65535")
        if p not in out:
            out.append(p)
    if len(out) > MAX_PORTS:
        die(f"портов не больше {MAX_PORTS}")
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
            die("не указан ни один порт (0 = все порты)")
        cfg["ports"] = ports
    if a.speed is not None:
        if a.speed < 0:
            die("скорость не может быть отрицательной")
        if a.speed > MAX_MBPS:
            die(f"{a.speed} Мбит/с — это больше 100 Гбит/с, проверь значение")
        cfg["speed_mbps"] = a.speed

    write_to_kernel(cfg)
    save_config(cfg)
    if not a.quiet:
        cmd_show(a)


def cmd_show(a):
    cfg = load_config()
    ports = ", ".join(map(str, cfg["ports"])) if cfg["ports"] != [0] else "ВСЕ ПОРТЫ"
    print()
    if cfg["speed_mbps"] > 0:
        print(f"  Скорость : {C['b']}{cfg['speed_mbps']:g} Мбит/с{C['r']} "
              f"на каждого пользователя, в обе стороны")
    else:
        print(f"  Скорость : {C['yel']}не ограничена{C['r']}")
    print(f"  Порты    : {ports}")
    print()


def cmd_restore(a):
    """Вызывается сервисом при старте: заливает config.json в свежие карты."""
    cfg = load_config()
    write_to_kernel(cfg)
    print(f"лимит {cfg['speed_mbps']:g} Мбит/с на портах "
          f"{','.join(map(str, cfg['ports']))}")


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
        print(f"{C['gry']}  замер скорости {a.interval} с…{C['r']}")
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

    limit = (f"{cfg['speed_mbps']:g} Мбит/с" if cfg["speed_mbps"] > 0
             else "не ограничено")
    ports = ", ".join(map(str, cfg["ports"])) if cfg["ports"] != [0] else "ВСЕ"
    print(f"\n  Лимит {C['b']}{limit}{C['r']} · порты {ports} · "
          f"всего IP: {len(rows)} · активных за минуту: {len(active)}")
    print("  " + "─" * 70)

    if not rows:
        print(f"  {C['gry']}трафика через шейпер ещё не было{C['r']}\n")
        return

    head = f"  {'IP':<30}{'скачал':>12}{'отдал':>12}"
    head += f"{'сейчас':>14}" if a.live else ""
    print(f"{C['gry']}{head}{C['r']}")

    shown = rows if a.full else rows[:a.top]
    for ip, c, dl, ul, idle in shown:
        mark = f"{C['gry']}·{C['r']}" if idle > 300 else " "
        line = f" {mark}{ip:<30}{fmt_bytes(c['down']):>12}{fmt_bytes(c['up']):>12}"
        if a.live:
            line += f"{dl:>9.1f} Мбит/с"
        print(line)

    if not a.full and len(rows) > a.top:
        print(f"  {C['gry']}… ещё {len(rows) - a.top} IP, "
              f"полный список: shaperctl status --full{C['r']}")
    print(f"  {C['gry']}· — нет трафика больше 5 минут{C['r']}\n")


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
        print(f"{C['grn']}✓ {a.ip} добавлен в белый список{C['r']}")

    elif a.action == "del":
        if os.path.exists(WL_FILE):
            kept = [l for l in open(WL_FILE) if l.strip() != a.ip]
            open(WL_FILE, "w").writelines(kept)
        map_delete("whitelist_map", ip_key(a.ip))
        print(f"{C['grn']}✓ {a.ip} убран из белого списка{C['r']}")

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
                    print(f"{C['yel']}⚠ пропущен неверный адрес: {s}{C['r']}")
        print(f"загружено в белый список: {n}")

    elif a.action == "list":
        found = False
        if os.path.exists(WL_FILE):
            for line in open(WL_FILE):
                if line.strip() and not line.startswith("#"):
                    print("  " + line.strip())
                    found = True
        if not found:
            print(f"  {C['gry']}белый список пуст{C['r']}")


# ──────────────────────────────── CLI ────────────────────────────────

def build_parser():
    p = argparse.ArgumentParser(
        prog="shaperctl",
        description="eBPF-шейпер: лимит скорости на пользователя. Всё в Мбит/с.")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("apply", help="задать порты и скорость")
    a.add_argument("--ports", default=None, help="через запятую, 0 = все порты")
    a.add_argument("--speed", type=float, default=None,
                   help="Мбит/с на пользователя, 0 = снять ограничение")
    a.add_argument("--quiet", action="store_true")
    a.set_defaults(func=cmd_apply)

    sub.add_parser("show", help="показать текущие настройки").set_defaults(func=cmd_show)
    sub.add_parser("restore", help="залить настройки в карты").set_defaults(func=cmd_restore)

    st = sub.add_parser("status", help="статистика по IP")
    st.add_argument("--live", action="store_true", help="замерить текущую скорость")
    st.add_argument("--interval", type=int, default=3)
    st.add_argument("--top", type=int, default=20)
    st.add_argument("--full", action="store_true")
    st.add_argument("--json", action="store_true")
    st.set_defaults(func=cmd_status)

    w = sub.add_parser("whitelist", help="белый список IP")
    w.add_argument("action", choices=["add", "del", "sync", "list"])
    w.add_argument("ip", nargs="?", default="")
    w.set_defaults(func=cmd_whitelist)

    return p


def main():
    if os.geteuid() != 0:
        die("нужны права root")
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
