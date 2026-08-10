#!/usr/bin/env bash
# menu.sh — текстовый интерфейс шейпера. Запускается командой `shaper`.
set -uo pipefail

APP_DIR="/opt/shaper"
ETC_DIR="/etc/shaper"
CTL="$APP_DIR/shaperctl.py"
ENGINE="$APP_DIR/engine.sh"

B='\033[1m'; N='\033[0m'; D='\033[90m'
G='\033[32m'; R='\033[31m'; Y='\033[33m'; C='\033[36m'

[[ $EUID -eq 0 ]] || { echo -e "${R}Нужны права root: sudo shaper${N}"; exit 1; }

hr()    { echo -e "${D}  ────────────────────────────────────────────────────────────${N}"; }
title() { clear; echo; echo -e "  ${B}$1${N}"; hr; }
pause() { echo; read -rsp "  Enter — назад " _; }
ask()   { local p="$1" d="${2:-}" v; read -rp "  $p${d:+ [$d]}: " v; echo "${v:-$d}"; }
cfg()   { python3 -c "
import json
try: c = json.load(open('$ETC_DIR/config.json'))
except Exception: c = {}
print(c.get('$1', '$2'))" 2>/dev/null || echo "$2"; }

status_line() {
    local st ifc speed ports
    if "$ENGINE" state >/dev/null 2>&1; then st="${G}● работает${N}"
    else st="${R}● остановлен${N}"; fi

    ifc="$(sed -n 's/^IFACE="\(.*\)"$/\1/p' "$ETC_DIR/.active_iface" 2>/dev/null)"
    [[ -z "$ifc" ]] && ifc="$(ip route get 1.1.1.1 2>/dev/null |
                              sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -1)"
    speed="$(cfg speed_mbps 0)"
    ports="$(python3 -c "
import json
try: p = json.load(open('$ETC_DIR/config.json'))['ports']
except Exception: p = []
print(', '.join(map(str, p)) if p != [0] else 'все')" 2>/dev/null || echo '?')"

    echo -e "  Статус: $st    интерфейс: ${B}${ifc:-?}${N}"
    if [[ "$speed" == "0" || -z "$speed" ]]; then
        echo -e "  Лимит : ${Y}не задан${N} ${D}— трафик не ограничивается${N}"
    else
        echo -e "  Лимит : ${B}${speed} Мбит/с${N} на пользователя, порты ${B}${ports}${N}"
    fi
}

# ── Настройка лимита ──────────────────────────────────────────────────
screen_limit() {
    local speed port cur_port
    cur_port="$(python3 -c "
import json
try: p = json.load(open('$ETC_DIR/config.json'))['ports']
except Exception: p = [443]
print(','.join(map(str, p)))" 2>/dev/null || echo 443)"

    title "Скорость на одного пользователя"
    echo -e "  ${D}Лимит действует на каждый IP отдельно и в обе стороны.${N}"
    echo -e "  ${D}Пятьдесят человек по 15 Мбит/с — это до 750 Мбит/с на канал.${N}"
    echo
    echo -e "  ${B}[1]${N}  10 Мбит/с   ${D}видео 1080p, экономия канала${N}"
    echo -e "  ${B}[2]${N}  15 Мбит/с   ${D}комфорт для большинства${N}"
    echo -e "  ${B}[3]${N}  20 Мбит/с   ${D}с запасом, 4K не тормозит${N}"
    echo -e "  ${B}[4]${N}  Ввести своё значение"
    echo -e "  ${B}[5]${N}  Снять ограничение"
    echo -e "  ${B}[0]${N}  Отмена"
    echo

    case "$(ask 'Выбор' 2)" in
        1) speed=10 ;;
        2) speed=15 ;;
        3) speed=20 ;;
        4) speed="$(ask 'Скорость, Мбит/с' 15)"
           [[ "$speed" =~ ^[0-9]+([.][0-9]+)?$ ]] || {
               echo -e "  ${R}Нужно число${N}"; pause; return; } ;;
        5) speed=0 ;;
        *) return ;;
    esac

    echo
    echo -e "  ${D}Порт, на который подключаются клиенты. В Remnawave-ноде${N}"
    echo -e "  ${D}это почти всегда 443. Несколько — через запятую, 0 = все.${N}"
    echo
    show_listening
    echo
    port="$(ask 'Порт' "$cur_port")"

    echo
    if [[ "$speed" == "0" ]]; then
        echo -e "  Ограничение будет ${Y}снято${N}, трафик пойдёт свободно."
    else
        echo -e "  Лимит ${B}${speed} Мбит/с${N} на каждого пользователя, порт ${B}${port}${N}."
    fi
    echo
    read -rp "  Применить? [Y/n]: " ans
    [[ "$ans" =~ ^[NnНн] ]] && { echo "  Отменено."; pause; return; }

    "$CTL" apply --ports "$port" --speed "$speed"
    pause
}

show_listening() {
    echo -e "  ${D}Порты, которые сейчас слушают процессы:${N}"
    ss -tulnpH 2>/dev/null | awk '
        {
            split($5, a, ":"); port = a[length(a)]
            name = ""
            if (match($0, /users:\(\("[^"]+/)) {
                name = substr($0, RSTART+9, RLENGTH-9); gsub(/"/, "", name)
            }
            if (port ~ /^[0-9]+$/ && !(port in seen)) { seen[port] = name }
        }
        END { for (p in seen) printf "    %-6s %s\n", p, seen[p] }
    ' | sort -n | head -12
}

# ── Статистика ────────────────────────────────────────────────────────
screen_stats() {
    while :; do
        title "Статистика"
        echo -e "  ${D}Сколько каждый IP прокачал за всё время работы шейпера.${N}"
        echo -e "  ${D}Кто грузит канал прямо сейчас — смотри «Монитор».${N}"
        echo
        echo "  [1] Показать (топ-20)"
        echo "  [2] Полный список IP"
        echo "  [0] Назад"
        echo
        case "$(ask 'Выбор')" in
            1) title "Статистика"; "$CTL" status; pause ;;
            2) title "Статистика"; "$CTL" status --full; pause ;;
            0|"") return ;;
        esac
    done
}

# ── Белый список ──────────────────────────────────────────────────────
screen_whitelist() {
    while :; do
        title "Белый список"
        echo -e "  ${D}Эти IP полностью минуют шейпер: свой адрес, мониторинг, панель.${N}"
        echo
        "$CTL" whitelist list
        hr
        echo "  [1] Добавить IP"
        echo "  [2] Убрать IP"
        echo "  [0] Назад"
        echo
        case "$(ask 'Выбор')" in
            1) local ip; ip="$(ask 'IP-адрес')"
               [[ -n "$ip" ]] && { "$CTL" whitelist add "$ip"; sleep 1; } ;;
            2) local ip; ip="$(ask 'IP-адрес')"
               [[ -n "$ip" ]] && { "$CTL" whitelist del "$ip"; sleep 1; } ;;
            0|"") return ;;
        esac
    done
}

# ── Сервис ────────────────────────────────────────────────────────────
screen_service() {
    while :; do
        title "Сервис"
        systemctl status shaper --no-pager 2>/dev/null | head -5 | sed 's/^/  /'
        hr
        echo "  [1] Запустить"
        echo "  [2] Остановить"
        echo "  [3] Перезапустить (пересобрать eBPF)"
        echo "  [4] Автозапуск при загрузке сервера"
        echo "  [5] Логи"
        echo "  [6] Проверить окружение"
        echo "  [0] Назад"
        echo
        case "$(ask 'Выбор')" in
            1) systemctl start shaper; sleep 1 ;;
            2) systemctl stop shaper; sleep 1 ;;
            3) rm -f "$APP_DIR/bpf/shaper.bpf.o"; systemctl restart shaper; sleep 2 ;;
            4) systemctl enable shaper && echo -e "  ${G}✓ включён${N}"; sleep 1 ;;
            5) title "Логи"; journalctl -u shaper -n 40 --no-pager | sed 's/^/  /'; pause ;;
            6) title "Проверка окружения"; doctor; pause ;;
            0|"") return ;;
        esac
    done
}

doctor() {
    local k ifc
    k="$(uname -r)"
    echo -e "  Ядро Linux        : $k $(awk -v v="${k%%-*}" 'BEGIN{split(v,a,".");print (a[1]>5||(a[1]==5&&a[2]>=4))?"\033[32m✓\033[0m":"\033[31m✗ нужно 5.4+\033[0m"}')"
    for b in clang bpftool tc python3; do
        printf "  %-18s: %s\n" "$b" "$(command -v $b >/dev/null && echo -e "${G}✓${N} $(command -v $b)" || echo -e "${R}✗ не установлен${N}")"
    done
    echo -e "  bpffs             : $(mountpoint -q /sys/fs/bpf && echo -e "${G}✓ примонтирована${N}" || echo -e "${R}✗ не примонтирована${N}")"
    ifc="$(ip route get 1.1.1.1 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -1)"
    echo -e "  Интерфейс наружу  : ${B}${ifc:-не определён}${N}"
    [[ -n "$ifc" ]] && echo -e "  Корневой qdisc    : $(tc qdisc show dev "$ifc" root 2>/dev/null | awk '{print $2}')"
    echo -e "  Карты закреплены  : $([[ -d /sys/fs/bpf/shaper/maps ]] && echo -e "${G}✓${N}" || echo -e "${D}нет (сервис не запущен)${N}")"
}

# ── Главное меню ──────────────────────────────────────────────────────
while :; do
    clear
    echo
    echo -e "  ${B}${C}Shape${N} ${D}· ограничитель скорости на пользователя${N}"
    hr
    status_line
    hr
    echo
    echo "  [1] Настроить лимит — скорость и порт"
    echo -e "  [2] Монитор ${D}— кто грузит канал прямо сейчас${N}"
    echo -e "  [3] Статистика ${D}— сколько прокачали всего${N}"
    echo "  [4] Белый список IP"
    echo "  [5] Сервис: запуск, логи, диагностика"
    echo "  [0] Выход"
    echo
    case "$(ask 'Выбор')" in
        1) screen_limit ;;
        2) "$CTL" monitor ;;
        3) screen_stats ;;
        4) screen_whitelist ;;
        5) screen_service ;;
        0|"") clear; exit 0 ;;
    esac
done
