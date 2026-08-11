#!/usr/bin/env bash
# menu.sh — текстовый интерфейс шейпера. Запускается командой `shaper`.
set -uo pipefail

APP_DIR="/opt/shaper"
ETC_DIR="/etc/shaper"
CONF="$ETC_DIR/shaper.conf"
CTL="$APP_DIR/shaperctl.py"
ENGINE="$APP_DIR/engine.sh"
REPO_URL="https://github.com/SkunkBG/shape.git"
VERSION="$(cat "$APP_DIR/VERSION" 2>/dev/null || echo '?')"

B='\033[1m'; N='\033[0m'; D='\033[90m'
G='\033[32m'; R='\033[31m'; Y='\033[33m'; C='\033[36m'

# shellcheck disable=SC1090
[[ -f "$CONF" ]] && source "$CONF"
UI_LANG="${UI_LANG:-}"

# shellcheck disable=SC1090
source "$APP_DIR/lang.sh"
ui_lang_load "${UI_LANG:-ru}"

[[ $EUID -eq 0 ]] || { echo -e "${R}${T[need_root]}${N}"; exit 1; }

# Шрифтовой знак вместо картинки: рисовать скунса псевдографикой в терминале
# смысла нет, а стоимость вывода нулевая — это статический текст.
banner() {
    local host; host="$(hostname -s 2>/dev/null || echo '?')"
    echo -e "  ${G}╔═╗╦ ╦╔═╗╔═╗╔═╗${N}   ${D}v$VERSION ${T[subtitle]}${N}"
    echo -e "  ${G}╚═╗╠═╣╠═╣╠═╝║╣ ${N}   ${D}🦨 SkunkBG${N}"
    echo -e "  ${G}╚═╝╩ ╩╩ ╩╩  ╚═╝${N}   ${D}${T[node]}: ${B}${host}${N}"
}

hr()    { echo -e "${D}  ────────────────────────────────────────────────────────────${N}"; }
title() { clear; echo; echo -e "  ${B}$1${N}"; hr; }
pause() { echo; read -rsp "  ${T[back]} " _; }
ask()   { local p="$1" d="${2:-}" v; read -rp "  $p${d:+ [$d]}: " v; echo "${v:-$d}"; }
cfg()   { python3 -c "
import json
try: c = json.load(open('$ETC_DIR/config.json'))
except Exception: c = {}
print(c.get('$1', '$2'))" 2>/dev/null || echo "$2"; }

conf_set() {
    touch "$CONF"
    if grep -q "^$1=" "$CONF"; then
        sed -i "s|^$1=.*|$1=\"$2\"|" "$CONF"
    else
        echo "$1=\"$2\"" >> "$CONF"
    fi
}

# ── Выбор языка ───────────────────────────────────────────────────────
screen_lang() {
    clear; echo
    banner
    hr
    echo -e "  ${B}Выбери язык / Choose language${N}"
    echo
    echo "  [1] 🇷🇺  Русский"
    echo "  [2] 🇬🇧  English"
    echo
    local a
    read -rp "  1-2 [1]: " a
    case "${a:-1}" in
        2) UI_LANG="en" ;;
        *) UI_LANG="ru" ;;
    esac
    conf_set UI_LANG "$UI_LANG"
    ui_lang_load "$UI_LANG"
    echo -e "  ${G}✓ ${T[lang_saved]}${N}"
    sleep 1
}

# ── Статус на главном экране ──────────────────────────────────────────
# Все значения читаются одним вызовом python: экран перерисовывается часто,
# плодить по семь процессов на кадр незачем. Разделитель — вертикальная черта.
read_state() {
    python3 - <<'PY' 2>/dev/null || echo "0|?|0|50|15|10|1|60|3|50"
import json
try:
    c = json.load(open("/etc/shaper/config.json"))
except Exception:
    c = {}
g = {"enabled": False, "both_dl_percent": 50, "both_ul_percent": 15,
     "both_ways_min": 10, "penalty_mbps": 1, "penalty_min": 60,
     "score_needed": 3, "download_gb_per_day": 50}
g.update(c.get("guard", {}))
ports = c.get("ports", [])
print("|".join([
    f"{float(c.get('speed_mbps', 0)):g}",
    ", ".join(map(str, ports)) if ports and ports != [0] else "*",
    "1" if g["enabled"] else "0",
    f"{g['both_dl_percent']:g}", f"{g['both_ul_percent']:g}",
    f"{g['both_ways_min']:g}",
    f"{g['penalty_mbps']:g}", f"{g['penalty_min']:g}", f"{g['score_needed']:g}",
    f"{g['download_gb_per_day']:g}",
]))
PY
}

status_line() {
    local ifc speed ports g_on bdl bul bmin pen dur score dgb dlv ulv auto_on=0 run_on=0

    "$ENGINE" state >/dev/null 2>&1 && run_on=1
    systemctl is-enabled shaper >/dev/null 2>&1 && auto_on=1

    ifc="$(sed -n 's/^IFACE="\(.*\)"$/\1/p' "$ETC_DIR/.active_iface" 2>/dev/null)"
    [[ -z "$ifc" ]] && ifc="$(ip route get 1.1.1.1 2>/dev/null |
                              sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -1)"

    IFS='|' read -r speed ports g_on bdl bul bmin pen dur score dgb <<< "$(read_state)"
    [[ "$ports" == "*" ]] && ports="${T[st_all]}"

    if (( run_on )); then
        echo -e "  🟢  ${T[st_shaper]} ${G}${T[st_running]}${N}   ${D}${T[st_iface]} ${ifc:-?}${N}"
    else
        echo -e "  🔴  ${T[st_shaper]} ${R}${T[st_stopped]}${N}  ${D}${T[st_nolimit]}${N}"
    fi

    if (( auto_on )); then
        echo -e "  🔁  ${T[st_auto]} ${G}${T[st_auto_on]}${N}    ${D}${T[st_auto_ok]}${N}"
    else
        echo -e "  ⚠️   ${T[st_auto]} ${Y}${T[st_auto_off]}${N}   ${D}${T[st_auto_warn]}${N}"
    fi

    if [[ "$speed" == "0" ]]; then
        echo -e "  ⚪  ${T[st_speed]} ${Y}${T[st_unlimited]}${N}"
    else
        echo -e "  🚀  ${T[st_speed]} ${B}${speed} Mbit/s${N} ${D}${T[st_peruser]}${N}"
    fi
    echo -e "  🔌  ${T[st_port]} ${B}${ports}${N}"

    if [[ "$g_on" == "1" ]]; then
        if [[ "$speed" == "0" ]]; then
            echo -e "  🚦  ${T[st_guard]} ${G}${T[st_g_on]}${N}    ${Y}${T[st_g_nolimit]}${N}"
        else
            dlv="$(awk "BEGIN{printf \"%g\", $speed*$bdl/100}")"
            ulv="$(awk "BEGIN{printf \"%g\", $speed*$bul/100}")"
            echo -e "  🚦  ${T[st_guard]} ${G}${T[st_g_on]}${N}" \
                    "${D}${T[st_g_both]} ↓${dlv} ↑${ulv} Mbit/s ${bmin} ${T[min]}" \
                    "+ ${score} ${T[st_g_pts]} → ${pen} Mbit/s ${T[g_for]} ${dur} ${T[min]}${N}"
            [[ "$dgb" != "0" ]] && echo -e "      ${D}${T[st_g_or]} ${dgb} ${T[st_g_gbday]}${N}"
        fi
    else
        echo -e "  🚦  ${T[st_guard]} ${D}${T[st_g_off]}${N}   ${D}${T[st_g_none]}${N}"
    fi
}

# ── Настройка лимита ──────────────────────────────────────────────────
show_listening() {
    echo -e "  ${D}${T[listening]}${N}"
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

screen_limit() {
    local speed port cur_port ans
    cur_port="$(python3 -c "
import json
try: p = json.load(open('$ETC_DIR/config.json'))['ports']
except Exception: p = [443]
print(','.join(map(str, p)))" 2>/dev/null || echo 443)"

    title "${T[lim_title]}"
    echo -e "  ${D}${T[lim_h1]}${N}"
    echo -e "  ${D}${T[lim_h2]}${N}"
    echo
    echo -e "  ${B}[1]${N}  10 Mbit/s   ${D}${T[lim_d10]}${N}"
    echo -e "  ${B}[2]${N}  15 Mbit/s   ${D}${T[lim_d15]}${N}"
    echo -e "  ${B}[3]${N}  20 Mbit/s   ${D}${T[lim_d20]}${N}"
    echo -e "  ${B}[4]${N}  ${T[lim_own]}"
    echo -e "  ${B}[5]${N}  ${T[lim_off]}"
    echo -e "  ${B}[0]${N}  ${T[cancel]}"
    echo

    case "$(ask "${T[choice]}" 2)" in
        1) speed=10 ;;
        2) speed=15 ;;
        3) speed=20 ;;
        4) speed="$(ask "${T[lim_ask]}" 15)"
           [[ "$speed" =~ ^[0-9]+([.][0-9]+)?$ ]] || {
               echo -e "  ${R}${T[need_num]}${N}"; pause; return; } ;;
        5) speed=0 ;;
        *) return ;;
    esac

    echo
    echo -e "  ${D}${T[port_h1]}${N}"
    echo -e "  ${D}${T[port_h2]}${N}"
    echo
    show_listening
    echo
    port="$(ask "${T[port_ask]}" "$cur_port")"

    echo
    if [[ "$speed" == "0" ]]; then
        echo -e "  ${Y}${T[conf_off]}${N}"
    else
        echo -e "  ${T[conf_on1]} ${B}${speed} Mbit/s${N} ${T[conf_on2]} ${B}${port}${N}."
    fi
    echo
    read -rp "  ${T[apply_q]}: " ans
    [[ "$ans" =~ ^[NnНн] ]] && { echo "  ${T[cancelled]}"; pause; return; }

    "$CTL" apply --ports "$port" --speed "$speed"
    pause
}

# ── Автоограничение ───────────────────────────────────────────────────
# Все настройки читаются одним вызовом: запуск python3 стоит десятки
# миллисекунд, а раньше их было десять на каждую отрисовку экрана.
guard_read() {
    python3 - <<'PY' 2>/dev/null || echo "0|3|50|15|10|1|60|4|2|50|0|600"
import json
try:
    g = json.load(open("/etc/shaper/config.json")).get("guard", {})
except Exception:
    g = {}
d = {"enabled": False, "score_needed": 3, "both_dl_percent": 50,
     "both_ul_percent": 15, "both_ways_min": 10, "penalty_mbps": 1,
     "penalty_min": 60, "hours_per_day": 4, "upload_gb_per_day": 2,
     "download_gb_per_day": 50, "download_gb_per_hour": 0, "packet_bytes": 600}
d.update(g)
print("|".join([
    "1" if d["enabled"] else "0",
    f"{d['score_needed']:g}", f"{d['both_dl_percent']:g}", f"{d['both_ul_percent']:g}",
    f"{d['both_ways_min']:g}", f"{d['penalty_mbps']:g}", f"{d['penalty_min']:g}",
    f"{d['hours_per_day']:g}", f"{d['upload_gb_per_day']:g}",
    f"{d['download_gb_per_day']:g}", f"{d['download_gb_per_hour']:g}",
    f"{d['packet_bytes']:g}",
]))
PY
}

# ── Готовые пресеты ───────────────────────────────────────────────────
# Каждый пресет — один вызов shaperctl со всеми флагами сразу. Ручная
# настройка остаётся: пресет только расставляет числа, дальше правь что хочешь.
guard_preset() {
    local speed ans
    speed="$(cfg speed_mbps 0)"
    while :; do
        title "${T[gp_title]}"
        echo -e "  ${D}${T[gp_h1]}${N}"
        echo
        echo -e "  ${B}[1]${N} 📱 ${T[gp_mobile]}"
        echo -e "      ${D}${T[gp_mobile_d1]}${N}"
        echo -e "      ${D}${T[gp_mobile_d2]}${N}"
        echo
        echo -e "  ${B}[2]${N} 🖥  ${T[gp_mixed]}"
        echo -e "      ${D}${T[gp_mixed_d]}${N}"
        echo
        echo -e "  ${B}[3]${N} 🚦 ${T[gp_torrent]}"
        echo -e "      ${D}${T[gp_torrent_d]}${N}"
        echo
        echo -e "  ${B}[0]${N} ← ${T[m0]}"
        echo
        case "$(ask "${T[choice]}")" in
            1) echo -e "\n  ${T[gp_will]}:"
               echo -e "  ${D}  · ${T[gp_p_hour]} ${B}3 GB${N}${D} — ${T[gp_m1]}${N}"
               echo -e "  ${D}  · ${T[gp_p_day]} 25 GB — ${T[gp_m2]}${N}"
               echo -e "  ${D}  · ${T[gp_p_pen]} 1 Mbit/s × 240 ${T[min]}${N}"
               if [[ "$speed" != "0" ]]; then
                   echo
                   echo -e "  ${D}${T[gp_m3]} $(awk "BEGIN{printf \"%.0f\", 3/($speed/8/1000)/60}") ${T[min]}${N}"
                   echo -e "  ${D}${T[gp_m4]} ~19 GB${N}"
               fi
               echo
               read -rp "  ${T[apply_q]}: " ans
               [[ "$ans" =~ ^[NnНн] ]] && continue
               "$CTL" guard --enable --score 3 --both-dl 50 --both-ul 15 --both-min 7 \
                   --packet 600 --hours 4 --upload-gb 2 \
                   --download-gb 25 --download-gbh 3 \
                   --penalty-mbps 1 --penalty-min 240 && pause; return ;;
            2) "$CTL" guard --enable --score 3 --both-dl 50 --both-ul 15 --both-min 10 \
                   --packet 600 --hours 4 --upload-gb 2 \
                   --download-gb 50 --download-gbh 0 \
                   --penalty-mbps 1 --penalty-min 60 && pause; return ;;
            3) "$CTL" guard --enable --score 3 --both-dl 50 --both-ul 15 --both-min 10 \
                   --packet 600 --hours 4 --upload-gb 2 \
                   --download-gb 0 --download-gbh 0 \
                   --penalty-mbps 1 --penalty-min 60 && pause; return ;;
            0|"") return ;;
        esac
    done
}

screen_guard() {
    local on score both_min bdl bul pen dur hours gb dgb dgbh pkt speed v
    while :; do
        speed="$(cfg speed_mbps 0)"
        IFS='|' read -r on score bdl bul both_min pen dur hours gb dgb dgbh pkt \
            <<< "$(guard_read)"

        title "${T[g_title]}"
        echo -e "  ${D}${T[g_h1]}${N}"
        echo -e "  ${D}${T[g_h2]}${N}"
        echo -e "  ${D}${T[g_h3]}${N}"
        echo
        if [[ "$on" == "1" ]]; then
            echo -e "  ${T[g_state]} : ${G}${T[g_on]}${N}"
        else
            echo -e "  ${T[g_state]} : ${D}${T[g_off]}${N}"
        fi
        if [[ "$speed" != "0" && -n "$speed" ]]; then
            echo -e "  ${T[g_req]} : ${B}↓$(awk "BEGIN{printf \"%g\", $speed*$bdl/100}")" \
                    "↑$(awk "BEGIN{printf \"%g\", $speed*$bul/100}") Mbit/s${N}" \
                    "${D}${T[g_bothways]}${N} ${B}${both_min}${N} ${T[min]}"
        else
            echo -e "  ${Y}${T[g_need_limit]}${N}"
        fi
        echo -e "  ${T[g_pen]} : ${B}${pen} Mbit/s${N} ${T[g_for]} ${B}${dur}${N} ${T[min]}"
        hr
        echo -e "  ${D}${T[g_signals]}  ${T[g_score_now]} ${score}${N}"
        echo -e "  ${D}  +2  ${T[why_packet]}${N}"
        echo -e "  ${D}  +1  ${T[why_peak]}${N}"
        echo -e "  ${D}  +2  ${T[why_hours]} (>${hours} ${T[hour]})${N}"
        echo -e "  ${D}  +1  ${T[why_upload]} (>${gb} GB)${N}"
        [[ "$dgb" != "0" ]] && echo -e "  ${D}${T[g_orpath]} ${T[why_download]} (>${dgb} GB)${N}"
        [[ "$dgbh" != "0" ]] && echo -e "  ${D}${T[g_orpath]} ${T[why_hourly]} (>${dgbh} GB)${N}"
        hr
        echo "  [1] ${T[g_toggle]}"
        echo "  [2] ${T[g_set_score]}"
        echo "  [3] ${T[g_set_both]}"
        echo "  [4] ${T[g_set_pen]}"
        echo "  [5] ${T[g_set_dur]}"
        echo "  [6] ${T[g_set_hours]}"
        echo "  [7] ${T[g_set_gb]}"
        echo -e "  [8] ${T[g_set_dl]} ${D}(${bdl}%)${N}"
        echo -e "  [9] ${T[g_set_ul]} ${D}(${bul}%)${N}"
        echo -e " [10] ${T[g_set_dgb]} ${D}(${dgb} GB)${N}"
        echo -e " [11] ${T[g_set_dgbh]} ${D}(${dgbh} GB)${N}"
        hr
        echo -e " ${B}[12]${N} ⚡ ${T[gp_menu]}"
        echo "  [0] ← ${T[m0]}"
        echo
        case "$(ask "${T[choice]}")" in
            1) if [[ "$on" == "1" ]]; then "$CTL" guard --disable --quiet
               else "$CTL" guard --enable --quiet; fi ;;
            2) v="$(ask "${T[g_set_score]}" "$score")"
               [[ "$v" =~ ^[1-6]$ ]] && "$CTL" guard --score "$v" --quiet ;;
            3) v="$(ask "${T[g_set_both]}" "$both_min")"
               [[ "$v" =~ ^[0-9]+$ ]] && "$CTL" guard --both-min "$v" --quiet ;;
            4) v="$(ask "${T[g_set_pen]}" "$pen")"
               [[ "$v" =~ ^[0-9]+([.][0-9]+)?$ ]] && "$CTL" guard --penalty-mbps "$v" --quiet ;;
            5) v="$(ask "${T[g_set_dur]}" "$dur")"
               [[ "$v" =~ ^[0-9]+$ ]] && "$CTL" guard --penalty-min "$v" --quiet ;;
            6) v="$(ask "${T[g_set_hours]}" "$hours")"
               [[ "$v" =~ ^[0-9]+([.][0-9]+)?$ ]] && "$CTL" guard --hours "$v" --quiet ;;
            7) v="$(ask "${T[g_set_gb]}" "$gb")"
               [[ "$v" =~ ^[0-9]+([.][0-9]+)?$ ]] && "$CTL" guard --upload-gb "$v" --quiet ;;
            8) echo -e "  ${D}${T[g_hint_dl]}${N}"
               v="$(ask "${T[g_set_dl]}" "$bdl")"
               [[ "$v" =~ ^[0-9]+$ ]] && "$CTL" guard --both-dl "$v" --quiet ;;
            9) echo -e "  ${D}${T[g_hint_ul]}${N}"
               v="$(ask "${T[g_set_ul]}" "$bul")"
               [[ "$v" =~ ^[0-9]+$ ]] && "$CTL" guard --both-ul "$v" --quiet ;;
            10) echo -e "  ${D}${T[g_hint_dgb]}${N}"
                v="$(ask "${T[g_set_dgb]}" "$dgb")"
                [[ "$v" =~ ^[0-9]+([.][0-9]+)?$ ]] && "$CTL" guard --download-gb "$v" --quiet ;;
            11) echo -e "  ${D}${T[g_hint_dgbh]}${N}"
                [[ "$speed" != "0" ]] && echo -e "  ${D}${T[g_hint_max]}" \
                    "$(awk "BEGIN{printf \"%.1f\", $speed*3600/8/1000}") GB${N}"
                v="$(ask "${T[g_set_dgbh]}" "$dgbh")"
                [[ "$v" =~ ^[0-9]+([.][0-9]+)?$ ]] && "$CTL" guard --download-gbh "$v" --quiet ;;
            12) guard_preset ;;
            0|"") return ;;
        esac
    done
}

# ── Ограниченные пользователи ─────────────────────────────────────────
limited_count() {
    python3 -c "
import json, time
try: p = json.load(open('$ETC_DIR/penalties.json'))
except Exception: p = {}
now = time.time()
print(sum(1 for v in p.values() if isinstance(v, dict) and v.get('until', 0) > now))
" 2>/dev/null || echo 0
}

screen_limited() {
    local ip ans
    while :; do
        title "${T[lm_title]}"
        "$CTL" limited
        hr
        echo "  [1] ${T[lm_release]}"
        echo "  [2] ${T[lm_release_all]}"
        echo "  [0] ← ${T[m0]}"
        echo
        case "$(ask "${T[choice]}")" in
            1) ip="$(ask "${T[lm_ask]}")"
               [[ -n "$ip" ]] && { "$CTL" release "$ip"; sleep 1; } ;;
            2) read -rp "  ${T[lm_confirm]} [y/N]: " ans
               [[ "$ans" =~ ^[YyДд] ]] && { "$CTL" release --all; sleep 1; } ;;
            0|"") return ;;
        esac
    done
}

# ── Статистика ────────────────────────────────────────────────────────
screen_stats() {
    while :; do
        title "${T[stats_title]}"
        echo -e "  ${D}${T[stats_d1]}${N}"
        echo -e "  ${D}${T[stats_d2]}${N}"
        echo
        echo "  [1] ${T[stats_top]}"
        echo "  [2] ${T[stats_full]}"
        echo "  [0] ← ${T[m0]}"
        echo
        case "$(ask "${T[choice]}")" in
            1) title "${T[stats_title]}"; "$CTL" status; pause ;;
            2) title "${T[stats_title]}"; "$CTL" status --full; pause ;;
            0|"") return ;;
        esac
    done
}

# ── Белый список ──────────────────────────────────────────────────────
screen_whitelist() {
    local ip
    while :; do
        title "${T[wl_title]}"
        echo -e "  ${D}${T[wl_d]}${N}"
        echo
        "$CTL" whitelist list
        hr
        echo "  [1] ${T[wl_add]}"
        echo "  [2] ${T[wl_del]}"
        echo "  [0] ← ${T[m0]}"
        echo
        case "$(ask "${T[choice]}")" in
            1) ip="$(ask "${T[wl_ask]}")"
               [[ -n "$ip" ]] && { "$CTL" whitelist add "$ip"; sleep 1; } ;;
            2) ip="$(ask "${T[wl_ask]}")"
               [[ -n "$ip" ]] && { "$CTL" whitelist del "$ip"; sleep 1; } ;;
            0|"") return ;;
        esac
    done
}

# ── Обновление из GitHub ──────────────────────────────────────────────
installed_version() {
    local v h
    v="$(cat "$APP_DIR/VERSION" 2>/dev/null || echo '?')"
    h="$(cat "$APP_DIR/.commit" 2>/dev/null)"
    echo "v$v${h:+ · $h}"
}

screen_update() {
    local tmp new_ver cur_hash ans
    title "${T[up_title]}"
    echo -e "  ${D}${T[up_src]} $REPO_URL${N}"
    echo -e "  ${D}${T[up_installed]} $(installed_version)${N}"
    echo

    if ! command -v git >/dev/null; then
        echo -e "  ${D}${T[up_git]}${N}"
        apt-get install -y -qq git >/dev/null 2>&1 ||
            dnf install -y -q git >/dev/null 2>&1 ||
            yum install -y -q git >/dev/null 2>&1 || {
                echo -e "  ${R}✗ ${T[up_nogit]}${N}"; pause; return; }
    fi

    tmp="$(mktemp -d)"
    echo -e "  ${D}${T[up_dl]}${N}"
    if ! git clone --depth 20 --quiet "$REPO_URL" "$tmp" 2>/dev/null; then
        echo -e "  ${R}✗ ${T[up_fail]}${N}"
        rm -rf "$tmp"; pause; return
    fi

    new_ver="$(git -C "$tmp" rev-parse --short HEAD)"
    cur_hash="$(cat "$APP_DIR/.commit" 2>/dev/null)"
    if [[ "$new_ver" == "$cur_hash" ]]; then
        echo -e "  ${G}✓ ${T[up_latest]} ($new_ver)${N}"
        rm -rf "$tmp"; pause; return
    fi

    echo
    echo -e "  ${B}${T[up_new]} $(cat "$tmp/VERSION" 2>/dev/null || echo '?') · $new_ver${N}"
    echo -e "  ${D}${T[up_changes]}${N}"
    git -C "$tmp" log --oneline -5 | sed 's/^/    /'
    echo
    echo -e "  ${D}${T[up_k1]}${N}"
    echo -e "  ${D}${T[up_k2]}${N}"
    echo -e "  ${D}${T[up_k3]}${N}"
    echo
    read -rp "  ${T[up_q]}: " ans
    if [[ ! "$ans" =~ ^[YyДд] ]]; then
        echo "  ${T[cancelled]}"; rm -rf "$tmp"; pause; return
    fi

    rm -rf "$APP_DIR.bak"
    cp -a "$APP_DIR" "$APP_DIR.bak" 2>/dev/null || true
    echo -e "  ${D}${T[up_backup]} $APP_DIR.bak${N}"
    echo

    # exec, а не вызов: bash не должен дочитывать menu.sh после того,
    # как установщик перезапишет этот файл.
    exec bash "$tmp/install.sh"
}

# ── Сервис ────────────────────────────────────────────────────────────
doctor() {
    local k ifc
    k="$(uname -r)"
    echo -e "  ${T[dr_kernel]}: $k $(awk -v v="${k%%-*}" -v msg="${T[dr_need]}" \
        'BEGIN{split(v,a,".");print (a[1]>5||(a[1]==5&&a[2]>=4))?"\033[32m✓\033[0m":"\033[31m✗ "msg"\033[0m"}')"
    for b in clang bpftool tc python3; do
        printf "  %-17s: %s\n" "$b" "$(command -v "$b" >/dev/null &&
            echo -e "${G}✓${N} $(command -v "$b")" || echo -e "${R}✗ ${T[dr_notinst]}${N}")"
    done
    echo -e "  ${T[dr_bpffs]}: $(mountpoint -q /sys/fs/bpf &&
        echo -e "${G}✓ ${T[dr_mounted]}${N}" || echo -e "${R}✗ ${T[dr_notmounted]}${N}")"
    ifc="$(ip route get 1.1.1.1 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -1)"
    echo -e "  ${T[dr_iface]}: ${B}${ifc:-${T[dr_undetected]}}${N}"
    [[ -n "$ifc" ]] && echo -e "  ${T[dr_qdisc]}: $(tc qdisc show dev "$ifc" root 2>/dev/null | awk '{print $2}')"
    printf "  %-17s: %s\n" "${T[dr_watch]}" "$(systemctl is-active shaper-watch >/dev/null 2>&1 &&
        echo -e "${G}✓ ${T[dr_running]}${N}" || echo -e "${Y}⚠ ${T[dr_stopped]}${N}")"
    echo -e "  ${T[dr_maps]}: $([[ -d /sys/fs/bpf/shaper/maps ]] &&
        echo -e "${G}✓${N}" || echo -e "${D}${T[dr_nosvc]}${N}")"
}

screen_service() {
    local auto_lbl
    while :; do
        if systemctl is-enabled shaper >/dev/null 2>&1; then
            auto_lbl="🔁 ${T[sv_auto]} ${G}${T[st_auto_on]}${N} ${D}${T[sv_to_off]}${N}"
        else
            auto_lbl="⚠️  ${T[sv_auto]} ${Y}${T[st_auto_off]}${N} ${D}${T[sv_to_on]}${N}"
        fi

        title "${T[sv_title]}"
        systemctl status shaper --no-pager 2>/dev/null | head -4 | sed 's/^/  /'
        hr
        echo -e "  [1] ▶️  ${T[sv_start]}"
        echo -e "  [2] ⏹  ${T[sv_stop]}"
        echo -e "  [3] 🔄 ${T[sv_restart]} ${D}${T[sv_restart_d]}${N}"
        echo -e "  [4] $auto_lbl"
        echo -e "  [5] 📜 ${T[sv_logs]}"
        echo -e "  [6] 🩺 ${T[sv_doctor]}"
        echo -e "  [7] ⬆️  ${T[sv_update]} ${D}(${T[sv_version]} $(installed_version))${N}"
        echo -e "  [8] 🌐 ${T[sv_lang]}"
        echo -e "  [0] ← ${T[m0]}"
        echo
        case "$(ask "${T[choice]}")" in
            1) systemctl start shaper; sleep 1 ;;
            2) systemctl stop shaper; sleep 1 ;;
            3) rm -f "$APP_DIR/bpf/shaper.bpf.o"; systemctl restart shaper; sleep 2 ;;
            4) if systemctl is-enabled shaper >/dev/null 2>&1; then
                   systemctl disable shaper >/dev/null 2>&1
                   echo -e "  ${Y}⚠ ${T[sv_auto_no]}${N}"
               else
                   systemctl enable shaper >/dev/null 2>&1
                   echo -e "  ${G}✓ ${T[sv_auto_yes]}${N}"
               fi
               sleep 2 ;;
            5) title "${T[sv_logs]}"
               # оба юнита: движок и сторож — штрафы пишет именно сторож
               journalctl -u shaper -u shaper-watch -n 40 --no-pager |
                   sed 's/^/  /'; pause ;;
            6) title "${T[dr_title]}"; doctor; pause ;;
            7) screen_update ;;
            8) screen_lang ;;
            0|"") return ;;
        esac
    done
}

# ── Главное меню ──────────────────────────────────────────────────────
[[ -z "$UI_LANG" ]] && screen_lang     # первый запуск — спросить язык

nlim=0
while :; do
    clear
    echo
    banner
    hr
    status_line
    hr
    echo
    nlim="$(limited_count)"
    echo -e "  [1] 🎚  ${T[m1]} ${D}${T[m1d]}${N}"
    echo -e "  [2] 🚦 ${T[m2]} ${D}${T[m2d]}${N}"
    echo -e "  [3] 📡 ${T[m3]} ${D}${T[m3d]}${N}"
    echo -e "  [4] 📊 ${T[m4]} ${D}${T[m4d]}${N}"
    if [[ "$nlim" != "0" ]]; then
        echo -e "  [6] 🚫 ${T[m6]} ${R}($nlim)${N}"
    else
        echo -e "  [6] 🚫 ${T[m6]} ${D}(0)${N}"
    fi
    echo -e "  [7] 🤍 ${T[m7]}"
    echo -e "  [8] 🔧 ${T[m8]} ${D}${T[m8d]}${N}"
    echo -e "  [0] 🚪 ${T[m0]}"
    hr
    echo -e "  ☕ ${D}${T[credit]}${N}"
    echo
    case "$(ask "${T[choice]}")" in
        1) screen_limit ;;
        2) screen_guard ;;
        3) "$CTL" monitor ;;
        4) screen_stats ;;
        6) screen_limited ;;
        7) screen_whitelist ;;
        8) screen_service ;;
        0|"") clear; exit 0 ;;
    esac
done
