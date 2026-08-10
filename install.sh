#!/usr/bin/env bash
# install.sh — установка шейпера. Запускать из распакованной папки проекта.
set -euo pipefail

APP_DIR="/opt/shaper"
ETC_DIR="/etc/shaper"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

G='\033[32m'; R='\033[31m'; Y='\033[33m'; B='\033[1m'; D='\033[90m'; N='\033[0m'
ok()   { echo -e "  ${G}✓${N} $*"; }
step() { echo; echo -e "${B}$*${N}"; }
die()  { echo -e "  ${R}✗ $*${N}" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "запускай от root: sudo bash install.sh"

if [[ "${1:-}" == "--uninstall" ]]; then
    step "Удаление"
    systemctl disable --now shaper shaper-watch 2>/dev/null || true
    "$APP_DIR/engine.sh" unload 2>/dev/null || true
    rm -f /etc/systemd/system/shaper.service \
          /etc/systemd/system/shaper-watch.service /usr/local/bin/shaper
    rm -rf "$APP_DIR"
    systemctl daemon-reload
    ok "удалено (конфиг $ETC_DIR оставлен — удали вручную, если не нужен)"
    exit 0
fi

step "Проверка ядра"
KV="$(uname -r)"
awk -v v="${KV%%-*}" 'BEGIN{split(v,a,".");exit !(a[1]>5||(a[1]==5&&a[2]>=4))}' \
    || die "нужно ядро 5.4+, у тебя $KV"
ok "ядро $KV подходит"

step "Установка зависимостей"
if command -v apt-get >/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq clang llvm libbpf-dev linux-libc-dev \
        iproute2 python3 >/dev/null
    command -v bpftool >/dev/null || apt-get install -y -qq bpftool >/dev/null 2>&1 \
        || apt-get install -y -qq "linux-tools-$(uname -r)" >/dev/null 2>&1 || true
elif command -v dnf >/dev/null; then
    dnf install -y -q clang llvm libbpf-devel kernel-headers iproute python3 bpftool >/dev/null
elif command -v yum >/dev/null; then
    yum install -y -q clang llvm libbpf-devel kernel-headers iproute python3 bpftool >/dev/null
else
    die "не знаю твой пакетный менеджер — поставь: clang, llvm, libbpf-dev, bpftool, iproute2"
fi

for b in clang bpftool tc python3; do
    command -v "$b" >/dev/null || die "$b так и не установился"
done
ok "clang, bpftool, tc, python3 на месте"

step "Очистка от прошлых версий"
# Демон Telegram-уведомлений и файлы правил из старой модели с правилами 0-7.
if [[ -f /etc/systemd/system/shaper-notify.service ]]; then
    systemctl disable --now shaper-notify >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/shaper-notify.service
    ok "убран shaper-notify.service"
fi
rm -f /var/lib/shaper/notify.state "$ETC_DIR/rules.json" "$ETC_DIR/rules.json.mib.bak"
rmdir /var/lib/shaper 2>/dev/null || true
# Объект пересобираем всегда: структуры карт могли поменяться между версиями.
rm -f "$APP_DIR/bpf/shaper.bpf.o"
ok "старые файлы убраны"

step "Копирование файлов"
mkdir -p "$APP_DIR/bpf" "$ETC_DIR"
install -m 755 "$SRC/shaperctl.py"     "$APP_DIR/shaperctl.py"
install -m 755 "$SRC/engine.sh"        "$APP_DIR/engine.sh"
install -m 755 "$SRC/menu.sh"          "$APP_DIR/menu.sh"
install -m 644 "$SRC/lang.sh"          "$APP_DIR/lang.sh"
install -m 644 "$SRC/VERSION"          "$APP_DIR/VERSION"
install -m 644 "$SRC/bpf/shaper.bpf.c" "$APP_DIR/bpf/shaper.bpf.c"

[[ -f "$ETC_DIR/config.json" ]] || echo '{"ports": [443], "speed_mbps": 0}' > "$ETC_DIR/config.json"
[[ -f "$ETC_DIR/penalties.json" ]] || echo '{}' > "$ETC_DIR/penalties.json"
[[ -f "$ETC_DIR/shaper.conf" ]] || cat > "$ETC_DIR/shaper.conf" <<'EOF'
# Сетевой интерфейс. Пусто = определить автоматически по маршруту в интернет.
IFACE=""
EOF
[[ -f "$ETC_DIR/whitelist.txt" ]] || cat > "$ETC_DIR/whitelist.txt" <<'EOF'
# IP, которые полностью минуют шейпер. По одному в строке.
# 203.0.113.10
EOF
ok "файлы в $APP_DIR, конфиг в $ETC_DIR"

# Хеш коммита, из которого ставим: по нему пункт «Обновить» понимает,
# есть ли в репозитории что-то новее. Номер версии лежит в файле VERSION.
if [[ -d "$SRC/.git" ]] && command -v git >/dev/null; then
    git -C "$SRC" rev-parse --short HEAD > "$APP_DIR/.commit" 2>/dev/null || true
fi
rm -f "$APP_DIR/.version"   # имя из версий до 1.3

step "Сборка eBPF"
if ! "$APP_DIR/engine.sh" build; then
    if [[ -d "$APP_DIR.bak" ]]; then
        echo -e "  ${Y}⚠ откатываюсь на прошлую версию${N}"
        rm -rf "$APP_DIR"
        mv "$APP_DIR.bak" "$APP_DIR"
        systemctl restart shaper 2>/dev/null || true
        die "новая версия не собралась, вернул прежнюю — она работает"
    fi
    die "eBPF не собрался"
fi

step "Регистрация сервиса"
install -m 644 "$SRC/systemd/shaper.service"       /etc/systemd/system/
install -m 644 "$SRC/systemd/shaper-watch.service" /etc/systemd/system/
systemctl daemon-reload

# Автостарт обязателен: без него после перезагрузки сервера лимит не применится,
# а клиенты молча получат безлимит. Проверяем результат, а не надеемся на него.
systemctl enable shaper >/dev/null 2>&1 || true
systemctl enable shaper-watch >/dev/null 2>&1 || true
if systemctl is-enabled shaper >/dev/null 2>&1; then
    ok "автостарт включён — переживёт перезагрузку сервера"
else
    echo -e "  ${R}✗ автостарт включить не удалось${N}"
    echo -e "  ${Y}  после ребута шейпер не поднимется, включи вручную:${N}"
    echo -e "  ${Y}  systemctl enable shaper${N}"
fi

cat > /usr/local/bin/shaper <<'EOF'
#!/usr/bin/env bash
if [[ $EUID -ne 0 ]] && command -v sudo >/dev/null; then exec sudo /opt/shaper/menu.sh "$@"; fi
exec /opt/shaper/menu.sh "$@"
EOF
chmod +x /usr/local/bin/shaper
ok "команда shaper создана"

step "Запуск"
# Именно restart: при обновлении сервис уже запущен, и `start` был бы пустышкой —
# в ядре осталась бы eBPF-программа прошлой версии.
if systemctl restart shaper; then
    ok "движок запущен"
    systemctl restart shaper-watch 2>/dev/null || true
    rm -rf "$APP_DIR.bak"
    "$APP_DIR/shaperctl.py" show
else
    echo -e "  ${Y}⚠ не стартанул — смотри: journalctl -u shaper -n 40${N}"
    [[ -d "$APP_DIR.bak" ]] && echo -e "  ${D}прошлая версия лежит в $APP_DIR.bak${N}"
fi

echo
echo -e "${B}Готово.${N} Shape v$(cat "$APP_DIR/VERSION" 2>/dev/null || echo '?')$(
    [[ -f "$APP_DIR/.commit" ]] && echo " · $(cat "$APP_DIR/.commit")")"
echo -e "  Запусти ${B}shaper${N}$([[ "$(python3 -c "
import json
try: print(json.load(open('$ETC_DIR/config.json'))['speed_mbps'])
except Exception: print(0)" 2>/dev/null)" == "0" ]] && echo " → «Настроить лимит»" || echo "")"
echo
