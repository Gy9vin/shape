#!/usr/bin/env bash
# engine.sh — сборка, загрузка и снятие eBPF-шейпера.
#   load | unload | reload | build | state
set -euo pipefail

APP_DIR="/opt/shaper"
ETC_DIR="/etc/shaper"
CONF="$ETC_DIR/shaper.conf"
BPF_SRC="$APP_DIR/bpf/shaper.bpf.c"
BPF_OBJ="$APP_DIR/bpf/shaper.bpf.o"
PIN_ROOT="/sys/fs/bpf/shaper"
PIN_MAPS="$PIN_ROOT/maps"
PIN_PROGS="$PIN_ROOT/progs"

G='\033[32m'; R='\033[31m'; Y='\033[33m'; N='\033[0m'
ok()   { echo -e "  ${G}✓${N} $*"; }
warn() { echo -e "  ${Y}⚠${N} $*"; }
err()  { echo -e "  ${R}✗${N} $*" >&2; }
die()  { err "$*"; exit 1; }

[[ $EUID -eq 0 ]] || die "нужны права root"

# shellcheck disable=SC1090
[[ -f "$CONF" ]] && source "$CONF"
IFACE="${IFACE:-}"

need_iface() {
    [[ -n "$IFACE" ]] || IFACE="$(ip route get 1.1.1.1 2>/dev/null |
                                  sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -1)"
    [[ -n "$IFACE" ]] || die "не удалось определить интерфейс, задай IFACE в $CONF"
    [[ -d "/sys/class/net/$IFACE" ]] || die "интерфейс $IFACE не существует"
}

# ── Сборка ────────────────────────────────────────────────────────────
build() {
    command -v clang >/dev/null || die "clang не установлен"
    mkdir -p "$(dirname "$BPF_OBJ")"

    local arch
    case "$(uname -m)" in
        x86_64)  arch=x86   ;;
        aarch64) arch=arm64 ;;
        armv7l)  arch=arm   ;;
        *)       arch="$(uname -m)" ;;
    esac

    # -g обязателен: карты описаны современным синтаксисом в секции .maps,
    # без BTF libbpf откажется открывать объект («BTF is required»).
    clang -O2 -g -target bpf \
          -D__TARGET_ARCH_"$arch" \
          -I/usr/include/"$(uname -m)"-linux-gnu \
          -c "$BPF_SRC" -o "$BPF_OBJ" 2>&1 | sed 's/^/    /' || die "не собралось"

    bpftool btf dump file "$BPF_OBJ" >/dev/null 2>&1 \
        || warn "в объекте нет BTF — проверь, что установлен libbpf-dev"
    ok "eBPF собран: $BPF_OBJ"
}

# ── qdisc ─────────────────────────────────────────────────────────────
setup_fq() {
    # EDT работает только если корневой qdisc — fq: он читает skb->tstamp.
    local root
    root="$(tc qdisc show dev "$IFACE" root 2>/dev/null | head -1)"

    if [[ "$root" == qdisc\ mq\ * ]]; then
        local n
        n="$(find "/sys/class/net/$IFACE/queues" -maxdepth 1 -name 'tx-*' | wc -l)"
        for ((i = 1; i <= n; i++)); do
            tc qdisc replace dev "$IFACE" parent ":$i" fq 2>/dev/null || true
        done
        ok "fq назначен на $n очередей (mq)"
    elif [[ "$root" == *" fq "* || "$root" == *" fq" ]]; then
        ok "fq уже активен"
    else
        tc qdisc replace dev "$IFACE" root fq
        ok "корневой qdisc заменён на fq"
    fi
}

# ── Загрузка ──────────────────────────────────────────────────────────
load() {
    need_iface
    for b in clang bpftool tc ip; do
        command -v "$b" >/dev/null || die "не найден $b — запусти install.sh"
    done

    mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
    [[ -f "$BPF_OBJ" && "$BPF_OBJ" -nt "$BPF_SRC" ]] || build

    unload_quiet
    mkdir -p "$PIN_ROOT"

    # libbpf 1.0+ не понимает SEC("classifier/down") — «unrecognized ELF
    # section name». Явный `type classifier` снимает вопрос. На старых libbpf
    # аргумент тоже поддерживается, но на всякий случай пробуем и без него.
    local out
    if ! out="$(bpftool prog loadall "$BPF_OBJ" "$PIN_PROGS" type classifier \
                   pinmaps "$PIN_MAPS" 2>&1)"; then
        rm -rf "$PIN_PROGS" "$PIN_MAPS" 2>/dev/null || true
        warn "загрузка с явным типом не прошла, пробую по имени секции"
        echo "$out" | sed 's/^/      /'
        if ! out="$(bpftool prog loadall "$BPF_OBJ" "$PIN_PROGS" \
                       pinmaps "$PIN_MAPS" 2>&1)"; then
            echo "$out" | sed 's/^/      /' >&2
            err "bpftool не смог загрузить eBPF-программу"
            echo "      • «BTF is required»         — объект собран без -g" >&2
            echo "      • «unrecognized ELF section» — несовместимость libbpf" >&2
            echo "      • «Operation not permitted»  — ядро без поддержки BPF" >&2
            exit 1
        fi
    fi

    [[ -e "$PIN_PROGS/shaper_down" && -e "$PIN_PROGS/shaper_up" ]] \
        || die "программы не нашлись в $PIN_PROGS: $(ls "$PIN_PROGS" 2>/dev/null | tr '\n' ' ')"
    ok "программа загружена, карты закреплены в $PIN_MAPS"

    setup_fq
    tc qdisc add dev "$IFACE" clsact 2>/dev/null || true

    tc filter add dev "$IFACE" egress  bpf da pinned "$PIN_PROGS/shaper_down" \
        || die "не прицепился фильтр на egress"
    tc filter add dev "$IFACE" ingress bpf da pinned "$PIN_PROGS/shaper_up" \
        || die "не прицепился фильтр на ingress"
    ok "фильтры повешены на $IFACE (egress + ingress)"

    "$APP_DIR/shaperctl.py" restore | sed 's/^/  /'
    [[ -f "$ETC_DIR/whitelist.txt" ]] && "$APP_DIR/shaperctl.py" whitelist sync | sed 's/^/  /'

    echo "IFACE=\"$IFACE\"" > "$ETC_DIR/.active_iface"
    ok "шейпер запущен"
}

unload_quiet() {
    local ifc="${IFACE:-}"
    [[ -z "$ifc" && -f "$ETC_DIR/.active_iface" ]] && . "$ETC_DIR/.active_iface" && ifc="$IFACE"
    if [[ -n "$ifc" && -d "/sys/class/net/$ifc" ]]; then
        tc filter del dev "$ifc" egress  2>/dev/null || true
        tc filter del dev "$ifc" ingress 2>/dev/null || true
        tc qdisc  del dev "$ifc" clsact  2>/dev/null || true
    fi
    rm -rf "$PIN_PROGS" "$PIN_MAPS" 2>/dev/null || true
}

unload() {
    unload_quiet
    ok "шейпер выгружен (qdisc fq оставлен — он безвреден)"
}

state() {
    need_iface
    local loaded=no filters
    [[ -d "$PIN_MAPS" ]] && loaded=yes
    filters="$(tc filter show dev "$IFACE" egress 2>/dev/null | grep -c shaper || true)"
    echo "iface=$IFACE loaded=$loaded egress_filters=$filters"
    [[ "$loaded" == yes && "$filters" -gt 0 ]]
}

case "${1:-}" in
    load)   load ;;
    unload) unload ;;
    reload) unload_quiet; load ;;
    build)  build ;;
    state)  state ;;
    *) echo "использование: $0 {load|unload|reload|build|state}"; exit 1 ;;
esac
