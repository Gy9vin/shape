#!/usr/bin/env bash
# Проверки shell-части Shape после аудита.
set -uo pipefail
SRC="${SHAPE_SRC:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
TMP="$(mktemp -d)"; CONF="$TMP/shaper.conf"
ok=0; fail=0
G='\033[32m'; R='\033[31m'; B='\033[1m'; N='\033[0m'
check() { if eval "$2"; then ok=$((ok+1)); echo -e "  ${G}✓${N} $1"
          else fail=$((fail+1)); echo -e "  ${R}✗ $1${N}"; fi; }

# Берём функции прямо из menu.sh, чтобы проверять живой код, а не копию.
{ sed -n '/^conf_safe()/,/^}/p' "$SRC/menu.sh"
  sed -n '/^conf_set()/,/^}/p'  "$SRC/menu.sh"; } > "$TMP/fn.sh"
# shellcheck disable=SC1090
source "$TMP/fn.sh"

echo -e "\n${B}1. Запись в shaper.conf — файл потом выполняется через source${N}"
: > "$CONF"
conf_set UI_LANG ru
check "нормальное значение записано" '[[ "$(grep -c "^UI_LANG=\"ru\"" "$CONF")" == 1 ]]'
conf_set UI_LANG en
check "повторная запись заменяет, а не дублирует" \
      '[[ "$(grep -c "^UI_LANG=" "$CONF")" == 1 ]] && grep -q "UI_LANG=\"en\"" "$CONF"'

for bad in 'x"; touch /tmp/shell_pwned; #' '$(touch /tmp/shell_pwned)' \
           '`touch /tmp/shell_pwned`' 'a b; id' 'v'$'\n''touch /tmp/shell_pwned' \
           'x&&id' 'x|id'; do
    conf_set TUNNEL_HOST "$bad" 2>/dev/null
    check "отвергнуто: ${bad:0:22}" '! grep -q "TUNNEL_HOST" "$CONF"'
done
check "ключ с мусором отвергнут" '! conf_set "A=1; id" v 2>/dev/null'

# Главная проверка: получившийся файл безопасно скормить source
conf_set TUNNEL_HOST "de.example.com"; conf_set TUNNEL_PORT 22
( set -e; source "$CONF" ) >/dev/null 2>&1
check "конфиг корректно читается через source" '[[ $? -eq 0 ]]'
check "команда из значения не выполнилась" '[[ ! -e /tmp/shell_pwned ]]'
check "права на конфиг 600" '[[ "$(stat -c %a "$CONF")" == 600 ]]'

echo -e "\n${B}2. Параметры SSH-туннеля${N}"
# Регулярные выражения берём из самого menu.sh — тест не должен расходиться с кодом.
HOST_RE="$(grep -o '\^\[A-Za-z0-9\.:_-\]{1,253}\$' "$SRC/menu.sh" | head -1)"
USER_RE="$(grep -o '\^\[A-Za-z_\]\[A-Za-z0-9_-\]{0,31}\$' "$SRC/menu.sh" | head -1)"
check "regexp хоста найден в menu.sh" '[[ -n "$HOST_RE" ]]'
check "regexp пользователя найден в menu.sh" '[[ -n "$USER_RE" ]]'

for bad in 'h.com -o ProxyCommand=id' 'h.com'$'\n''ExecStartPre=/bin/sh -c id' \
           'h.com;id' '$(id)' 'h.com|id' 'h com'; do
    check "хост отвергнут: ${bad:0:26}" '! [[ "$bad" =~ $HOST_RE ]]'
done
for good in 'de.example.com' '203.0.113.10' '2001:db8::1'; do
    check "хост принят: $good" '[[ "$good" =~ $HOST_RE ]]'
done
for bad in 'root -oProxyCommand=id' 'a;id' '$(id)' 'root'$'\n''x'; do
    check "пользователь отвергнут: ${bad:0:22}" '! [[ "$bad" =~ $USER_RE ]]'
done
check "пользователь root принят" '[[ "root" =~ $USER_RE ]]'
check "пользователь shape-vpn принят" '[[ "shape-vpn" =~ $USER_RE ]]'

echo -e "\n${B}3. Имя интерфейса в engine.sh${N}"
source <(grep -m1 "^iface_ok()" "$SRC/engine.sh")
for bad in 'eth0; rm -rf /' '$(id)' 'a/../../etc' 'очень-длинное-имя-интерфейса' ''; do
    check "интерфейс отвергнут: ${bad:0:24}" '! iface_ok "$bad"'
done
for good in eth0 ens3 enp0s3 eth0.100 br-lan; do
    check "интерфейс принят: $good" 'iface_ok "$good"'
done

echo -e "\n${B}4. Синтаксис и целостность${N}"
for f in menu.sh lang.sh engine.sh install.sh; do
    check "bash -n $f" "bash -n '$SRC/$f'"
done
check "shaperctl.py компилируется" "python3 -m py_compile '$SRC/shaperctl.py'"
# каждая функция, которую вызывает меню, должна быть определена
missing="$(python3 - "$SRC/menu.sh" <<'PY'
import re, sys
s = open(sys.argv[1]).read()
d = set(re.findall(r'^([a-z_]+)\(\)\s*\{', s, re.M))
u = set(re.findall(r'\b(screen_[a-z_]+|tunnel_[a-z_]+|guard_[a-z_]+|conf_set|conf_safe|limited_count|read_state|tg_read|doctor|banner|status_line|installed_version|show_listening|tn_bad)\b', s))
print(",".join(sorted(u - d)))
PY
)"
check "все функции меню определены (${missing:-нет пропусков})" '[[ -z "$missing" ]]'

# в systemd-юнитах не должно быть опций, создающих пространство монтирования,
# для сервиса, который монтирует /sys/fs/bpf
check "shaper.service без PrivateTmp/ProtectHome" \
      '! grep -qE "^(PrivateTmp|ProtectHome|ProtectSystem)=" "$SRC/systemd/shaper.service"'
check "shaper-watch.service имеет ReadWritePaths=/etc/shaper" \
      'grep -q "^ReadWritePaths=/etc/shaper" "$SRC/systemd/shaper-watch.service"'
check "ни один юнит не запрещает запись в /sys" \
      '! grep -q "ProtectKernelTunables=yes" "$SRC"/systemd/*.service'

rm -rf "$TMP"
echo -e "\n${B}Пресеты автоограничения${N}"
# Порог в гигабайтах за час осмыслен только относительно канала, поэтому
# быстрый пресет обязан его вычислять, а не брать числом.
check "пресет для быстрых нод есть" \
      'grep -q "gp_fast" "$SRC/menu.sh"'
check "часовой порог вычисляется, а не зашит" \
      'grep -A12 "gp_fast_nolimit" "$SRC/menu.sh" | grep -q "speed/8/1000\*3600"'
check "берётся половина канала" \
      'grep -q "speed/8/1000\*3600\*0.5" "$SRC/menu.sh"'
check "без заданного лимита есть запасное значение" \
      'grep -B4 "gp_fast_nolimit" "$SRC/menu.sh" | grep -q "gbh=20"'
check "вычисленное число показывается до применения" \
      'grep -B2 -A14 "gp_fast_calc" "$SRC/menu.sh" | grep -q "apply_q"'
check "порог размера пакета одинаков во всех пресетах" \
      '[[ $(grep -c -- "--packet 600" "$SRC/menu.sh") -eq 4 ]]'
check "суточные признаки одинаковы во всех пресетах" \
      '[[ $(grep -c -- "--hours 4 --upload-gb 2" "$SRC/menu.sh") -eq 4 ]]'
# Обязательный размер пакета нужен только там, где порог отдачи опущен:
# в остальных пресетах он ничего не добавил бы, а поведение усложнил.
check "обязательный пакет включает только торрент-пресет" \
      '[[ $(grep -c -- "--require-packet on" "$SRC/menu.sh") -eq 1 ]]'
check "торрент-пресет опускает порог отдачи до трёх процентов" \
      'grep -q -- "--both-ul 3 " "$SRC/menu.sh"'
check "в остальных пресетах порог отдачи прежний" \
      '[[ $(grep -c -- "--both-ul 15" "$SRC/menu.sh") -eq 3 ]]'
# Раздающий по определению качает меньше, чем отдаёт. Порог вниз в 50% требовал
# от него ещё и много качать — и адрес с 3.4 Мбит вниз при лимите 10 не
# проходил обязательное условие, хотя отдавал 7.1 пакетами по 1400 байт.
check "в торрент-пресете порог скачивания опущен" \
      'grep -q -- "--both-dl 10 --both-ul 3" "$SRC/menu.sh"'
check "в остальных пресетах порог скачивания прежний" \
      '[[ $(grep -c -- "--both-dl 50" "$SRC/menu.sh") -eq 3 ]]'
check "низкий порог вниз идёт только вместе с требованием пакетов" \
      '[[ $(grep -c -- "--both-dl 10" "$SRC/menu.sh") -eq \
          $(grep -c -- "--require-packet on" "$SRC/menu.sh") ]]'

# Арифметика: полоса в Мбит/с → гигабайты за час. Ошибка здесь тихо сделала
# бы порог в восемь раз строже или мягче, и заметили бы это по жалобам.
for pair in "10 2.2" "50 11.2" "100 22.5" "1000 225.0"; do
    set -- $pair
    got="$(awk "BEGIN{printf \"%.1f\", $1/8/1000*3600*0.5}")"
    check "$1 Мбит/с → порог $2 ГБ/час" '[[ "'"$got"'" == "'"$2"'" ]]' "получено $got"
done

echo -e "\n${B}Очередь fq${N}"
# Без fq ядро игнорирует расставленное время отправки, и скачивание не
# ограничивается вообще. Раньше ошибка назначения глушилась, и движок печатал
# «fq назначен» поверх оставшегося fq_codel — нода молча раздавала безлимит.
check "движок проверяет результат, а не только пытается назначить" \
      'grep -q "fq_offenders" "$SRC/engine.sh"'
check "ошибка назначения больше не выдаётся за успех" \
      '! grep -q "ok \"fq назначен на" "$SRC/engine.sh"'
check "движок пробует подгрузить модуль" \
      'grep -q "modprobe sch_fq" "$SRC/engine.sh"'
check "без fq загрузка не срывается" \
      'grep -qE "setup_fq (\"[\$]ifc\" )?\|\| true" "$SRC/engine.sh"'
# Подвеситься к очередям mq выходит не всегда: при дескрипторе «0:» ядро не
# может разрешить parent :1 и отвечает «Failed to find specified qdisc».
# Тогда единственный путь — заменить корень целиком.
check "есть запасной путь через замену корня" \
      '[[ $(grep -c "tc qdisc replace dev \"\$IFACE\" root fq" "$SRC/engine.sh") -ge 2 ]]'
check "ошибка tc показывается, а не глушится" \
      'grep -q "err \"tc: \$err_out\"" "$SRC/engine.sh"'
check "запасной путь идёт после проверки, а не вместо неё" \
      '[[ $(grep -n "fq_offenders" "$SRC/engine.sh" | wc -l) -ge 3 ]]'
check "доктор смотрит все очереди, а не только корень" \
      '! grep -q "tc qdisc show dev \\"\$ifc\\" root" "$SRC/menu.sh"'
check "доктор знает, что fq_codel — это беда" \
      'grep -q "dr_qdisc_bad" "$SRC/menu.sh"'
check "в метриках есть отдельный признак готовности" \
      'grep -q "shape_edt_ready" "$SRC/shaperctl.py"'
check "предупреждение видно на главном экране состояния" \
      'grep -q "edt_off" "$SRC/shaperctl.py"'

echo -e "\n${B}Экран панели${NC:-}${N}"
# Подписи на экране панели выровнены пробелами внутри самих строк: printf в
# bash считает байты, а кириллица в UTF-8 занимает по два, поэтому %-14s
# разъезжается ровно на русском. Раз ширина зашита в строку, её надо стеречь —
# одна подпись длиннее остальных, и колонка съезжает.
widths="$(python3 - "$SRC/lang.sh" <<'PY'
import re, sys
seen = {}
for line in open(sys.argv[1], encoding="utf-8"):
    m = re.search(r'\[(pn_l_[a-z_]+)\]="([^"]*)"', line)
    if m:
        seen.setdefault(len(m.group(2)), 0)
        seen[len(m.group(2))] += 1
print(" ".join(str(w) for w in sorted(seen)))
PY
)"
check "все подписи экрана панели одной ширины" \
      '[[ $(echo "'"$widths"'" | wc -w) -eq 1 ]]' "ширины: $widths"
check "подписи не пустые" '[[ -n "'"$widths"'" && "'"$widths"'" != "0" ]]'

# Значения на экране собираются из отдельных полей. Склейка вида «1/60» уже
# один раз приводила к тому, что в меню показывалось «Действие: notify 1/60»
# без пояснения, что это за числа.
check "поля панели не склеиваются в одно значение" \
      '! grep -q "%s/%s" "$SRC/menu.sh"'
check "у чисел на экране панели есть единицы" \
      'grep -q "pn_u_sec" "$SRC/menu.sh" && grep -q "pn_u_min" "$SRC/menu.sh" \
       && grep -q "pn_u_mbps" "$SRC/menu.sh"'

# Панель — ежедневный экран, ему место на главной, а не в «Сервисе» среди
# обновления и удаления.
check "панель вызывается с главного меню" \
      'grep -qE "^ *9\) screen_panel ;;" "$SRC/menu.sh"'
check "и убрана из Сервиса" \
      '[[ $(grep -c "screen_panel ;;" "$SRC/menu.sh") -eq 1 ]]'
check "в Сервисе вернулась прежняя нумерация" \
      'grep -qE "^ *11\) screen_backup ;;" "$SRC/menu.sh" &&
       grep -qE "^ *12\) screen_uninstall ;;" "$SRC/menu.sh"'

echo -e "\n${B}Список интерфейсов в engine.sh (режим HAProxy: «eth0 lo»)${N}"
# Берём настоящий кусок разбора IFACE из engine.sh и гоняем его на разных значениях.
IFTMP="$(mktemp -d)"
sed -n '/^iface_ok()/,/^IFACE="\${IFACES\[\*\]-}"/p' "$SRC/engine.sh" > "$IFTMP/ifaces.sh"
parse_ifaces() {   # $1 = значение IFACE; печатает «N|список|stderr»
    bash -c 'set -u; CONF=/etc/shaper/shaper.conf; err() { echo "ERR:$*" >&2; }; IFACE="$1"; source "$2";
             echo "${#IFACES[@]}|${IFACES[*]-}"' _ "$1" "$IFTMP/ifaces.sh" 2>&1
}
check "кусок разбора найден в engine.sh" '[[ -s "$IFTMP/ifaces.sh" ]]'
check "один интерфейс работает как раньше" '[[ "$(parse_ifaces eth0)" == "1|eth0" ]]'
check "список через пробел" '[[ "$(parse_ifaces "eth0 lo")" == "2|eth0 lo" ]]'
check "лишние пробелы и табы не мешают" '[[ "$(parse_ifaces "  eth0 	 lo  ")" == "2|eth0 lo" ]]'
check "дубль схлопывается" '[[ "$(parse_ifaces "lo eth0 lo")" == "2|lo eth0" ]]'
check "пустой IFACE — пусто (дальше автоопределение)" '[[ "$(parse_ifaces "")" == "0|" ]]'
out="$(parse_ifaces 'eth0 $(touch /tmp/shell_pwned) lo')"
check "инъекция в имени отброшена, остальное цело" \
      '[[ "$out" == *"2|eth0 lo" ]] && [[ ! -e /tmp/shell_pwned ]]'
check "о негодном имени сказано" '[[ "$out" == *ERR:* ]]'
out="$(cd / && parse_ifaces '*')"
check "шаблон «*» не раскрывается в имена файлов" '[[ "$out" == *"0|" ]]'
check "полностью негодное значение — пусто, а не падение" \
      '[[ "$(parse_ifaces "a/../b")" == *"0|" ]]'

echo -e "\n${B}engine.sh и режим HAProxy: фильтры на каждом интерфейсе${N}"
check "фильтры вешаются в цикле по интерфейсам" \
      'grep -q "for ifc in \"\${IFACES\[@\]}\"" "$SRC/engine.sh"'
check "fq ставится для каждого интерфейса отдельно" \
      'grep -q "setup_fq \"\$ifc\"" "$SRC/engine.sh"'
check "в .active_iface пишется весь список" \
      'grep -q "IFACE=.*IFACES\[\*\].*active_iface" "$SRC/engine.sh"'
check "выгрузка снимает фильтры и с интерфейса из прошлого запуска" \
      'grep -q "unload_targets" "$SRC/engine.sh"'
check "на lo при выгрузке возвращается родной qdisc" \
      'grep -q "tc qdisc del dev lo root" "$SRC/engine.sh"'
check "о правиле «0» вместе с lo предупреждают" 'grep -q "lo_note" "$SRC/engine.sh"'
check "программа игнорирует правило «0» на loopback" \
      'grep -q "skb->ifindex == LOOPBACK_IFINDEX" "$SRC/bpf/shaper.bpf.c"'
check "uninstall.sh обходит весь список интерфейсов" \
      'grep -q "for iface in \$ifaces" "$SRC/uninstall.sh"'
check "в меню есть экран режима HAProxy в Сервисе" \
      'grep -q "^screen_haproxy()" "$SRC/menu.sh" && grep -qE "^ *13\) screen_haproxy ;;" "$SRC/menu.sh"'
check "меню делает всё через shaperctl, а не правит IFACE само" \
      'grep -q "\"\$CTL\" haproxy on" "$SRC/menu.sh" && ! grep -q "conf_set IFACE" "$SRC/menu.sh"'

echo -e "\n${B}Немобильный лимит в меню${N}"
check "пункт [6] на экране лимита ведёт в screen_nonmobile" \
      'sed -n "/^screen_limit()/,/^}/p" "$SRC/menu.sh" | grep -qE "^ *6\) screen_nonmobile; return ;;"'
check "меню включает и выключает режим только через shaperctl" \
      'grep -q "\"\$CTL\" nonmobile on --speed" "$SRC/menu.sh" && grep -q "\"\$CTL\" nonmobile off" "$SRC/menu.sh"'
check "скорость по умолчанию при включении — 1" \
      'grep -q "ask \"\${T\[nm_ask\]}\" 1" "$SRC/menu.sh"'
check "режим не вынесен в Сервис и не добавлен отдельным экраном главного меню" \
      '! sed -n "/^screen_service()/,/^}/p" "$SRC/menu.sh" | grep -q nonmobile'
check "скорость немобильного лимита на экране выводится через %g, а не сырым числом" \
      '! grep -q "\$(cfg nonmobile_mbps 0) Mbit/s" "$SRC/menu.sh"'
for k in st_nm st_nm_d nm_item nm_to_on nm_to_off nm_h1 nm_h2 nm_ask nm_off_q; do
    check "ключ lang.sh $k есть в обоих языках" \
          '[[ "$(grep -c "^ *\[$k\]=" "$SRC/lang.sh")" == 2 ]]'
done

echo -e "\n${B}Блокировка немобильных в меню${N}"
check "пункт [7] на экране лимита ведёт в screen_nonmobile_block" \
      'sed -n "/^screen_limit()/,/^}/p" "$SRC/menu.sh" | grep -qE "^ *7\) screen_nonmobile_block; return ;;"'
check "меню включает и выключает блок только через shaperctl" \
      'grep -q "\"\$CTL\" nonmobile block on" "$SRC/menu.sh" && grep -q "\"\$CTL\" nonmobile block off" "$SRC/menu.sh"'
check "включение блока требует явного подтверждения (по Enter — отмена)" \
      'sed -n "/^screen_nonmobile_block()/,/^}/p" "$SRC/menu.sh" | grep -q "nmb_on_q" && sed -n "/^screen_nonmobile_block()/,/^}/p" "$SRC/menu.sh" | grep -qF "case \"\$ans\" in"'
check "предупреждение перечисляет, кого заблокирует" \
      'sed -n "/^screen_nonmobile_block()/,/^}/p" "$SRC/menu.sh" | grep -q "nmb_warn1" && sed -n "/^screen_nonmobile_block()/,/^}/p" "$SRC/menu.sh" | grep -q "nmb_warn2" && sed -n "/^screen_nonmobile_block()/,/^}/p" "$SRC/menu.sh" | grep -q "nmb_warn3"'
check "подтверждение не опирается на класс символов с кириллицей (в локали C «н» = «Д»)" \
      '! sed -n "/^screen_nonmobile_block()/,/^}/p" "$SRC/menu.sh" | grep -qE "=~ \^\[YyДд\]"'
# Поведение, а не текст: функция исполняется с заглушками в локали C.
nmb_run() {
    local lc="$1" ans="$2"
    LC_ALL="$lc" ANS="$ans" SRC="$SRC" bash -c '
        eval "$(sed -n "/^screen_nonmobile_block()/,/^}/p" "$SRC/menu.sh")"
        T=(x)     # индексный массив: все ключи сводятся к одному слоту, текст не важен
        R= Y= D= N=
        nmb_on() { return 1; }
        nmb_ports_all() { return 1; }
        pause() { :; }
        CTL=ctl
        ctl() { echo "CTL:$*"; }
        screen_nonmobile_block <<< "$ANS"' 2>&1
}
check "ответ «нет» в локали C не включает блок" \
      '[[ "$(nmb_run C "нет")" != *"CTL:"* ]]'
check "ответ «н» в локали C не включает блок" \
      '[[ "$(nmb_run C "н")" != *"CTL:"* ]]'
check "ответ «да» включает блок в локали C" \
      '[[ "$(nmb_run C "да")" == *"CTL:nonmobile block on"* ]]'
check "ответ «Д» включает блок в локали C" \
      '[[ "$(nmb_run C "Д")" == *"CTL:nonmobile block on"* ]]'
check "ответ «y» включает блок" \
      '[[ "$(nmb_run C "y")" == *"CTL:nonmobile block on"* ]]'
check "пустой ответ (Enter) не включает блок" \
      '[[ "$(nmb_run C "")" != *"CTL:"* ]]'
check "ответ «нет» в UTF-8 не включает блок" \
      '[[ "$(nmb_run en_US.UTF-8 "нет")" != *"CTL:"* ]]'
check "при портах с 0 меню отказывает тем же сообщением и не спрашивает" \
      'sed -n "/^screen_nonmobile_block()/,/^}/p" "$SRC/menu.sh" | grep -q "nmb_ports_all" && sed -n "/^screen_nonmobile_block()/,/^}/p" "$SRC/menu.sh" | grep -q "nmb_ports0"'
check "блок не вынесен в Сервис" \
      '! sed -n "/^screen_service()/,/^}/p" "$SRC/menu.sh" | grep -q "nonmobile block"'
check "шапка меню показывает включённую блокировку" \
      'sed -n "/^status_line()/,/^}/p" "$SRC/menu.sh" | grep -q "st_nmb"'
check "блок читается из конфига только как настоящий true" \
      'grep -q "c.get(.nonmobile_block.) is True" "$SRC/menu.sh"'
check "engine.sh: whitelist sync стоит раньше restore (блок не режет белый список)" \
      '[[ $(grep -n "shaperctl.py\" whitelist sync" "$SRC/engine.sh" | head -1 | cut -d: -f1) -lt $(grep -n "shaperctl.py\" restore" "$SRC/engine.sh" | head -1 | cut -d: -f1) ]]'
for k in nmb_ports0 st_nmb st_nmb_d nmb_item nmb_to_on nmb_to_off nmb_warn0 nmb_warn1 nmb_warn2 nmb_warn3 nmb_warn4 nmb_on_q nmb_off_q; do
    check "ключ lang.sh $k есть в обоих языках" \
          '[[ "$(grep -c "^ *\[$k\]=" "$SRC/lang.sh")" == 2 ]]'
done

echo -e "\n${B}Итог: $ok пройдено, $fail провалено${N}"
[[ $fail -eq 0 ]]
