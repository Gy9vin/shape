/*
 * Shape — ограничитель скорости на пользователя (eBPF + EDT)
 *
 * Одна настройка: список портов и скорость в Мбит/с. Каждый IP-адрес,
 * работающий через эти порты, получает свой независимый лимит.
 *
 * Download (egress): Earliest Departure Time — пакеты не теряются,
 *                    а равномерно растягиваются во времени, отдаёт fq qdisc.
 * Upload  (ingress): Token Bucket — лишние пакеты дропаются, TCP снизит окно.
 *
 * Единицы. Наружу скорость в Мбит/с, ядру нужны байты в секунду, поэтому в
 * карте лежит пересчитанное значение: bytes_per_sec = Мбит/с * 125000.
 * Пересчёт делает shaperctl.py.
 *
 * Карты:
 *   config_map     : 0 -> struct config     (bytes_per_sec, 0 = выключено)
 *   port_map       : port (u32) -> u8       (порт 0 = все порты)
 *   whitelist_map  : ip (4x u32) -> u8      (к этим IP лимит не применяется,
 *                                            но их трафик всё равно считается)
 *   penalty_map    : ip -> struct penalty   (штраф нарушителю на время)
 *   user_state_map_down/up : ip -> struct user_state
 *   pp_conn_map    : relay ip:port -> ip    (PROXY protocol: соединение
 *                                            релея CDN ↔ настоящий клиент)
 *
 * Карты состояний — LRU: упёрлись в потолок, ядро само вытесняет давно
 * неактивные адреса. Фоновая чистка не нужна.
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Карты LRU набиваются до потолка и остаются полными, а сторож дампит их
 * целиком каждые несколько секунд. Поэтому размер определяет не память, а
 * процессорное время на разбор JSON: 65536 записей — это 10 МБ и почти
 * секунда на слабом ядре, 8192 — полтора мегабайта и десятки миллисекунд.
 * Запас всё равно огромный: на ноду со 150 клиентами приходится 300-500
 * адресов в сутки с учётом смены мобильных IP. */
/* Номера заголовков расширения IPv6. Приходят из linux/in6.h, но на части
 * дистрибутивов этот заголовок в цепочку не попадает — подстрахуемся. */
#ifndef IPPROTO_HOPOPTS
#define IPPROTO_HOPOPTS   0
#endif
#ifndef IPPROTO_ROUTING
#define IPPROTO_ROUTING   43
#endif
#ifndef IPPROTO_FRAGMENT
#define IPPROTO_FRAGMENT  44
#endif
#ifndef IPPROTO_DSTOPTS
#define IPPROTO_DSTOPTS   60
#endif

#define MAX_USERS      8192
/* Если EDT уводит отправку больше чем на 2 с вперёд — очередь безнадёжна. */
#define EDT_HORIZON_NS 2000000000ULL
/* Допустимый всплеск на upload: 200 мс «в долг». */
#define UL_BUCKET_NS   200000000ULL

/* 8 байт: bytes_per_sec */
struct config {
    __u64 bytes_per_sec;
};

/* 16 байт: IPv4 в addr[0], IPv6 целиком */
struct ip_key {
    __u32 addr[4];
};

/* 16 байт: персональный штраф для нарушителя.
 * Записи создаёт сторож из userspace, здесь только читаем.
 * until_ns — в шкале bpf_ktime_get_ns (CLOCK_MONOTONIC). */
struct penalty {
    __u64 rate_bytes_per_sec;
    __u64 until_ns;
};

/* 32 байта: last_departure_ns, total_bytes, last_seen_ns, packets
 * packets нужен, чтобы посчитать средний размер пакета. В карте отдачи
 * это отделяет раздачу (полные пакеты 1200-1400 байт) от просмотра видео,
 * где вверх уходят только ACK по 60-80 байт. */
struct user_state {
    __u64 last_departure_ns;
    __u64 total_bytes;
    __u64 last_seen_ns;
    __u64 packets;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, struct config);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key,   __u32);
    __type(value, __u8);
} port_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key,   struct ip_key);
    __type(value, __u8);
} whitelist_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key,   struct ip_key);
    __type(value, struct penalty);
} penalty_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_USERS);
    __type(key,   struct ip_key);
    __type(value, struct user_state);
} user_state_map_down SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_USERS);
    __type(key,   struct ip_key);
    __type(value, struct user_state);
} user_state_map_up SEC(".maps");

/* PROXY protocol: «IP:порт релея» → настоящий адрес клиента.
 * Запись заводит первый сегмент соединения, принёсший заголовок,
 * FIN/RST её удаляют; порт релея уникален для соединения. LRU —
 * страховка от утечки, если соединение оборвалось без FIN. */
struct pp_key {
    __u32 addr[4];    /* адрес релея: IPv4 в addr[0], IPv6 целиком */
    __u16 port;       /* порт релея в этом соединении */
    __u16 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_USERS);
    __type(key,   struct pp_key);
    __type(value, struct ip_key);
} pp_conn_map SEC(".maps");


/* Разбор заголовка PROXY protocol из начала TCP-потока. Возвращает 1
 * и адрес клиента в out, если заголовок нашёлся.
 *
 * v2 — бинарный: 12-байтовая сигнатура, затем версия/команда,
 * семейство, длина и адреса. Команда LOCAL (соединение без клиента)
 * игнорируется. v1 — текстовый «PROXY TCP4 a.b.c.d …». Варианты UDP
 * не встречаются на практике: vless/reality ездят по TCP. */
static __always_inline int parse_pp(__u8 *p, void *data_end, struct ip_key *out)
{
    if ((void *)(p + 28) > data_end)
        return 0;                   /* короче минимальной головы v2/TCP4 */

    if (p[0] == 0x0D && p[1] == 0x0A && p[2] == 0x0D && p[3] == 0x0A &&
        p[4] == 0x00 && p[5] == 0x0D && p[6] == 0x0A && p[7] == 0x51 &&
        p[8] == 0x55 && p[9] == 0x49 && p[10] == 0x54 && p[11] == 0x0A) {
        if (p[12] >> 4 != 2)         /* версия */
            return 0;
        if ((p[12] & 0x0F) != 1)    /* команда PROXY, не LOCAL */
            return 0;
        if (p[13] == 0x11) {        /* TCP4: адрес клиента с 16-го байта */
            out->addr[0] = ((__u32)p[16] << 24) | ((__u32)p[17] << 16) |
                           ((__u32)p[18] << 8) | (__u32)p[19];
            return 1;
        }
        if (p[13] == 0x21) {        /* TCP6: 16 байт адреса */
            if ((void *)(p + 32) > data_end)
                return 0;
#pragma unroll
            for (int i = 0; i < 4; i++)
                out->addr[i] = ((__u32)p[16 + i * 4] << 24) |
                               ((__u32)p[17 + i * 4] << 16) |
                               ((__u32)p[18 + i * 4] << 8) |
                               (__u32)p[19 + i * 4];
            return 1;
        }
        return 0;
    }

    /* v1: «PROXY TCP4 a.b.c.d …» — до 15 знаков на адрес */
    if (p[0] == 'P' && p[1] == 'R' && p[2] == 'O' && p[3] == 'X' &&
        p[4] == 'Y' && p[5] == ' ' && p[6] == 'T' && p[7] == 'C' &&
        p[8] == 'P' && p[9] == '4' && p[10] == ' ') {
        __u32 ip = 0, oct = 0;
        int dots = 0;
#pragma unroll
        for (int i = 11; i < 26; i++) {
            __u8 ch = p[i];
            if (ch >= '0' && ch <= '9' && oct < 0xFF)
                oct = oct * 10 + (ch - '0');
            else if (ch == '.' && dots < 3) {
                ip = (ip << 8) | (oct & 0xFF); oct = 0; dots++;
            } else if (ch == ' ' && dots == 3) {
                out->addr[0] = (ip << 8) | (oct & 0xFF);
                return 1;
            } else
                return 0;
        }
    }
    return 0;
}


/*
 * direction: 0 = download (egress, пакет ИДЁТ к пользователю  → ключ по daddr)
 *            1 = upload   (ingress, пакет ИДЁТ от пользователя → ключ по saddr)
 */
static __always_inline int process_packet(struct __sk_buff *skb,
                                          __u32 direction,
                                          void *user_map)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    /* Трафик ноды нередко приходит внутри IPIP-туннеля: хостер отдаёт белый
     * IP через туннель, и на наружном интерфейсе каждый пакет обёрнут лишним
     * заголовком с protocol 4 (IPv4-in-IPv4) или 41 (IPv6 внутри IPv4).
     * Наружные адреса — это концы туннеля, а не клиенты, поэтому заголовок
     * разворачивается на один уровень: иначе вместо TCP/UDP шейпер видит
     * протокол туннеля, и весь трафик уходит мимо учёта и лимита.
     * Границы внутреннего заголовка проверяются в ветках ниже. */
    void *l3 = (void *)(eth + 1);
    __u16 eth_type = eth->h_proto;
    if (eth_type == bpf_htons(ETH_P_IP)) {
        struct iphdr *outer = l3;
        if ((void *)(outer + 1) > data_end)
            return TC_ACT_OK;
        if (outer->ihl >= 5 &&
            (outer->protocol == IPPROTO_IPIP ||
             outer->protocol == IPPROTO_IPV6)) {
            l3 += (__u32)outer->ihl * 4;
            if (outer->protocol == IPPROTO_IPV6)
                eth_type = bpf_htons(ETH_P_IPV6);
        }
    }

    struct ip_key key = {0};
    __u16 sport = 0, dport = 0;
    __u8  proto = 0;
    void *l4 = 0;
    /* Порты не удалось прочитать: не первый фрагмент или незнакомый L4.
     * Такой пакет всё равно принадлежит клиенту, поэтому шейпим его, если
     * включено правило «все порты», и пропускаем, если правило по портам. */
    __u32 no_ports = 0;

    if (eth_type == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = l3;
        if ((void *)(ip + 1) > data_end)
            return TC_ACT_OK;
        if (ip->ihl < 5)
            return TC_ACT_OK;

        key.addr[0] = (direction == 0) ? ip->daddr : ip->saddr;
        proto = ip->protocol;
        l4 = (void *)ip + (ip->ihl * 4);

        /* Не первый фрагмент: на месте заголовка L4 лежат данные. Раньше эти
         * байты читались как порты — и полезная нагрузка иногда случайно
         * совпадала с 443, а иногда нет. Смещение фрагмента — младшие 13 бит
         * frag_off; старшие три это флаги, их отбрасываем. */
        if (ip->frag_off & bpf_htons(0x1FFF))
            no_ports = 1;

    } else if (eth_type == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = l3;
        if ((void *)(ip6 + 1) > data_end)
            return TC_ACT_OK;

        if (direction == 0)
            __builtin_memcpy(key.addr, ip6->daddr.in6_u.u6_addr32, 16);
        else
            __builtin_memcpy(key.addr, ip6->saddr.in6_u.u6_addr32, 16);

        proto = ip6->nexthdr;
        l4 = (void *)(ip6 + 1);

        /* Цепочка заголовков расширения. Без неё пакет с любым hop-by-hop
         * впереди выглядел бы как «протокол не TCP и не UDP» и уходил мимо
         * шейпера — клиенту достаточно добавить один пустой заголовок, чтобы
         * получить безлимит на отдачу. Глубина ограничена: верификатору нужен
         * конечный цикл, а больше двух-трёх заголовков в жизни не встречается. */
#pragma unroll
        for (int i = 0; i < 3; i++) {
            if (proto == IPPROTO_TCP || proto == IPPROTO_UDP)
                break;
            if (proto == IPPROTO_FRAGMENT) {
                /* Заголовок фрагмента: 8 байт, дальше либо первый фрагмент
                 * с портами, либо продолжение без них. */
                struct frag_hdr {
                    __u8  nexthdr;
                    __u8  reserved;
                    __be16 frag_off;
                    __be32 identification;
                } *fh = l4;
                if ((void *)(fh + 1) > data_end)
                    return TC_ACT_OK;
                if (fh->frag_off & bpf_htons(0xFFF8))
                    no_ports = 1;
                proto = fh->nexthdr;
                l4 = (void *)(fh + 1);
            } else if (proto == IPPROTO_HOPOPTS || proto == IPPROTO_ROUTING ||
                       proto == IPPROTO_DSTOPTS) {
                struct ext_hdr {
                    __u8 nexthdr;
                    __u8 hdrlen;    /* длина в восьмёрках байт, не считая первой */
                } *eh = l4;
                if ((void *)(eh + 1) > data_end)
                    return TC_ACT_OK;
                proto = eh->nexthdr;
                l4 = (void *)l4 + ((__u32)(eh->hdrlen + 1) << 3);
            } else {
                break;
            }
        }
    } else {
        return TC_ACT_OK;   /* ARP, VLAN и прочее — не трогаем */
    }

    /* ── Скорость. Ноль = ограничение выключено ── */
    __u32 zero = 0;
    struct config *conf = bpf_map_lookup_elem(&config_map, &zero);
    if (!conf || conf->bytes_per_sec == 0)
        return TC_ACT_OK;

    /* ── Порты ── */
    if (no_ports) {
        /* нечего читать, решение примет проверка правила «все порты» */
    } else if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        sport = bpf_ntohs(tcp->source);
        dport = bpf_ntohs(tcp->dest);
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        sport = bpf_ntohs(udp->source);
        dport = bpf_ntohs(udp->dest);
    } else {
        return TC_ACT_OK;   /* ICMP и прочее не шейпим */
    }

    /* Матчим строго по направлению, а не «sport или dport»:
     *   download (egress к клиенту)  : порт сервера = sport
     *   upload   (ingress от клиента): порт сервера = dport
     *
     * Иначе под правило «443» попал бы ещё и исходящий трафик самой ноды
     * к чужим сайтам на 443 (там dport=443) — он шейпился бы второй раз
     * и учитывался под IP этого сайта.
     */
    __u32 key_port = (direction == 0) ? sport : dport;
    if (no_ports || !bpf_map_lookup_elem(&port_map, &key_port)) {
        if (!bpf_map_lookup_elem(&port_map, &zero))  /* порт 0 = все порты */
            return TC_ACT_OK;
    }

    /* ── PROXY protocol (клиенты за CDN/релеем) ──
     * CDN терминирует TCP клиента и открывает к ноде своё соединение:
     * на уровне пакетов отправитель — адрес релея, и все клиенты узла
     * делили бы один лимит. Настоящий адрес клиента приходит только в
     * заголовке PROXY protocol — первых байтах потока; их же читает
     * Xray с acceptProxyProtocol. Заголовок парсится один раз на
     * сегменте, который его принёс, пара «IP:порт релея» запоминается,
     * и все пакеты соединения — в обе стороны — шейпятся по адресу
     * клиента из заголовка. Прямым клиентам без заголовка это не
     * мешает: сигнатура не совпадает — ключ берётся из IP-заголовка,
     * как раньше. Ничего настраивать не нужно. */
    if (proto == IPPROTO_TCP && !no_ports) {
        struct pp_key ck = {0};
        __builtin_memcpy(ck.addr, key.addr, sizeof(ck.addr));
        ck.port = (direction == 0) ? dport : sport;

        if (direction == 1) {
            /* Upload: если записи нет, сегмент мог принести заголовок. */
            struct ip_key *client = bpf_map_lookup_elem(&pp_conn_map, &ck);
            if (client) {
                __builtin_memcpy(key.addr, client->addr, sizeof(key.addr));
            } else {
                struct tcphdr *tcp = l4;
                __u8 doff = ((__u8 *)tcp)[12] >> 4;
                __u8 *pl = (__u8 *)tcp + ((__u32)doff << 2);
                struct ip_key real = {0};
                if (parse_pp(pl, data_end, &real)) {
                    bpf_map_update_elem(&pp_conn_map, &ck, &real, BPF_ANY);
                    __builtin_memcpy(key.addr, real.addr, sizeof(key.addr));
                }
            }
        } else {
            /* Download: отдача идёт к релею — ключ по клиенту. */
            struct ip_key *client = bpf_map_lookup_elem(&pp_conn_map, &ck);
            if (client)
                __builtin_memcpy(key.addr, client->addr, sizeof(key.addr));
        }

        /* Соединение закрылось — запись не нужна: релей может отдать
         * тот же порт другому клиенту. FIN/RST есть в обоих
         * направлениях, порядок не важен. */
        if (((__u8 *)l4)[13] & (0x01 | 0x04))
            bpf_map_delete_elem(&pp_conn_map, &ck);
    }

    __u64 now = bpf_ktime_get_ns();
    __u32 len = skb->len;

    struct user_state *st = bpf_map_lookup_elem(user_map, &key);
    if (!st) {
        struct user_state fresh = {
            .last_departure_ns = now,
            .last_seen_ns      = now,
            .total_bytes       = len,
            .packets           = 1,
        };
        bpf_map_update_elem(user_map, &key, &fresh, BPF_ANY);
        return TC_ACT_OK;   /* первый пакет пропускаем без задержки */
    }

    __sync_fetch_and_add(&st->total_bytes, len);
    __sync_fetch_and_add(&st->packets, 1);
    st->last_seen_ns = now;

    /* ── Белый список ──
     * Проверяется здесь, а не в начале: счётчики адреса должны вестись в
     * любом случае. Раньше проверка стояла до учёта, и адрес из белого
     * списка исчезал отовсюду — из монитора, статистики и метрик. Понять,
     * сколько канала он съедает, было нельзя вообще никак, хотя съедать он
     * может сколько угодно: лимит к нему не применяется.
     *
     * Теперь считаем всех, а ограничиваем не всех.
     */
    if (bpf_map_lookup_elem(&whitelist_map, &key))
        return TC_ACT_OK;

    /* Персональный штраф важнее общего лимита. Просроченные записи вычищает
     * сторож; здесь просто игнорируем их по времени. */
    __u64 rate = conf->bytes_per_sec;
    struct penalty *pen = bpf_map_lookup_elem(&penalty_map, &key);
    if (pen && pen->rate_bytes_per_sec > 0 && now < pen->until_ns)
        rate = pen->rate_bytes_per_sec;

    /* Значение перечитано из карты, а не то, что проверяли в начале: между
     * проверкой и этой строкой лимит могли снять из userspace. Деление на
     * ноль в BPF даёт ноль, а не панику, но пакет тогда уехал бы с нулевой
     * задержкой мимо всякого учёта — лучше честно пропустить. */
    if (rate == 0)
        return TC_ACT_OK;

    __u64 delay_ns  = ((__u64)len * 1000000000ULL) / rate;
    __u64 departure = st->last_departure_ns;
    if (now > departure)
        departure = now;

    if (direction == 0) {
        /* Download: сдвигаем время отправки, fq придержит пакет. */
        departure += delay_ns;
        if (departure - now > EDT_HORIZON_NS)
            return TC_ACT_SHOT;
        st->last_departure_ns = departure;
        skb->tstamp = departure;
    } else {
        /* Upload: ведро на 200 мс, переполнилось — дроп. */
        if (departure - now > UL_BUCKET_NS)
            return TC_ACT_SHOT;
        st->last_departure_ns = departure + delay_ns;
    }

    return TC_ACT_OK;
}

SEC("classifier/down")
int shaper_down(struct __sk_buff *skb)
{
    return process_packet(skb, 0, &user_state_map_down);
}

SEC("classifier/up")
int shaper_up(struct __sk_buff *skb)
{
    return process_packet(skb, 1, &user_state_map_up);
}

char _license[] SEC("license") = "GPL";
