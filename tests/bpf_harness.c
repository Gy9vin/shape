#define _GNU_SOURCE
/*
 * Стенд для shaper.bpf.c: тот же исходник собирается обычным gcc, карты
 * подменяются простой таблицей в памяти. Так можно прогнать через реальный
 * код разбора пакеты, которых на живой ноде не дождёшься — фрагменты,
 * заголовки расширения IPv6, обрезанные заголовки.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#define _GNU_SOURCE
#include <sys/mman.h>

/* ── заглушки хелперов ── */
static unsigned long long fake_now = 1000000000ULL;
void *bpf_map_lookup_elem(void *map, const void *key);
long  bpf_map_update_elem(void *map, const void *key, const void *value,
                          unsigned long long flags);
long  bpf_map_delete_elem(void *map, const void *key);
static unsigned long long bpf_ktime_get_ns_impl(void) { return fake_now; }
#define bpf_ktime_get_ns bpf_ktime_get_ns_impl

/* bpf_skb_pull_data: на живом ядре подтягивает начало нагрузки из страниц
 * (frags) в линейную часть, то есть сдвигает data_end. Здесь «линейная
 * часть» задаётся linear_len: пакет целиком лежит в буфере, а data_end
 * обрезается — так выглядит loopback и GSO/GRO, где нагрузка в страницах. */
struct __sk_buff;
long bpf_skb_pull_data(struct __sk_buff *skb, unsigned int len);
static int pull_calls = 0;      /* сколько раз программа просила подтянуть */
static int pull_fail = 0;       /* 1 = хелпер возвращает ошибку */

#define SEC(NAME)
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_ntohs(x) __builtin_bswap16(x)
#define bpf_htonl(x) __builtin_bswap32(x)
#define bpf_ntohl(x) __builtin_bswap32(x)
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#include "../bpf/shaper.bpf.c"

/* ── карта в памяти ── */
struct ent { void *map; unsigned char key[32]; unsigned char val[64]; int used; };
static struct ent table[4096];
static int keysize(void *m) {
    if (m == (void *)&config_map || m == (void *)&port_map) return 4;
    if (m == (void *)&pp_conn_map) return sizeof(struct pp_key);
    if (m == (void *)&mobile_lpm) return sizeof(struct mobile_key);
    if (m == (void *)&port_stat_map_down || m == (void *)&port_stat_map_up)
        return sizeof(struct port_stat_key);
    return 16;
}
/* Размер значения: user_state (48 байт) больше прежних 32, поэтому копировать
 * «с запасом» уже нельзя — обрезалась бы хвостовая часть счётчиков. */
static int valsize(void *m) {
    if (m == (void *)&config_map) return sizeof(struct config);
    if (m == (void *)&user_state_map_down || m == (void *)&user_state_map_up)
        return sizeof(struct user_state);
    if (m == (void *)&penalty_map) return sizeof(struct penalty);
    if (m == (void *)&port_stat_map_down || m == (void *)&port_stat_map_up)
        return sizeof(struct port_stat);
    if (m == (void *)&pp_conn_map) return sizeof(struct ip_key);
    return 1;
}
/* LPM-дерево: линейный поиск самого длинного префикса. prefixlen считается
 * от начала данных, то есть от слова family — как в ядре. */
static int lpm_bits_match(const unsigned char *a, const unsigned char *b, unsigned bits) {
    unsigned full = bits / 8, rem = bits % 8;
    if (memcmp(a, b, full)) return 0;
    if (rem && ((a[full] ^ b[full]) & (0xFF << (8 - rem)) & 0xFF)) return 0;
    return 1;
}
void *bpf_map_lookup_elem(void *map, const void *key) {
    int ks = keysize(map);
    if (map == (void *)&mobile_lpm) {
        const struct mobile_key *q = key;
        void *best = NULL; long best_pl = -1;
        for (int i = 0; i < 4096; i++) {
            if (!table[i].used || table[i].map != map) continue;
            const struct mobile_key *e = (const struct mobile_key *)table[i].key;
            if (e->prefixlen > q->prefixlen || (long)e->prefixlen <= best_pl) continue;
            if (lpm_bits_match((const unsigned char *)&e->family,
                               (const unsigned char *)&q->family, e->prefixlen)) {
                best = table[i].val; best_pl = e->prefixlen;
            }
        }
        return best;
    }
    for (int i = 0; i < 4096; i++)
        if (table[i].used && table[i].map == map && !memcmp(table[i].key, key, ks))
            return table[i].val;
    return NULL;
}
long bpf_map_update_elem(void *map, const void *key, const void *value,
                         unsigned long long flags) {
    (void)flags;
    int ks = keysize(map);
    for (int i = 0; i < 4096; i++)
        if (table[i].used && table[i].map == map && !memcmp(table[i].key, key, ks)) {
            memcpy(table[i].val, value, valsize(map)); return 0;
        }
    for (int i = 0; i < 4096; i++)
        if (!table[i].used) {
            table[i].used = 1; table[i].map = map;
            memcpy(table[i].key, key, ks);
            memset(table[i].val, 0, sizeof(table[i].val));
            memcpy(table[i].val, value, valsize(map));
            return 0;
        }
    return -1;
}
long bpf_map_delete_elem(void *map, const void *key) {
    int ks = keysize(map);
    for (int i = 0; i < 4096; i++)
        if (table[i].used && table[i].map == map && !memcmp(table[i].key, key, ks)) {
            table[i].used = 0;
            return 0;
        }
    return -1;
}
static void map_put(void *m, const void *k, const void *v) {
    bpf_map_update_elem(m, k, v, 0);
}

/* ── сборка пакетов ── */
/* data и data_end в struct __sk_buff — 32-битные: в ядре их подменяет
 * верификатор, а в обычной программе указатель просто обрежется. Поэтому
 * буфер кладём в младшие 4 ГБ адресного пространства. */
static unsigned char *pkt;
static struct __sk_buff skb;
static void pkt_alloc(void) {
    /* MAP_32BIT есть только на x86_64, поэтому просто просим конкретный
     * низкий адрес — он свободен в любом обычном процессе. */
    pkt = mmap((void *)0x20000000UL, 4096, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (pkt == MAP_FAILED || (unsigned long)pkt >> 32) {
        perror("mmap"); exit(2);
    }
}

/* 0 = пакет линейный целиком; иначе столько байт от начала кадра. */
static int linear_len = 0;

long bpf_skb_pull_data(struct __sk_buff *s, unsigned int want) {
    pull_calls++;
    if (pull_fail)
        return -14;
    if (want > s->len)
        return -12;
    unsigned long have = s->data_end - s->data;
    if (want > have)
        s->data_end = s->data + want;
    return 0;
}

static int run_pkt(int len, int direction) {
    skb.data = (unsigned long)pkt;
    skb.data_end = (unsigned long)pkt + (linear_len && linear_len < len ? linear_len : len);
    skb.len = len;
    skb.tstamp = 0;
    return direction == 0 ? shaper_down(&skb) : shaper_up(&skb);
}

/* IPv4 + TCP/UDP. frag_off — сырое значение поля (в хостовом порядке). */
static int build_v4(unsigned proto, unsigned sport, unsigned dport,
                    unsigned frag_off, int payload, unsigned dst, unsigned src)
{
    memset(pkt, 0, 2048);
    pkt[12] = 0x08; pkt[13] = 0x00;                 /* ethertype IPv4 */
    struct iphdr *ip = (struct iphdr *)(pkt + 14);
    ip->version = 4; ip->ihl = 5; ip->protocol = proto;
    ip->frag_off = __builtin_bswap16(frag_off);
    ip->daddr = dst; ip->saddr = src;
    /* tot_len и doff, как у настоящего пакета: по ним программа отличает
     * сегмент с данными от чистого ACK/SYN. */
    ip->tot_len = __builtin_bswap16(20 + (proto == IPPROTO_TCP ? 20 : 8) + payload);
    unsigned char *l4 = pkt + 14 + 20;
    if (proto == IPPROTO_TCP)
        l4[12] = 5 << 4;
    if (!(frag_off & 0x1FFF)) {
        l4[0] = sport >> 8; l4[1] = sport & 0xFF;
        l4[2] = dport >> 8; l4[3] = dport & 0xFF;
    } else {
        /* «полезная нагрузка», случайно похожая на порт 443 */
        l4[0] = 0x01; l4[1] = 0xBB; l4[2] = 0x01; l4[3] = 0xBB;
    }
    return 14 + 20 + (proto == IPPROTO_TCP ? 20 : 8) + payload;
}

/* IPv6 с цепочкой заголовков расширения перед TCP */
static int build_v6_ext(int n_ext, unsigned sport, unsigned dport, int payload)
{
    memset(pkt, 0, 2048);
    pkt[12] = 0x86; pkt[13] = 0xDD;
    struct ipv6hdr *ip6 = (struct ipv6hdr *)(pkt + 14);
    ip6->version = 6;
    ip6->daddr.in6_u.u6_addr32[0] = 0x0120;
    ip6->daddr.in6_u.u6_addr32[3] = 0x99;
    ip6->saddr.in6_u.u6_addr32[0] = 0x0120;
    ip6->saddr.in6_u.u6_addr32[3] = 0x99;
    unsigned char *p = pkt + 14 + 40;
    ip6->nexthdr = n_ext ? IPPROTO_HOPOPTS : IPPROTO_TCP;
    for (int i = 0; i < n_ext; i++) {
        p[0] = (i == n_ext - 1) ? IPPROTO_TCP : IPPROTO_DSTOPTS;
        p[1] = 0;               /* hdrlen 0 => 8 байт */
        p += 8;
    }
    p[0] = sport >> 8; p[1] = sport & 0xFF;
    p[2] = dport >> 8; p[3] = dport & 0xFF;
    p[12] = 5 << 4;
    ip6->payload_len = __builtin_bswap16((int)(p - (pkt + 14 + 40)) + 20 + payload);
    return (int)(p - pkt) + 20 + payload;
}

/* IPv6 с произвольным адресом клиента (daddr) */
static int build_v6_addr(const unsigned char a[16], unsigned sport,
                         unsigned dport, int payload)
{
    memset(pkt, 0, 2048);
    pkt[12] = 0x86; pkt[13] = 0xDD;
    struct ipv6hdr *ip6 = (struct ipv6hdr *)(pkt + 14);
    ip6->version = 6;
    memcpy(&ip6->daddr, a, 16);
    memcpy(&ip6->saddr, a, 16);
    ip6->nexthdr = IPPROTO_TCP;
    unsigned char *p = pkt + 14 + 40;
    p[0] = sport >> 8; p[1] = sport & 0xFF;
    p[2] = dport >> 8; p[3] = dport & 0xFF;
    p[12] = 5 << 4;
    ip6->payload_len = __builtin_bswap16(20 + payload);
    return 14 + 40 + 20 + payload;
}

/* IPIP: наружный IPv4 с protocol 4, внутри обычный IPv4+L4.
 * out_dst/out_src — концы туннеля, dst/src — настоящие адреса. */
static int build_ipip_v4(unsigned inner_proto, unsigned sport, unsigned dport,
                         int payload, unsigned dst, unsigned src,
                         unsigned out_dst, unsigned out_src)
{
    memset(pkt, 0, 2048);
    pkt[12] = 0x08; pkt[13] = 0x00;                 /* ethertype IPv4 */
    struct iphdr *out = (struct iphdr *)(pkt + 14);
    out->version = 4; out->ihl = 5; out->protocol = IPPROTO_IPIP;
    out->daddr = out_dst; out->saddr = out_src;
    struct iphdr *in = (struct iphdr *)(pkt + 14 + 20);
    in->version = 4; in->ihl = 5; in->protocol = inner_proto;
    in->daddr = dst; in->saddr = src;
    in->tot_len = __builtin_bswap16(20 + (inner_proto == IPPROTO_TCP ? 20 : 8) + payload);
    out->tot_len = __builtin_bswap16(20 + 20 + (inner_proto == IPPROTO_TCP ? 20 : 8) + payload);
    unsigned char *l4 = pkt + 14 + 20 + 20;
    if (inner_proto == IPPROTO_TCP)
        l4[12] = 5 << 4;
    l4[0] = sport >> 8; l4[1] = sport & 0xFF;
    l4[2] = dport >> 8; l4[3] = dport & 0xFF;
    return 14 + 20 + 20 + (inner_proto == IPPROTO_TCP ? 20 : 8) + payload;
}

/* IPv6 внутри IPv4: protocol 41, TCP сразу за заголовком IPv6 */
static int build_ipip_v6(unsigned sport, unsigned dport, int payload)
{
    memset(pkt, 0, 2048);
    pkt[12] = 0x08; pkt[13] = 0x00;
    struct iphdr *out = (struct iphdr *)(pkt + 14);
    out->version = 4; out->ihl = 5; out->protocol = IPPROTO_IPV6;
    struct ipv6hdr *in = (struct ipv6hdr *)(pkt + 14 + 20);
    in->version = 6;
    in->nexthdr = IPPROTO_TCP;
    in->saddr.in6_u.u6_addr32[0] = 0x019A;
    in->saddr.in6_u.u6_addr32[3] = 0x77;
    unsigned char *l4 = pkt + 14 + 20 + 40;
    l4[0] = sport >> 8; l4[1] = sport & 0xFF;
    l4[2] = dport >> 8; l4[3] = dport & 0xFF;
    l4[12] = 5 << 4;
    in->payload_len = __builtin_bswap16(20 + payload);
    out->tot_len = __builtin_bswap16(20 + 40 + 20 + payload);
    return 14 + 20 + 40 + 20 + payload;
}

/* TCP-пакет с настоящими флагами и точной полезной нагрузкой — для
 * проверки PROXY protocol: у сборщиков выше поле doff равно нулю,
 * поэтому полезная нагрузка из них не читается. */
static int build_tcp_raw(unsigned dst, unsigned src, unsigned sport,
                         unsigned dport, unsigned char flags,
                         const void *payload, int payload_len)
{
    memset(pkt, 0, 2048);
    pkt[12] = 0x08; pkt[13] = 0x00;
    struct iphdr *ip = (struct iphdr *)(pkt + 14);
    ip->version = 4; ip->ihl = 5; ip->protocol = IPPROTO_TCP;
    ip->daddr = dst; ip->saddr = src;
    ip->tot_len = __builtin_bswap16(20 + 20 + (payload_len > 0 ? payload_len : 0));
    unsigned char *t = pkt + 14 + 20;
    t[0] = sport >> 8; t[1] = sport & 0xFF;
    t[2] = dport >> 8; t[3] = dport & 0xFF;
    t[12] = 5 << 4;                    /* doff = 5 */
    t[13] = flags;
    if (payload_len > 0)
        memcpy(t + 20, payload, payload_len);
    return 14 + 20 + 20 + payload_len;
}

/* Как build_tcp_raw, но внутри IPIP-туннеля (protocol 4). */
static int build_ipip_tcp_raw(unsigned dst, unsigned src, unsigned sport,
                              unsigned dport, unsigned char flags,
                              const void *payload, int payload_len)
{
    memset(pkt, 0, 2048);
    pkt[12] = 0x08; pkt[13] = 0x00;
    struct iphdr *out = (struct iphdr *)(pkt + 14);
    out->version = 4; out->ihl = 5; out->protocol = IPPROTO_IPIP;
    out->daddr = 0x0A0000C8; out->saddr = 0x0A0000C9;
    struct iphdr *in = (struct iphdr *)(pkt + 14 + 20);
    in->version = 4; in->ihl = 5; in->protocol = IPPROTO_TCP;
    in->daddr = dst; in->saddr = src;
    in->tot_len = __builtin_bswap16(20 + 20 + (payload_len > 0 ? payload_len : 0));
    out->tot_len = __builtin_bswap16(20 + 20 + 20 + (payload_len > 0 ? payload_len : 0));
    unsigned char *t = pkt + 14 + 20 + 20;
    t[0] = sport >> 8; t[1] = sport & 0xFF;
    t[2] = dport >> 8; t[3] = dport & 0xFF;
    t[12] = 5 << 4;
    t[13] = flags;
    if (payload_len > 0)
        memcpy(t + 20, payload, payload_len);
    return 14 + 20 + 20 + 20 + payload_len;
}

/* ── сборщики заголовков PROXY protocol ── */
static const unsigned char ppsig[12] = {
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D,
    0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A
};

/* v2, TCP4: 16 байт головы + адреса и порты */
static int ppv2_tcp4(void *buf, unsigned client)
{
    unsigned char *p = buf;
    memcpy(p, ppsig, 12);
    p[12] = 0x21;                     /* версия 2, команда PROXY */
    p[13] = 0x11;                     /* семейство TCP4 */
    p[14] = 0x00; p[15] = 0x0C;       /* длина адресной части = 12 */
    p[16] = client >> 24; p[17] = (client >> 16) & 0xFF;
    p[18] = (client >> 8) & 0xFF;  p[19] = client & 0xFF;
    return 28;
}

/* v2, TCP6: клиент 2001:db8::99 */
static int ppv2_tcp6(void *buf)
{
    unsigned char *p = buf;
    memcpy(p, ppsig, 12);
    p[12] = 0x21;
    p[13] = 0x21;                     /* семейство TCP6 */
    p[14] = 0x00; p[15] = 0x24;       /* длина = 36 */
    memset(p + 16, 0, 16);            /* адрес клиента 2001:db8::99 */
    p[16] = 0x20; p[17] = 0x01;
    p[26] = 0x0D; p[27] = 0xB8;
    p[31] = 0x99;
    return 52;
}

/* v1: текстовая строка «PROXY TCP4 a.b.c.d …» */
static int ppv1_tcp4(void *buf, unsigned client)
{
    return sprintf((char *)buf, "PROXY TCP4 %u.%u.%u.%u 10.0.0.9 1111 443\r\n",
                   (client >> 24) & 0xFF, (client >> 16) & 0xFF,
                   (client >> 8) & 0xFF, client & 0xFF);
}

static int ok = 0, fail = 0;
static void check(const char *name, int cond) {
    if (cond) { ok++; printf("  \033[32m✓\033[0m %s\n", name); }
    else      { fail++; printf("  \033[31m✗ %s\033[0m\n", name); }
}

int main(void)
{
    pkt_alloc();
    struct config cfg = { .bytes_per_sec = 10 * 125000 };   /* 10 Мбит/с */
    unsigned zero = 0, p443 = 443;
    unsigned char one = 1;
    map_put(&config_map, &zero, &cfg);
    map_put(&port_map, &p443, &one);

    unsigned CLIENT = 0x0100007F, SERVER = 0x0200007F;
    int len;

    printf("\n\033[1m1. Базовый разбор\033[0m\n");
    len = build_v4(IPPROTO_TCP, 443, 51000, 0, 1400, CLIENT, SERVER);
    check("download на порт 443 принят к учёту", run_pkt(len, 0) == TC_ACT_OK);
    struct ip_key k = {0}; k.addr[0] = CLIENT;
    check("состояние клиента заведено", bpf_map_lookup_elem(&user_state_map_down, &k) != NULL);

    len = build_v4(IPPROTO_TCP, 51000, 8080, 0, 1400, CLIENT, SERVER);
    struct ip_key k2 = {0}; k2.addr[0] = 0x0300007F;
    len = build_v4(IPPROTO_TCP, 51000, 8080, 0, 1400, 0x0300007F, SERVER);
    run_pkt(len, 0);
    check("чужой порт не учитывается",
          bpf_map_lookup_elem(&user_state_map_down, &k2) == NULL);

    printf("\n\033[1m2. Задержка растёт пропорционально размеру\033[0m\n");
    unsigned long long t0, t1;
    fake_now = 2000000000ULL;
    len = build_v4(IPPROTO_TCP, 443, 51000, 0, 1400, CLIENT, SERVER);
    run_pkt(len, 0); t0 = skb.tstamp;
    run_pkt(len, 0); t1 = skb.tstamp;
    /* 1454 байта при 1.25 МБ/с ≈ 1.16 мс на пакет */
    check("шаг между отправками близок к 1.16 мс",
          (t1 - t0) > 1000000 && (t1 - t0) < 1400000);
    check("время отправки не в прошлом", t1 >= fake_now);

    printf("\n\033[1m3. Фрагменты IPv4 (была дыра: порты читались из данных)\033[0m\n");
    struct ip_key kf = {0}; kf.addr[0] = 0x0A00007F;
    len = build_v4(IPPROTO_TCP, 0, 0, 0x00B9, 1400, 0x0A00007F, SERVER);  /* offset != 0 */
    int r = run_pkt(len, 0);
    check("не первый фрагмент не считается трафиком порта 443",
          bpf_map_lookup_elem(&user_state_map_down, &kf) == NULL && r == TC_ACT_OK);

    /* с правилом «все порты» тот же фрагмент обязан шейпиться */
    map_put(&port_map, &zero, &one);
    len = build_v4(IPPROTO_TCP, 0, 0, 0x00B9, 1400, 0x0A00007F, SERVER);
    run_pkt(len, 0);
    check("при правиле «все порты» фрагмент шейпится",
          bpf_map_lookup_elem(&user_state_map_down, &kf) != NULL);
    /* убираем правило «все порты» обратно */
    for (int i = 0; i < 4096; i++)
        if (table[i].used && table[i].map == (void *)&port_map &&
            *(unsigned *)table[i].key == 0) table[i].used = 0;

    printf("\n\033[1m4. Заголовки расширения IPv6 (была дыра: пакет уходил мимо)\033[0m\n");
    struct ip_key k6 = {0}; k6.addr[0] = 0x0120; k6.addr[3] = 0x99;
    for (int n = 0; n <= 2; n++) {
        for (int i = 0; i < 4096; i++)
            if (table[i].used && table[i].map == (void *)&user_state_map_up)
                table[i].used = 0;
        len = build_v6_ext(n, 51000, 443, 1200);
        run_pkt(len, 1);
        char msg[80];
        snprintf(msg, sizeof msg, "upload с %d заголовками расширения учтён", n);
        check(msg, bpf_map_lookup_elem(&user_state_map_up, &k6) != NULL);
    }

    printf("\n\033[1m5. Обрезанные и битые пакеты\033[0m\n");
    check("пустой кадр не роняет разбор", run_pkt(4, 0) == TC_ACT_OK);
    check("только ethernet-заголовок", run_pkt(14, 0) == TC_ACT_OK);
    len = build_v4(IPPROTO_TCP, 443, 51000, 0, 0, CLIENT, SERVER);
    check("IPv4 без места под TCP", run_pkt(14 + 20 + 4, 0) == TC_ACT_OK);
    len = build_v6_ext(2, 51000, 443, 0);
    check("IPv6 с оборванной цепочкой", run_pkt(14 + 40 + 8, 1) == TC_ACT_OK);
    struct iphdr *ip = (struct iphdr *)(pkt + 14);
    len = build_v4(IPPROTO_TCP, 443, 51000, 0, 100, CLIENT, SERVER);
    ip->ihl = 3;   /* невозможная длина заголовка */
    check("IPv4 с ihl < 5 отброшен из разбора", run_pkt(len, 0) == TC_ACT_OK);
    len = build_v4(IPPROTO_ICMP, 0, 0, 0, 100, CLIENT, SERVER);
    check("ICMP не шейпится", run_pkt(len, 0) == TC_ACT_OK);

    printf("\n\033[1m6. Белый список и штраф\033[0m\n");
    struct ip_key kw = {0}; kw.addr[0] = 0x0B00007F;
    map_put(&whitelist_map, &kw, &one);
    len = build_v4(IPPROTO_TCP, 443, 51000, 0, 1400, 0x0B00007F, SERVER);
    run_pkt(len, 0);                       /* первый пакет заводит запись */
    check("адрес из белого списка попадает в учёт",
          bpf_map_lookup_elem(&user_state_map_down, &kw) != NULL);
    struct user_state *wst = bpf_map_lookup_elem(&user_state_map_down, &kw);
    unsigned long long before = wst->total_bytes;
    skb.tstamp = 0;
    run_pkt(len, 0);
    check("его байты считаются", wst->total_bytes > before);
    check("но время отправки ему не назначается", skb.tstamp == 0);
    len = build_v4(IPPROTO_TCP, 51000, 443, 0, 1400, SERVER, 0x0B00007F);
    run_pkt(len, 1);
    struct user_state *wup = bpf_map_lookup_elem(&user_state_map_up, &kw);
    check("отдача тоже считается", wup != NULL && wup->total_bytes > 0);

    struct penalty pen = { .rate_bytes_per_sec = 1 * 125000,
                           .until_ns = fake_now + 60000000000ULL };
    struct ip_key kp = {0}; kp.addr[0] = 0x0C00007F;
    map_put(&penalty_map, &kp, &pen);
    len = build_v4(IPPROTO_TCP, 443, 51000, 0, 1400, 0x0C00007F, SERVER);
    run_pkt(len, 0);                       /* первый пакет заводит запись */
    run_pkt(len, 0); t0 = skb.tstamp;
    run_pkt(len, 0); t1 = skb.tstamp;
    check("штрафник тормозится в 10 раз сильнее",
          (t1 - t0) > 10000000 && (t1 - t0) < 14000000);

    pen.until_ns = fake_now - 1;           /* штраф истёк */
    map_put(&penalty_map, &kp, &pen);
    run_pkt(len, 0); t0 = skb.tstamp;
    run_pkt(len, 0); t1 = skb.tstamp;
    check("после истечения штрафа скорость общая",
          (t1 - t0) > 1000000 && (t1 - t0) < 1400000);

    printf("\n\033[1m7. Лимит снят на ходу\033[0m\n");
    struct config off = { .bytes_per_sec = 0 };
    map_put(&config_map, &zero, &off);
    len = build_v4(IPPROTO_TCP, 443, 51000, 0, 1400, CLIENT, SERVER);
    check("нулевой лимит пропускает без деления на ноль",
          run_pkt(len, 0) == TC_ACT_OK);

    /* Hysteria2 и вообще QUIC — это UDP/443, а не TCP. Ветка UDP в разборе
     * есть с самого начала, но до появления первой такой ноды её ничто не
     * проверяло: весь набор гонял только TCP. */
    printf("\n\033[1m8. UDP: QUIC на том же порту\033[0m\n");
    map_put(&config_map, &zero, &cfg);           /* вернуть лимит 10 Мбит/с */
    unsigned QCLIENT = 0x1100007F;
    struct ip_key ku = {0}; ku.addr[0] = QCLIENT;

    len = build_v4(IPPROTO_UDP, 443, 51000, 0, 1200, QCLIENT, SERVER);
    check("download по UDP/443 принят к учёту", run_pkt(len, 0) == TC_ACT_OK);
    struct user_state *su = bpf_map_lookup_elem(&user_state_map_down, &ku);
    check("состояние клиента QUIC заведено", su != NULL);
    check("байты посчитаны", su && su->total_bytes > 0);
    /* Первый пакет нового адреса пропускается без задержки намеренно —
     * задержку считаем со второго, как и для TCP. */
    check("первый пакет не задержан", skb.tstamp == 0);
    len = build_v4(IPPROTO_UDP, 443, 51000, 0, 1200, QCLIENT, SERVER);
    run_pkt(len, 0);
    check("со второго пакета отправка откладывается", skb.tstamp > 0);

    fake_now = 5000000000ULL;
    len = build_v4(IPPROTO_UDP, 443, 51000, 0, 1200, QCLIENT, SERVER);
    run_pkt(len, 0); t0 = skb.tstamp;
    run_pkt(len, 0); t1 = skb.tstamp;
    /* 1254 байта при 1.25 МБ/с ≈ 1.0 мс на пакет */
    check("шаг между UDP-пакетами соответствует лимиту",
          (t1 - t0) > 850000 && (t1 - t0) < 1200000);

    unsigned QUP = 0x1200007F;
    struct ip_key ku2 = {0}; ku2.addr[0] = QUP;
    len = build_v4(IPPROTO_UDP, 51000, 443, 0, 1200, SERVER, QUP);
    run_pkt(len, 1);
    check("upload по UDP/443 учтён по адресу отправителя",
          bpf_map_lookup_elem(&user_state_map_up, &ku2) != NULL);

    unsigned QOTHER = 0x1300007F;
    struct ip_key ku3 = {0}; ku3.addr[0] = QOTHER;
    len = build_v4(IPPROTO_UDP, 4444, 51000, 0, 1200, QOTHER, SERVER);
    run_pkt(len, 0);
    check("UDP на чужом порту не учитывается",
          bpf_map_lookup_elem(&user_state_map_down, &ku3) == NULL);

    /* Исходящий QUIC самой ноды к чужому сайту: dport=443 на egress.
     * Под правило «443» он попасть не должен — иначе трафик ноды шейпился
     * бы повторно и записывался на адрес чужого сайта. */
    unsigned SITE = 0x1400007F;
    struct ip_key ku4 = {0}; ku4.addr[0] = SITE;
    len = build_v4(IPPROTO_UDP, 51000, 443, 0, 1200, SITE, SERVER);
    run_pkt(len, 0);
    check("исходящий QUIC ноды под правило не попадает",
          bpf_map_lookup_elem(&user_state_map_down, &ku4) == NULL);

    /* Обрезанный UDP-заголовок: восьми байт нет. Должно быть решение
     * «пропустить», а не чтение за границей пакета. */
    unsigned TRUNC = 0x1500007F;
    len = build_v4(IPPROTO_UDP, 443, 51000, 0, 0, TRUNC, SERVER);
    check("обрезанный UDP-заголовок не роняет разбор",
          run_pkt(14 + 20 + 4, 0) == TC_ACT_OK);

    /* Белый список работает одинаково для обоих протоколов. */
    unsigned QWL = 0x1600007F;
    struct ip_key kwu = {0}; kwu.addr[0] = QWL;
    map_put(&whitelist_map, &kwu, &one);
    len = build_v4(IPPROTO_UDP, 443, 51000, 0, 1200, QWL, SERVER);
    run_pkt(len, 0);                       /* первый — заводит состояние */
    run_pkt(len, 0);                       /* второй — доходит до проверки */
    struct user_state *sw = bpf_map_lookup_elem(&user_state_map_down, &kwu);
    check("адрес из белого списка по UDP считается", sw != NULL);
    check("его байты растут", sw && sw->total_bytes > 1200);
    check("но задержка не применяется", skb.tstamp == 0);

    printf("\n\033[1m9. IPIP-туннель (хостер отдаёт белый IP через туннель)\033[0m\n");
    unsigned TUN_GW = 0x0D00007F, IC_DOWN = 0x1700007F, IC_UP = 0x1800007F;

    /* download: снаружи пакет SERVER->GW, внутри SERVER->клиент */
    len = build_ipip_v4(IPPROTO_TCP, 443, 51000, 1400,
                        IC_DOWN, SERVER, TUN_GW, SERVER);
    run_pkt(len, 0);
    struct ip_key ki = {0}; ki.addr[0] = IC_DOWN;
    check("IPIP download учтён по внутреннему адресу клиента",
          bpf_map_lookup_elem(&user_state_map_down, &ki) != NULL);
    struct ip_key ko = {0}; ko.addr[0] = TUN_GW;
    check("наружный адрес туннеля в карту не попадает",
          bpf_map_lookup_elem(&user_state_map_down, &ko) == NULL);

    /* upload: снаружи GW->SERVER, внутри клиент->SERVER:443 */
    len = build_ipip_v4(IPPROTO_TCP, 51000, 443, 100,
                        SERVER, IC_UP, SERVER, TUN_GW);
    run_pkt(len, 1);
    struct ip_key ki2 = {0}; ki2.addr[0] = IC_UP;
    check("IPIP upload учтён по внутреннему адресу клиента",
          bpf_map_lookup_elem(&user_state_map_up, &ki2) != NULL);

    fake_now = 6000000000ULL;
    len = build_ipip_v4(IPPROTO_TCP, 443, 51000, 1400,
                        IC_DOWN, SERVER, TUN_GW, SERVER);
    run_pkt(len, 0); t0 = skb.tstamp;
    run_pkt(len, 0); t1 = skb.tstamp;
    check("IPIP download тормозится как обычный пакет",
          (t1 - t0) > 1000000 && (t1 - t0) < 1400000);

    len = build_ipip_v4(IPPROTO_TCP, 443, 51000, 1400,
                        IC_DOWN, SERVER, TUN_GW, SERVER);
    check("обрезанный внутренний IPv4 не роняет разбор",
          run_pkt(14 + 20 + 10, 0) == TC_ACT_OK);

    struct ip_key k6t = {0}; k6t.addr[0] = 0x019A; k6t.addr[3] = 0x77;
    len = build_ipip_v6(51000, 443, 200);
    run_pkt(len, 1);
    check("IPv6 внутри туннеля (protocol 41) тоже учтён",
          bpf_map_lookup_elem(&user_state_map_up, &k6t) != NULL);

    printf("\n\033[1m10. PROXY protocol (клиенты за CDN/релеем)\033[0m\n");
    unsigned p9080 = 9080;
    map_put(&port_map, &p9080, &one);
    unsigned RELAY = 0x1B00007F, PPCLI = 0x1C00007F, PPCLI2 = 0x1D00007F;
    unsigned char pay[80];
    static unsigned char pay1400[1400];
    memset(pay1400, 0x41, sizeof pay1400);

    /* upload: первый сегмент соединения несёт заголовок v2 */
    int plen = ppv2_tcp4(pay, PPCLI);
    len = build_tcp_raw(SERVER, RELAY, 60001, 9080, 0x18, pay, plen);
    run_pkt(len, 1);
    struct ip_key kpc = {0}; kpc.addr[0] = __builtin_bswap32(PPCLI);
    struct ip_key kr = {0}; kr.addr[0] = RELAY;
    check("upload за CDN учтён по настоящему клиенту",
          bpf_map_lookup_elem(&user_state_map_up, &kpc) != NULL);
    struct pp_key ckk = {0};
    ckk.addr[0] = RELAY; ckk.port = 60001;
    check("соединение релея запомнено",
          bpf_map_lookup_elem(&pp_conn_map, &ckk) != NULL);
    check("адрес релея в учёт не попадает",
          bpf_map_lookup_elem(&user_state_map_up, &kr) == NULL);

    /* середина потока: заголовка нет, ключ берётся из карты */
    struct user_state *pcst = bpf_map_lookup_elem(&user_state_map_up, &kpc);
    unsigned long long pcb = pcst ? pcst->total_bytes : 0;
    len = build_tcp_raw(SERVER, RELAY, 60001, 9080, 0x18,
                        "\x17\x03\x03\x00\x10", 5);
    run_pkt(len, 1);
    pcst = bpf_map_lookup_elem(&user_state_map_up, &kpc);
    check("пакеты без заголовка сходятся к тому же клиенту",
          pcst != NULL && pcst->total_bytes > pcb);

    /* download: отдача идёт к релею, ключ — по клиенту */
    fake_now = 7000000000ULL;
    len = build_tcp_raw(RELAY, SERVER, 9080, 60001, 0x18, pay1400, 1400);
    run_pkt(len, 0);
    struct ip_key kpd = {0}; kpd.addr[0] = __builtin_bswap32(PPCLI);
    check("download за CDN учтён по настоящему клиенту",
          bpf_map_lookup_elem(&user_state_map_down, &kpd) != NULL);
    run_pkt(len, 0); t0 = skb.tstamp;
    run_pkt(len, 0); t1 = skb.tstamp;
    check("download за CDN тормозится как обычный пакет",
          (t1 - t0) > 1000000 && (t1 - t0) < 1400000);

    /* FIN: запись соединения больше не нужна */
    len = build_tcp_raw(SERVER, RELAY, 60001, 9080, 0x11, NULL, 0);
    run_pkt(len, 1);
    check("FIN удаляет соединение из карты",
          bpf_map_lookup_elem(&pp_conn_map, &ckk) == NULL);

    /* v2 с IPv6-клиентом */
    plen = ppv2_tcp6(pay);
    len = build_tcp_raw(SERVER, RELAY, 60002, 9080, 0x18, pay, plen);
    run_pkt(len, 1);
    struct ip_key k6pp = {0};
    k6pp.addr[0] = __builtin_bswap32(0x20010000UL); k6pp.addr[2] = __builtin_bswap32(0xDB8);
    k6pp.addr[3] = __builtin_bswap32(0x99);
    check("IPv6-клиент из заголовка v2 учтён",
          bpf_map_lookup_elem(&user_state_map_up, &k6pp) != NULL);

    /* v1 — текстовый */
    plen = ppv1_tcp4(pay, PPCLI2);
    len = build_tcp_raw(SERVER, RELAY, 60003, 9080, 0x18, pay, plen);
    run_pkt(len, 1);
    struct ip_key kpc2 = {0}; kpc2.addr[0] = __builtin_bswap32(PPCLI2);
    check("текстовый заголовок v1 тоже разобран",
          bpf_map_lookup_elem(&user_state_map_up, &kpc2) != NULL);

    /* без заголовка — прежнее поведение: ключ из IP-заголовка */
    len = build_tcp_raw(SERVER, RELAY, 60004, 9080, 0x18,
                        "\x16\x03\x01\x00\xAB", 5);
    run_pkt(len, 1);
    check("без заголовка трафик числится за релеем (как раньше)",
          bpf_map_lookup_elem(&user_state_map_up, &kr) != NULL);

    /* v2 команда LOCAL — «не проксировали», клиента в заголовке нет */
    plen = ppv2_tcp4(pay, PPCLI);
    pay[12] = 0x20;                   /* версия 2, команда LOCAL */
    len = build_tcp_raw(SERVER, RELAY, 60005, 9080, 0x18, pay, plen);
    run_pkt(len, 1);
    struct pp_key ckk5 = {0};
    ckk5.addr[0] = RELAY; ckk5.port = 60005;
    check("команда LOCAL не заводит запись",
          bpf_map_lookup_elem(&pp_conn_map, &ckk5) == NULL);

    printf("\n\033[1m11. PROXY protocol при нагрузке в нелинейной части skb\033[0m\n");
    /* loopback (HAProxy на той же ноде) и GSO/GRO: в линейной части только
     * заголовки Ethernet+IP+TCP, байты нагрузки лежат в страницах. */
    unsigned HDRS = 14 + 20 + 20;
    unsigned RELAY2 = 0x2B00007F, PPCLI3 = 0x2C00007F;
    linear_len = HDRS;

    /* контроль: без pull_data заголовок в такой раскладке не виден */
    plen = ppv2_tcp4(pay, PPCLI3);
    len = build_tcp_raw(SERVER, RELAY2, 61001, 9080, 0x18, pay, plen);
    pull_fail = 1; pull_calls = 0;
    run_pkt(len, 1);
    struct ip_key kr2 = {0}; kr2.addr[0] = RELAY2;
    struct pp_key c61001 = {0}; c61001.addr[0] = RELAY2; c61001.port = 61001;
    check("pull_data отказал: пакет не ломается, ключ по IP-заголовку",
          pull_calls == 1 && bpf_map_lookup_elem(&user_state_map_up, &kr2) != NULL &&
          bpf_map_lookup_elem(&pp_conn_map, &c61001) == NULL);
    pull_fail = 0;

    /* v2 TCP4, нагрузка не в линейной части */
    map_put(&pp_conn_map, &c61001, &(struct ip_key){0}); bpf_map_delete_elem(&pp_conn_map, &c61001);
    pull_calls = 0;
    run_pkt(len, 1);
    struct ip_key kpc3 = {0}; kpc3.addr[0] = __builtin_bswap32(PPCLI3);
    check("v2 из нелинейной части прочитан (клиент, а не релей)",
          pull_calls == 1 && bpf_map_lookup_elem(&user_state_map_up, &kpc3) != NULL);
    check("соединение запомнено после pull_data",
          bpf_map_lookup_elem(&pp_conn_map, &c61001) != NULL);

    /* запись есть — pull_data больше не нужен ни на одном пакете */
    pull_calls = 0;
    len = build_tcp_raw(SERVER, RELAY2, 61001, 9080, 0x18, pay1400, 1400);
    run_pkt(len, 1);
    run_pkt(len, 1);
    check("при известном соединении pull_data не вызывается", pull_calls == 0);

    /* FIN из нелинейного пакета по-прежнему чистит карту */
    len = build_tcp_raw(SERVER, RELAY2, 61001, 9080, 0x11, NULL, 0);
    run_pkt(len, 1);
    check("FIN удаляет соединение и в нелинейной раскладке",
          bpf_map_lookup_elem(&pp_conn_map, &c61001) == NULL);

    /* чистый ACK и короткая нагрузка: заголовку взяться неоткуда */
    pull_calls = 0;
    len = build_tcp_raw(SERVER, RELAY2, 61002, 9080, 0x10, NULL, 0);
    run_pkt(len, 1);
    check("пакет без нагрузки не вызывает pull_data", pull_calls == 0);
    len = build_tcp_raw(SERVER, RELAY2, 61002, 9080, 0x18, "\x16\x03\x01\x00\xAB", 5);
    run_pkt(len, 1);
    check("нагрузка короче заголовка PROXY не вызывает pull_data", pull_calls == 0);

    /* v2 TCP6 — самая длинная двоичная голова (52 байта) */
    plen = ppv2_tcp6(pay);
    len = build_tcp_raw(SERVER, RELAY2, 61003, 9080, 0x18, pay, plen);
    pull_calls = 0;
    run_pkt(len, 1);
    check("IPv6-клиент из нелинейной части прочитан",
          pull_calls == 1 && bpf_map_lookup_elem(&user_state_map_up, &k6pp) != NULL);

    /* v1 — текстовая строка */
    plen = ppv1_tcp4(pay, PPCLI2);
    len = build_tcp_raw(SERVER, RELAY2, 61004, 9080, 0x18, pay, plen);
    struct pp_key c61004 = {0}; c61004.addr[0] = RELAY2; c61004.port = 61004;
    run_pkt(len, 1);
    check("текстовый v1 из нелинейной части прочитан",
          bpf_map_lookup_elem(&pp_conn_map, &c61004) != NULL);

    /* нагрузка меньше, чем PP_PULL_LEN: просим ровно столько, сколько есть */
    plen = ppv2_tcp4(pay, PPCLI3);
    len = build_tcp_raw(SERVER, RELAY2, 61005, 9080, 0x18, pay, plen);
    struct pp_key c61005 = {0}; c61005.addr[0] = RELAY2; c61005.port = 61005;
    run_pkt(len, 1);
    check("нагрузка ровно в 28 байт (граница) читается",
          bpf_map_lookup_elem(&pp_conn_map, &c61005) != NULL);

    /* IPIP-туннель: смещение нагрузки включает наружный IP-заголовок */
    plen = ppv2_tcp4(pay, PPCLI3);
    len = build_ipip_tcp_raw(SERVER, RELAY2, 61006, 9080, 0x18, pay, plen);
    linear_len = 14 + 20 + 20 + 20;
    struct pp_key c61006 = {0}; c61006.addr[0] = RELAY2; c61006.port = 61006;
    run_pkt(len, 1);
    check("PROXY внутри IPIP при нелинейной нагрузке прочитан",
          bpf_map_lookup_elem(&pp_conn_map, &c61006) != NULL);

    /* download-направление не требует pull_data вовсе */
    linear_len = HDRS;
    pull_calls = 0;
    len = build_tcp_raw(RELAY2, SERVER, 9080, 61005, 0x18, pay1400, 1400);
    run_pkt(len, 0);
    check("download pull_data не вызывает", pull_calls == 0);

    /* линейный пакет (как раньше) pull_data не трогает */
    linear_len = 0;
    pull_calls = 0;
    plen = ppv2_tcp4(pay, PPCLI3);
    len = build_tcp_raw(SERVER, RELAY2, 61007, 9080, 0x18, pay, plen);
    run_pkt(len, 1);
    check("линейный пакет: заголовок читается без pull_data", pull_calls == 0 &&
          bpf_map_lookup_elem(&user_state_map_up, &kpc3) != NULL);

    printf("\n\033[1m12. Loopback: правило «все порты» не действует (двойной учёт)\033[0m\n");
    unsigned p7777 = 7777;
    struct ip_key kall = {0}; kall.addr[0] = 0x3C00007F;
    map_put(&port_map, &zero, &one);                /* правило «все порты» */
    len = build_v4(IPPROTO_TCP, 51000, 7777, 0, 100, SERVER, 0x3C00007F);

    skb.ifindex = 2;                                /* обычный интерфейс */
    run_pkt(len, 1);
    check("на внешнем интерфейсе «все порты» работает",
          bpf_map_lookup_elem(&user_state_map_up, &kall) != NULL);

    for (int i = 0; i < 4096; i++)
        if (table[i].used && table[i].map == (void *)&user_state_map_up)
            table[i].used = 0;
    skb.ifindex = 1;                                /* lo */
    run_pkt(len, 1);
    check("на lo «все порты» игнорируется",
          bpf_map_lookup_elem(&user_state_map_up, &kall) == NULL);

    len = build_v4(IPPROTO_TCP, 0, 0, 0x00B9, 1400, 0x3C00007F, SERVER);
    run_pkt(len, 0);
    check("на lo фрагмент без портов тоже не считается",
          bpf_map_lookup_elem(&user_state_map_down, &kall) == NULL);

    map_put(&port_map, &p7777, &one);               /* явный порт */
    len = build_v4(IPPROTO_TCP, 51000, 7777, 0, 100, SERVER, 0x3C00007F);
    run_pkt(len, 1);
    check("на lo явный порт шейпится как обычно",
          bpf_map_lookup_elem(&user_state_map_up, &kall) != NULL);
    struct user_state *lost = bpf_map_lookup_elem(&user_state_map_up, &kall);
    unsigned long long before_lo = lost ? lost->packets : 0;
    run_pkt(len, 1);
    lost = bpf_map_lookup_elem(&user_state_map_up, &kall);
    check("один пакет на lo считается один раз",
          lost != NULL && lost->packets == before_lo + 1);

    skb.ifindex = 0;
    for (int i = 0; i < 4096; i++)
        if (table[i].used && table[i].map == (void *)&port_map &&
            (*(unsigned *)table[i].key == 0 || *(unsigned *)table[i].key == 7777))
            table[i].used = 0;
    /* ── 11. Статистика «клиент × порт» ── */
    printf("\n\033[1m11. Статистика по портам\033[0m\n");
    unsigned PSCLI = 0x0500007F;
    int len443 = build_v4(IPPROTO_TCP, 443, 51000, 0, 1400, PSCLI, SERVER);
    run_pkt(len443, 0);
    run_pkt(len443, 0);
    struct port_stat_key pk443 = {0};
    pk443.addr[0] = PSCLI; pk443.port = 443;
    struct port_stat *ps = bpf_map_lookup_elem(&port_stat_map_down, &pk443);
    check("download разложен по порту 443",
          ps && ps->bytes == 2 * (unsigned long long)len443 && ps->packets == 2);

    int len9080 = build_v4(IPPROTO_TCP, 9080, 51001, 0, 800, PSCLI, SERVER);
    run_pkt(len9080, 0);
    struct port_stat_key pk9080 = {0};
    pk9080.addr[0] = PSCLI; pk9080.port = 9080;
    struct port_stat *ps2 = bpf_map_lookup_elem(&port_stat_map_down, &pk9080);
    struct ip_key kps = {0};
    kps.addr[0] = PSCLI;
    struct user_state *su11 = bpf_map_lookup_elem(&user_state_map_down, &kps);
    check("второй порт считается отдельно",
          ps2 && ps2->bytes == (unsigned long long)len9080);
    check("сумма по портам равна общему счётчику клиента",
          su11 && ps && ps2 && su11->total_bytes == ps->bytes + ps2->bytes);

    run_pkt(build_v4(IPPROTO_TCP, 51002, 443, 0, 300, SERVER, 0x0600007F), 1);
    struct port_stat_key pu443 = {0};
    pu443.addr[0] = 0x0600007F; pu443.port = 443;
    check("upload тоже разложен по порту",
          bpf_map_lookup_elem(&port_stat_map_up, &pu443) != NULL);

    run_pkt(build_v4(IPPROTO_TCP, 51003, 8080, 0, 300, SERVER, 0x0700007F), 1);
    struct port_stat_key pw = {0};
    pw.addr[0] = 0x0700007F; pw.port = 8080;
    check("чужой порт в статистику не попадает",
          bpf_map_lookup_elem(&port_stat_map_up, &pw) == NULL);

    /* за CDN статистика ведётся по настоящему клиенту */
    plen = ppv2_tcp4(pay, PPCLI);
    len = build_tcp_raw(SERVER, RELAY, 60007, 9080, 0x18, pay, plen);
    run_pkt(len, 1);
    len = build_tcp_raw(RELAY, SERVER, 9080, 60007, 0x18, pay, 28);
    run_pkt(len, 0);
    struct port_stat_key pr = {0}, ppc = {0};
    pr.addr[0] = RELAY;   pr.port = 9080;
    ppc.addr[0] = __builtin_bswap32(PPCLI);  ppc.port = 9080;
    check("за CDN статистика по настоящему клиенту, не по релею",
          bpf_map_lookup_elem(&port_stat_map_down, &pr) == NULL &&
          bpf_map_lookup_elem(&port_stat_map_down, &ppc) != NULL);

    /* белый список: не тормозим, но считаем по портам */
    struct ip_key kw11 = {0};
    kw11.addr[0] = 0x0800007F;
    map_put(&whitelist_map, &kw11, &one);
    run_pkt(build_v4(IPPROTO_TCP, 443, 51004, 0, 1400, 0x0800007F, SERVER), 0);
    run_pkt(build_v4(IPPROTO_TCP, 443, 51004, 0, 1400, 0x0800007F, SERVER), 0);
    struct port_stat_key pw11 = {0};
    pw11.addr[0] = 0x0800007F; pw11.port = 443;
    check("белый список: по портам считается, но не тормозится",
          bpf_map_lookup_elem(&port_stat_map_down, &pw11) != NULL && skb.tstamp == 0);
    bpf_map_delete_elem(&whitelist_map, &kw11);


    /* ── Немобильный лимит ──
     * Клиенты вне сетей мобильных операторов получают отдельную скорость.
     * Сети лежат в LPM-дереве mobile_lpm; v4 и v6 различаются словом family. */
    printf("\n\033[1m13. Немобильный лимит\033[0m\n");
    {
        struct config on  = { .bytes_per_sec = 10 * 125000,
                              .nonmobile_bytes_per_sec = 1 * 125000 };
        struct config on0 = { .bytes_per_sec = 0,
                              .nonmobile_bytes_per_sec = 1 * 125000 };
        /* 1.2.3.0/24 мобильная, v6 2001:db8::/32 мобильная */
        struct mobile_key m4 = { .prefixlen = 32 + 24, .family = 4 };
        m4.addr[0] = 0x00030201;                        /* 1.2.3.0 */
        struct mobile_key m6 = { .prefixlen = 32 + 32, .family = 6 };
        m6.addr[0] = 0xB80D0120;                        /* 2001:0db8:: */
        map_put(&mobile_lpm, &m4, &one);
        map_put(&mobile_lpm, &m6, &one);

        unsigned MOB4 = 0x04030201, NON4 = 0x08070605;  /* 1.2.3.4 / 5.6.7.8 */
        unsigned char mob6[16] = {0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,0x42};
        unsigned char non6[16] = {0x2a,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,0x07};
        unsigned char lo6[16]  = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        /* первые 32 бита как у v4-клиента 1.2.3.4, но это IPv6 */
        unsigned char clash6[16] = {0x01,0x02,0x03,0x04,0,0,0,0,0,0,0,0,0,0,0,1};
        unsigned long long d;

        /* Шаг задержки между вторым и третьим пакетом клиента. */
        #define STEP4(ADDR) ({ int l_ = build_v4(IPPROTO_TCP, 443, 51000, 0, 1400, (ADDR), SERVER); \
                               run_pkt(l_, 0); run_pkt(l_, 0); unsigned long long a_ = skb.tstamp; \
                               run_pkt(l_, 0); skb.tstamp - a_; })
        #define STEP6(A16) ({ int l_ = build_v6_addr((A16), 443, 51000, 1400); \
                              run_pkt(l_, 0); run_pkt(l_, 0); unsigned long long a_ = skb.tstamp; \
                              run_pkt(l_, 0); skb.tstamp - a_; })
        #define IS_GENERAL(d) ((d) > 1000000 && (d) < 1400000)   /* ~1.16 мс на 10 Мбит/с */
        #define IS_NONMOB(d)  ((d) > 11000000 && (d) < 12300000) /* ~11.6 мс на 1 Мбит/с */

        map_put(&config_map, &zero, &cfg);               /* режим выключен */
        d = STEP4(NON4);
        check("режим выключен: чужой адрес идёт по общему лимиту", IS_GENERAL(d));

        map_put(&config_map, &zero, &on);
        d = STEP4(MOB4);
        check("режим включён: адрес из мобильной сети v4 — общий лимит", IS_GENERAL(d));
        d = STEP4(NON4 + 0x100);
        check("режим включён: промах в mobile_lpm v4 — немобильный лимит", IS_NONMOB(d));
        d = STEP6(mob6);
        check("режим включён: адрес из мобильной сети v6 — общий лимит", IS_GENERAL(d));
        d = STEP6(non6);
        check("режим включён: промах в mobile_lpm v6 — немобильный лимит", IS_NONMOB(d));

        d = STEP4(0x0500007F);                           /* 127.0.0.5 */
        check("loopback v4 не считается немобильным", IS_GENERAL(d));
        d = STEP6(lo6);
        check("loopback v6 (::1) не считается немобильным", IS_GENERAL(d));

        d = STEP6(clash6);
        check("v6 с теми же первыми 32 битами, что у мобильного v4, — не мобильный",
              IS_NONMOB(d));
        /* и наоборот: в дереве только v6-сеть 0102:0300::/24, v4 1.2.3.4 в неё не попадает */
        bpf_map_delete_elem(&mobile_lpm, &m4);
        struct mobile_key m6b = { .prefixlen = 32 + 24, .family = 6 };
        m6b.addr[0] = 0x00030201;
        map_put(&mobile_lpm, &m6b, &one);
        d = STEP4(0x04030202);
        check("v4 1.2.3.x не попадает в v6-сеть с теми же байтами", IS_NONMOB(d));
        d = STEP6(clash6);
        check("а v6-адрес в этой v6-сети — мобильный", IS_GENERAL(d));
        bpf_map_delete_elem(&mobile_lpm, &m6b);
        map_put(&mobile_lpm, &m4, &one);

        /* белый список важнее всего */
        struct ip_key kwm = {0}; kwm.addr[0] = 0x0A090807;
        map_put(&whitelist_map, &kwm, &one);
        int lw = build_v4(IPPROTO_TCP, 443, 51000, 0, 1400, 0x0A090807, SERVER);
        run_pkt(lw, 0); run_pkt(lw, 0);
        check("белый список: немобильный лимит не применяется", skb.tstamp == 0);
        bpf_map_delete_elem(&whitelist_map, &kwm);

        /* штраф и персональная скорость приоритетнее немобильного лимита */
        struct penalty pn = { .rate_bytes_per_sec = 2 * 125000,
                              .until_ns = fake_now + 60000000000ULL };
        struct ip_key kpn = {0}; kpn.addr[0] = 0x0B090807;
        map_put(&penalty_map, &kpn, &pn);
        d = STEP4(0x0B090807);
        check("штраф приоритетнее немобильного лимита (~5.8 мс на 2 Мбит/с)",
              d > 5300000 && d < 6300000);
        bpf_map_delete_elem(&penalty_map, &kpn);

        /* просроченный штраф на немобильном адресе — снова немобильный лимит */
        pn.until_ns = fake_now - 1;
        struct ip_key kpe = {0}; kpe.addr[0] = 0x0C090807;
        map_put(&penalty_map, &kpe, &pn);
        d = STEP4(0x0C090807);
        check("просроченный штраф: действует немобильный лимит", IS_NONMOB(d));
        bpf_map_delete_elem(&penalty_map, &kpe);

        /* общий лимит 0 + режим включён: немобильный работает */
        map_put(&config_map, &zero, &on0);
        d = STEP4(0x0D090807);
        check("общий лимит 0, режим включён: немобильный лимит работает", IS_NONMOB(d));
        d = STEP4(MOB4 + 0x01000000);
        check("общий лимит 0: мобильный адрес идёт без лимита", skb.tstamp == 0);
        d = STEP4(0x0600007F);
        check("общий лимит 0: loopback идёт без лимита", skb.tstamp == 0);

        /* всё выключено: ранний выход как раньше, адрес даже не учитывается */
        struct config alloff = {0};
        map_put(&config_map, &zero, &alloff);
        struct ip_key kao = {0}; kao.addr[0] = 0x0E090807;
        run_pkt(build_v4(IPPROTO_TCP, 443, 51000, 0, 1400, 0x0E090807, SERVER), 0);
        check("оба лимита выключены: пакет мимо учёта",
              bpf_map_lookup_elem(&user_state_map_down, &kao) == NULL);

        map_put(&config_map, &zero, &cfg);
        (void)d;
    }


    /* ── Блокировка немобильных ──
     * nonmobile_block приоритетнее немобильной скорости: клиент вне сетей
     * мобильных операторов просто не проходит (SHOT в обе стороны). Белый
     * список, активный штраф/персональная скорость и loopback не блокируются. */
    printf("\n\033[1m14. Блокировка немобильных\033[0m\n");
    {
        struct config blk  = { .bytes_per_sec = 10 * 125000,
                               .nonmobile_bytes_per_sec = 1 * 125000,
                               .nonmobile_block = 1 };
        struct config blk0 = { .nonmobile_block = 1 };   /* больше ничего не задано */
        struct config nom  = { .bytes_per_sec = 10 * 125000,
                               .nonmobile_bytes_per_sec = 1 * 125000 };
        struct mobile_key m4 = { .prefixlen = 32 + 24, .family = 4 };
        m4.addr[0] = 0x00030201;                        /* 1.2.3.0/24 мобильная */
        struct mobile_key m6 = { .prefixlen = 32 + 32, .family = 6 };
        m6.addr[0] = 0xB80D0120;                        /* 2001:0db8::/32 */
        map_put(&mobile_lpm, &m4, &one);
        map_put(&mobile_lpm, &m6, &one);
        unsigned MOB4 = 0x04030201, NON4 = 0x28070605;  /* 1.2.3.4 / 5.6.7.40 */
        unsigned char mob6[16] = {0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,0x42};
        unsigned char non6[16] = {0x2a,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,0x09};
        unsigned char lo6[16]  = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        int l, r1, r2;

        map_put(&config_map, &zero, &blk);
        l = build_v4(IPPROTO_TCP, 443, 51000, 0, 1400, NON4, SERVER);
        r1 = run_pkt(l, 0);
        check("блок: первый пакет немобильного (download) сброшен", r1 == TC_ACT_SHOT);
        r2 = run_pkt(l, 0);
        check("блок: следующие пакеты тоже сброшены", r2 == TC_ACT_SHOT);
        l = build_v4(IPPROTO_TCP, 51000, 443, 0, 1400, SERVER, NON4);
        check("блок: upload немобильного сброшен", run_pkt(l, 1) == TC_ACT_SHOT);
        check("блок: upload немобильного сброшен повторно", run_pkt(l, 1) == TC_ACT_SHOT);
        l = build_v6_addr(non6, 443, 51000, 1400);
        check("блок: немобильный IPv6 сброшен", run_pkt(l, 0) == TC_ACT_SHOT);

        struct ip_key kb = {0}; kb.addr[0] = NON4;
        struct user_state *sb = bpf_map_lookup_elem(&user_state_map_down, &kb);
        check("заблокированный адрес виден: запись создана", sb != NULL);
        check("заблокированный: отброшено посчитано",
              sb && sb->dropped_packets == 2 && sb->dropped_bytes == 2ULL * (14 + 20 + 20 + 1400));
        check("заблокированный: пропущенного нет", sb && sb->total_bytes == 0 && sb->packets == 0);
        struct port_stat_key pkb = {0}; pkb.addr[0] = NON4; pkb.port = 443;
        check("заблокированный: статистика по портам не растёт",
              bpf_map_lookup_elem(&port_stat_map_down, &pkb) == NULL);

        l = build_v4(IPPROTO_TCP, 443, 51000, 0, 1400, MOB4, SERVER);
        check("блок: мобильный v4 проходит", run_pkt(l, 0) == TC_ACT_OK && run_pkt(l, 0) == TC_ACT_OK);
        l = build_v4(IPPROTO_TCP, 51000, 443, 0, 1400, SERVER, MOB4);
        check("блок: мобильный v4 проходит (upload)", run_pkt(l, 1) == TC_ACT_OK);
        l = build_v6_addr(mob6, 443, 51000, 1400);
        check("блок: мобильный v6 проходит", run_pkt(l, 0) == TC_ACT_OK && run_pkt(l, 0) == TC_ACT_OK);
        l = build_v4(IPPROTO_TCP, 443, 51000, 0, 1400, 0x0500007F, SERVER);
        check("блок: loopback v4 проходит", run_pkt(l, 0) == TC_ACT_OK && run_pkt(l, 0) == TC_ACT_OK);
        l = build_v6_addr(lo6, 443, 51000, 1400);
        check("блок: loopback v6 проходит", run_pkt(l, 0) == TC_ACT_OK && run_pkt(l, 0) == TC_ACT_OK);

        struct ip_key kwb = {0}; kwb.addr[0] = 0x29070605;
        map_put(&whitelist_map, &kwb, &one);
        l = build_v4(IPPROTO_TCP, 443, 51000, 0, 1400, 0x29070605, SERVER);
        check("блок: белый список проходит (включая первый пакет)",
              run_pkt(l, 0) == TC_ACT_OK && run_pkt(l, 0) == TC_ACT_OK && skb.tstamp == 0);
        bpf_map_delete_elem(&whitelist_map, &kwb);

        struct penalty pn = { .rate_bytes_per_sec = 2 * 125000,
                              .until_ns = fake_now + 60000000000ULL };
        struct ip_key kpb = {0}; kpb.addr[0] = 0x2A070605;
        map_put(&penalty_map, &kpb, &pn);
        l = build_v4(IPPROTO_TCP, 443, 51000, 0, 1400, 0x2A070605, SERVER);
        check("блок: активный штраф/персональная скорость не блокируется",
              run_pkt(l, 0) == TC_ACT_OK && run_pkt(l, 0) == TC_ACT_OK && skb.tstamp > 0);
        pn.until_ns = fake_now - 1;
        map_put(&penalty_map, &kpb, &pn);
        check("блок: просроченный штраф — снова блок", run_pkt(l, 0) == TC_ACT_SHOT);
        bpf_map_delete_elem(&penalty_map, &kpb);

        /* блок приоритетнее немобильного лимита, но независим от него */
        map_put(&config_map, &zero, &nom);
        l = build_v4(IPPROTO_TCP, 443, 51000, 0, 1400, 0x2B070605, SERVER);
        check("блок выключен, лимит задан: немобильный не сбрасывается",
              run_pkt(l, 0) == TC_ACT_OK && run_pkt(l, 0) == TC_ACT_OK);

        /* блок при нулевых скоростях: ранний выход его не глушит */
        map_put(&config_map, &zero, &blk0);
        l = build_v4(IPPROTO_TCP, 443, 51000, 0, 1400, 0x2C070605, SERVER);
        check("общий лимит 0 и нет немобильной скорости: блок работает",
              run_pkt(l, 0) == TC_ACT_SHOT);
        l = build_v4(IPPROTO_TCP, 443, 51000, 0, 1400, MOB4 + 0x01000000, SERVER);
        check("... а мобильный идёт без лимита",
              run_pkt(l, 0) == TC_ACT_OK && run_pkt(l, 0) == TC_ACT_OK && skb.tstamp == 0);

        /* все три нуля: ранний выход, адрес не учитывается */
        struct config alloff = {0};
        map_put(&config_map, &zero, &alloff);
        struct ip_key kz = {0}; kz.addr[0] = 0x2D070605;
        l = build_v4(IPPROTO_TCP, 443, 51000, 0, 1400, 0x2D070605, SERVER);
        check("все три нуля: пропуск мимо учёта",
              run_pkt(l, 0) == TC_ACT_OK &&
              bpf_map_lookup_elem(&user_state_map_down, &kz) == NULL);

        map_put(&config_map, &zero, &cfg);
    }

    /* ── Учёт: пропущенное и отброшенное раздельно ── */
    printf("\n\033[1m15. Учёт пропущенного и отброшенного\033[0m\n");
    {
        unsigned long long sent_b, sent_p;
        int l, got_shot;
        map_put(&config_map, &zero, &cfg);                /* 10 Мбит/с */
        fake_now = 50000000000ULL;

        /* download: горизонт EDT */
        unsigned DCL = 0x3A070605;
        struct ip_key kd = {0}; kd.addr[0] = DCL;
        l = build_v4(IPPROTO_TCP, 443, 51000, 0, 1400, DCL, SERVER);
        run_pkt(l, 0);
        struct user_state *sd = bpf_map_lookup_elem(&user_state_map_down, &kd);
        check("первый пакет: пропущен и учтён",
              sd && sd->total_bytes == (unsigned long long)l && sd->packets == 1 &&
              sd->dropped_bytes == 0 && sd->dropped_packets == 0);
        sent_b = l; sent_p = 1; got_shot = 0;
        for (int i = 0; i < 4000; i++) {
            if (run_pkt(l, 0) == TC_ACT_SHOT) got_shot = 1;
            sent_b += l; sent_p++;
        }
        sd = bpf_map_lookup_elem(&user_state_map_down, &kd);
        check("download: горизонт EDT сработал", got_shot);
        check("download: пропущенное + отброшенное = отправленному (байты)",
              sd && sd->total_bytes + sd->dropped_bytes == sent_b);
        check("download: пропущенное + отброшенное = отправленному (пакеты)",
              sd && sd->packets + sd->dropped_packets == sent_p);
        check("download: отброшенное посчитано отдельно",
              sd && sd->dropped_packets > 0 && sd->dropped_bytes == sd->dropped_packets * l);
        struct port_stat_key pkd = {0}; pkd.addr[0] = DCL; pkd.port = 443;
        struct port_stat *psd = bpf_map_lookup_elem(&port_stat_map_down, &pkd);
        check("download: статистика по портам — только пропущенное",
              psd && sd && psd->bytes == sd->total_bytes && psd->packets == sd->packets);
        unsigned long long tb = sd->total_bytes, db = sd->dropped_bytes;
        run_pkt(l, 0);
        sd = bpf_map_lookup_elem(&user_state_map_down, &kd);
        check("сброшенный пакет не растит total_bytes, но растит dropped_bytes",
              sd->total_bytes == tb && sd->dropped_bytes == db + l);

        /* upload: ведро 200 мс */
        unsigned UCL = 0x3B070605;
        struct ip_key ku = {0}; ku.addr[0] = UCL;
        l = build_v4(IPPROTO_TCP, 51000, 443, 0, 1400, SERVER, UCL);
        sent_b = sent_p = 0; got_shot = 0;
        for (int i = 0; i < 600; i++) {
            if (run_pkt(l, 1) == TC_ACT_SHOT) got_shot = 1;
            sent_b += l; sent_p++;
        }
        struct user_state *su = bpf_map_lookup_elem(&user_state_map_up, &ku);
        check("upload: ведро переполнилось", got_shot);
        check("upload: пропущенное + отброшенное = отправленному",
              su && su->total_bytes + su->dropped_bytes == sent_b &&
              su->packets + su->dropped_packets == sent_p && su->dropped_packets > 0);
        struct port_stat_key pku = {0}; pku.addr[0] = UCL; pku.port = 443;
        struct port_stat *psu = bpf_map_lookup_elem(&port_stat_map_up, &pku);
        check("upload: статистика по портам — только пропущенное",
              psu && su && psu->bytes == su->total_bytes && psu->packets == su->packets);

        /* белый список и нулевая скорость — это пропущенное */
        unsigned WCL = 0x3C070605;
        struct ip_key kw = {0}; kw.addr[0] = WCL;
        map_put(&whitelist_map, &kw, &one);
        l = build_v4(IPPROTO_TCP, 443, 51000, 0, 1400, WCL, SERVER);
        for (int i = 0; i < 3000; i++) run_pkt(l, 0);
        struct user_state *sw = bpf_map_lookup_elem(&user_state_map_down, &kw);
        check("белый список: всё учтено как пропущенное",
              sw && sw->total_bytes == 3000ULL * l && sw->packets == 3000 &&
              sw->dropped_bytes == 0 && sw->dropped_packets == 0);
        bpf_map_delete_elem(&whitelist_map, &kw);
        fake_now = 5000000000ULL;
    }


    /* ── Блок и TCP без нагрузки ──
     * Рукопожатие, чистые ACK, FIN и RST блок не режет: иначе клиент за
     * релеем PROXY protocol не смог бы прислать заголовок, по которому
     * определяется его настоящий адрес. Режутся сегменты с данными и весь UDP. */
    printf("\n\033[1m16. Блок: TCP без нагрузки и PROXY protocol\033[0m\n");
    {
        struct config blk = { .bytes_per_sec = 10 * 125000, .nonmobile_block = 1 };
        map_put(&config_map, &zero, &blk);
        unsigned char dpay[1500]; memset(dpay, 0x17, sizeof dpay);
        unsigned NONB = 0x5B070605;                    /* 5.6.7.91, не мобильный */
        unsigned char non6[16] = {0x2a,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,0x0b};
        int l;

        /* прямой немобильный клиент: рукопожатие проходит, данные режутся */
        l = build_tcp_raw(SERVER, NONB, 51000, 443, 0x02, NULL, 0);
        check("прямой немобильный: SYN проходит (upload)", run_pkt(l, 1) == TC_ACT_OK);
        l = build_tcp_raw(NONB, SERVER, 443, 51000, 0x12, NULL, 0);
        check("прямой немобильный: SYN-ACK проходит (download)", run_pkt(l, 0) == TC_ACT_OK);
        l = build_tcp_raw(SERVER, NONB, 51000, 443, 0x10, NULL, 0);
        check("прямой немобильный: чистый ACK проходит", run_pkt(l, 1) == TC_ACT_OK);
        check("... и чистый ACK с паддингом Ethernet (кадр длиннее IP-пакета)",
              run_pkt(l + 6, 1) == TC_ACT_OK);
        l = build_tcp_raw(SERVER, NONB, 51000, 443, 0x18, dpay, 300);
        check("прямой немобильный: первые данные (ClientHello) срезаны", run_pkt(l, 1) == TC_ACT_SHOT);
        l = build_tcp_raw(NONB, SERVER, 443, 51000, 0x18, dpay, 1400);
        check("прямой немобильный: данные вниз срезаны", run_pkt(l, 0) == TC_ACT_SHOT);
        l = build_tcp_raw(SERVER, NONB, 51000, 443, 0x11, NULL, 0);
        check("прямой немобильный: FIN проходит", run_pkt(l, 1) == TC_ACT_OK);
        l = build_tcp_raw(SERVER, NONB, 51000, 443, 0x04, NULL, 0);
        check("прямой немобильный: RST проходит", run_pkt(l, 1) == TC_ACT_OK);
        struct ip_key kb = {0}; kb.addr[0] = NONB;
        struct user_state *ub = bpf_map_lookup_elem(&user_state_map_up, &kb);
        check("рукопожатие учтено как пропущенное, данные — как отброшенное",
              ub && ub->total_bytes > 0 && ub->dropped_packets == 1);

        /* UDP режется целиком, даже без нагрузки */
        l = build_v4(IPPROTO_UDP, 51000, 443, 0, 0, SERVER, NONB);
        check("немобильный UDP срезан", run_pkt(l, 1) == TC_ACT_SHOT);
        l = build_v4(IPPROTO_UDP, 443, 51000, 0, 1200, NONB, SERVER);
        check("немобильный UDP срезан (download)", run_pkt(l, 0) == TC_ACT_SHOT);

        /* IPv6, в том числе с цепочкой заголовков, и IPIP */
        l = build_v6_addr(non6, 443, 51000, 0);
        check("IPv6 немобильный: пустой TCP проходит", run_pkt(l, 0) == TC_ACT_OK);
        l = build_v6_addr(non6, 443, 51000, 200);
        check("IPv6 немобильный: данные срезаны", run_pkt(l, 0) == TC_ACT_SHOT);
        l = build_ipip_tcp_raw(SERVER, NONB, 51001, 443, 0x02, NULL, 0);
        check("IPIP: SYN немобильного проходит", run_pkt(l, 1) == TC_ACT_OK);
        l = build_ipip_tcp_raw(SERVER, NONB, 51001, 443, 0x18, dpay, 200);
        check("IPIP: данные немобильного срезаны", run_pkt(l, 1) == TC_ACT_SHOT);
        l = build_ipip_v6(51002, 443, 0);
        check("IPv6 в IPv4-туннеле: пустой TCP не считается данными", run_pkt(l, 1) != TC_ACT_SHOT);

        /* мобильный клиент не затрагивается */
        l = build_tcp_raw(SERVER, 0x09030201, 51003, 443, 0x18, dpay, 300);
        check("мобильный: данные проходят", run_pkt(l, 1) == TC_ACT_OK);

        /* Релей CDN: адрес релея немобильный, клиент приходит в заголовке PROXY */
        unsigned RLY = 0x5C070605;                     /* 5.6.7.92 */
        unsigned char pp[64];
        int ppl = ppv2_tcp4(pp, 0x01020309);           /* клиент 1.2.3.9 — мобильный */
        l = build_tcp_raw(SERVER, RLY, 60100, 443, 0x02, NULL, 0);
        check("релей: SYN проходит под ключом релея", run_pkt(l, 1) == TC_ACT_OK);
        l = build_tcp_raw(SERVER, RLY, 60100, 443, 0x18, pp, ppl);
        check("релей + PROXY с мобильным клиентом: первый сегмент с данными проходит",
              run_pkt(l, 1) == TC_ACT_OK);
        struct pp_key ck = {0}; ck.addr[0] = RLY; ck.port = 60100;
        check("... запись pp_conn_map заведена", bpf_map_lookup_elem(&pp_conn_map, &ck) != NULL);
        l = build_tcp_raw(SERVER, RLY, 60100, 443, 0x18, dpay, 400);
        check("... следующие данные от этого клиента проходят", run_pkt(l, 1) == TC_ACT_OK);
        l = build_tcp_raw(RLY, SERVER, 443, 60100, 0x18, dpay, 1400);
        check("... и отдача ему проходит", run_pkt(l, 0) == TC_ACT_OK);
        struct ip_key kcl = {0}; kcl.addr[0] = __builtin_bswap32(0x01020309);
        check("учёт идёт по настоящему клиенту, не по релею",
              bpf_map_lookup_elem(&user_state_map_up, &kcl) != NULL);

        ppl = ppv2_tcp4(pp, 0x05060708);               /* клиент 5.6.7.8 — немобильный */
        l = build_tcp_raw(SERVER, RLY, 60101, 443, 0x02, NULL, 0);
        check("релей: SYN нового соединения проходит", run_pkt(l, 1) == TC_ACT_OK);
        l = build_tcp_raw(SERVER, RLY, 60101, 443, 0x18, pp, ppl);
        check("релей + PROXY с немобильным клиентом: данные срезаны", run_pkt(l, 1) == TC_ACT_SHOT);
        struct pp_key ck2 = {0}; ck2.addr[0] = RLY; ck2.port = 60101;
        check("... запись pp_conn_map всё равно заведена", bpf_map_lookup_elem(&pp_conn_map, &ck2) != NULL);
        l = build_tcp_raw(RLY, SERVER, 443, 60101, 0x18, dpay, 1400);
        check("... отдача ему тоже срезана", run_pkt(l, 0) == TC_ACT_SHOT);

        map_put(&config_map, &zero, &cfg);
    }

    /* ── last_seen: срезанное не делает адрес «активным» ── */
    printf("\n\033[1m17. Срезанный пакет не обновляет last_seen_ns\033[0m\n");
    {
        struct config on = { .bytes_per_sec = 10 * 125000 };
        struct config blk = { .bytes_per_sec = 10 * 125000, .nonmobile_block = 1 };
        unsigned char dpay[1500]; memset(dpay, 0x17, sizeof dpay);
        int l;
        fake_now = 70000000000ULL;
        map_put(&config_map, &zero, &blk);
        unsigned FRESH = 0x5D070605;
        l = build_tcp_raw(FRESH, SERVER, 443, 51000, 0x18, dpay, 500);
        check("новый заблокированный: срезан", run_pkt(l, 0) == TC_ACT_SHOT);
        struct ip_key kf = {0}; kf.addr[0] = FRESH;
        struct user_state *sf = bpf_map_lookup_elem(&user_state_map_down, &kf);
        check("его запись создана, last_seen_ns = 0 (не активен)", sf && sf->last_seen_ns == 0);
        fake_now += 5000000000ULL;
        run_pkt(l, 0);
        sf = bpf_map_lookup_elem(&user_state_map_down, &kf);
        check("повторные сбросы last_seen_ns не трогают", sf && sf->last_seen_ns == 0);

        /* клиент с трафиком до блока: сбросы не продлевают его «активность» */
        map_put(&config_map, &zero, &on);
        unsigned OLD = 0x5E070605;
        struct ip_key ko = {0}; ko.addr[0] = OLD;
        l = build_tcp_raw(OLD, SERVER, 443, 51000, 0x18, dpay, 500);
        run_pkt(l, 0); run_pkt(l, 0);
        struct user_state *so = bpf_map_lookup_elem(&user_state_map_down, &ko);
        unsigned long long seen0 = so ? so->last_seen_ns : 1;
        check("пропущенный пакет ставит last_seen_ns", so && seen0 == fake_now);
        map_put(&config_map, &zero, &blk);
        fake_now += 9000000000ULL;
        check("после включения блока клиент срезается", run_pkt(l, 0) == TC_ACT_SHOT);
        so = bpf_map_lookup_elem(&user_state_map_down, &ko);
        check("last_seen_ns остался от последнего пропущенного пакета",
              so && so->last_seen_ns == seen0 && so->dropped_packets == 1);
        map_put(&config_map, &zero, &cfg);
        fake_now = 5000000000ULL;
    }

    printf("\n\033[1mИтог: %d пройдено, %d провалено\033[0m\n", ok, fail);
    return fail ? 1 : 0;
}
