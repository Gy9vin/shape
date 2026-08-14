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
static unsigned long long bpf_ktime_get_ns_impl(void) { return fake_now; }
#define bpf_ktime_get_ns bpf_ktime_get_ns_impl

#define SEC(NAME)
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_ntohs(x) __builtin_bswap16(x)
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#include "../bpf/shaper.bpf.c"

/* ── карта в памяти ── */
struct ent { void *map; unsigned char key[16]; unsigned char val[32]; int used; };
static struct ent table[4096];
static int keysize(void *m) {
    if (m == (void *)&config_map || m == (void *)&port_map) return 4;
    return 16;
}
void *bpf_map_lookup_elem(void *map, const void *key) {
    int ks = keysize(map);
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
            memcpy(table[i].val, value, 32); return 0;
        }
    for (int i = 0; i < 4096; i++)
        if (!table[i].used) {
            table[i].used = 1; table[i].map = map;
            memcpy(table[i].key, key, ks); memcpy(table[i].val, value, 32);
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

static int run_pkt(int len, int direction) {
    skb.data = (unsigned long)pkt;
    skb.data_end = (unsigned long)pkt + len;
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
    unsigned char *l4 = pkt + 14 + 20;
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
    return (int)(p - pkt) + 20 + payload;
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

    printf("\n\033[1mИтог: %d пройдено, %d провалено\033[0m\n", ok, fail);
    return fail ? 1 : 0;
}
