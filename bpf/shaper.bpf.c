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
 *   whitelist_map  : ip (4x u32) -> u8      (эти IP минуют шейпер)
 *   penalty_map    : ip -> struct penalty   (штраф нарушителю на время)
 *   user_state_map_down/up : ip -> struct user_state
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

#define MAX_USERS      65536
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

/* 24 байта: last_departure_ns, total_bytes, last_seen_ns */
struct user_state {
    __u64 last_departure_ns;
    __u64 total_bytes;
    __u64 last_seen_ns;
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

    struct ip_key key = {0};
    __u16 sport = 0, dport = 0;
    __u8  proto = 0;
    void *l4 = 0;

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (struct iphdr *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return TC_ACT_OK;
        if (ip->ihl < 5)
            return TC_ACT_OK;

        key.addr[0] = (direction == 0) ? ip->daddr : ip->saddr;
        proto = ip->protocol;
        l4 = (void *)ip + (ip->ihl * 4);

    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = (struct ipv6hdr *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return TC_ACT_OK;

        if (direction == 0)
            __builtin_memcpy(key.addr, ip6->daddr.in6_u.u6_addr32, 16);
        else
            __builtin_memcpy(key.addr, ip6->saddr.in6_u.u6_addr32, 16);

        proto = ip6->nexthdr;
        l4 = (void *)(ip6 + 1);
    } else {
        return TC_ACT_OK;   /* ARP, VLAN и прочее — не трогаем */
    }

    /* ── Скорость. Ноль = ограничение выключено ── */
    __u32 zero = 0;
    struct config *conf = bpf_map_lookup_elem(&config_map, &zero);
    if (!conf || conf->bytes_per_sec == 0)
        return TC_ACT_OK;

    /* ── Белый список: свой адрес, мониторинг, панель ── */
    if (bpf_map_lookup_elem(&whitelist_map, &key))
        return TC_ACT_OK;

    /* ── Порты ── */
    if (proto == IPPROTO_TCP) {
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
    if (!bpf_map_lookup_elem(&port_map, &key_port)) {
        if (!bpf_map_lookup_elem(&port_map, &zero))  /* порт 0 = все порты */
            return TC_ACT_OK;
    }

    __u64 now = bpf_ktime_get_ns();
    __u32 len = skb->len;

    struct user_state *st = bpf_map_lookup_elem(user_map, &key);
    if (!st) {
        struct user_state fresh = {
            .last_departure_ns = now,
            .last_seen_ns      = now,
            .total_bytes       = len,
        };
        bpf_map_update_elem(user_map, &key, &fresh, BPF_ANY);
        return TC_ACT_OK;   /* первый пакет пропускаем без задержки */
    }

    __sync_fetch_and_add(&st->total_bytes, len);
    st->last_seen_ns = now;

    /* Персональный штраф важнее общего лимита. Просроченные записи вычищает
     * сторож; здесь просто игнорируем их по времени. */
    __u64 rate = conf->bytes_per_sec;
    struct penalty *pen = bpf_map_lookup_elem(&penalty_map, &key);
    if (pen && pen->rate_bytes_per_sec > 0 && now < pen->until_ns)
        rate = pen->rate_bytes_per_sec;

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
