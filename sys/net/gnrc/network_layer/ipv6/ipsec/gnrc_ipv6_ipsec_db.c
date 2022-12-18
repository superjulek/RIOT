#include "net/gnrc/ipv6/ipsec/ipsec_db.h"
#include "net/ipv6/addr.h"
#include <errno.h>

typedef struct __attribute__((__packed__)) {
    uint8_t set;
    ipsec_sa_t sa_ext;
} internal_ipsec_sa_t;

typedef struct __attribute__((__packed__)) {
    uint8_t set;
    ipsec_sp_t sp_ext;
} internal_ipsec_sp_t;


/**
 * @todo
 * Add mutex and dynamic listsSS
 */
static internal_ipsec_sa_t sadb[IPSEC_MAX_SA_NUM];
static internal_ipsec_sp_t spdb[IPSEC_MAX_SP_NUM];

int sadb_init(void)
{
    for (int i = 0; i < IPSEC_MAX_SA_NUM; ++i) {
        sadb[i] = (internal_ipsec_sa_t){0};
    }
    return 0;
}

int spdb_init(void)
{
    for (int i = 0; i < IPSEC_MAX_SP_NUM; ++i) {
        spdb[i] = (internal_ipsec_sp_t){0};
    }
    return 0;
}

int sasp_tmp_init(void)
{
    ipsec_sp_t sp = {
        .rule = IPSEC_SP_RULE_BYPASS,
        .tun_dst_mask = 0,
        .tun_src_mask = 0,
        .proto = PROTNUM_ICMPV6,
    };
    add_sp(&sp);
    return 0;
}

uint32_t get_spi(void)
{
    static uint32_t spi = 256;

    return spi++;
}

int add_sa(ipsec_sa_t *sa)
{
    internal_ipsec_sa_t *entry;

    for (int i = 0; i < IPSEC_MAX_SA_NUM; ++i) {
        entry = &sadb[i];
        if (entry->set == 0) {
            entry->sa_ext = *sa;
            entry->set = 1;
            return 0;
        }
    }
    return -ENOMEM;
}

int add_sp(ipsec_sp_t *sp)
{
    internal_ipsec_sp_t *entry;

    for (int i = 0; i < IPSEC_MAX_SP_NUM; ++i) {
        entry = &spdb[i];
        if (entry->set == 0) {
            entry->sp_ext = *sp;
            entry->set = 1;
            return 0;
        }
    }
    return -ENOMEM;
}

int del_sa(uint32_t spi)
{
    internal_ipsec_sa_t *entry;

    for (int i = 0; i < IPSEC_MAX_SA_NUM; ++i) {
        entry = &sadb[i];
        if (entry->sa_ext.spi == spi) {
            entry->sa_ext = (ipsec_sa_t){0};
            entry->set = 0;
            return 0;
        }
    }
    return -ENOENT;
}

int del_sp(uint32_t sp_idx)
{
    internal_ipsec_sp_t *entry;

    if (sp_idx >= IPSEC_MAX_SP_NUM) {
        return -ENOENT;
    }
    entry = &spdb[sp_idx];
    if (entry->set == 0) {
        return -ENOENT;
    }
    entry->set = 0;
    entry->sp_ext = (ipsec_sp_t){0};
    return -ENOENT;
}

int get_sp_by_ts(ipsec_ts_t *ts, ipsec_sp_t *sp)
{
    internal_ipsec_sp_t *entry;

    for (int i = 0; i < IPSEC_MAX_SP_NUM; ++i) {
        entry = &spdb[i];
        if (entry->set == 0) {
            continue;
        }
        if (entry->sp_ext.src_port && entry->sp_ext.src_port != ts->src_port) {
            continue;
        }
        if (entry->sp_ext.dst_port && entry->sp_ext.dst_port != ts->dst_port) {
            continue;
        }
        if (entry->sp_ext.proto && entry->sp_ext.proto != ts->proto) {
            continue;
        }
        if (ipv6_addr_match_prefix(&entry->sp_ext.tun_src, &ts->src)
            < entry->sp_ext.tun_src_mask) {
            continue;
        }
        if (ipv6_addr_match_prefix(&entry->sp_ext.tun_dst, &ts->dst)
            < entry->sp_ext.tun_dst_mask) {
            continue;
        }
        *sp = entry->sp_ext;
        return 0;
    }
    return -ENOENT;
}
