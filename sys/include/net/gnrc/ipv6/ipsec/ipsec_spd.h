/*
 * Copyright (C) 2022 Juliusz Neuman
 */


#ifndef NET_GNRC_IPV6_IPSEC_SPD_H
#define NET_GNRC_IPV6_IPSEC_SPD_H


#include "net/gnrc/pkt.h"
#include "net/gnrc/ipv6/ipsec/ipsec_ts.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    IPSEC_SP_RULE_PROTECT,
    IPSEC_SP_RULE_BYPASS,
    IPSEC_SP_RULE_DROP,
    IPSEC_SP_RULE_ERROR,
} ipsec_sp_rule_t;

typedef struct {
    uint32_t reqid;   
} ipsec_sp_t;

ipsec_sp_rule_t ipsec_get_policy_rule(ipsec_ts_t *ts);

#ifdef __cplusplus
}
#endif

#endif /* NET_GNRC_IPV6_IPSEC_SPD_H */
