/*
 * Copyright (C) 2022 Juliusz Neuman
 */


#ifndef NET_GNRC_IPV6_IPSEC_TS_H
#define NET_GNRC_IPV6_IPSEC_TS_H


#include "net/gnrc/pkt.h"
#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
    uint16_t a;
} ipsec_ts_t;

int ipsec_ts_from_pkt(gnrc_pktsnip_t *pkt, ipsec_ts_t *ts);

#ifdef __cplusplus
}
#endif

#endif /* NET_GNRC_IPV6_IPSEC_TS_H */
