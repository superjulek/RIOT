/*
 * Copyright (C) 2022 Juliusz Neuman
 */

/**
 * @defgroup    net_gnrc_ipv6_ipsec IPSec implementation
 * @ingroup     net_gnrc_ipv6
 * @brief       Implementation of ESP IPSec
 * @see [RFC ____](https://tools.ietf.org/html/rfc___)
 * @{
 *
 * @file
 * @brief       Definititions for IPv6 IPSec
 *
 * @author      Juliusz Neuman <neuman.juliusz@gmail.com>
 */

#ifndef NET_GNRC_IPV6_IPSEC_H
#define NET_GNRC_IPV6_IPSEC_H


#include "net/gnrc/pkt.h"
#ifdef __cplusplus
extern "C" {
#endif

gnrc_pktsnip_t *process_esp_header(gnrc_pktsnip_t *pkt);

#ifdef __cplusplus
}
#endif

#endif /* NET_GNRC_IPV6_IPSEC_H */
