#ifndef NET_GNRC_IPV6_ESP_H
#define NET_GNRC_IPV6_ESP_H

#include <stdbool.h>

#include "sched.h"

#include "net/gnrc/ipv6/ipsec/config.h"

#ifdef __cplusplus
extern "C" {
#endif

gnrc_pktsnip_t *process_esp_header(gnrc_pktsnip_t *pkt);

#ifdef __cplusplus
}
#endif

#endif /* NET_GNRC_IPV6_ESP_H */
