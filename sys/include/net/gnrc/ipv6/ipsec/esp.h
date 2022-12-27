#ifndef NET_GNRC_IPV6_ESP_H
#define NET_GNRC_IPV6_ESP_H

#include <stdbool.h>

#include "sched.h"
#include "net/gnrc/pkt.h"

#include "net/gnrc/ipv6/ipsec/config.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
* @brief Data type to represent an ESP packet header.
*/
typedef struct __attribute__((packed)) {
	network_uint32_t spi;
	network_uint32_t sn;
} ipv6_esp_hdr_t;

/**
 * @brief Data type to represent an ESP packet trailer.
*/
typedef struct __attribute__((packed)) {
	uint8_t pl;
	uint8_t nh;
} ipv6_esp_trl_t;

/**
* @brief   Marks, Decrypts and returns pkt at next header. If the ipsec rules
             dictate tunnel mode, packet is consumed and processed.
*
* @param[in] pktsnip at ESP EXT header
*
* @return  processed ESP pkt at next header poisition
* @return  NULL on tunnel mode
*/
gnrc_pktsnip_t *esp_header_process(gnrc_pktsnip_t *pkt, uint8_t protnum);
#ifdef __cplusplus
}
#endif

#endif /* NET_GNRC_IPV6_ESP_H */
