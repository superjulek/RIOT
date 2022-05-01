/**
 * Print thread information.
 *
 * Copyright (C) 2013, INRIA.
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * @ingroup sys_ps
 * @{
 * @file
 * @brief   IKE
 * @author      Juliusz Neuman <superjulek@interia.pl>
 * @}
 */

#include "ike/ike.h"
#include "ike/ike_structures.h"

#include <stdio.h>
#include <stdint.h>


#include "net/gnrc/ipv6.h"
#include "net/gnrc/netif.h"
#include "net/gnrc/netif/hdr.h"
#include "net/gnrc/udp.h"
#include "net/gnrc/netreg.h"
#include "net/utils.h"

#include "random.h"

#define IKE_NONCE_I_LEN 16

typedef struct {
    size_t len;
    char *ptr;
} chunk_t;

inline void free_chunk(chunk_t *chunk)
{
    if (chunk->len)
    {
        free(chunk->ptr);
    }
}

inline chunk_t malloc_chunk(size_t size)
{
    chunk_t chunk = {
        .len = size,
        .ptr = malloc(size),
    };
    return chunk;
}

inline void printf_chunk(chunk_t chunk)
{
    printf("0x");
    for (int i = 0; i < (int)chunk.len; ++i)
    {
        printf("%02X ", *(chunk.ptr + i) & 0xff);
    }
}

typedef struct {
    ike_state_t state;
    uint64_t ike_spi_i;
    uint64_t ike_spi_r;
    chunk_t ike_nonce_i;
} _ike_ctx_t;

static _ike_ctx_t ike_ctx;

static int _send_data(char *addr_str, char *data, size_t datalen);
static int _init_context(void);
static int _reset_context(void);
static int _build_init_i(char **msg, size_t *msg_len);


int ike_init(char *addr_str)
{
    if (ike_ctx.state != IKE_STATE_OFF)
    {
        if (_reset_context() < 0)
        {
            puts("Resetting IKE context failed");
        }
    }
    if (_init_context() < 0)
    {
        puts("Initiating IKE context failed");
    }
    size_t len;
    char *data;
    if (_build_init_i(&data, &len) < 0)
    {
        return -1;
    }
    _send_data(addr_str, data, len);
    free(data);

    return 0;
}


static int _send_data(char *addr_str, char *data, size_t datalen)
{
    netif_t *netif;
    uint16_t port = 500;
    ipv6_addr_t addr;

    /* parse destination address */
    if (netutils_get_ipv6(&addr, &netif, addr_str) < 0)
    {
        puts("Error: unable to parse destination address");
        return -1;
    }

    gnrc_pktsnip_t *payload, *udp, *ip;
    unsigned payload_size;
    /* allocate payload */
    payload = gnrc_pktbuf_add(NULL, data, datalen, GNRC_NETTYPE_UNDEF);
    if (payload == NULL) {
        puts("Error: unable to copy data to packet buffer");
        return -1;
    }
    /* store size for output */
    payload_size = (unsigned)payload->size;
    /* allocate UDP header, set source port := destination port */
    udp = gnrc_udp_hdr_build(payload, port, port);
    if (udp == NULL) {
        puts("Error: unable to allocate UDP header");
        gnrc_pktbuf_release(payload);
        return -1;
    }
    /* allocate IPv6 header */
    ip = gnrc_ipv6_hdr_build(udp, NULL, &addr);
    if (ip == NULL) {
        puts("Error: unable to allocate IPv6 header");
        gnrc_pktbuf_release(udp);
        return -1;
    }
    /* send packet */
    if (!gnrc_netapi_dispatch_send(GNRC_NETTYPE_UDP,
                                   GNRC_NETREG_DEMUX_CTX_ALL, ip)) {
        puts("Error: unable to locate UDP thread");
        gnrc_pktbuf_release(ip);
        return -1;
    }
    /* access to `payload` was implicitly given up with the send operation
     * above
     * => use temporary variable for output */
    printf("Success: sent %u byte(s) to [%s]:%u\n", payload_size, addr_str,
           port);
    return 0;
}

static int _reset_context(void)
{
    puts("Resetting IKE context");
    ike_ctx.state = IKE_STATE_OFF;
    ike_ctx.ike_spi_i = 0;
    ike_ctx.ike_spi_r = 0;
    free_chunk(&ike_ctx.ike_nonce_i);
    return 0;
}

static int _init_context(void)
{
    puts("Initiating IKE context");
    /* Generate random values */
    uint64_t spi_i;
    random_bytes((uint8_t *)&spi_i, sizeof(uint64_t));
    chunk_t ike_nonce_i = malloc_chunk(IKE_NONCE_I_LEN);
    random_bytes((uint8_t *)ike_nonce_i.ptr, ike_nonce_i.len);
    printf("New IKE initiator SPI: 0x%llX\n", spi_i);
    printf("New IKE initiatior Nonce: ");
    printf_chunk(ike_nonce_i);
    puts("");
    _ike_ctx_t new_ike_ctx = {
        .ike_spi_i = spi_i,
        .state = IKE_STATE_NEGOTIATION,
        .ike_nonce_i = ike_nonce_i,
    };
    ike_ctx = new_ike_ctx;
    return 0;
}

static int _build_init_i(char **msg, size_t *msg_len)
{
    /* Construct IKE header */
    ike_header_t hdr = {
        .ike_sa_spi_i = htonll(ike_ctx.ike_spi_i),
        .ike_sa_spi_r = 0,
        .next_payload = IKE_PT_NONCE,
        .mjver_mnver = IKE_V2_MJVER | IKE_V2_MNVER,
        .exchange_type = IKE_ET_IKE_SA_INIT,
        .flags = IKE_INITIATOR_FLAG,
        .message_id = 0,
        .length = 0,
    };
    *msg_len = sizeof(ike_header_t);
    /* Contruct Nonce payload */
    ike_nonce_payload_t nonce_p = {
        .hdr = {
            .next_payload = IKE_PT_NO_NEXT_PAYLOAD,
            .critical_reserved = 0,
            .payload_length = htons(offsetof(ike_nonce_payload_t, nonce_data) + ike_ctx.ike_nonce_i.len),
        },
        .nonce_data = ike_ctx.ike_nonce_i.ptr,
    };
    *msg_len += ntohs(nonce_p.hdr.payload_length);
    /**/
    /* Build messsage */
    hdr.length = htonl(*msg_len);
    *msg = malloc(*msg_len);
    char *p = *msg;
    memcpy(p, &hdr, sizeof(ike_header_t));
    p += sizeof(ike_header_t);
    memcpy(p, (char *)&nonce_p, offsetof(ike_nonce_payload_t, nonce_data));
    p += offsetof(ike_nonce_payload_t, nonce_data);
    memcpy(p, nonce_p.nonce_data, ike_ctx.ike_nonce_i.len);
    return 0;
}