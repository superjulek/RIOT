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
#include "ike/chunk.h"
#include "ike/ike_payloads.h"

#include <stdio.h>
#include <stdint.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/dh.h>
#include <wolfssl/wolfcrypt/hmac.h>

#include "net/gnrc/ipv6.h"
#include "net/gnrc/netif.h"
#include "net/gnrc/netif/hdr.h"
#include "net/gnrc/udp.h"
#include "net/gnrc/netreg.h"
#include "net/utils.h"
#include "xtimer.h"
#include "od.h"

#include "random.h"

#define IKE_NONCE_I_LEN 32
#define MSG_BUF_LEN 1280

#define ID_I "sun.strongswan.org"
#define PSK "This is a strong password"

typedef struct
{
    ike_state_t state;
    uint64_t ike_spi_i;
    uint64_t ike_spi_r;
    uint32_t child_spi_i;
    uint32_t child_spi_r;
    chunk_t ike_nonce_i;
    chunk_t ike_nonce_r;
    ike_transform_encr_t ike_encr;
    size_t ike_key_size;
    ike_transform_prf_t ike_prf;
    ike_transform_integ_t ike_integ;
    ike_transform_dh_t ike_dh;
    ike_transform_esn_t ike_esn;
    ike_transform_encr_t child_encr;
    size_t child_key_size;
    ike_transform_integ_t child_integ;
    ike_transform_esn_t child_esn;
    DhKey wc_priv_key;
    WC_RNG wc_rng;
    chunk_t pubkey_i;
    chunk_t privkey_i;
    chunk_t pubkey_r;
    chunk_t shared_secret;
    chunk_t skeyseed;
    chunk_t sk_d;
    chunk_t sk_ai;
    chunk_t sk_ar;
    chunk_t sk_ei;
    chunk_t sk_er;
    chunk_t sk_pi;
    chunk_t sk_pr;
    chunk_t id_i;
    chunk_t psk;
    chunk_t real_message_1;
    chunk_t real_message_2;
    struct {
        ipv6_addr_t start;
        ipv6_addr_t end;
    } local_ts;
    struct {
        ipv6_addr_t start;
        ipv6_addr_t end;
    } remote_ts;
    struct {
        ike_id_type_t type;
        chunk_t id;
    } remote_id;
} _ike_ctx_t;

static _ike_ctx_t ike_ctx;

static int _send_data(char *addr_str, char *data, size_t datalen);
static int _receive_data(char *addr_str, char *data, size_t *datalen, uint32_t timeout);
static int _init_context(void);
static int _reset_context(void);
static int _build_init_i(char *msg, size_t *msg_len);
static int _build_auth_i(char *msg, size_t *msg_len);
static int _parse_init_r(char *msg, size_t msg_len);
static int _parse_auth_r(char *msg, size_t msg_len);
static int _parse_auth_r_decrypted(char *msg, size_t msg_len, ike_payload_type_t first_type);
static int _generate_key(void);
static int _get_secrets(void);
static int _get_auth(chunk_t input, chunk_t *auth_data);
static int _prf(chunk_t key, chunk_t seed, chunk_t *out);
static int _prf_plus(chunk_t key, chunk_t seed, size_t len, chunk_t *out);
static int _generate_child_key(void);

static inline uint32_t untoh32(void *network)
{
    char *unaligned = (char *)network;
    uint32_t tmp;

    memcpy(&tmp, unaligned, sizeof(tmp));
    return ntohl(tmp);
}

int ike_init(char *addr_str)
{
    size_t len;
    char data_out[MSG_BUF_LEN];
    char data_in[MSG_BUF_LEN];
    uint32_t timeout = 5;
    if (ike_ctx.state != IKE_STATE_OFF)
    {
        if (_reset_context() < 0)
        {
            puts("Resetting IKE context failed");
            return -1;
        }
    }
    if (_init_context() < 0)
    {
        puts("Initiating IKE context failed");
        return -1;
    }
    if (_build_init_i(data_out, &len) < 0)
    {
        puts("Building IKE INIT message failed");
        return -1;
    }
    if (_send_data(addr_str, data_out, len) < 0)
    {
        puts("Sending IKE INIT message failed");
        return -1;
    }
    if (_receive_data(addr_str, data_in, &len, timeout) < 0)
    {
        puts("Receiving IKE INIT message failed");
        // TODO: retry
        return -1;
    }
    if (_parse_init_r(data_in, len) < 0)
    {
        puts("Parsing IKE INIT message failed");
        return -1;
    }
    if (_build_auth_i(data_out, &len) < 0)
    {
        puts("Building IKE AUTH message failed");
        return -1;
    }
    if (_send_data(addr_str, data_out, len) < 0)
    {
        puts("Sending IKE AUTH message failed");
        return -1;
    }
    if (_receive_data(addr_str, data_in, &len, timeout) < 0)
    {
        puts("Receiving IKE AUTH message failed");
        // TODO: retry
        return -1;
    }
    if (_parse_auth_r(data_in, len) < 0)
    {
        puts("Parsing IKE AUTH message failed");
        return -1;
    }
    if (_generate_child_key() < 0)
    {
        puts("Generating Child Keying material failed");
        return -1;
    }
    puts("Tunnel established");

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
    if (payload == NULL)
    {
        puts("Error: unable to copy data to packet buffer");
        return -1;
    }
    /* store size for output */
    payload_size = (unsigned)payload->size;
    /* allocate UDP header, set source port := destination port */
    udp = gnrc_udp_hdr_build(payload, port, port);
    if (udp == NULL)
    {
        puts("Error: unable to allocate UDP header");
        gnrc_pktbuf_release(payload);
        return -1;
    }
    /* allocate IPv6 header */
    ip = gnrc_ipv6_hdr_build(udp, NULL, &addr);
    if (ip == NULL)
    {
        puts("Error: unable to allocate IPv6 header");
        gnrc_pktbuf_release(udp);
        return -1;
    }
    /* send packet */
    if (!gnrc_netapi_dispatch_send(GNRC_NETTYPE_UDP,
                                   GNRC_NETREG_DEMUX_CTX_ALL, ip))
    {
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

static void _process_incoming(gnrc_pktsnip_t *pkt, chunk_t *recv_chunk)
{
    int snips = 0;
    int size = 0;
    gnrc_pktsnip_t *snip = pkt;
    // int address_ok = false;
    // uint64_t src_port = 0;

    while (snip != NULL)
    {
        printf("~~ SNIP %2i - size: %3u byte, type: ", snips, (unsigned int)snip->size);

        size_t hdr_len = 0;

        switch (snip->type)
        {
        case GNRC_NETTYPE_UDP:
            printf("NETTYPE_UDP (%i)\n", snip->type);
            if (IS_USED(MODULE_UDP))
            {
                udp_hdr_print(snip->data);
                hdr_len = sizeof(udp_hdr_t);
            }
            break;
        case GNRC_NETTYPE_IPV6:
            printf("NETTYPE_IPV6 (%i)\n", snip->type);
            if (IS_USED(MODULE_IPV6_HDR))
            {
                ipv6_hdr_print(snip->data);
                hdr_len = sizeof(ipv6_hdr_t);
            }
            break;
        case GNRC_NETTYPE_NETIF:
            printf("NETTYPE_NETIF (%i)\n", snip->type);
            if (IS_USED(MODULE_GNRC_NETIF_HDR))
            {
                gnrc_netif_hdr_print(snip->data);
                hdr_len = snip->size;
            }
            break;
        case GNRC_NETTYPE_UNDEF:
            printf("NETTYPE_UNDEF (%i)\n", snip->type);
            if (hdr_len < snip->size)
            {
                size_t data_size = snip->size - hdr_len;
                od_hex_dump(((uint8_t *)snip->data) + hdr_len, data_size, OD_WIDTH_DEFAULT);
                if (data_size <= MSG_BUF_LEN)
                {
                    memcpy(recv_chunk->ptr, snip->data, data_size);
                    recv_chunk->len = data_size;
                }
            }
            break;
        default:
            break;
        }

        ++snips;
        size += snip->size;
        snip = snip->next;
    }
    printf("~~ PKT    - %2i snips, total size: %3i byte\n", snips, size);
}

static void *_eventloop(void *arg)
{
    chunk_t *recv_chunk = (chunk_t *)arg;
    msg_t msg, reply;
    msg_t server_queue[1];

    /* setup the message queue */
    msg_init_queue(server_queue, 1);

    reply.content.value = (uint32_t)(-ENOTSUP);
    reply.type = GNRC_NETAPI_MSG_TYPE_ACK;

    while (1)
    {
        msg_receive(&msg);

        switch (msg.type)
        {
        case GNRC_NETAPI_MSG_TYPE_RCV:
            printf("Packets received");
            _process_incoming(msg.content.ptr, recv_chunk);
            gnrc_pktbuf_release(msg.content.ptr);
            break;
        case GNRC_NETAPI_MSG_TYPE_GET:
        case GNRC_NETAPI_MSG_TYPE_SET:
            msg_reply(&msg, &reply);
            break;
        default:
            break;
        }
    }

    /* never reached */
    return NULL;
}

static int _receive_data(char *addr_str, char *data, size_t *datalen, uint32_t timeout)
{
    (void)addr_str;
    uint16_t port = 500;
    chunk_t receive_chunk = {
        .ptr = data,
    };

    gnrc_netreg_entry_t server = GNRC_NETREG_ENTRY_INIT_PID(0, KERNEL_PID_UNDEF);
    kernel_pid_t server_pid = KERNEL_PID_UNDEF;
    static char server_stack[THREAD_STACKSIZE_MAIN];

    server_pid = thread_create(server_stack, sizeof(server_stack), THREAD_PRIORITY_MAIN - 1,
                               THREAD_CREATE_STACKTEST, _eventloop, (void *)&receive_chunk, "UDP server");
    if (server_pid <= KERNEL_PID_UNDEF)
    {
        puts("Error: can not start server thread");
        return -1;
    }
    /* register server to receive messages from given port */
    gnrc_netreg_entry_init_pid(&server, port, server_pid);
    gnrc_netreg_register(GNRC_NETTYPE_UDP, &server);
    printf("Waiting for message on port %" PRIu16 "\n", port);
    for (uint32_t i = 0; i < timeout; ++i)
    {
        xtimer_sleep(1);
        if (receive_chunk.len)
        {
            break;
        }
    }
    gnrc_netreg_unregister(GNRC_NETTYPE_UDP, &server);
    gnrc_netreg_entry_init_pid(&server, 0, KERNEL_PID_UNDEF);
    puts("Finished waiting");
    if (receive_chunk.len)
    {
        puts("Received data:");
        od_hex_dump(receive_chunk.ptr, receive_chunk.len, 0);
        *datalen = receive_chunk.len;
        return 0;
    }
    return -ENOMSG;
}

static int _reset_context(void)
{
    puts("Resetting IKE context");
    ike_ctx.state = IKE_STATE_OFF;
    ike_ctx.ike_spi_i = 0;
    ike_ctx.ike_spi_r = 0;
    ike_ctx.child_spi_i = 0;
    ike_ctx.child_spi_r = 0;
    free_chunk(&ike_ctx.ike_nonce_i);
    free_chunk(&ike_ctx.privkey_i);
    free_chunk(&ike_ctx.pubkey_i);
    free_chunk(&ike_ctx.shared_secret);
    free_chunk(&ike_ctx.skeyseed);
    free_chunk(&ike_ctx.sk_d);
    free_chunk(&ike_ctx.sk_ai);
    free_chunk(&ike_ctx.sk_ar);
    free_chunk(&ike_ctx.sk_ei);
    free_chunk(&ike_ctx.sk_er);
    free_chunk(&ike_ctx.sk_pi);
    free_chunk(&ike_ctx.sk_pr);
    free_chunk(&ike_ctx.id_i);
    free_chunk(&ike_ctx.psk);
    free_chunk(&ike_ctx.real_message_1);
    free_chunk(&ike_ctx.real_message_2);
    free_chunk(&ike_ctx.remote_id.id);
    wc_FreeDhKey(&ike_ctx.wc_priv_key);
    wc_FreeRng(&ike_ctx.wc_rng);

    return 0;
}

static int _init_context(void)
{
    puts("Initiating IKE context");

    /* Generate random values */
    uint64_t ike_spi_i;
    uint32_t child_spi_i;
    random_bytes((uint8_t *)&ike_spi_i, sizeof(uint64_t));
    printf("New IKE initiator SPI: 0x%llX\n", ike_spi_i);
    random_bytes((uint8_t *)&child_spi_i, sizeof(uint32_t));
    printf("New IKE initiator SPI: 0x%X\n", child_spi_i);

    chunk_t ike_nonce_i = malloc_chunk(IKE_NONCE_I_LEN);
    random_bytes((uint8_t *)ike_nonce_i.ptr, ike_nonce_i.len);
    printf("New IKE initiatior Nonce:");
    printf_chunk(ike_nonce_i, 8);

    chunk_t id_i = malloc_chunk(strlen(ID_I));
    memcpy(id_i.ptr, ID_I, id_i.len);

    chunk_t psk = malloc_chunk(strlen(PSK));
    memcpy(psk.ptr, PSK, psk.len);

    _ike_ctx_t new_ike_ctx = {
        .ike_spi_i = ike_spi_i,
        .child_spi_i = child_spi_i,
        .state = IKE_STATE_NEGOTIATION,
        .ike_nonce_i = ike_nonce_i,
        .ike_encr = IKE_TRANSFORM_ENCR_AES_CBC,
        .ike_key_size = 128,
        .ike_prf = IKE_TRANSFORM_PRF_HMAC_SHA1,
        .ike_integ = IKE_TRANSFORM_AUTH_HMAC_SHA1_96,
        .child_encr = IKE_TRANSFORM_ENCR_AES_CBC,
        .child_key_size = 128,
        .child_integ = IKE_TRANSFORM_AUTH_HMAC_SHA1_96,
        .ike_dh = IKE_TRANSFORM_MODP2048,
        .ike_esn = IKE_TRANSFORM_ESN_OFF,
        .id_i = id_i,
        .psk = psk,
    };
    ike_ctx = new_ike_ctx;
    _generate_key(); // TODO: check fail
    return 0;
}

static int _build_init_i(char *msg, size_t *msg_len)
{
    size_t cur_len = 0;
    size_t new_len;
    int error;

    /* Construct IKE header */
    ike_header_t hdr = {
        .ike_sa_spi_i = htonll(ike_ctx.ike_spi_i),
        .ike_sa_spi_r = 0,
        .next_payload = IKE_PT_SECURITY_ASSOCIATION,
        .mjver_mnver = IKE_V2_MJVER | IKE_V2_MNVER,
        .exchange_type = IKE_ET_IKE_SA_INIT,
        .flags = IKE_INITIATOR_FLAG,
        .message_id = htonl(0),
        .length = 0,
    };
    cur_len += sizeof(hdr);

    /* Construct SA payload */
    error = build_sa_payload(msg + cur_len, MSG_BUF_LEN - cur_len, &new_len, IKE_PT_NONCE, IKE_PROTO_IKE, ike_ctx.ike_encr,
                             ike_ctx.ike_prf, ike_ctx.ike_integ, ike_ctx.ike_dh, ike_ctx.ike_esn, ike_ctx.ike_key_size, empty_chunk);
    if (error < 0)
        return error;
    cur_len += new_len;

    /* Construct Nonce payload */
    error = build_nonce_payload(msg + cur_len, MSG_BUF_LEN - cur_len, &new_len, IKE_PT_KEY_EXCHANGE, ike_ctx.ike_nonce_i);
    if (error < 0)
        return error;
    cur_len += new_len;

    /* Construct Key Exchange payload */
    error = build_key_exchange_payload(msg + cur_len, MSG_BUF_LEN - cur_len, &new_len, IKE_PT_NO_NEXT_PAYLOAD, ike_ctx.ike_dh, ike_ctx.pubkey_i);
    if (error < 0)
        return error;
    cur_len += new_len;

    /* Prepend header */
    hdr.length = htonl(cur_len);
    memcpy(msg, &hdr, sizeof(hdr));
    *msg_len = cur_len;

    ike_ctx.real_message_1 = malloc_chunk(cur_len);
    memcpy(ike_ctx.real_message_1.ptr, msg, ike_ctx.real_message_1.len);

    return 0;
}

static int _parse_init_r(char *msg, size_t msg_len)
{
    size_t remaining_len = msg_len;
    char *p = msg;
    ike_header_t *ike_hdr;
    size_t cur_len;
    ike_payload_type_t next_type;
    if (msg_len < sizeof(ike_header_t))
    {
        puts("Message too short");
        return -EMSGSIZE;
    }
    ike_hdr = (ike_header_t *)p;
    if (ntohl(ike_hdr->length) != msg_len)
    {
        puts("Message length mismatch");
        return -EMSGSIZE;
    }
    if (ike_ctx.ike_spi_i != ntohll(ike_hdr->ike_sa_spi_i))
    {
        puts("SPI mismatch");
        return -EPROTO;
    }
    ike_ctx.ike_spi_r = ntohll(ike_hdr->ike_sa_spi_r);
    // TODO: more checks
    next_type = ike_hdr->next_payload;
    remaining_len -= sizeof(ike_header_t);
    p += sizeof(ike_header_t);
    while (remaining_len > 0)
    {
        switch (next_type)
        {
        case IKE_PT_NONCE:
            if (process_nonce_payload(p, remaining_len, &cur_len, &next_type, &ike_ctx.ike_nonce_r) < 0)
            {
                puts("Nonce payload parsing failed");
                return -1;
            }
            printf("Parsed nonce payload of size %u\n", cur_len);
            printf_chunk(ike_ctx.ike_nonce_r, 4);
            break;
        case IKE_PT_SECURITY_ASSOCIATION:
            if (process_sa_payload(p, remaining_len, &cur_len, &next_type, NULL, NULL, NULL, 
                NULL, NULL, NULL, NULL, NULL) < 0)
            {
                puts("Nonce payload parsing failed");
                return -1;
            }
            printf("Parsed nonce payload of size %u\n", cur_len);
            printf_chunk(ike_ctx.ike_nonce_r, 4);
            break;
        case IKE_PT_KEY_EXCHANGE:
        {
        }
            ike_transform_dh_t dh_r;
            if (process_key_exchange_payload(p, remaining_len, &cur_len, &next_type, &dh_r, &ike_ctx.pubkey_r))
            {
                puts("Nonce payload parsing failed");
                return -1;
            }
            printf("Parsed key exchange payload of size %u\n", cur_len);
            printf_chunk(ike_ctx.pubkey_r, 8);
            break;
        default:
            if (process_unknown_payload(p, remaining_len, &cur_len, &next_type) < 0)
            {
                puts("Unknown payload parsing failed");
                return -1;
            }
            printf("Parsed unknown payload of size %u\n", cur_len);
        }
        remaining_len -= cur_len;
        p += cur_len;
    }
    if (_get_secrets() < 0)
    {
        puts("Getting secrets failed");
    }
    ike_ctx.real_message_2 = malloc_chunk(msg_len);
    memcpy(ike_ctx.real_message_2.ptr, msg, msg_len);
    return 0;
}

static int _build_auth_i(char *msg, size_t *msg_len)
{
    size_t cur_len = 0;
    size_t new_len;
    int error;

    /* Construct IKE header */
    ike_header_t hdr = {
        .ike_sa_spi_i = htonll(ike_ctx.ike_spi_i),
        .ike_sa_spi_r = htonll(ike_ctx.ike_spi_r),
        .next_payload = IKE_PT_ENCRYPTED_AND_AUTHENTICATED,
        .mjver_mnver = IKE_V2_MJVER | IKE_V2_MNVER,
        .exchange_type = IKE_ET_IKE_AUTH,
        .flags = IKE_INITIATOR_FLAG,
        .message_id = htonl(1),
    };
    memcpy(msg, &hdr, sizeof(hdr));
    cur_len += sizeof(hdr);

    /* Construct Identification payload */
    error = build_identification_payload(msg + cur_len, MSG_BUF_LEN - cur_len, &new_len, IKE_PT_AUTHENTICATION, IKE_ID_TYPE_FQDN, ike_ctx.id_i);
    if (error < 0)
        return error;
    cur_len += new_len;

    /* Construct Authentication payload */
    chunk_t authed_data;
    chunk_t auth_data = malloc_chunk(ike_ctx.real_message_1.len + ike_ctx.ike_nonce_r.len + HASH_SIZE_SHA1);
    memcpy(auth_data.ptr, ike_ctx.real_message_1.ptr, ike_ctx.real_message_1.len);
    memcpy(auth_data.ptr + ike_ctx.real_message_1.len, ike_ctx.ike_nonce_r.ptr, ike_ctx.ike_nonce_r.len);
    chunk_t idx = {.len = new_len - sizeof(ike_generic_payload_header_t), .ptr = msg + cur_len - new_len + sizeof(ike_generic_payload_header_t)};
    chunk_t maced_id;
    error = _prf(ike_ctx.sk_pi, idx, &maced_id);
    if (error < 0)
    {
        free_chunk(&auth_data);
        return error;
    }
    memcpy(auth_data.ptr + ike_ctx.real_message_1.len + ike_ctx.ike_nonce_r.len, maced_id.ptr, maced_id.len);
    free_chunk(&maced_id);
    error = _get_auth(auth_data, &authed_data);
    free_chunk(&auth_data);
    if (error < 0)
        return error;
    error = build_auth_payload(msg + cur_len, MSG_BUF_LEN - cur_len, &new_len, IKE_PT_SECURITY_ASSOCIATION, IKE_AUTH_METHOD_PSK, authed_data);
    free_chunk(&authed_data);
    if (error < 0)
        return error;
    cur_len += new_len;

    /* Construct SA payload */
    uint32_t n_spi = htonl(ike_ctx.child_spi_i);
    error = build_sa_payload(msg + cur_len, MSG_BUF_LEN - cur_len, &new_len, IKE_PT_TRAFFIC_SELECTOR_I, IKE_PROTO_ESP, ike_ctx.child_encr, 0, ike_ctx.child_integ, 0, IKE_TRANSFORM_ESN_OFF, ike_ctx.child_key_size, (chunk_t){.ptr = (char *)&n_spi, .len = sizeof(n_spi)});
    if (error < 0)
        return error;
    cur_len += new_len;

    /* Construct TSi payload */
    error = build_ts_payload(msg + cur_len, MSG_BUF_LEN - cur_len, &new_len, IKE_PT_TRAFFIC_SELECTOR_R);
    if (error < 0)
        return error;
    cur_len += new_len;

    /* Construct TSr payload */
    error = build_ts_payload(msg + cur_len, MSG_BUF_LEN - cur_len, &new_len, IKE_PT_NO_NEXT_PAYLOAD);
    if (error < 0)
        return error;
    cur_len += new_len;

    /* Construct Encrypted payload */
    chunk_t enc_in = {
        .ptr = msg + sizeof(hdr),
        .len = cur_len - sizeof(hdr),
    };
    error = build_encrypted_payload(msg + sizeof(hdr), MSG_BUF_LEN - sizeof(hdr), &new_len, IKE_PT_IDENTIFICATION_I,
                                    enc_in, ike_ctx.sk_ei, ike_ctx.sk_ai);
    if (error < 0)
        return error;

    *msg_len = sizeof(hdr) + new_len;
    return 0;
}

static int _parse_auth_r(char *msg, size_t msg_len)
{
    size_t remaining_len = msg_len;
    char *p = msg;
    ike_header_t *ike_hdr;
    size_t cur_len;
    ike_payload_type_t next_type;
    chunk_t decrypted_msg;
    int error;
    if (msg_len < sizeof(ike_header_t))
    {
        puts("Message too short");
        return -EMSGSIZE;
    }
    ike_hdr = (ike_header_t *)p;
    if (ntohl(ike_hdr->length) != msg_len)
    {
        puts("Message length mismatch");
        return -EMSGSIZE;
    }
    if (ike_ctx.ike_spi_r != ntohll(ike_hdr->ike_sa_spi_r) || ike_ctx.ike_spi_i != ntohll(ike_hdr->ike_sa_spi_i))
    {
        puts("SPI mismatch");
        return -EPROTO;
    }
    // TODO: more checks
    next_type = ike_hdr->next_payload;
    remaining_len -= sizeof(ike_header_t);
    p += sizeof(ike_header_t);
    error = process_encrypted_payload(p, remaining_len, &cur_len, &next_type, &decrypted_msg, ike_ctx.sk_er, ike_ctx.sk_ar);
    if (error)
    {
        puts("Payload decryption failed");
        return -EBADMSG;
    }
    puts("Decrypted data:");
    printf_chunk(decrypted_msg, 8);
    if (_parse_auth_r_decrypted(decrypted_msg.ptr, decrypted_msg.len, next_type))
    {
        puts("Parsing decrypted content failed");
        return -EBADMSG;
    }
    free_chunk(&decrypted_msg);
    return 0;
}

static int _parse_auth_r_decrypted(char *msg, size_t msg_len, ike_payload_type_t first_type)
{
    ike_payload_type_t next_type = first_type;
    size_t remaining_len = msg_len;
    char *p = msg;
    size_t cur_len;
    chunk_t idx = empty_chunk;
    chunk_t auth_data_recv = {.len = HASH_SIZE_SHA1};
    auth_data_recv.ptr = alloca(auth_data_recv.len);

    while (remaining_len > 0)
    {
        switch (next_type)
        {
            case IKE_PT_SECURITY_ASSOCIATION:
                if (process_sa_payload(p, remaining_len, &cur_len, &next_type, NULL, NULL, NULL,
                    NULL, NULL, NULL, NULL, NULL) < 0)
                {
                    puts("SA payload parsing failed");
                    return -1;
                }
                break;
            case IKE_PT_IDENTIFICATION_R:
                if (process_identification_payload(p, remaining_len, &cur_len, &next_type, &ike_ctx.remote_id.type, &ike_ctx.remote_id.id) < 0)
                {
                    puts("ID payload parsing failed");
                    return -1;
                }
                idx.len = cur_len - sizeof(ike_generic_payload_header_t);
                idx.ptr = alloca(idx.len);
                memcpy(idx.ptr, p + sizeof(ike_generic_payload_header_t), idx.len);
                printf("Received ID (%d):\n", ike_ctx.remote_id.type);
                printf_chunk(ike_ctx.remote_id.id, 8);
                printf("%.*s\n", ike_ctx.remote_id.id.len, ike_ctx.remote_id.id.ptr);
                break;
            case IKE_PT_AUTHENTICATION:
                {}
                ike_auth_method_t auth_method;
                if (process_auth_payload(p, remaining_len, &cur_len, &next_type, &auth_method, &auth_data_recv) < 0)
                {
                    puts("AUTH payload parsing failed");
                    return -1;
                }
                if (auth_method != IKE_AUTH_METHOD_PSK)
                {
                    puts("Unsupported AUTH method");
                    return -1;
                }
                break;
            case IKE_PT_TRAFFIC_SELECTOR_I:
                if (process_ts_payload(p, remaining_len, &cur_len, &next_type, &ike_ctx.local_ts.start, &ike_ctx.local_ts.end) < 0)
                {
                    puts("TSi payload parsing failed");
                    return -1;
                }
                puts("Received TSi");
                puts("From:");
                od_hex_dump(&ike_ctx.local_ts.start, 16, 16);
                puts("To:");
                od_hex_dump(&ike_ctx.local_ts.end, 16, 16);
                break;
            case IKE_PT_TRAFFIC_SELECTOR_R:
                if (process_ts_payload(p, remaining_len, &cur_len, &next_type, &ike_ctx.remote_ts.start, &ike_ctx.remote_ts.end) < 0)
                {
                    puts("TSr payload parsing failed");
                    return -1;
                }
                puts("Received TSi");
                puts("From:");
                od_hex_dump(&ike_ctx.remote_ts.start, 16, 16);
                puts("To:");
                od_hex_dump(&ike_ctx.remote_ts.end, 16, 16);
                break;
            default:
                if (process_unknown_payload(p, remaining_len, &cur_len, &next_type) < 0)
                {
                    puts("Unknown payload parsing failed");
                    return -1;
                }
                printf("Parsed unknown payload of size %u\n", cur_len);
            }
        remaining_len -= cur_len;
        p += cur_len;
    }
    // verify
    /* Construct Authentication */
    chunk_t authed_data;
    chunk_t auth_data = {.len = (ike_ctx.real_message_2.len + ike_ctx.ike_nonce_i.len + HASH_SIZE_SHA1)};
    auth_data.ptr = alloca(auth_data.len);
    chunk_t maced_id;
    if (_prf(ike_ctx.sk_pr, idx, &maced_id) < 0)
    {
        return -1;
    }
    memcpy(auth_data.ptr, ike_ctx.real_message_2.ptr, ike_ctx.real_message_2.len);
    memcpy(auth_data.ptr + ike_ctx.real_message_2.len, ike_ctx.ike_nonce_i.ptr, ike_ctx.ike_nonce_i.len);
    memcpy(auth_data.ptr + ike_ctx.real_message_2.len + ike_ctx.ike_nonce_i.len, maced_id.ptr, maced_id.len);
    free_chunk(&maced_id);
    if (_get_auth(auth_data, &authed_data) < 0)
    {
        return -1;
    }
    if (authed_data.len != auth_data_recv.len || memcmp(authed_data.ptr, auth_data_recv.ptr, authed_data.len))
    {
        puts("Authentication failed");
        return -1;
    }
    return 0;
}

static int _generate_child_key(void)
{
    chunk_t enc_i = {.len = 16, .ptr = alloca(16)};
    chunk_t int_i = {.len = 20, .ptr = alloca(20)};
    chunk_t enc_r = {.len = 16, .ptr = alloca(16)};
    chunk_t int_r = {.len = 20, .ptr = alloca(20)};
    chunk_t parts[] = {enc_i, int_i, enc_r, int_r};
    chunk_t nonces = {.len = ike_ctx.ike_nonce_i.len + ike_ctx.ike_nonce_r.len};
    chunk_t out;
    nonces.ptr = alloca(nonces.len);
    memcpy(nonces.ptr, ike_ctx.ike_nonce_i.ptr, ike_ctx.ike_nonce_i.len);
    memcpy(nonces.ptr + ike_ctx.ike_nonce_i.len, ike_ctx.ike_nonce_r.ptr, ike_ctx.ike_nonce_r.len);
    if (_prf_plus(ike_ctx.sk_d, nonces, 72, &out) < 0)
    {
        return -1;
    }
    puts("Generated keying material");
    printf_chunk(out, 8);
    char *p = out.ptr;
    for (size_t i = 0; i < countof(parts); ++i)
    {
        chunk_t part = parts[i];
        memcpy(part.ptr, p, part.len);
        p += part.len;
    }
    puts("Encryption Initiator");
    printf_chunk(enc_i, 8);
    puts("Encryption Responder");
    printf_chunk(enc_r, 8);
    puts("Integrity Initiator");
    printf_chunk(int_i, 8);
    puts("Integrity Responder");
    printf_chunk(int_r, 8);
    free_chunk(&out);
    return 0;
}
static int _generate_key(void)
{
    const u_char p[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
                        0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
                        0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
                        0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
                        0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
                        0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
                        0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
                        0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D, 0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
                        0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
                        0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
                        0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D, 0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
                        0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
                        0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
                        0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9, 0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
                        0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
                        0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    const u_char g[] = {0x02};
    ike_ctx.pubkey_i = malloc_chunk(256);
    ike_ctx.privkey_i = malloc_chunk(29);

    if (wc_InitRng(&ike_ctx.wc_rng) != 0)
    {
        return -1;
    }
    if (wc_InitDhKey(&ike_ctx.wc_priv_key) != 0)
    {
        wc_FreeRng(&ike_ctx.wc_rng);
        return -1;
    }
    if (wc_DhSetKey(&ike_ctx.wc_priv_key, p, sizeof(p), g, sizeof(g)) != 0)
    {
        wc_FreeRng(&ike_ctx.wc_rng);
        wc_FreeDhKey(&ike_ctx.wc_priv_key);
        return -1;
    }
    if (wc_DhGenerateKeyPair(&ike_ctx.wc_priv_key, &ike_ctx.wc_rng, (u_char *)ike_ctx.privkey_i.ptr, &ike_ctx.privkey_i.len,
                             (u_char *)ike_ctx.pubkey_i.ptr, &ike_ctx.pubkey_i.len) != 0)
    {
        wc_FreeRng(&ike_ctx.wc_rng);
        wc_FreeDhKey(&ike_ctx.wc_priv_key);
        return -1;
    }
    puts("Pub:");
    printf_chunk(ike_ctx.pubkey_i, 8);
    puts("Priv:");
    printf_chunk(ike_ctx.privkey_i, 8);
    return 0;
}

static int _get_secrets(void)
{
    ike_ctx.shared_secret = malloc_chunk(ike_ctx.pubkey_i.len);
    word32 len;
    if (wc_DhAgree(&ike_ctx.wc_priv_key, (u_char *)ike_ctx.shared_secret.ptr, &len,
                   (u_char *)ike_ctx.privkey_i.ptr, ike_ctx.privkey_i.len,
                   (u_char *)ike_ctx.pubkey_r.ptr, ike_ctx.pubkey_r.len) != 0)
    {
        puts("Getting shared secret failed");
        return -1;
    }
    ike_ctx.shared_secret.len = len;
    puts("Shared secret:");
    printf_chunk(ike_ctx.shared_secret, 8);
    chunk_t nonce_concat = malloc_chunk(ike_ctx.ike_nonce_i.len + ike_ctx.ike_nonce_r.len);
    memcpy(nonce_concat.ptr, ike_ctx.ike_nonce_i.ptr, ike_ctx.ike_nonce_i.len);
    memcpy(nonce_concat.ptr + ike_ctx.ike_nonce_i.len, ike_ctx.ike_nonce_r.ptr, ike_ctx.ike_nonce_r.len);
    if (_prf(nonce_concat, ike_ctx.shared_secret, &ike_ctx.skeyseed) != 0)
    {
        puts("Computing SKEYSEED failed");
        free_chunk(&nonce_concat);
        return -1;
    }
    free_chunk(&nonce_concat);
    puts("SKEYSEED:");
    printf_chunk(ike_ctx.skeyseed, 8);
    chunk_t crypto_concat = empty_chunk;
    chunk_t ni_nr_spi_spr = malloc_chunk(ike_ctx.ike_nonce_i.len + ike_ctx.ike_nonce_r.len + sizeof(ike_ctx.ike_spi_i) + sizeof(ike_ctx.ike_spi_r));
    uint64_t n_ike_spi_i = htonll(ike_ctx.ike_spi_i);
    uint64_t n_ike_spi_r = htonll(ike_ctx.ike_spi_r);
    memcpy(ni_nr_spi_spr.ptr, ike_ctx.ike_nonce_i.ptr, ike_ctx.ike_nonce_i.len);
    memcpy(ni_nr_spi_spr.ptr + ike_ctx.ike_nonce_i.len, ike_ctx.ike_nonce_r.ptr, ike_ctx.ike_nonce_r.len);
    memcpy(ni_nr_spi_spr.ptr + ike_ctx.ike_nonce_i.len + ike_ctx.ike_nonce_r.len, &n_ike_spi_i, sizeof(ike_ctx.ike_spi_i));
    memcpy(ni_nr_spi_spr.ptr + ike_ctx.ike_nonce_i.len + ike_ctx.ike_nonce_r.len + sizeof(ike_ctx.ike_spi_i), &n_ike_spi_r, sizeof(ike_ctx.ike_spi_r));

    if (_prf_plus(ike_ctx.skeyseed, ni_nr_spi_spr, 5 * KEY_SIZE_SHA1 + 2 * (ike_ctx.ike_key_size / 8), &crypto_concat) != 0)
    {
        free_chunk(&ni_nr_spi_spr);
        return -1;
    }
    ike_ctx.sk_d = malloc_chunk(KEY_SIZE_SHA1);
    ike_ctx.sk_ai = malloc_chunk(KEY_SIZE_SHA1);
    ike_ctx.sk_ar = malloc_chunk(KEY_SIZE_SHA1);
    ike_ctx.sk_ei = malloc_chunk(ike_ctx.ike_key_size / 8);
    ike_ctx.sk_er = malloc_chunk(ike_ctx.ike_key_size / 8);
    ike_ctx.sk_pi = malloc_chunk(KEY_SIZE_SHA1);
    ike_ctx.sk_pr = malloc_chunk(KEY_SIZE_SHA1);
    chunk_t *parts[] = {
        &ike_ctx.sk_d,
        &ike_ctx.sk_ai,
        &ike_ctx.sk_ar,
        &ike_ctx.sk_ei,
        &ike_ctx.sk_er,
        &ike_ctx.sk_pi,
        &ike_ctx.sk_pr,
    };
    const char *parts_names[] = {
        "SK_d",
        "SK_ai",
        "SK_ar",
        "SK_ei",
        "SK_er",
        "SK_pi",
        "SK_pr",
    };
    char *p = crypto_concat.ptr;
    for (u_int i = 0; i < sizeof(parts) / sizeof(*parts); ++i)
    {
        chunk_t *part = parts[i];
        memcpy(part->ptr, p, part->len);
        p += part->len;
        puts(parts_names[i]);
        printf_chunk(*part, 8);
    }

    free_chunk(&ni_nr_spi_spr);
    free_chunk(&crypto_concat);

    return 0;
}

static int _get_auth(chunk_t input, chunk_t *auth_data)
{
    chunk_t inner_key;
    char pad_text[] = "Key Pad for IKEv2";
    chunk_t textc = {.ptr = pad_text, .len = strlen(pad_text)};

    if (_prf(ike_ctx.psk, textc, &inner_key) != 0)
    {
        return -1;
    }
    if (_prf(inner_key, input, auth_data) != 0)
    {
        free_chunk(&inner_key);
        return -1;
    }
    return 0;
}

static int _prf(chunk_t key, chunk_t seed, chunk_t *out)
{
    Hmac hmac;
    if (wc_HmacInit(&hmac, NULL, INVALID_DEVID) != 0)
        return -1;
    if (wc_HmacSetKey(&hmac, WC_HASH_TYPE_SHA, (u_char *)key.ptr, key.len) != 0)
        return -1;
    if (wc_HmacUpdate(&hmac, (u_char *)seed.ptr, seed.len) != 0)
        return -1;
    *out = malloc_chunk(HASH_SIZE_SHA1);
    if (wc_HmacFinal(&hmac, (u_char *)out->ptr) != 0)
    {
        free_chunk(out);
        return -1;
    }
    wc_HmacFree(&hmac);
    return 0;
}

static int _prf_plus(chunk_t key, chunk_t seed, size_t len, chunk_t *out)
{
    uint8_t cnt = 0x01;
    chunk_t ret = empty_chunk;
    int ret_code = -1;
    chunk_t first_seed = malloc_chunk(seed.len + 1);
    chunk_t next_seed = malloc_chunk(HASH_SIZE_SHA1 + seed.len + 1);
    memcpy(first_seed.ptr, seed.ptr, seed.len);
    memcpy(first_seed.ptr + seed.len, &cnt, 1);
    memcpy(next_seed.ptr + HASH_SIZE_SHA1, seed.ptr, seed.len);
    chunk_t t = empty_chunk;
    if (_prf(key, first_seed, &t) != 0)
        goto exit;
    ret = malloc_chunk(t.len);
    memcpy(ret.ptr, t.ptr, t.len);
    while (ret.len < len)
    {
        cnt++;
        memcpy(next_seed.ptr, t.ptr, t.len);
        memcpy(next_seed.ptr + HASH_SIZE_SHA1 + seed.len, &cnt, 1);
        free_chunk(&t);
        if (_prf(key, next_seed, &t) != 0)
            goto exit;
        ret.ptr = realloc(ret.ptr, ret.len + HASH_SIZE_SHA1);
        memcpy(ret.ptr + ret.len, t.ptr, t.len);
        ret.len += HASH_SIZE_SHA1;
    }
    *out = ret;
    ret_code = 0;
exit:
    free_chunk(&first_seed);
    free_chunk(&next_seed);
    free_chunk(&t);
    return ret_code;
}
