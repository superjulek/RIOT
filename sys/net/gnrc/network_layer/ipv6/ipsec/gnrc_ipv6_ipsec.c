#include <assert.h>

#include "sched.h"
#include "net/gnrc.h"
#include "thread.h"
#include "utlist.h"

#include "net/gnrc/ipv6/ipsec/esp.h"
#include "net/gnrc/ipv6/ipsec/ipsec.h"
#include "net/gnrc/ipv6/ipsec/ipsec_db.h"
#include "net/gnrc/ipv6/hdr.h"
#include "net/gnrc/netif.h"
#include "net/gnrc/ipv6.h"
#include "net/esp.h"
#include "net/gnrc/ipv6/ext.h"

#define ENABLE_DEBUG 1
#include "debug.h"

static kernel_pid_t _pid = KERNEL_PID_UNDEF;

static char _stack[GNRC_IPV6_IPSEC_STACK_SIZE + DEBUG_EXTRA_STACKSIZE];

/* handles GNRC_NETAPI_MSG_TYPE_RCV commands */
static void _receive(gnrc_pktsnip_t *pkt);
/* handles GNRC_NETAPI_MSG_TYPE_SND commands */
static void _send(gnrc_pktsnip_t *pkt);
/* Main event loop for IPv6 IPSEC */
static void *_event_loop(void *args);

ipsec_sp_rule_t ipsec_get_policy_rule(ipsec_ts_t *ts, ipsec_traffic_dir_t dir)
{
    (void) dir;
    ipsec_sp_t sp;

    if (get_sp_by_ts(ts, &sp) < 0)
    {
        DEBUG("ipv6_ipsec: No SPD policy for this packet found\n");
        return IPSEC_SP_RULE_DROP;
    }
    return sp.rule;
}

kernel_pid_t gnrc_ipv6_ipsec_init(void)
{
    if (_pid > KERNEL_PID_UNDEF) {
        return _pid;
    }
    sadb_init();
    spdb_init();
    sasp_tmp_init();

    _pid = thread_create(_stack, sizeof(_stack), GNRC_IPV6_IPSEC_PRIO,
                         THREAD_CREATE_STACKTEST, _event_loop, NULL, "ipv6_esp");

    return _pid;
}

kernel_pid_t gnrc_opv6_ipsec_get_pid(void)
{
    return _pid;
}

// TODO: Move to ESP c file
static gnrc_pktsnip_t *build_esp_data(uint8_t *data, size_t data_len, uint8_t nh)
{
    uint32_t spi = 0x12345678;
    static uint32_t seq = 0;
    size_t encrypted_data_len, icv_len, total_len;
    uint8_t padding_len;
    uint8_t *encrypted_data, *icv, *start;
    gnrc_pktsnip_t *esp;
    esp_header_t *esp_header;

    /**
     * TODO:
     * Do encryption and authentiaction
     */
    encrypted_data = data;
    icv = NULL;
    encrypted_data_len = data_len;
    icv_len = 0;
    padding_len = (4 - (encrypted_data_len + 2) % 4) % 4;
    total_len = 10 + encrypted_data_len + padding_len +  icv_len;
    esp = gnrc_pktbuf_add(NULL, NULL, total_len, MODULE_GNRC_NETTYPE_IPV6_EXT_ESP);
    start = (uint8_t *)esp->data;
    esp_header = (esp_header_t*) start;
    esp_header->spi.u32 = htobe32(spi);
    esp_header->seq.u32 = htobe32(seq);
    memcpy(start + 8, encrypted_data, encrypted_data_len);
    memcpy(start + 8 + encrypted_data_len + padding_len, &padding_len, 1);
    memcpy(start + 8 + encrypted_data_len + padding_len + 1, &nh, 1);
    memcpy(start + 8 + encrypted_data_len + padding_len + 2, icv, icv_len);

    seq++;
    return esp;

}

static gnrc_pktsnip_t *encapsulate(gnrc_pktsnip_t *pkt)
{
    ipv6_hdr_t *ipv6_hdr = gnrc_ipv6_get_header(pkt);
    gnrc_pktsnip_t *esp_data, *rest, *ipv6;
    uint8_t nh;

    ipv6 = gnrc_pktsnip_search_type(pkt, GNRC_NETTYPE_IPV6);
    if (ipv6_hdr == NULL || ipv6 == NULL) {
        return NULL;
    }
    nh = ipv6_hdr->nh;
    ipv6_hdr->nh = PROTNUM_IPV6_EXT_ESP;
    rest = ipv6->next;
    if (gnrc_pktbuf_merge(rest)) {
        return NULL;
    }
    pkt = gnrc_pkt_delete(pkt, rest);
    esp_data = build_esp_data(rest->data, rest->size, nh);
    if (esp_data == NULL) {
        gnrc_pktbuf_release(rest);
        return NULL;
    }
    ipv6_hdr->len.u16 = htobe16(be16toh(ipv6_hdr->len.u16) + esp_data->size - rest->size);

    ipv6 = gnrc_pkt_append(ipv6, esp_data);
    gnrc_pktbuf_release(rest);
    return pkt;
}

void gnrc_ipv6_ipsec_dispatch_recv(gnrc_pktsnip_t *pkt)
{
    gnrc_nettype_t type;

#ifndef MODULE_GNRC_IPV6
    type = GNRC_NETTYPE_UNDEF;
    for (gnrc_pktsnip_t *ptr = pkt; (ptr || (type == GNRC_NETTYPE_UNDEF));
         ptr = ptr->next) {
        if ((ptr->next) && (ptr->next->type == GNRC_NETTYPE_NETIF)) {
            type = ptr->type;
            break;
        }
    }
#else   /* MODULE_GNRC_IPV6 */
    /* just assume normal IPv6 traffic */
    type = GNRC_NETTYPE_IPV6;
#endif  /* MODULE_GNRC_IPV6 */
    if (!gnrc_netapi_dispatch_receive(type,
                                      GNRC_NETREG_DEMUX_CTX_ALL, pkt)) {
        DEBUG("ipv6_ipsec: No receivers for this packet found\n");
        gnrc_pktbuf_release(pkt);
    }
}

void gnrc_ipv6_ipsec_dispatch_send(gnrc_pktsnip_t *pkt)
{
    assert(pkt->type == GNRC_NETTYPE_NETIF);
    gnrc_netif_hdr_t *hdr = pkt->data;

    if (gnrc_netif_send(gnrc_netif_get_by_pid(hdr->if_pid), pkt) < 1) {
        DEBUG("ipv6_ipsec: unable to send %p over interface %u\n", (void *)pkt,
              hdr->if_pid);
        gnrc_pktbuf_release(pkt);
    }
}

static void _receive(gnrc_pktsnip_t *pkt)
{
    gnrc_pktsnip_t *payload;

    /* seize payload as a temporary variable */
    payload = gnrc_pktbuf_start_write(pkt); /* need to duplicate since pkt->next
                                             * might get replaced */

    if (payload == NULL) {
        DEBUG("ipv6_ipsec: can not get write access on received packet\n");
#if defined(DEVELHELP) && ENABLE_DEBUG
        gnrc_pktbuf_stats();
#endif
        gnrc_pktbuf_release(pkt);
        return;
    }

    pkt = payload;  /* reset pkt from temporary variable */

    payload = gnrc_pktsnip_search_type(pkt, GNRC_NETTYPE_IPV6_EXT_ESP);

    if ((payload == NULL) || (payload->size < 1)) {
        DEBUG("ipv6_ipsec: Received packet has no IPSEC payload\n");
        gnrc_pktbuf_release(pkt);
        return;
    }
    gnrc_ipv6_ipsec_dispatch_recv(pkt);
}

static void _send(gnrc_pktsnip_t *pkt)
{
    gnrc_pktsnip_t *tmp;
    gnrc_netif_t *netif;

    netif = gnrc_netif_hdr_get_netif(pkt->data);

    if (netif == NULL) {
        DEBUG("ipv6_ipsec: Can not IPSEC specific interface information.\n");
        gnrc_pktbuf_release(pkt);
        return;
    }

    if ((pkt == NULL) || (pkt->size < sizeof(gnrc_netif_hdr_t))) {
        DEBUG("ipv6_ipsec: Sending packet has no netif header\n");
        gnrc_pktbuf_release(pkt);
        return;
    }

#ifdef MODULE_GNRC_IPV6
    if ((pkt->next == NULL) || (pkt->next->type != GNRC_NETTYPE_IPV6)) {
        DEBUG("6lo: Sending packet has no IPv6 header\n");
        gnrc_pktbuf_release(pkt);
        return;
    }
#endif

    tmp = gnrc_pktbuf_start_write(pkt);

    if (tmp == NULL) {
        DEBUG("ipv6_ipsec: no space left in packet buffer\n");
        gnrc_pktbuf_release(pkt);
        return;
    }
    pkt = tmp;
    tmp = encapsulate(pkt);
    if (tmp == NULL) {
        DEBUG("ipv6_ipsec: payload encapsulation failed\n");
        gnrc_pktbuf_release(pkt);
        return;
    }

    gnrc_ipv6_ipsec_dispatch_send(tmp);
}

static void *_event_loop(void *args)
{
    msg_t msg, reply, msg_q[GNRC_IPV6_IPSEC_MSG_QUEUE_SIZE];
    gnrc_netreg_entry_t me_reg = GNRC_NETREG_ENTRY_INIT_PID(GNRC_NETREG_DEMUX_CTX_ALL,
                                                            thread_getpid());

    (void)args;
    msg_init_queue(msg_q, GNRC_IPV6_IPSEC_MSG_QUEUE_SIZE);

    /* register interest in all IPSEC packets */
    gnrc_netreg_register(GNRC_NETTYPE_IPV6_EXT_ESP, &me_reg);

    /* preinitialize ACK */
    reply.type = GNRC_NETAPI_MSG_TYPE_ACK;

    /* start event loop */
    while (1) {
        DEBUG("ipv6_ipsec: waiting for incoming message.\n");
        msg_receive(&msg);

        switch (msg.type) {
        case GNRC_NETAPI_MSG_TYPE_RCV:
            DEBUG("ipv6_ipsec: GNRC_NETDEV_MSG_TYPE_RCV received\n");
            _receive(msg.content.ptr);
            break;

        case GNRC_NETAPI_MSG_TYPE_SND:
            DEBUG("ipv6_ipsec: GNRC_NETDEV_MSG_TYPE_SND received\n");
            _send(msg.content.ptr);
            break;

        case GNRC_NETAPI_MSG_TYPE_GET:
        case GNRC_NETAPI_MSG_TYPE_SET:
            DEBUG("ipv6_ipsec: reply to unsupported get/set\n");
            reply.content.value = -ENOTSUP;
            msg_reply(&msg, &reply);
            break;

        default:
            DEBUG("ipv6_ipsec: operation not supported\n");
            break;
        }
    }

    return NULL;
}
