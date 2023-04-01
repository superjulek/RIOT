/*
 * Copyright (C) 2019 Daniele Lacamera
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       Demonstrating DTLS 1.2 client using wolfSSL
 *
 * @author      Daniele Lacamera <daniele@wolfssl.com>
 * @}
 */

#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include <sock_tls.h>
#include <net/sock.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "net/gnrc/netif.h"
#include "log.h"

#define SERVER_PORT 11111
#define APP_DTLS_BUF_SIZE 1500

static sock_tls_t skv;
static sock_tls_t *sk = &skv;

static void usage(const char *cmd_name)
{
    LOG(LOG_ERROR, "Usage: %s <server-address>\n", cmd_name);
}

int dtls_client(int argc, char **argv)
{
    int ret = 0;
    char buf[APP_DTLS_BUF_SIZE] = {0};
    char *iface;
    char *addr_str;
    int connect_timeout = 0;
    const int max_connect_timeouts = 5;

    if (argc != 2) {
        usage(argv[0]);
        return -1;
    }

    for (int i = 0; i < APP_DTLS_BUF_SIZE; ++i)
    {
        buf[i] = i % 256;
    }

    addr_str = argv[1];
    sock_udp_ep_t local = SOCK_IPV6_EP_ANY;
    sock_udp_ep_t remote = SOCK_IPV6_EP_ANY;

    /* Parsing <address> */
    iface = ipv6_addr_split_iface(addr_str);
    if (!iface) {
        if (gnrc_netif_numof() == 1) {
            /* assign the single interface found in gnrc_netif_numof() */
            remote.netif = (uint16_t)gnrc_netif_iter(NULL)->pid;
        }
    }
    else {
        gnrc_netif_t *netif = gnrc_netif_get_by_pid(atoi(iface));
        if (netif == NULL) {
            LOG(LOG_ERROR, "ERROR: interface not valid\n");
            usage(argv[0]);
            return -1;
        }
        remote.netif = (uint16_t)netif->pid;
    }
    if (ipv6_addr_from_str((ipv6_addr_t *)remote.addr.ipv6, addr_str) == NULL) {
        LOG(LOG_ERROR, "ERROR: unable to parse destination address\n");
        usage(argv[0]);
        return -1;
    }
    remote.port = SERVER_PORT;
    if (sock_dtls_create(sk, &local, &remote, 0, wolfDTLSv1_2_client_method()) != 0) {
        LOG(LOG_ERROR, "ERROR: Unable to create DTLS sock\n");
        return -1;
    }

    wolfSSL_CTX_set_verify(sk->ctx, SSL_VERIFY_NONE, 0);

    if (sock_dtls_session_create(sk) < 0)
        return -1;
    wolfSSL_dtls_set_timeout_init(sk->ssl, 5);
    LOG(LOG_INFO, "connecting to server...\n");
    /* attempt to connect until the connection is successful */
    do {
        ret = wolfSSL_connect(sk->ssl);
        if ((ret != SSL_SUCCESS)) {
            if(wolfSSL_get_error(sk->ssl, ret) == SOCKET_ERROR_E) {
                LOG(LOG_WARNING, "Socket error: reconnecting...\n");
                sock_dtls_session_destroy(sk);
                connect_timeout = 0;
                if (sock_dtls_session_create(sk) < 0)
                    return -1;
            }
            if ((wolfSSL_get_error(sk->ssl, ret) == WOLFSSL_ERROR_WANT_READ) &&
                    (connect_timeout++ >= max_connect_timeouts)) {
                LOG(LOG_WARNING, "Server not responding: reconnecting...\n");
                sock_dtls_session_destroy(sk);
                connect_timeout = 0;
                if (sock_dtls_session_create(sk) < 0)
                    return -1;
            }
        }
    } while(ret != SSL_SUCCESS);

    /* set remote endpoint */
    sock_dtls_set_endpoint(sk, &remote);
    for (int i = 1; i < APP_DTLS_BUF_SIZE - 1; ++i)
    {
        LOG(LOG_INFO, "Sending %d bytes\n", i);
        wolfSSL_write(sk->ssl, buf, i);
        ret = wolfSSL_read(sk->ssl, buf, APP_DTLS_BUF_SIZE - 1);
        LOG(LOG_INFO, "wolfSSL_read returned %d\n", ret);
    }

    // /* send the hello message */
    // wolfSSL_write(sk->ssl, buf, strlen(buf));

    // /* wait for a reply, indefinitely */
    // do {
    //     ret = wolfSSL_read(sk->ssl, buf, APP_DTLS_BUF_SIZE - 1);
    //     LOG(LOG_INFO, "wolfSSL_read returned %d\n", ret);
    // } while (ret <= 0);
    // buf[ret] = (char)0;
    // LOG(LOG_INFO, "Received: '%s'\n", buf);

    /* Clean up and exit. */
    LOG(LOG_INFO, "Closing connection.\n");
    sock_dtls_session_destroy(sk);
    sock_dtls_close(sk);
    return 0;
}
