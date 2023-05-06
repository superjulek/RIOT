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

#include <net/sock/udp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "net/gnrc/netif.h"
#include "log.h"
#include "xtimer.h"

#define SERVER_PORT 11111
#define APP_UDP_BUF_SIZE 1400

static void usage(const char *cmd_name)
{
    printf("Usage: %s <server-address>\n", cmd_name);
}

int udp_client(int argc, char **argv)
{
    int ret = 0;
    uint8_t buf[APP_UDP_BUF_SIZE] = {0};
    uint8_t rcv_buf[APP_UDP_BUF_SIZE] = {0};
    char *iface;
    char *addr_str;

    if (argc != 2) {
        usage(argv[0]);
        return -1;
    }

    for (int i = 0; i < APP_UDP_BUF_SIZE; ++i)
    {
        buf[i] = i % 256;
    }

    addr_str = argv[1];
    sock_udp_ep_t local = SOCK_IPV6_EP_ANY;
    sock_udp_ep_t remote = SOCK_IPV6_EP_ANY;
    sock_udp_t sckv;
    sock_udp_t *sck = &sckv;

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
            printf("ERROR: interface not valid\n");
            usage(argv[0]);
            return -1;
        }
        remote.netif = (uint16_t)netif->pid;
    }
    if (ipv6_addr_from_str((ipv6_addr_t *)remote.addr.ipv6, addr_str) == NULL) {
        printf("ERROR: unable to parse destination address\n");
        usage(argv[0]);
        return -1;
    }
    remote.port = SERVER_PORT;
    if (sock_udp_create(sck, &local, &remote, 0)) {
        printf("ERROR: Unable to create UDP sock\n");
        return -1;
    }


    printf("Sending first message ...\n");
    /* attempt to connect until the connection is successful */
    do {
        const char *hello_msg = "Hello\n";
        ret = sock_udp_send(sck, hello_msg, strlen(hello_msg), &remote);
        ret = sock_udp_recv(sck, rcv_buf, sizeof(rcv_buf), 10000000, NULL);
        if (ret > 0 && strcmp(hello_msg, (char*)rcv_buf) == 0)
        {
            printf("Server responded same\n");
            break;
        }
        else if(ret > 0)
        {
            printf("Server mumblebumble\n");
            continue;
        }
    } while(true);

    for (int i = 1; i < APP_UDP_BUF_SIZE - 1; ++i)
    {
        memset(rcv_buf, 0, i);
        printf("Sending %d bytes\n", i);
        sock_udp_send(sck, buf, i, &remote);
        ret = sock_udp_recv(sck, rcv_buf, sizeof(rcv_buf), 100000000, NULL);
        if (ret <= 0)
        {
            printf("Error %d\n", ret);
            break;
        }
        printf("Server returned %d\n", ret);
        if (memcmp(buf, rcv_buf, i) != 0)
        {
            printf("Error in received data!\n");
            break;
        }
        for (int j = 0; j < APP_UDP_BUF_SIZE; ++j)
        {
            if (buf[j] != j % 256) {
                printf("Stack error!!!");
                break;
            }
        }
        //xtimer_msleep(20);
        if (i == APP_UDP_BUF_SIZE -2)
        i = 1;
    }

    /* Clean up and exit. */
    printf("Closing connection.\n");
    sock_udp_close(sck);
    return 0;
}

int udp_benchmark(int argc, char **argv)
{
    int ret = 0;
    uint8_t buf[APP_UDP_BUF_SIZE] = {0};
    char *iface;
    char *addr_str;

    if (argc != 2) {
        usage(argv[0]);
        return -1;
    }

    addr_str = argv[1];
    sock_udp_ep_t local = SOCK_IPV6_EP_ANY;
    sock_udp_ep_t remote = SOCK_IPV6_EP_ANY;
    sock_udp_t sckv;
    sock_udp_t *sck = &sckv;

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
            printf("ERROR: interface not valid\n");
            usage(argv[0]);
            return -1;
        }
        remote.netif = (uint16_t)netif->pid;
    }
    if (ipv6_addr_from_str((ipv6_addr_t *)remote.addr.ipv6, addr_str) == NULL) {
        printf("ERROR: unable to parse destination address\n");
        usage(argv[0]);
        return -1;
    }
    remote.port = SERVER_PORT;
    if (sock_udp_create(sck, &local, &remote, 0)) {
        printf("ERROR: Unable to create UDP sock\n");
        return -1;
    }

    int i_max = 5;
    for (int i = 1; i <= i_max; ++i)
    {
        printf("Sending first message %d time ...\n", i);
        const char *hello_msg = "Hello";
        if (sock_udp_send(sck, hello_msg, strlen(hello_msg), &remote) <= 0)
        {
            printf("Error sending\n");
            if (i == i_max)
            {
                sock_udp_close(sck);
                return -1;
            }
        }
        break;
    }
    int gcnt = 0;
    while(true)
    {
        ret = sock_udp_recv(sck, buf, sizeof(buf), 20000000, NULL);
        if (ret <= 0)
        {
            printf("Error receiving %d\n", ret);
            break;
        }
        ret = sock_udp_send(sck, buf, ret, &remote);
        if (ret <= 0)
        {
            printf("Error sending %d\n", ret);
            break;
        }
        gcnt++;
    }
    /* Clean up and exit. */
    printf("Closing connection.\n");
    printf("Success: %d.\n", gcnt);
    sock_udp_close(sck);
    return 0;
}
