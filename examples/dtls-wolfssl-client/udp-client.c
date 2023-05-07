#include <net/sock/udp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "net/gnrc/netif.h"
#include "log.h"
#include "xtimer.h"

#include "clients.h"
#include "clients-cfg.h"


const char *hello_msg = "Hello";
static sock_udp_t _socket;

static int udp_connect(const char *addr, uint16_t port)
{
    sock_udp_ep_t remote = SOCK_IPV6_EP_ANY;
    remote.port = port;

    if (ipv6_addr_from_str((ipv6_addr_t *)remote.addr.ipv6, addr) == NULL) {
        puts("UDP: Unable to parse destination address");
        return -1;
    }
    if (sock_udp_create(&_socket, NULL, &remote, 0)) {
        puts("UDP: Unable to create UDP sock");
        return -1;
    }

    puts("UDP: Sending first message ...");
    if(sock_udp_send(&_socket, hello_msg, strlen(hello_msg), NULL) < 0)
    {
        puts("UDP: Send failed");
        return -1;
    }
    return 0;
}
static int udp_send(const char *msg, size_t msg_len)
{
    int ret = sock_udp_send(&_socket, msg, msg_len, NULL);
    if (ret < 0)
    {
        puts("UDP: Send failed");
    }
    return ret;
}
static int udp_receive(char *msg, size_t max_len)
{
    int ret = sock_udp_recv(&_socket, msg, max_len, TIMEOUT * 1000000, NULL);
    if (ret <= 0)
    {
        puts("UDP: Receive failed");
    }
    return ret;
}
static int udp_close(void)
{
    sock_udp_close(&_socket);
    return 0;
}

client_t udp_client = {
    .connect = udp_connect,
    .send = udp_send,
    .receive = udp_receive,
    .close = udp_close,
};
