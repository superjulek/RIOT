
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include <sock_tls.h>
#include <net/sock.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "net/gnrc/netif.h"
#include "log.h"
#include "xtimer.h"

#include "clients.h"
#include "clients-cfg.h"



static sock_tls_t _socket;


static int dtls_connect(const char *addr, uint16_t port)
{
    sock_udp_ep_t remote = SOCK_IPV6_EP_ANY;
    remote.port = port;

    if (ipv6_addr_from_str((ipv6_addr_t *)remote.addr.ipv6, addr) == NULL){
        puts("DTLS: Unable to parse destination address");
        return -1;
    }
    if (sock_dtls_create(&_socket, NULL, &remote, 0, wolfDTLSv1_2_client_method()) != 0) {
        puts("DTLS: Unable to create DTLS sock");
        return -1;
    }

    wolfSSL_CTX_set_verify(_socket.ctx, SSL_VERIFY_NONE, 0);
    wolfSSL_CTX_set_cipher_list(_socket.ctx, "DHE-RSA-AES128-SHA");

    if (sock_dtls_session_create(&_socket) < 0)
        return -1;
    wolfSSL_dtls_set_timeout_init(_socket.ssl, TIMEOUT);
    puts("DTLS: Connecting to server");
    uint32_t wolfSSL_connect_start = xtimer_now_usec();

    int ret = wolfSSL_connect(_socket.ssl);
    if (ret != SSL_SUCCESS) {
        printf("DTLS: Unable to connect to server (%d)\n", wolfSSL_get_error(_socket.ssl, ret));
        sock_dtls_session_destroy(&_socket);
        wolfSSL_CTX_free(_socket.ctx);
        wolfSSL_CTX_free(_socket.ctx);
        sock_dtls_close(&_socket);
        return -1;
    }
    uint32_t wolfSSL_connect_end = xtimer_now_usec();
    printf("%7"PRIu32" total\n", wolfSSL_connect_end - wolfSSL_connect_start);

    sock_dtls_set_endpoint(&_socket, &remote);
    wolfSSL_CTX_set_timeout(_socket.ctx, TIMEOUT);
    return 0;
}
static int dtls_send(const char *msg, size_t msg_len)
{
    int ret = wolfSSL_write(_socket.ssl, msg, msg_len);
    if (ret < 0)
    {
        puts("DTLS: Send failed");
    }
    return ret;
}
static int dtls_receive(char *msg, size_t max_len)
{
    int ret = wolfSSL_read(_socket.ssl, msg, max_len);
    if (ret <= 0)
    {
        puts("DTLS: Receive failed");
    }
    return ret;
}
static int dtls_close(void)
{
    sock_dtls_session_destroy(&_socket);
    wolfSSL_CTX_free(_socket.ctx);
    wolfSSL_CTX_free(_socket.ctx);
    sock_dtls_close(&_socket);
    return 0;
}

client_t dtls_client = {
    .connect = dtls_connect,
    .send = dtls_send,
    .receive = dtls_receive,
    .close = dtls_close,
};
