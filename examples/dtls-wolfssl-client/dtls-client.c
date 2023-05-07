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
    wolfSSL_CTX_set_cipher_list(_socket.ctx, "AES128-SHA");

    if (sock_dtls_session_create(&_socket) < 0)
        return -1;
    wolfSSL_dtls_set_timeout_init(_socket.ssl, TIMEOUT);
    puts("DTLS: Connecting to server");
    uint32_t wolfSSL_connect_start = xtimer_now_usec();

    if (wolfSSL_connect(_socket.ssl) != SSL_SUCCESS) {
        puts("DTLS: Unable to connect to server");
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
    sock_dtls_close(&_socket);
    return 0;
}

client_t dtls_client = {
    .connect = dtls_connect,
    .send = dtls_send,
    .receive = dtls_receive,
    .close = dtls_close,
};



// int _dtls_client(int argc, char **argv)
// {
//     int ret = 0;
//     char buf[APP_DTLS_BUF_SIZE] = {0};
//     char *iface;
//     char *addr_str;
//     int connect_timeout = 0;
//     const int max_connect_timeouts = 5;

//     if (argc != 2) {
//         usage(argv[0]);
//         return -1;
//     }

//     for (int i = 0; i < APP_DTLS_BUF_SIZE; ++i)
//     {
//         buf[i] = i % 256;
//     }

//     addr_str = argv[1];
//     sock_udp_ep_t local = SOCK_IPV6_EP_ANY;
//     sock_udp_ep_t remote = SOCK_IPV6_EP_ANY;

//     /* Parsing <address> */
//     iface = ipv6_addr_split_iface(addr_str);
//     if (!iface) {
//         if (gnrc_netif_numof() == 1) {
//             /* assign the single interface found in gnrc_netif_numof() */
//             remote.netif = (uint16_t)gnrc_netif_iter(NULL)->pid;
//         }
//     }
//     else {
//         gnrc_netif_t *netif = gnrc_netif_get_by_pid(atoi(iface));
//         if (netif == NULL) {
//             LOG(LOG_ERROR, "ERROR: interface not valid\n");
//             usage(argv[0]);
//             return -1;
//         }
//         remote.netif = (uint16_t)netif->pid;
//     }
//     if (ipv6_addr_from_str((ipv6_addr_t *)remote.addr.ipv6, addr_str) == NULL) {
//         LOG(LOG_ERROR, "ERROR: unable to parse destination address\n");
//         usage(argv[0]);
//         return -1;
//     }
//     remote.port = SERVER_PORT;
//     if (sock_dtls_create(sk, &local, &remote, 0, wolfDTLSv1_2_client_method()) != 0) {
//         LOG(LOG_ERROR, "ERROR: Unable to create DTLS sock\n");
//         return -1;
//     }

//     wolfSSL_CTX_set_verify(sk->ctx, SSL_VERIFY_NONE, 0);
//     wolfSSL_CTX_set_cipher_list(sk->ctx, "AES128-SHA");

//     if (sock_dtls_session_create(sk) < 0)
//         return -1;
//     wolfSSL_dtls_set_timeout_init(sk->ssl, 20);
//     LOG(LOG_INFO, "connecting to server...\n");
//     /* attempt to connect until the connection is successful */
//     uint32_t wolfSSL_connect_start;
//     do {
//         wolfSSL_connect_start = xtimer_now_usec();
//         ret = wolfSSL_connect(sk->ssl);
//         if ((ret != SSL_SUCCESS)) {
//             if(wolfSSL_get_error(sk->ssl, ret) == SOCKET_ERROR_E) {
//                 LOG(LOG_WARNING, "Socket error: reconnecting...\n");
//                 sock_dtls_session_destroy(sk);
//                 connect_timeout = 0;
//                 if (sock_dtls_session_create(sk) < 0)
//                     return -1;
//             }
//             if ((wolfSSL_get_error(sk->ssl, ret) == WOLFSSL_ERROR_WANT_READ) &&
//                     (connect_timeout++ >= max_connect_timeouts)) {
//                 LOG(LOG_WARNING, "Server not responding: reconnecting...\n");
//                 sock_dtls_session_destroy(sk);
//                 connect_timeout = 0;
//                 if (sock_dtls_session_create(sk) < 0)
//                     return -1;
//             }
//         }
//     } while(ret != SSL_SUCCESS);
//     uint32_t wolfSSL_connect_end = xtimer_now_usec();
//     printf("%7"PRIu32" total\n", wolfSSL_connect_end - wolfSSL_connect_start);

//     /* set remote endpoint */
//     sock_dtls_set_endpoint(sk, &remote);
//     for (int i = 1; i < APP_DTLS_BUF_SIZE - 1; ++i)
//     {
//         LOG(LOG_INFO, "Sending %d bytes\n", i);
//         wolfSSL_write(sk->ssl, buf, i);
//         ret = wolfSSL_read(sk->ssl, buf, APP_DTLS_BUF_SIZE - 1);
//         LOG(LOG_INFO, "wolfSSL_read returned %d\n", ret);
//         if (ret != i)
//             break;
//     }

//     // /* send the hello message */
//     // wolfSSL_write(sk->ssl, buf, strlen(buf));

//     // /* wait for a reply, indefinitely */
//     // do {
//     //     ret = wolfSSL_read(sk->ssl, buf, APP_DTLS_BUF_SIZE - 1);
//     //     LOG(LOG_INFO, "wolfSSL_read returned %d\n", ret);
//     // } while (ret <= 0);
//     // buf[ret] = (char)0;
//     // LOG(LOG_INFO, "Received: '%s'\n", buf);

//     /* Clean up and exit. */
//     LOG(LOG_INFO, "Closing connection.\n");
//     sock_dtls_session_destroy(sk);
//     sock_dtls_close(sk);
//     return 0;
// }

// int dtls_benchmark(int argc, char **argv)
// {
//     int ret = 0;
//     char buf[APP_DTLS_BUF_SIZE] = {0};
//     char *iface;
//     char *addr_str;
//     int connect_timeout = 0;
//     const int max_connect_timeouts = 5;

//     if (argc != 2) {
//         usage(argv[0]);
//         return -1;
//     }


//     addr_str = argv[1];
//     sock_udp_ep_t local = SOCK_IPV6_EP_ANY;
//     sock_udp_ep_t remote = SOCK_IPV6_EP_ANY;

//     /* Parsing <address> */
//     iface = ipv6_addr_split_iface(addr_str);
//     if (!iface) {
//         if (gnrc_netif_numof() == 1) {
//             /* assign the single interface found in gnrc_netif_numof() */
//             remote.netif = (uint16_t)gnrc_netif_iter(NULL)->pid;
//         }
//     }
//     else {
//         gnrc_netif_t *netif = gnrc_netif_get_by_pid(atoi(iface));
//         if (netif == NULL) {
//             LOG(LOG_ERROR, "ERROR: interface not valid\n");
//             usage(argv[0]);
//             return -1;
//         }
//         remote.netif = (uint16_t)netif->pid;
//     }
//     if (ipv6_addr_from_str((ipv6_addr_t *)remote.addr.ipv6, addr_str) == NULL) {
//         LOG(LOG_ERROR, "ERROR: unable to parse destination address\n");
//         usage(argv[0]);
//         return -1;
//     }
//     remote.port = SERVER_PORT;
//     if (sock_dtls_create(sk, &local, &remote, 0, wolfDTLSv1_2_client_method()) != 0) {
//         LOG(LOG_ERROR, "ERROR: Unable to create DTLS sock\n");
//         return -1;
//     }

//     wolfSSL_CTX_set_verify(sk->ctx, SSL_VERIFY_NONE, 0);

//     if (sock_dtls_session_create(sk) < 0)
//         return -1;
//     wolfSSL_dtls_set_timeout_init(sk->ssl, 20);
//     LOG(LOG_INFO, "connecting to server...\n");
//     /* attempt to connect until the connection is successful */
//     uint32_t wolfSSL_connect_start;
//     do {
//         wolfSSL_connect_start = xtimer_now_usec();
//         ret = wolfSSL_connect(sk->ssl);
//         if ((ret != SSL_SUCCESS)) {
//             if(wolfSSL_get_error(sk->ssl, ret) == SOCKET_ERROR_E) {
//                 LOG(LOG_WARNING, "Socket error: reconnecting...\n");
//                 sock_dtls_session_destroy(sk);
//                 connect_timeout = 0;
//                 if (sock_dtls_session_create(sk) < 0)
//                     return -1;
//             }
//             if ((wolfSSL_get_error(sk->ssl, ret) == WOLFSSL_ERROR_WANT_READ) &&
//                     (connect_timeout++ >= max_connect_timeouts)) {
//                 LOG(LOG_WARNING, "Server not responding: reconnecting...\n");
//                 sock_dtls_session_destroy(sk);
//                 connect_timeout = 0;
//                 if (sock_dtls_session_create(sk) < 0)
//                     return -1;
//             }
//         }
//     } while(ret != SSL_SUCCESS);
//     uint32_t wolfSSL_connect_end = xtimer_now_usec();
//     printf("%7"PRIu32" total\n", wolfSSL_connect_end - wolfSSL_connect_start);

//     /* set remote endpoint */
//     sock_dtls_set_endpoint(sk, &remote);

//     int gcnt = 0;
//     while(true)
//     {
//         ret = wolfSSL_read(sk->ssl, buf, sizeof(buf));
//         if (ret <= 0)
//         {
//             printf("Error receiving %d\n", ret);
//             break;
//         }
//         ret = wolfSSL_write(sk->ssl, buf, ret);
//         if (ret <= 0)
//         {
//             printf("Error sending %d\n", ret);
//             break;
//         }
//         gcnt++;
//     }

//     LOG(LOG_INFO, "Closing connection.\n");
//     printf("Success: %d.\n", gcnt);
//     sock_dtls_session_destroy(sk);
//     sock_dtls_close(sk);
//     return 0;
// }
