#include "clients.h"
#include "clients-cfg.h"
#include <stdio.h>
#include <string.h>


extern client_t udp_client;
extern client_t dtls_client;

int client_cmd(client_t *c, const char *addr)
{
    uint8_t buf[BUF_SIZE] = {0};
    uint8_t rcv_buf[BUF_SIZE] = {0};

    if (c->connect(addr, SERVER_PORT) < 0)
        return -1;
    for (int i = 1; i <= BUF_SIZE; ++i)
    {
        printf("Sending %d bytes\n", i);
        if (c->send((char*)buf, i) < 0)
            goto error;
        if (c->receive((char*)rcv_buf, BUF_SIZE) != i)
        {
            puts("Server returned different size");
            goto error;
        }
        if (memcmp(buf, rcv_buf, i) != 0)
        {
            puts("Server returned other data");
            goto error;
        }
        for (int j = 0; j < BUF_SIZE; ++j)
        {
            if (buf[j] != 0) {
                puts("Stack error");
                break;
            }
        }
    }
    c->close();
    return 0;
error:
    c->close();
    return -1;
}

int benchmark_cmd(client_t *c, const char *addr)
{
    int gcnt = 0;
    uint8_t buf[BUF_SIZE] = {0};

    if (c->connect(addr, SERVER_PORT) < 0)
        return -1;
    while(1)
    {
        int rsize = c->receive((char*)buf, BUF_SIZE);
        if (rsize < 0)
            goto error;
        if (c->send((char*)buf, rsize) < 0)
            goto error;
        gcnt++;
    }
    printf("Success: %d.\n", gcnt);
    c->close();
    return 0;
error:
    printf("Success: %d.\n", gcnt);
    c->close();
    return -1;
}

int udp_client_cmd(int argc, char **argv)
{
    if (argc != 2) {
        return -1;
    }
    return client_cmd(&udp_client, argv[1]);
}

int udp_benchmark_cmd(int argc, char **argv)
{
    if (argc != 2) {
        return -1;
    }
    return benchmark_cmd(&udp_client, argv[1]);
}

int dtls_client_cmd(int argc, char **argv)
{
    if (argc != 2) {
        return -1;
    }
    return client_cmd(&dtls_client, argv[1]);
}

int dtls_benchmark_cmd(int argc, char **argv)
{
    if (argc != 2) {
        return -1;
    }
    return benchmark_cmd(&dtls_client, argv[1]);
}
