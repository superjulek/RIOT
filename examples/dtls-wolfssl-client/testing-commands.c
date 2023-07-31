#include "clients.h"
#include "clients-cfg.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <xtimer.h>


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
    int tries = 0;
    while(1)
    {
        tries++;
        int rsize = c->receive((char*)buf, BUF_SIZE);
        if (rsize < 0)
        {
            if (tries > 10)
                goto error;
            continue;
        }
        if (c->send((char*)buf, rsize) < 0)
        {
            if (tries > 10)
                goto error;
            continue;
        }
        gcnt++;
        tries = 0;
    }
    printf("Success: %d.\n", gcnt);
    c->close();
    return 0;
error:
    printf("Success: %d.\n", gcnt);
    c->close();
    return -1;
}

int loop_cmd(client_t *c, const char *addr, int loop_num)
{
    uint8_t buf[1] = {0};
    uint8_t rcv_buf[1] = {0};

    for (int i = 0; i < loop_num; ++i)
    {
        if (c->connect(addr, SERVER_PORT) < 0)
            return -1;
        xtimer_msleep(500);


        printf("Sending 1 byte\n");
        if (c->send((char*)buf, 1) < 0)
            goto error;
        if (c->receive((char*)rcv_buf, 1) != 1)
        {
            puts("Server returned different size");
            goto error;
        }
        if (memcmp(buf, rcv_buf, 1) != 0)
        {
            puts("Server returned other data");
            goto error;
        }
        printf("Success.\n");
        c->close();
        xtimer_msleep(500);
    }
    return 0;
error:
    printf("Error.\n");
    c->close();
    return -1;
}

uint8_t buf[1001];

int send_cmd(client_t *c, const char *addr, int size)
{
    if ((size_t) size > sizeof(buf))
    {
        puts("Requested too big size");
        return -1;
    }
    static client_t *local_client = NULL;
    if (local_client && local_client != c)
    {
        puts("Closing last client");
        local_client->close();
        local_client = NULL;
    }
    if (!local_client) {
        puts("Connecting");
        local_client = c;
        if (local_client->connect(addr, SERVER_PORT) < 0)
            return -1;
    }
    if (size == 0)
        return 0;
    printf("Sending %d bytes\n", size);
    if (local_client->send((char*)buf, size) < 0)
        goto error;
    if (local_client->receive((char*)buf, sizeof(buf)) != size)
    {
        puts("Server returned different size");
        goto error;
    }
    return 0;
error:
    local_client->close();
    local_client = NULL;
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

int udp_send_cmd(int argc, char **argv)
{
    if (argc != 3) {
        return -1;
    }
    return send_cmd(&udp_client, argv[1], atoi(argv[2]));
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

int dtls_loop_cmd(int argc, char **argv)
{
    if (argc != 3) {
        return -1;
    }
    return loop_cmd(&dtls_client, argv[1], atoi(argv[2]));
}

int dtls_send_cmd(int argc, char **argv)
{
    if (argc != 3) {
        return -1;
    }
    return send_cmd(&dtls_client, argv[1], atoi(argv[2]));
}
