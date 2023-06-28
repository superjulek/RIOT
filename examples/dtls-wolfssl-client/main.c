/*
 * Copyright (C) 2019 Daniele Lacamera
 *
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
 * @brief       Example application  for DTLS 1.2 using wolfSSL
 *
 * @author      Daniele Lacamera <daniele@wolfssl.com>
 *
 * @}
 */

#include <wolfssl/ssl.h>

#include "shell.h"
#include "msg.h"
#include "log.h"

#ifdef WITH_RIOT_SOCKETS
#error RIOT-OS is set to use sockets but this DTLS app is configured for socks.
#endif

#define MAIN_QUEUE_SIZE     (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

extern int dtls_client_cmd(int argc, char **argv);
extern int dtls_benchmark_cmd(int argc, char **argv);
extern int dtls_loop_cmd(int argc, char **argv);
extern int udp_client_cmd(int argc, char **argv);
extern int udp_benchmark_cmd(int argc, char **argv);

static const shell_command_t shell_commands[] = {
    { "dtlsc", "Start a DTLS client", dtls_client_cmd },
    { "dtlsb", "Start a DTLS benchmark", dtls_benchmark_cmd },
    { "dtlsl", "Start a DTLS loop", dtls_loop_cmd },
    { "udpc", "Start a UDP client", udp_client_cmd },
    { "udpb", "Start a UDP benchmark", udp_benchmark_cmd },
    { NULL, NULL, NULL }
};

int main(void)
{
    /* we need a message queue for the thread running the shell in order to
     * receive potentially fast incoming networking packets */
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);
    LOG(LOG_INFO, "RIOT wolfSSL DTLS testing implementation\n");
    wolfSSL_Init();
    wolfSSL_Debugging_ON();

    /* start shell */
    LOG(LOG_INFO, "All up, running the shell now\n");
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    /* should be never reached */
    return 0;
}
