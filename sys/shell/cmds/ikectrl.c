/*
 * Copyright (C) 2013  INRIA.
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     sys_shell_commands
 * @{
 *
 * @file
 * @brief       Shell commands for the IKE module
 *
 * @author      Juliusz Neuman <superjulek@interia.pl>
 *
 * @}
 */

#include "ike/ike.h"
#include "shell.h"

#include <stdio.h>

int _parse_ike_cmd(int argc, char **argv);
static void _print_ike_usage(char *cmdname);

int _parse_ike_cmd(int argc, char **argv)
{
    char *cmdname = argv[0];
    int res = 1;

    /* parse command line arguments */
    for (int i = 1; i < argc; i++) {
        char *arg = argv[i];
        if (arg[0] != '-')
        {
            break;
        }
        switch (arg[1]) {
            case 'h':
                _print_ike_usage(cmdname);
                res = 0;
                break;
            case 'i':
                if (i + 1 >= argc)
                {
                    puts("No peer address given");
                    break;
                }
                res = ike_init(argv[i + 1]);
                break;
            default:
                break;
        }
    }
    if (res != 0)
    {
        _print_ike_usage(cmdname);
    }
    return res;

}

static void _print_ike_usage(char *cmdname)
{
    printf("%s [-i addrs]\n",
           cmdname);
    puts("     -i - initialize IKE SA to addrs");
}

SHELL_COMMAND(ikectrl, "Control IKE daemon", _parse_ike_cmd);
