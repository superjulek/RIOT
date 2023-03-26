#include <stdio.h>

#include "net_benchmark.h"
#include "shell.h"

int _parse_bench_cmd(int argc, char **argv);
static void _print_usage(char *cmdname);

int _parse_bench_cmd(int argc, char **argv)
{
    char *cmdname = argv[0];
    int res = 1;

    /* parse command line arguments */
    for (int i = 1; i < argc; i++) {
        char *arg = argv[i];
        if (arg[0] != '-') {
            break;
        }
        switch (arg[1]) {
        case 'h':
            _print_usage(cmdname);
            res = 0;
            break;
        case 'i':
            if (i + 1 >= argc) {
                puts("No peer address given");
                break;
            }
            res = net_bench(argv[i + 1]);
            break;
        default:
            break;
        }
    }
    if (res != 0) {
        _print_usage(cmdname);
    }
    return res;

}

SHELL_COMMAND(bench_control, "Command for benchmarking networks", _parse_bench_cmd);

static void _print_usage(char *cmdname)
{
    printf("%s [-i addrs]\n", cmdname);
    puts("     -i - peer addrs");
}
