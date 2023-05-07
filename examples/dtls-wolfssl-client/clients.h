#include <stdint.h>
#include <stddef.h>

typedef struct client_t {
    int (*connect)(const char *addr, uint16_t port);
    int (*send)(const char *msg, size_t msg_size);
    int (*receive)(char *msg, size_t max_size);
    int (*close)(void);
} client_t;
