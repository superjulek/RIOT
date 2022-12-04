
#ifndef NET_GNRC_IPV6_ESP_CONFIG_H
#define NET_GNRC_IPV6_ESP_CONFIG_H

#include "kernel_defines.h"
#include "timex.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Default stack size to use for the ESP thread.
 */
#ifndef GNRC_IPV6_ESP_STACK_SIZE
#define GNRC_IPV6_ESP_STACK_SIZE           (THREAD_STACKSIZE_DEFAULT)
#endif

#ifdef __cplusplus
}
#endif

#endif /* NET_GNRC_IPV6_ESP_CONFIG_H */
