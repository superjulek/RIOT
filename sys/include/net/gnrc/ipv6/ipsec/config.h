
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

/**
 * @brief   Default priority for the ESP thread.
 */
#ifndef GNRC_IPV6_ESP_PRIO
#define GNRC_IPV6_ESP_PRIO                 (THREAD_PRIORITY_MAIN - 4)
#endif

/**
 * @brief   Default message queue size to use for the ESP thread (as
 *          exponent of 2^n).
 *
 * As the queue size ALWAYS needs to be power of two, this option represents the
 * exponent of 2^n, which will be used as the size of the queue.
 */
#ifndef CONFIG_GNRC_IPV6_ESP_MSG_QUEUE_SIZE_EXP
#define CONFIG_GNRC_IPV6_ESP_MSG_QUEUE_SIZE_EXP   (3U)
#endif

/**
 * @brief   Message queue size to use for the ESP thread.
 */
#ifndef GNRC_IPV6_ESP_MSG_QUEUE_SIZE
#define GNRC_IPV6_ESP_MSG_QUEUE_SIZE    (1 << CONFIG_GNRC_IPV6_ESP_MSG_QUEUE_SIZE_EXP)
#endif

#ifdef __cplusplus
}
#endif

#endif /* NET_GNRC_IPV6_ESP_CONFIG_H */
