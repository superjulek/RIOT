/*
 * Copyright (C) 2010 Freie Universität Berlin
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    sys_ps IKE
 * @ingroup     sys
 * @brief       Control IKE daemon
 * @{
 *
 * @file
 * @brief       IKE
 *
 * @author      Juliusz Neuman <superjulek@interia.pl>
 */

#ifndef IKE_CHUNK_H
#define IKE_CHUNK_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>


typedef struct {
    size_t len;
    char *ptr;
} chunk_t;


void free_chunk(chunk_t *chunk);

chunk_t malloc_chunk(size_t size);

void printf_chunk(chunk_t chunk);

extern chunk_t empty_chunk;

#ifdef __cplusplus
}
#endif

#endif /* IKE_CHUNK_H */
/** @} */
