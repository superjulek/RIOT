/**
 * Print thread information.
 *
 * Copyright (C) 2013, INRIA.
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * @ingroup sys_ps
 * @{
 * @file
 * @brief   IKE
 * @author      Juliusz Neuman <superjulek@interia.pl>
 * @}
 */

#include "ike/chunk.h"
#include <stdio.h>
#include <stdlib.h>

chunk_t empty_chunk = {
    .ptr = NULL,
    .len = 0,
};
void free_chunk(chunk_t *chunk)
{
    if (chunk->len)
    {
        free(chunk->ptr);
    }
}

chunk_t malloc_chunk(size_t size)
{
    chunk_t chunk = {
        .len = size,
        .ptr = malloc(size),
    };
    return chunk;
}

void printf_chunk(chunk_t chunk)
{
    printf("0x");
    for (int i = 0; i < (int)chunk.len; ++i)
    {
        printf("%02X ", *(chunk.ptr + i) & 0xff);
    }
}
