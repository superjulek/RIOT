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

#ifndef IKE_PAYLOADS_H
#define IKE_PAYLOADS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "ike_structures.h"
#include "chunk.h"

#include "stddef.h"

int build_sa_payload(char *start, size_t max_len, ike_payload_type_t next_payload, ike_protocol_id_t protocol,
    ike_transform_encr_t encr, ike_transform_prf_t prf, ike_transform_integ_t integ,
    ike_transform_dh_t dh, ike_transform_esn_t esn, size_t key_size, chunk_t spi);

int process_sa_payload(char *start, size_t max_len, ike_payload_type_t *next_payload, ike_protocol_id_t *protocol,
    ike_transform_encr_t *encr, ike_transform_prf_t *prf, ike_transform_integ_t *integ,
    ike_transform_dh_t *dh, ike_transform_esn_t *esn, size_t *key_size, chunk_t *spi);

#ifdef __cplusplus
}
#endif

#endif /* IKE_PAYLOADS_H */
/** @} */
