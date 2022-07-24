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
extern "C"
{
#endif

#include "ike_structures.h"
#include "chunk.h"

#include "stddef.h"

    int build_sa_payload(char *start, size_t max_len, size_t *new_len, ike_payload_type_t next_payload, ike_protocol_id_t protocol,
                         ike_transform_encr_t encr, ike_transform_prf_t prf, ike_transform_integ_t integ,
                         ike_transform_dh_t dh, ike_transform_esn_t esn, size_t key_size, chunk_t spi);

    int process_sa_payload(char *start, size_t max_len, size_t *cur_len, ike_payload_type_t *next_payload, ike_protocol_id_t *protocol,
                           ike_transform_encr_t *encr, ike_transform_prf_t *prf, ike_transform_integ_t *integ,
                           ike_transform_dh_t *dh, ike_transform_esn_t *esn, size_t *key_size, chunk_t *spi);

    int build_nonce_payload(char *start, size_t max_len, size_t *new_len, ike_payload_type_t next_payload, chunk_t nonce);

    int process_nonce_payload(char *start, size_t max_len, size_t *cur_len, ike_payload_type_t *next_payload, chunk_t *nonce);

    int build_identification_payload(char *start, size_t max_len, size_t *new_len, ike_payload_type_t next_payload, ike_id_type_t id_type, chunk_t id);

    int build_auth_payload(char *start, size_t max_len, size_t *new_len, ike_payload_type_t next_payload, ike_auth_method_t auth_method, chunk_t auth_data);

    int build_key_exchange_payload(char *start, size_t max_len, size_t *new_len, ike_payload_type_t next_payload, ike_transform_dh_t dh, chunk_t key_data);

    int build_ts_payload(char *start, size_t max_len, size_t *new_len, ike_payload_type_t next_payload);

    int process_key_exchange_payload(char *start, size_t max_len, size_t *cur_len, ike_payload_type_t *next_payload, ike_transform_dh_t *dh, chunk_t *key_data);

    int process_generic_payload_header(char *start, size_t max_len, size_t *cur_len, ike_payload_type_t *next_payload);

    int process_unknown_payload(char *start, size_t max_len, size_t *cur_len, ike_payload_type_t *next_payload);

    int build_encrypted_payload(char *start, size_t max_len, size_t *new_len, ike_payload_type_t first_payload, chunk_t enc_data, chunk_t ekey, chunk_t akey);

    int process_encrypted_payload(char *start, size_t max_len, size_t *cur_len, ike_payload_type_t *next_payload, chunk_t *dec_data, chunk_t ekey, chunk_t akey);

#ifdef __cplusplus
}
#endif

#endif /* IKE_PAYLOADS_H */
/** @} */
