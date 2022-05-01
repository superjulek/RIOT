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

#ifndef IKE_STRUCTURES_H
#define IKE_STRUCTURES_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IKE_V2_MJVER 2 << 4
#define IKE_V2_MNVER 0

#define IKE_RESPONSE_FLAG   1<<5
#define IKE_VERSION_FLAG    1<<4
#define IKE_INITIATOR_FLAG  1<<3

typedef enum {
    IKE_ET_IKE_SA_INIT = 34,
    IKE_ET_IKE_AUTH = 35,
    IKE_ET_CREATE_CHILD_SA = 36,
    IKE_ET_INFORMATIONAL = 37,

} ike_exchange_type_t;

typedef enum {
    IKE_PT_NO_NEXT_PAYLOAD = 0,
    IKE_PT_SECURITY_ASSOCIATION = 33,
    IKE_PT_KEY_EXCHANGE = 34,
    IKE_PT_IDENTIFICATION_I = 35,
    IKE_PT_IDENTIFICATION_R = 36,
    IKE_PT_CERTIFICATE = 37,
    IKE_PT_CERTIFICATE_REQUEST = 38,
    IKE_PT_AUTHENTICATION = 39,
    IKE_PT_NONCE = 40,
    IKE_PT_NOTIFY = 41,
    IKE_PT_DELETE = 42,
    IKE_PT_TRAFFIC_SELECTOR_I = 44,
    IKE_PT_TRAFFIC_SELECTOR_R = 45,
    IKE_PT_ENCRYPTED_AND_AUTHENTICATED = 46,
} ike_payload_type_t;

typedef struct __attribute__((packed)) {
    uint64_t ike_sa_spi_i;
    uint64_t ike_sa_spi_r;
    uint8_t next_payload;
    uint8_t mjver_mnver; // JJJJNNNN
    uint8_t exchange_type;
    uint8_t flags;
    uint32_t message_id;
    uint32_t length;
} ike_header_t;

typedef struct __attribute__((packed)) {
    uint8_t next_payload;
    uint8_t critical_reserved; // CRRRRRRR
    uint16_t payload_length;
} ike_generic_payload_header_t;

/* Variable length payloads */

typedef struct __attribute__((packed)) {
    uint16_t t_attribute_type; // first bit always set
    uint16_t attribute_value;

} ike_transform_attribute_t;

typedef struct __attribute__((packed)) {
    uint8_t last;
    uint8_t reserved1;
    uint16_t transform_length;
    uint8_t transform_type;
    uint8_t reserved2;
    uint16_t transform_id;
    ike_transform_attribute_t **attributes;
} ike_transform_substructure_t;

typedef struct __attribute__((packed)) {
    uint8_t last;
    uint8_t reserved;
    uint16_t proposal_length;
    uint8_t proposal_num;
    uint8_t protosol_id;
    uint8_t spi_size;
    uint8_t num_transforms;
    char * spi;
    ike_transform_substructure_t **transforms;
} ike_proposal_substructure_t;

typedef struct __attribute__((packed)) {
    ike_generic_payload_header_t hdr;
    ike_proposal_substructure_t **proposals;
} ike_security_association_payload_t;

typedef struct __attribute__((packed)) {
    ike_generic_payload_header_t hdr;
    uint16_t diffie_helman_group_num;
    uint16_t reserved;
    char *key_exchange_data;
} ike_key_exchange_payload_t;

typedef struct __attribute__((packed)) {
    ike_generic_payload_header_t hdr;
    char *nonce_data;
} ike_nonce_payload_t;

#ifdef __cplusplus
}
#endif

#endif /* IKE_STRUCTURES_H */
/** @} */
