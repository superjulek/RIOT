#include "ike/ike_payloads.h"

#include <errno.h>
#include <string.h>
#include <byteorder.h>


int build_nonce_payload(char *start, size_t max_len, size_t *new_len, ike_payload_type_t next_payload, chunk_t nonce)
{
    size_t len = sizeof(ike_generic_payload_header_t) + nonce.len;
    if (max_len < len)
    {
        return -ENOMEM;
    };
    ike_generic_payload_header_t h = {
        .next_payload = next_payload,
        .payload_length = htons(len),
    };
    memcpy(start, &h, sizeof(h));
    memcpy(start + sizeof(h), nonce.ptr, nonce.len);
    *new_len = len;

    return 0;
}


int process_nonce_payload(char *start, size_t max_len, size_t *cur_len, ike_payload_type_t *next_payload, chunk_t *nonce)
{
    (void)start; /* Unused parameter */
    (void)max_len; /* Unused parameter */
    (void)cur_len; /* Unused parameter */
    (void)next_payload; /* Unused parameter */
    (void)nonce; /* Unused parameter */
    return 0;
}
