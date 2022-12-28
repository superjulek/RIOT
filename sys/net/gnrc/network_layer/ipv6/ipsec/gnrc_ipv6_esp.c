#include "net/gnrc/ipv6.h"
#include "net/gnrc/ipv6/ipsec/ipsec.h"
#include "net/gnrc/ipv6/ipsec/ipsec_db.h"
#include "net/gnrc/ipv6/ipsec/esp.h"
#include "crypto/aes.h"
#include "hashes/sha1.h"
#include "crypto/modes/cbc.h"

#define ENABLE_DEBUG 0
#include "debug.h"


static int _calc_fields(const ipsec_sa_t *sa, uint8_t *iv_size, uint8_t *icv_size,
						uint8_t *block_size) {

	/* On using DietESP: If Implicit IV is used, that has to be minded here */

	switch(sa->crypt_info.cipher) {
		case IPSEC_CIPHER_AES128_CBC:
				*block_size = 4;
				*iv_size = 16;
			break;
		default:
			DEBUG("ipsec_esp: ERROR unsupported cipher\n");
			return -1;
	}
	switch(sa->crypt_info.hash) {
		case IPSEC_HASH_SHA1:
				*icv_size = 12;
			break;
		default:
			DEBUG("ipsec_esp: ERROR unsupported hash\n");
			return -1;
	}
	return 0;
}

static int _decrypt(gnrc_pktsnip_t *esp, const ipsec_sa_t *sa) {

	/* On using DietESP: On en- and decryption some negotiated DietESP rules
	need to be checked and minded for all ciphers, like e.g. Implicit IV */
    uint8_t icv_size, iv_size, block_size;
    size_t enc_len;
    ipv6_esp_trl_t trl;
    uint8_t *pld, *iv;
    cipher_t cipher;
    uint8_t data[2048]; // TODO

	if (_calc_fields(sa, &iv_size, &icv_size, &block_size))
        return -1;
    iv = (uint8_t*)esp->data + sizeof(ipv6_esp_hdr_t);
    pld = iv + iv_size;
    enc_len = esp->size - sizeof(ipv6_esp_hdr_t) - iv_size - icv_size;
    switch (sa->crypt_info.cipher)
    {
        case IPSEC_CIPHER_AES128_CBC:
            if (cipher_init(&cipher, CIPHER_AES, sa->crypt_info.key, 16)!= CIPHER_INIT_SUCCESS)
                return -1;

            if (cipher_decrypt_cbc(&cipher, iv, pld, enc_len, data) < 0)
                return -1;
            break;
        default:
            return -1;
    }
    trl = *(ipv6_esp_trl_t*)((uint8_t*)esp->data + esp->size - icv_size - sizeof(ipv6_esp_trl_t));

    (void) trl;
	return 0;
}

gnrc_pktsnip_t *esp_header_process(gnrc_pktsnip_t *esp, uint8_t protnum) {
	gnrc_pktsnip_t *data_snip;
	gnrc_pktsnip_t *new_ipv6;
	ipsec_sa_t sa;
	uint8_t *nh;

	uint8_t iv_size;
	uint8_t icv_size;
	uint32_t spi;
	uint32_t sn;
	uint8_t padding_size;
	uint8_t data_size;
	uint8_t blocksize;

	assert(protnum == PROTNUM_IPV6_EXT_ESP);
	DEBUG("ipv6_esp: Rx ESP packet\n");


	spi = byteorder_ntohl(*(network_uint32_t*)esp->data);
	sn = byteorder_ntohl(*(network_uint32_t*)((uint8_t*)esp->data + 4));

	DEBUG("ipv6_esp: Rx pkt spi: %i  sn: %i\n", (int)spi, (int)sn);

	if(ipsec_get_sa_by_spi(spi, &sa)) {
		DEBUG("ipv6_esp: Rx sa by spi not found. spi: %i\n", (int)spi);
		/* pkt will be released by caller */
		return NULL;
	}

	/* TODO: Send SN to 'Anti Replay Window' processing
	 * pkt = _check_arpw() /@return NULL if out of range
	 */

	/* Authenticate and Decrypt ESP packet */
	switch(sa.c_mode) {
		case IPSEC_CIPHER_MODE_ENC_AUTH:
			//_verify(esp, sa);
			_decrypt(esp, &sa);
			break;
		default:
			DEBUG("ipv6_esp: ERROR Cipher mode not supported\n");
			return NULL;
	}

	/* TODO: Check against SPD database.
	 *
	 * -> After the packet is decrypted, we need to check it against the SDP
	 * rule set, since we where not able to determine its content before
	 * decryption. This stems from the fact, that an SA can be shared by
	 * multiple SPD rules. Imagine a scenario where a single SA is used for all
	 * comunication between two systems, but where the SPD rules states to
	 * DISCARD all TCP traffic. */

	/** On using DietESP: At this stange we send the decrypted packet to the
	 * EHC routines to decompress it */

	/* we do not need blocksize here, but else we'd need two methods */
	_calc_fields(&sa, &iv_size, &icv_size, &blocksize);
	nh = (uint8_t*)esp->data + esp->size - (icv_size + 1);
	padding_size = *(nh - 1);
	data_size = esp->size -
		(sizeof(ipv6_esp_hdr_t) + sizeof(ipv6_esp_trl_t) + padding_size
		 + icv_size + iv_size);
	data_snip = gnrc_pktbuf_add(NULL, NULL, data_size, gnrc_nettype_from_protnum(*nh));
	memcpy(data_snip->data,
		(((uint8_t*)esp->data) + sizeof(ipv6_esp_hdr_t) + iv_size), data_size);

	if(sa.mode != IPSEC_MODE_TRANSPORT) {
        DEBUG("ipv6_esp: Only transport mode supported");
        gnrc_pktbuf_release(data_snip);
        return NULL;
	}
	//esp = gnrc_pktbuf_replace_snip(esp, esp, data_snip); TODO!!!

	/* adjusting original ipv6 header fields*/
	LL_SEARCH_SCALAR(esp, new_ipv6, type, GNRC_NETTYPE_IPV6);
	/* TODO: consider intermediate ext headers for len */
	((ipv6_hdr_t*)new_ipv6->data)->len = byteorder_htons((uint16_t)esp->size);
	if(esp->next->type == GNRC_NETTYPE_IPV6) {
		((ipv6_hdr_t*)esp->next->data)->nh = gnrc_nettype_to_protnum(esp->type);
	} else {	/* prev header is ext header */
		((ipv6_ext_t*)esp->next->data)->nh = gnrc_nettype_to_protnum(esp->type);
	}

	/* TODO: add original? pktsize to SA bytecount limiters */

	return esp;
}
