#ifndef _PEP1_H
#define _PEP1_H

/* PEP1 Encapsulation Protocol
 * (C) Pedro Zorzenon Neto  https://github.com/pzn1977/pep1 */

/* These functions can handle bigger data sizes (up to 2GB) per
 * package and they are more complicated to use since they work per
 * block:
 *
 *  pep1_init()
 *  pep1_encode_init();
 *  pep1_encode_datablock();
 *  pep1_decode_header();
 *  pep1_decode_datablock_init();
 *  pep1_decode_datablock();
 *
 * These funcions are very simple to use and can handle small
 * amount of data (limited to PAP1_SIMPLE_MAXSIZE_PLAIN bytes):
 *
 * pep1_simple_encode();
 * pep1_simple_decode_stage1();
 * pep1_simple_decode_stage2();
 * pep1_simple_decode();
 *
 * see usage examples in pep1.c main()
 *
 * NOTE: this program was developed for small processors,
 * it is not thread-safe
 */

#include <stdint.h>

void pep1_init(void);
uint8_t * pep1_encode_init (uint32_t auth_id, uint32_t payload_size,
			    uint8_t *key_common, uint8_t *key_priv);

/* IMPORTANT: pep1 encodes/decodes 16 bytes per datablock */
/* returns NULL if finished encoding */
uint8_t * pep1_encode_datablock (uint8_t dat[]);

/* returns 0 if header is OK, or returns an error number.
 *   dat[] must have 36 bytes */
int pep1_decode_header (uint32_t * auth_id, uint32_t * payload_size,
			uint8_t *key_common, uint8_t dat[]);

/* returns 0 if datablockheader is OK, or returns an error number */
int pep1_decode_datablock_init (uint8_t *key_priv, uint8_t dat[]);

/* IMPORTANT: pep1 encodes/decodes 16 bytes per datablock */
/* returns:
 *   0 data is been processed (still not last package, can't
 *                             check key+checksum yet)
 *   1 data is OK (this is the last package)
 *  -1 data error (wrong key or checksum mismatch) */
int pep1_decode_datablock (uint8_t dat[]);

/* pap1_simple_* functions have a size limit */
#define PEP1_SIMPLE_MAXSIZE_PLAIN   (16*1024)
#define PEP1_SIMPLE_ENC_OVERHEAD (4 + 16 + 1 + 15 + 16 + 4 + 16)
#define PEP1_SIMPLE_MAXSIZE_ENCODED (PEP1_SIMPLE_MAXSIZE_PLAIN + \
				     PEP1_SIMPLE_ENC_OVERHEAD)
#define PEP1_ENCODED_MINSIZE 52


/* inputs: auth_id, payload_size, key_common, key_priv, dat_in
 * output: dat_out
 * returns: dat_out size (in bytes) */
int pep1_simple_encode (uint32_t auth_id, uint32_t payload_size,
			  uint8_t *key_common, uint8_t *key_priv,
			  uint8_t dat_in[], uint8_t dat_out[]);

/* inputs: key_common, dat_in
 * outputs: auth_id, payload_size
 * returns: 0 if decoded successfully, else returns an error number */
int pep1_simple_decode_stage1 (uint32_t * auth_id, uint32_t * payload_size,
			       uint8_t *key_common, uint8_t dat[]);
/* inputs: key_priv, dat_in
 * output: dat_out
 * returns: 0 if decoded successfully, else returns an error number */
int pep1_simple_decode_stage2 (uint8_t *key_priv,
			       uint8_t dat_in[], uint8_t dat_out[]);

/* inputs: key_common, key_priv, dat_in
 * outputs: auth_id, payload_size, dat_out
 * returns: 0 if decoded successfully, else returns an error number
 *
 * this function only makes sense if you already know auth_id and
 * key_priv in advance (probably because you are a client and only
 * communicates with a single server).
*/
int pep1_simple_decode (uint32_t * auth_id, uint32_t * payload_size,
			uint8_t *key_common, uint8_t *key_priv,
			uint8_t dat_in[], uint8_t dat_out[]);

#endif
