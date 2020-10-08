#ifndef _TWOFISH_SYMMETRIC_H
#define _TWOFISH_SYMMETRIC_H

#include <stdint.h>

/* key must have exactly 16 bytes */
void twofish_keyinit (uint8_t key[]);

/* size must be multiple of 16 bytes */
void twofish_encrypt (uint8_t *buf, int size);

/* size must be multiple of 16 bytes */
void twofish_decrypt (uint8_t *buf, int size);

#endif
