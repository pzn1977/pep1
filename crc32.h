#ifndef _CRC32_H
#define _CRC32_H

#include <stdint.h>

void crc32start(uint32_t *buf);
void crc32appendc(uint32_t *buf, uint8_t c);
void crc32appendn(uint32_t *buf, uint8_t *dat, size_t len);
void crc32result(uint32_t *buf);

#endif
