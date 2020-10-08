/* PEP1 Encapsulation Protocol
 * (C) Pedro Zorzenon Neto  https://github.com/pzn1977/pep1 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>

#include "crc32.h"
#include "twofish_symmcrypt.h"

#include "pep1.h"

static uint8_t hdr[36];
static uint8_t pad;
static uint8_t xor[16];
static uint32_t psz, siz, crc;

void pep1_init(void) {
  /* check processor endianess and abort if wrong */
  static int init_done = 0;
  uint32_t a;
  uint8_t *b;
  if (init_done) return;
  a = 0x01234567;
  b = (uint8_t*) &a;
  if ((b[0] != 0x67) ||
      (b[1] != 0x45) ||
      (b[2] != 0x23) ||
      (b[3] != 0x01)) {
    fprintf(stderr,"FATAL ERROR: pep1_init(): "
	    "unexpected processor endianess\n");
    abort();
  }

  if (RAND_MAX < 268435455) { /* at least 28 bits */
    fprintf(stderr,"FATAL ERROR: pep1_init(): "
	    "random number generator is too small\n");
    abort();
  }

  /* initialize random number generator */
  srandom((unsigned int) (time(NULL) ^ getpid()));

  init_done = 1;
}

uint8_t * pep1_encode_init (uint32_t auth_id, uint32_t payload_size,
			    uint8_t *key_common, uint8_t *key_priv) {
  uint32_t r;
  /* first block */
  memcpy(hdr,"Pep1",4); /* MagicNumber */
  /* second block */
  memcpy(hdr+4,(uint8_t*)&auth_id,4);
  memcpy(hdr+8,(uint8_t*)&payload_size,4);
  psz = payload_size; siz = 0;
  r = random();
  r &= 0x7fffffff; /* MSB-bit is always 0, reserved for extensions */
  memcpy(hdr+12,(uint8_t*)&r,4);
  crc32start(&crc);
  crc32appendn(&crc, hdr+4, 12);
  memcpy(hdr+16,(uint8_t*)&crc,4);
  twofish_keyinit(key_common);
  twofish_encrypt (hdr+4,16);
  /* third block */
  pad = (16 - ((payload_size + 4) & 0x0f)) & 0x0f; /* padding size */
  hdr[20] = pad;
  r = random(); memcpy(hdr+21,(uint8_t*)&r,3);
  r = random(); memcpy(hdr+24,(uint8_t*)&r,4);
  r = random(); memcpy(hdr+28,(uint8_t*)&r,4);
  r = random(); memcpy(hdr+32,(uint8_t*)&r,4);
  crc32start(&crc);
  crc32appendn(&crc, hdr+20, 16);
  twofish_keyinit(key_priv);
  twofish_encrypt (hdr+20,16);
  memcpy(xor,hdr+20,16);
  return hdr;
}

uint8_t * pep1_encode_datablock (uint8_t dat[]) {
  int i;
  if (siz >= (psz+pad+4)) return NULL; /* finished encoding blocks */
  if (siz+16 > psz) {
    /* last blocks of data, must work with a buffer
     * or else we could risk a segfault writing beyond 'dat' limits */
    static uint8_t blk[16];
    memset(blk,0xff,16);
    if (siz < psz) {
      memcpy(blk,dat,psz-siz);
    }
    crc32appendn(&crc, blk, 12);
    if (((psz-siz) <= 12) || (siz >= psz)) {
      memcpy(blk+12,(uint8_t*)&crc,4);
    } else {
      crc32appendn(&crc, blk+12, 4);
    }
    for (i=0; i<16; i++) blk[i] ^= xor[i];
    twofish_encrypt(blk,16);
    memcpy(xor,blk,16);
    siz += 16;
    return blk;
  }
  crc32appendn(&crc, dat, 16);
  for (i=0; i<16; i++) dat[i] ^= xor[i];
  twofish_encrypt(dat,16);
  memcpy(xor,dat,16);
  siz += 16;
  return dat;
}

int pep1_decode_header (uint32_t * auth_id, uint32_t * payload_size,
			uint8_t *key_common, uint8_t dat[]) {
  uint32_t r;
  if (memcmp(dat,"Pep1",4) != 0) return 1; /* unknown header */
  twofish_keyinit(key_common);
  twofish_decrypt (dat+4,16);
  crc32start(&crc);
  crc32appendn(&crc, dat+4, 12);
  if (crc != *((uint32_t*)(dat+16))) return 2; /* CRC mismatch */
  memcpy((uint8_t*)auth_id,dat+4,4);
  memcpy((uint8_t*)&psz,dat+8,4);
  *payload_size = psz;
  memcpy((uint8_t*)&r,dat+12,4);
  if (r & 0x80000000) return 3; /* bit reserved for future use */
  return 0;
}

int pep1_decode_datablock_init (uint8_t *key_priv, uint8_t dat[]) {
  siz = 0;
  twofish_keyinit(key_priv);
  memcpy(xor,dat,16);
  twofish_decrypt (dat,16);
  crc32start(&crc);
  crc32appendn(&crc, dat, 16);
  pad = dat[0];
  if (pad > 0x0f) return 4; /* pad out of range */
  return 0;
}

int pep1_decode_datablock (uint8_t dat[]) {
  uint8_t b[16];
  int i;
  if (psz+pad < siz) return -1;
  memcpy(b,xor,16);
  memcpy(xor,dat,16);
  twofish_decrypt(dat,16);
  for (i=0; i<16; i++) dat[i] ^= b[i];
  if (psz+pad-siz == 12) {
    crc32appendn(&crc, dat, 12);
    if (crc == *((uint32_t*)(dat+12))) {
      siz += 16;
      return 1;
    } else {
      siz += 16;
      return -1;
    }
  } else {
    crc32appendn(&crc, dat, 16);
  }
  siz += 16;
  return 0;
}

int pep1_simple_encode (uint32_t auth_id, uint32_t payload_size,
			uint8_t *key_common, uint8_t *key_priv,
			uint8_t dat_in[], uint8_t dat_out[]) {
  uint8_t * h;
  uint32_t i = 0;
  pep1_init();
  if (payload_size > PEP1_SIMPLE_MAXSIZE_PLAIN) return 0;
  h = pep1_encode_init(auth_id, payload_size, key_common, key_priv);
  memcpy(dat_out,h,36);
  while (h != NULL) {
    h = pep1_encode_datablock(dat_in + i);
    if (h) {
      memcpy(dat_out+i+36,h,16);
      i += 16;
    }
  }
  return 36 + i;
}

int pep1_simple_decode_stage1 (uint32_t * auth_id, uint32_t * payload_size,
			       uint8_t *key_common, uint8_t dat[]) {
  int i;
  i = pep1_decode_header(auth_id, payload_size, key_common, dat);
  if ((i == 0) && ((*payload_size) > PEP1_SIMPLE_MAXSIZE_PLAIN))
    return 5; /* out of memory */
  return i;
}

int pep1_simple_decode_stage2 (uint8_t *key_priv,
			       uint8_t dat_in[], uint8_t dat_out[]) {
  int i = 0, j = 0;
  pep1_decode_datablock_init(key_priv, dat_in + 20);
  while (i >= 0) {
    i = pep1_decode_datablock(dat_in + j + 36);
    if (i >= 0) {
      if (j+16 <= psz) {
	memcpy(dat_out + j, dat_in + j + 36, 16);
      } else {
	int i;
	i = psz-j;
	if (i > 0) memcpy(dat_out + j, dat_in + j + 36, i);
      }
      j += 16;
    }
    if (i == 1) return 0;
  }
  return 6;
}

int pep1_simple_decode (uint32_t * auth_id, uint32_t * payload_size,
			uint8_t *key_common, uint8_t *key_priv,
			uint8_t dat_in[], uint8_t dat_out[]) {
  int i;
  i = pep1_simple_decode_stage1 (auth_id, payload_size,
				 key_common, dat_in);
  if (i != 0) return i;

  i = pep1_simple_decode_stage2 (key_priv, dat_in, dat_out);
  if (i != 0) return i;

  return 0;
}

#ifdef PEP1_TEST
static void hexprint (char * title, uint8_t *b, int size) {
  int i;
  if (title != NULL) { printf("%s:",title); }
  for (i=0; i<size; i++) {
    printf(" %02x",b[i]);
  }
  printf("\n");
}
static void chexprint (char * title, uint8_t *b, int size) {
  int i;
  if (title != NULL) { printf("%s:",title); }
  printf("\"");
  for (i=0; i<size; i++) {
    printf("\\x%02x",b[i]);
  }
  printf("\"\n");
}
static void hexchrprint (char * title, uint8_t *b, int size) {
  int i;
  if (title != NULL) { printf("%s:",title); }
  for (i=0; i<size; i++) {
    printf(" %02x",b[i]);
  }
  printf(" | ");
  for (i=0; i<size; i++) {
    if ((b[i] >= 0x20) && (b[i] <= 0x7e)) {
      printf("%c",b[i]);
    } else {
      printf("?");
    }
  }
  printf("\n");
}
int main (void) {
  uint8_t * h;
  uint8_t d[200];
  int i, j;

  pep1_init();


  if (1) {
    strcpy((char*)d,"This is a Test! This data will be crypted!");
    h = pep1_encode_init(0x12345678,
			 (uint32_t) strlen((char*)d),
			 (uint8_t*) "0123456789ABCDEF",
			 (uint8_t*) "abcdef0123456789");
    chexprint(NULL,h,4);
    chexprint(NULL,h+4,16);
    chexprint(NULL,h+20,16);
    j = 0;
    while (h != NULL) {
      h = pep1_encode_datablock(d + j);
      j += 16;
      if (h) {
	chexprint(NULL,h,16);
      }
    }
    printf("\n");
  }


  if (1) { /* per block decode example */
    uint32_t auth_id, payload_size, dsize;
    dsize = 4 + ( 16 * 5 ); /* data below has 5 lines with 16 bytes */
    memcpy(d,
	   "\x50\x65\x70\x31"
	   "\x47\x65\xae\xb0\x6c\xda\xd8\xfa\x7c\x64\x40\xf8\x6a\x89\xcb\xbf"
	   "\x8a\x11\x3f\x65\x8c\x89\xb8\x49\xa5\x26\x60\xf0\x47\xfa\x19\x89"
	   "\xff\xb4\x68\x48\x3b\x13\x19\x38\x24\x23\x41\x72\x38\xde\x06\xdf"
	   "\x59\xe2\x3d\xa4\xa9\x1d\x90\x13\xeb\x92\x49\x89\xe0\x93\x09\x2d"
	   "\x64\x90\xa9\x3d\x6d\x2a\x65\x8e\x94\x16\x5a\x04\x55\x23\x3a\x0a"
	   , dsize);
    i = pep1_decode_header (&auth_id, &payload_size,
			    (uint8_t*) "0123456789ABCDEF", d);
    if (i != 0) {
      printf("header error %d\n", i);
      return 1;
    }
    printf("header auth=0x%08x size=%u\n",auth_id,payload_size);

    pep1_decode_datablock_init((uint8_t*) "abcdef0123456789", d + 20);

    j = 36;
    for (j=36; j<dsize; j+=16) {
      i = pep1_decode_datablock(d + j);
      printf("i=%d ",i);
      hexchrprint("",d + j, 16);
    }
    printf("\n");
  }

  /* lets make "simple" examples to encode at most 200 bytes */
  uint8_t d_enc[200+PEP1_SIMPLE_ENC_OVERHEAD];

  if (1) { /* simple encode example */
    int i, p;
    uint8_t d_txt[200];
    strcpy((char*)d_txt,"This is a Test! This data will be crypted!");
    p = strlen((char *)d_txt);
    i = pep1_simple_encode (0x12345678, p,
			    (uint8_t*) "0123456789ABCDEF",
			    (uint8_t*) "abcdef0123456789",
			    d_txt, d_enc);
    if (i > 0) {
      printf("payload size is %d\n",p);
      printf("enc size is %d\n",i);
      hexprint("enc", d_enc, i);
    } else {
      /* ERROR: payload_size is bigger than supported by pep1_simple_encode
       * try to change #define and increase the max value */
    }
    printf("\n");

    if (1) {
      /* simple 2-stage decode example */
      uint8_t d_dec[200];
      uint32_t auth_id, payload_size;
      int i;
      i = pep1_simple_decode_stage1 (&auth_id, &payload_size,
				     (uint8_t*) "0123456789ABCDEF", d_enc);
      if (i != 0) {
	printf("pep1_simple_decode_stage1 failed with status %d\n",i);
      } else {
	printf("payload size is %d\n",payload_size);
	printf("auth_id is 0x%08x\n",auth_id);
	/* this is the right time to check auth_id and fetch
	 * key_priv from some local database to use in stage2 */
	i = pep1_simple_decode_stage2 ((uint8_t*) "abcdef0123456789",
				       d_enc, d_dec);
	if (i != 0) {
	  printf("pep1_simple_decode_stage2 failed with status %d\n",i);
	} else {
	  hexchrprint("dec2", d_dec, payload_size);
	}
      }
      printf("\n");
    } else {
      /* simple 1-stage decode example */
      uint8_t d_dec[200];
      uint32_t auth_id, payload_size;
      int i;
      i = pep1_simple_decode (&auth_id, &payload_size,
			      (uint8_t*) "0123456789ABCDEF",
			      (uint8_t*) "abcdef0123456789",
			      d_enc, d_dec);
      if (i != 0) {
	printf("pep1_simple_decode failed with status %d\n",i);
      } else {
	hexchrprint("decS", d_dec, payload_size);
      }
    }
  }

  return 0;

}
#endif
