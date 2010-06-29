/**
 *
 * Kristjan Valur Jonsson
 *
 * AES Encryption Implementation. Ported quick-and-dirty to the Arduino 
 * from the aes Intel platform implementation
 *
 *
 */
 
#include <string.h>

#ifndef __AES_CRYPT_H__
#define __AES_CRYPT_H__

//
// These switches control the use of t-table transformations v.s. the 8-bit version as used in the
// textbook and various other sources. T-tables can be generated on startup or loaded from the
// pre-generated definitions. See the initialization for the latter case in the code.
//
//#define t_box_transform  // 32 bit optimization, else vanilla 8 bit.
//#define t_table_generate

//#define unroll_encrypt_loop 

//#define verbose_debug

// Some defines to aid code readability
#define KEY_BYTES 16
#define KEY_WORDS 4
#define ROUNDS 10
#define BLOCK_BYTE_SIZE 16

// Dummy key for testing normally this would be secret.
extern unsigned char pKey[]; // FIPS key
extern unsigned char pKeys[KEY_BYTES*12];

void KeyExpansion(const void *key, void *keys);
//inline void KeyExpansion(const void *key, void *keys);

void addRoundKey(void *pText, const unsigned long *pKeys, int round);
//inline void addRoundKey(void *pText, const unsigned long *pKeys, int round);

#ifndef t_box_transform
//inline void subAndShift(void *pText);
void subAndShift(void *pText);

//inline void mixColumns(void *pText);
void mixColumns(void *pText);

//inline void ttransform(void *pText, const unsigned int *pKeys, int round);
void ttransform(void *pText, const unsigned int *pKeys, int round);

//inline void lttransform(void *pText, const unsigned int *pKeys, int round);
void lttransform(void *pText, const unsigned int *pKeys, int round);
#endif

#define ntransform(text,keys,round) subAndShift(text);mixColumns(text);addRoundKey(text,keys,round);

//inline void encryptBlock(void *pText, const unsigned long *pKeys);
void encryptBlock(void *pText, const unsigned long *pKeys);
//void encryptBlock(void *pText, const unsigned long *pKeys);

#if defined(t_box_transform) && defined(t_table_generate)
//inline void initializeTboxes();
void initializeTboxes();
#endif

#endif
