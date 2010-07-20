/*
 * Kristjan Valur Jonsson,
 * Benedikt Kristinsson
 *
 * AES Encryption Implementation. Ported quick-and-dirty to the Arduino 
 * from the aes Intel platform implementation
 *
 *
 */
 
#include <string.h>
//#include <math.h> // ?

#ifndef __AES_CRYPT_H__
#define __AES_CRYPT_H__

// Assume Arduino Duemilanove if we are compiling without the -D flag. 
#if !(defined(_INTEL_32) || defined(_INTEL_64))
// Defines for the arduino platform
#define _ARDUINO_DUEMILANOVE         
#define unroll_encrypt_loop
#endif

//#define unroll_encrypt_loop 
//#define verbose_debug

// typedef's depending on platform
#ifdef _ARDUINO_DUEMILANOVE
typedef unsigned char       byte_ard;
typedef int                 int16_ard;
typedef unsigned int        u_int16_ard;
typedef long                int32_ard;
typedef unsigned long       u_int32_ard;
#endif
#ifdef  _INTEL_32
typedef unsigned char       byte_ard;
typedef short               int16_ard;
typedef unsigned short      u_int16_ard;
typedef int                 int32_ard;
typedef unsigned int        u_int32_ard;
typedef long long           int64_ard;
typedef unsigned long long  u_int64_ard;
#endif
#ifdef  _INTEL_64
typedef unsigned char       byte_ard;
typedef short               int16_ard;
typedef unsigned short      u_int16_ard;
typedef int                 int32_ard;
typedef unsigned int        u_int32_ard;
typedef long                int64_ard;
typedef unsigned long       u_int64_ard;
#endif

// Some defines to aid code readability
#define KEY_BYTES 16
#define KEY_WORDS 4 // Nb
#define ROUNDS 10   // Nr
#define BLOCK_BYTE_SIZE 16 

extern unsigned char pKey[]; // The secret encryption key
extern unsigned char pKeys[KEY_BYTES*12];

// Common
void KeyExpansion(const void *key, void *keys);
void AddRoundKey(void *pText, const u_int32_ard *pKeys, int round);

// Encryption
void subAndShift(void *pText);
void mixColumns(void *pText);
#define ntransform(text,keys,round) subAndShift(text);mixColumns(text);addRoundKey(text,keys,round);
void EncryptBlock(void *pText, const u_int32_ard *pKeys);

// Decryption
void InvSubAndShift(void *pText);
void InvMixColumns(void *pText);
void DecryptBlock(void* pEncrypted, const u_int32_ard *pKeys);



#endif  //__AES_CRYPT_H__
