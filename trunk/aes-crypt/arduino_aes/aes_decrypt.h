// Benedikt Kristinsson

// AES Decryption Implementation

#include <string.h>

#ifndef __AES_DECRYPT_H__
#define __AES_DECRYPT_H__

// Intel32 and amd64 has to pass the -D flag to the compiler. If it doesnt, Arduino is 
// assumed

#if !(defined(_INTEL_32) || defined(_INTEL_64))
#include "environment.h"
#endif

// Types defined
#ifdef _ARDUINO_DUEMILANOVE
typedef unsigned char		byte_ard;
typedef int					int16_ard;
typedef unsigned int		u_int16_ard;
typedef long				int32_ard;
typedef unsigned long		u_int32_ard;
#endif
#ifdef  _INTEL_32
typedef unsigned char		byte_ard;
typedef short				int16_ard;
typedef unsigned short		u_int16_ard;
typedef int					int32_ard;
typedef unsigned int		u_int32_ard;
typedef long long			int64_ard;
typedef unsigned long long	u_int64_ard;
#endif
#ifdef  _INTEL_64
typedef unsigned char		byte_ard;
typedef short				int16_ard;
typedef unsigned short		u_int16_ard;
typedef int					int32_ard;
typedef unsigned int		u_int32_ard;
typedef long				int64_ard;
typedef unsigned long		u_int64_ard;
#endif


//#define verbose_debug
//#define unroll_decrypt_loop

// Some defines to aid code readability
#define KEY_BYTES 16
#define KEY_WORDS 4 //Nb
#define ROUNDS 10 //Nr
#define BLOCK_BYTE_SIZE 16

extern unsigned char pKey[]; // The secret encryption key
extern unsigned char pKeys[KEY_BYTES*12];

void KeyExpansion(const void *key, void* keys);

void AddRoundKey(void *pText, const u_int32_ard *pKeys, int round);

void InvSubAndShift(void *pText);

void InvMixColumns(void *pText);

#endif // __AES_DECRYPT_H__
