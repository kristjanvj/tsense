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
#include <math.h>

#ifndef __AES_CRYPT_H__
#define __AES_CRYPT_H__

/* Do not include the the environment file if we are compiling for something
 * other than Arduino. The reason is that there does not seem to be a way 
 * seem to be a way to pass preprocessor macros to the gcc-avr compiler with 
 * the native Arduino IDE. This can be done on gcc/g++ using the '-D' option.
 *
 * BK: Intel32 and Intel32 compiles the code using the -D flag. gcc-avr doesnt 
 *     support -D so ifdef's are used instead. 
 */

#if !(defined(_INTEL_32) || defined(_INTEL_64))
#include "environment.h"    // Define platform in environment.h
#endif

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

/* These switches control the use of t-table transformations v.s. the 8-bit 
 * version as used in the textbook and various other sources. T-tables can be 
 * generated on startup or loaded from the pre-generated definitions. See the
 * initialization for the latter case in the code.
 */
//#define t_box_transform  // 32 bit optimization, else vanilla 8 bit.
//#define t_table_generate

//#define unroll_encrypt_loop 

//#define verbose_debug

// Some defines to aid code readability
#define KEY_BYTES 16
#define KEY_WORDS 4
#define ROUNDS 10
#define BLOCK_BYTE_SIZE 16

extern unsigned char pKey[]; // The secret encryption key
extern unsigned char pKeys[KEY_BYTES*12];

void KeyExpansion(const void *key, void *keys);

void addRoundKey(void *pText, const u_int32_ard *pKeys, int round);

#ifndef t_box_transform
void subAndShift(void *pText);

void mixColumns(void *pText);

void ttransform(void *pText, const u_int32_ard *pKeys, int round);

void lttransform(void *pText, const u_int32_ard *pKeys, int round);
#endif

#define ntransform(text,keys,round) subAndShift(text);mixColumns(text);addRoundKey(text,keys,round);

void encryptBlock(void *pText, const u_int32_ard *pKeys);

#if defined(t_box_transform) && defined(t_table_generate)
void initializeTboxes();
#endif

// ----------------------------------------------------------------------------
// CMAC Caclulations.
// ----------------------------------------------------------------------------

#define CMAC_VALID 1
#define CMAC_INVALID 0

const byte_ard constRb[] =
    {0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
     0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x87};

void leftShiftKey(byte_ard *orig, byte_ard *shifted);
void xorToLength(byte_ard *p, byte_ard *q, byte_ard *r);
void initBlockZero(byte_ard *block);
void expandMacKey(byte_ard *origKey, byte_ard *newKey);
void aesCMac(byte_ard *K, byte_ard *M, long length, byte_ard *cmac);
int verifyAesCMac(byte_ard *K, byte_ard *M, long M_length, byte_ard* MACm);


#endif
