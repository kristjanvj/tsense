/*
   File name: aes_common.h
   Date:      2010-07-19 11:12
   Author:    Kristjan Runarsson
*/

#ifndef __AES_COMMON_H__
#define __AES_COMMON_H__

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

#define BLOCK_BYTE_SIZE 16

#endif
