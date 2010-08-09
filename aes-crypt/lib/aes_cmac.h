/*
 * File name: aes_cmac.h
 * Date:      2010-07-19 11:00
 * Author:    Kristjan Runarsson
 */

 
#include <string.h>
#include <math.h>
#include "aes_crypt.h"

#ifndef __AES_CMAC_H__
#define __AES_CMAC_H__

#define CMAC_VALID 1
#define CMAC_INVALID 0

const byte_ard constRb[] =
    {0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
     0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x87};

void leftShiftKey(byte_ard *orig, byte_ard *shifted);
void xorToLength(byte_ard *p, byte_ard *q, byte_ard *r);
void initBlockZero(byte_ard *block);
void expandMacKey(byte_ard *origKey, byte_ard *newKey);
void aesCMac(const u_int32_ard* KS, byte_ard *M, long length, byte_ard *cmac);
int verifyAesCMac(byte_ard *K, byte_ard *M, long M_length, byte_ard* MACm);


#endif
