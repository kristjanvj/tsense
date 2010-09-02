/*
 * aes_utils.cpp
 *
 * A basket for various utility methods used in the Tsense project
 * regarding the AES crypto functions.  NOTE: Some methods are platform 
 * dependent. 
 *
 */
#include "string.h"
#include "aes_crypt.h"

int generateKey(byte_ard *newKey);
int generateKeyOfLength(byte_ard *newKey, int length);
void  printByteArd(unsigned char* pBytes, unsigned long dLength, int textWidth);
