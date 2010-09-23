// Benedikt Kristinsson
// Deciphers the example block in FIPS 197 Appendix B. 

#include "aes_crypt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define BLOCK_SIZE 16
#define print_key_schedule


// printBytes2 KVJ
void printBytes2(unsigned char* pBytes, unsigned long dLength, int textWidth=16)
{	
	int bytecount=0;
	for(unsigned long i=0;i<dLength;i++)
	{
		printf("%.2x ",pBytes[i]);
		if ( ++bytecount == textWidth )
		{
			printf("\n");
			bytecount=0;
		}
	}
	if ( bytecount != 0 )
		printf("\n");
}

int main(int argc, char *argv[])
{
  // Key and 16 byte block as per FIPS 197, Appendix B (Cipher Example)

  byte_ard pKey[] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c 
  };

  // The ciphertext according to the FIPS and block_e.cpp
  byte_ard pCipherBlock[] = {
    0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32 
  };

  // Allocate memory and generate the key schedule
  byte_ard pKeys[KEY_BYTES*12];
  KeyExpansion(pKey, pKeys);

  printf("\nCiphertext: \n");
  printBytes2((unsigned char *)pCipherBlock, BLOCK_SIZE);

  #ifdef print_key_schedule
  printf("\nKey Schdedule: \n");
  printBytes2((unsigned char *)pKeys, BLOCK_SIZE*11);
  printf("\n");
  #endif

  // Decrypt the single block
  DecryptBlock(pCipherBlock, (const u_int32_ard*)pKeys);
  printf("\nPlaintext: \n");
  printBytes2((unsigned char *)pCipherBlock, BLOCK_SIZE);
  
  return 0;
}
