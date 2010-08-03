// Benedikt Kristinsson
// CBC Mac test cases

#include "aes_crypt.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

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

int main()
{
  /*
   * In order to use the CBC Mode of Operation the following has to be declared
   *  - A unsigned char (byte_ard) array containing the cleartext
   *  - Another unsigned char array where the size modulus 16 == 0. This will hold the cipertext
   *  - The length of the plaintext array. int32
   *  - The number of chars needed to 'pad' the array.
   *  - Initialization vector
   *  - AES 128-bit key
   */

  byte_ard Key[] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c 
  };

  byte_ard IV[] = {
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,  0x30, 0x30 
  };

  // Allocate memory for key schedule and generate it.
  byte_ard Keys[KEY_BYTES*12];
  KeyExpansion(Key, Keys);

  //const char *text;
  //text = "Helo world!";

  byte_ard text[] = {
      0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21
  };  // Hello world!
  
  u_int32_ard blocks = 0;
  u_int32_ard length = 0;
  u_int32_ard padding = 0;

  // Count the string length
  while (text[length] != '\0')
    length = length + 1;

  // Decide on the padding
  if ((length % BLOCK_BYTE_SIZE) == 0)
    padding = 0;
  else
    padding = BLOCK_BYTE_SIZE - (length % BLOCK_BYTE_SIZE);

  // Each block is 4 bytes. BLOCK_BYTE_SIZE
  blocks = (length + padding) / BLOCK_BYTE_SIZE;

  // Allocate memory
  byte_ard buffer[blocks * BLOCK_BYTE_SIZE];
  
  printf("length: %d\npadding: %d \nblocks:%d blocks \n\n", length, padding, blocks);

  printf("\nKey: \n");
  printBytes2(Key, BLOCK_BYTE_SIZE);
  printf("\nInitialization vector: \n");
  printBytes2(IV, BLOCK_BYTE_SIZE);
  printf("\nPlaintext: \n");
  printBytes2((byte_ard*)text, BLOCK_BYTE_SIZE);



  CBCEncrypt((void *) text, (void *) buffer, length, padding,  (const u_int32_ard*)Keys, (const u_int16_ard*)IV);

  printf("After CBC: \n");
  printBytes2((byte_ard*)buffer, BLOCK_BYTE_SIZE);
  
  //printf("testing: \n%.2x\n", (char)text[198]);
  
  return 0;
}
