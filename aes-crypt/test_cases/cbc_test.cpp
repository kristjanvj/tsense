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

int len(byte_ard* str)
{
  int i=0;
  while (str[i] != '\0')
    i++;
  return i+1;   // Count the null char
  //return i;
  
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

  //const char *tmp;
  u_int32_ard padding = 0;

  
  //int blocks = 1;
  // tmp = "abcdefghijklmnopabcdefghijklmnopabcdefghijklmnopabcdefghijklmnopabcdefghijklmnopabcdefghijklmnopabcdefghijklmnopabcdefghijklmnopabcdefghijklmnopabcdefghijklmno";
  tmp = "12345678901234568";

  byte_ard *text = (byte_ard*)tmp;

  u_int32_ard length = len(text);

  // Decide on the padding
  if ((length % BLOCK_BYTE_SIZE) == 0)
    padding = 0;
  else
    padding = BLOCK_BYTE_SIZE - (length % BLOCK_BYTE_SIZE);  

  u_int32_ard needed_length  = length + padding;
  
  printf("length: %d\npadding: %d\nneeded_length: %d\n\n", length, padding, needed_length);

  byte_ard buffer[needed_length];
  byte_ard decipher_buffer[needed_length];

  printf("\nPlaintext : \n");
  printBytes2((byte_ard*)text, length);

  CBCEncrypt((void *) text, (void *) buffer, length, padding,  (const u_int32_ard*)Keys, (const u_int16_ard*)IV);

  printf("\nAfter CBC: \n");
  printBytes2((byte_ard*)buffer, needed_length);
  
  // now try to decipher the ciphered buffer.
  CBCDecrypt((void *) buffer, (void *) decipher_buffer, needed_length, (const u_int32_ard*)Keys, (const u_int16_ard*)IV);
  
  printf("buffer: %d", len(buffer));
  

  printf("\nCBC Decipher: \n");
  printBytes2((byte_ard*)decipher_buffer, needed_length);
  
  
  
  return 0;
}
