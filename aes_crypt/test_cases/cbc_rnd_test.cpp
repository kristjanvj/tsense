// Benedikt Kristinsson
// CBC Mac test cases

#include "aes_crypt.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctime>


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

bool runTest(byte_ard *text, int length, const u_int32_ard *Keys, const u_int16_ard *IV, bool verbose=false, bool printableStr=false)
{
  u_int32_ard padding = 0;

  // Decide on the padding
  if ((length % BLOCK_BYTE_SIZE) == 0)
    padding = 0;
  else
    padding = BLOCK_BYTE_SIZE - (length % BLOCK_BYTE_SIZE);  

  u_int32_ard needed_length  = length + padding;
  
  printf("length: %d\npadding: %d\nneeded_length: %d\n", length, padding, needed_length);

  byte_ard buffer[needed_length+1];
  byte_ard decipher_buffer[needed_length+1];

  memset(buffer,0,needed_length+1);
  memset(decipher_buffer,0,needed_length+1);

  if(verbose) {
    printf("\nPlaintext : \n");
    printBytes2((byte_ard*)text, length);
    if (printableStr) printf("printf(): \n%s\n\n", text);
  }

  CBCEncrypt((void *) text, (void *) buffer, length, padding,  Keys, IV);

  if(verbose) {
    printf("\nAfter CBC: \n");
    printBytes2((byte_ard*)buffer, needed_length);
  }

  // now try to decipher the ciphered buffer.
  CBCDecrypt((void *) buffer, (void *) decipher_buffer, needed_length, Keys, IV);
   
  if(verbose) {
    printf("\nCBC Decipher: \n");
    printBytes2((byte_ard*)decipher_buffer, needed_length);
    if (printableStr) printf("printf(): \n%s\n\n", decipher_buffer);
  }

  bool retval=true;
  for(int i=0; i<length; i++)
  {
    if (text[i]!=decipher_buffer[i])
    {
      retval=false;
      break;
    }
  }
  if ( retval )
    printf("Checks out\n");
  else
    printf("Failed!\n");  

  return retval;
}

bool do_rnd_test(const u_int32_ard *Keys, const u_int16_ard *IV, bool verbose=false, bool printableStr=false)
{
  srand((unsigned)time(0));
  int testBufLen=rand() % 2048;
  byte_ard text[testBufLen];
  for( int i=0; i<testBufLen; i++)
  {
    text[i] = rand() % 254;  
  }

  return runTest(text,testBufLen,(u_int32_ard*)Keys,(u_int16_ard*)IV,verbose,printableStr);
}

bool do_str_tests(const u_int32_ard *Keys, const u_int16_ard *IV, bool verbose=false, bool printableStr=false)
{
  const char *tmp;
  byte_ard *text;
  bool retval=true;

  tmp = "abcdefghijklmnop\0";
  text = (byte_ard*)tmp;
  printf("\n'%s'\n",tmp);
  retval &= runTest(text,strlen(tmp),Keys,IV,verbose,printableStr);

  tmp = "abcdefghijklmnopabcdefghijklmnopabcdefghijklmnopabcdefghijklmnopabcdefghijklmnopabcdefghijklmnopabcdefghijklmnopabcdefghijklmnopabcdefghijklmnopabcdefghijklmnop\0";
  text = (byte_ard*)tmp;
  printf("\n'%s'\n",tmp);  
  retval &= runTest(text,strlen(tmp),Keys,IV,verbose,printableStr);

  tmp = "abcdefghijklmnopabcd\0";
  text = (byte_ard*)tmp;
  printf("\n'%s'\n",tmp);
  retval &= runTest(text,strlen(tmp),Keys,IV,verbose,printableStr);

  tmp = "abcdefghijklmnopabcdefghijklmnopabcdefghijklmnopabcdefghijklmnopabcdefghijklmnopabcdefghijklmnopabcdefghijklmnopabcdefghijklmnopabcdefghijklmnopabcdefghijklmnopabcd\0";
  text = (byte_ard*)tmp;
  printf("\n'%s'\n",tmp);
  retval &= runTest(text,strlen(tmp),Keys,IV,verbose,printableStr);

  tmp = "Hello, this is an ascii test string and I really hope that encrypt and decrypt works out!\0";
  text = (byte_ard*)tmp;
  printf("\n'%s'\n",tmp);
  retval &= runTest(text,strlen(tmp),Keys,IV,verbose,printableStr);

  return retval;
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
 
  bool success = true;
  
  // Do some fixed string tests and keep fingers crossed ....
  printf("\nDo the fixed string tests:\n");
  success &= do_str_tests((u_int32_ard*)Keys,(u_int16_ard*)IV,true,true);

  // Do some random buffer tests ...
  for( int i=0; i<=20; i++)
  {
	printf("\nRandom test #%d:\n",i);
    success &= do_rnd_test((u_int32_ard*)Keys,(u_int16_ard*)IV,false,false);
  }
  
  if (!success)
    printf("\nProblems!\n");
  else
    printf("\nAll OK!\n");

  return 0;
}
