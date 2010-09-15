
/**
 * Kristjan V. Jonsson
 * Timed CBC-mode AES test
 */

#include "aes_crypt.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>


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

double encrypt_decrypt_test(int blockCount, int repetitions)
{
  byte_ard Key[] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c 
  };

  byte_ard IV[] = {
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,  0x30, 0x30 
  };

  // Allocate memory for key schedule and generate it.
  byte_ard Keys[KEY_BYTES*12];
  KeyExpansion(Key, Keys);

  // allocate some buffers to hold data
  int length = 16*blockCount;
  unsigned char *buf = (unsigned char *)malloc(length);
  unsigned char *ecbuf = (unsigned char *)malloc(length);
  unsigned char *dcbuf = (unsigned char *)malloc(length);

  // Fill the plaintext buffer with random data of multiples of block length.
  srand(time(NULL));
  for ( int i=0; i<(16*blockCount); i++ )
    buf[i] = rand() % 0xFF;
  
  // Start the timed test
  timeval tstart, tstop, tresult;  
  gettimeofday(&tstart,NULL);
  for( int i=0; i<repetitions; i++ )
  {
  	CBCEncrypt(	(void *)buf, (void *)ecbuf, length, AUTOPAD, 
				(const u_int32_ard*)Keys, (const u_int16_ard*)IV);
  	CBCDecrypt(	(void *)ecbuf, (void *)dcbuf, length, 
				(const u_int32_ard*)Keys, (const u_int16_ard*)IV);
  }
  gettimeofday(&tstop,NULL);

  // Calculate the results
  timersub(&tstop,&tstart,&tresult);
  double totaltime = tresult.tv_sec * 1000000.0 + tresult.tv_usec;
  double timePerOperation = totaltime / repetitions;
  double timePerBlock = timePerOperation / blockCount;

  // Check if decryption is consistent with plaintext
  if ( strncmp((char *)buf, (char *)dcbuf,length) != 0 )
	printf("Error in encrypt/decrypt!\n");

  // Output timing results.
  printf("blocks: %d\n", blockCount);
  printf("Duration: %f usec\n", totaltime);
  printf("Per operation: %f usec\n", timePerOperation);
  printf("Per block: %f usec\n", timePerBlock);
  printf("\n");

  /****
  // Dont print the blocks except when debugging
  printf("\nPlaintext : \n");
  printBytes2((byte_ard*)buf, length);

  printf("\nAfter CBC: \n");
  printBytes2((byte_ard*)ecbuf, length);
     
  printf("\nCBC Decipher: \n");
  printBytes2((byte_ard*)dcbuf, length);
  ****/

  return timePerBlock;
}

int main()
{
  int repetitions = 100000; // For some timing accuracy

  double totaltime=0.0;
  int trials=0;
  for( int i=1; i<256; i+=i )
  {
    totaltime+=encrypt_decrypt_test(i,repetitions);  
    trials++;
  }

  double aveTimeBlock = (totaltime/trials);
  double aveBlocksPerSec = (1/aveTimeBlock)*1000000.0;
  double aveBytesPerSec = 16*aveBlocksPerSec;

  printf("Done.\nAverage time is %f usec/block\n\n", aveTimeBlock);
  printf("  Throughput: %f MB/sec\n",  aveBytesPerSec/(1024*1024));

  return 0;
}
