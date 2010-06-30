
/**
 *
 * Kristjan Valur Jonsson
 * March 2010
 *
 * AES Encryption Implementation
 * 
 * Spring 2010
 *
 * Compile: g++ -Wall aes.cc -O2 -o aes        // for full optimization
 *          g++ -Wall aes.cc -O0 -pg -o aes    // for profiling, no optimization and profiling info included
 *          gcc -Wall aes.c -O2 -std=gnu99 -lm -o aes // for c code
 *
 * Usage:
 *   This implementation takes a stream as input, consisting of 128 bytes of key, followed by an 
 *   arbitrary length input. Use the following (on an unix sustem):
 *      $ ./aes < fips.in > fips.out
 *   The output file is optional, if omitted the output is directed to the stdout.
 *   The following in handy to see the output in a more readable format:
 *      $ ./aes < fips.in | hexdump -C
 *
 * References:
 * - Textbook: Cryptography. Theory and Practice. Stinson.
 * - http://www.csrc.nist.gov/publications/fips/fips197/fips-197.pdf
 * - Daemen and Rijmen: AES Proposal: Rijndael (1999).
 * - Brian Gladman. A Specification for Rijndael, the AES Algorithm. March, 2001.
 * - http://en.wikipedia.org/wiki/Advanced_Encryption_Standard
 * - http://en.wikipedia.org/wiki/Rijndael_key_schedule
 * - http://en.wikipedia.org/wiki/Rijndael_S-box
 * - http://en.wikipedia.org/wiki/Finite_field_arithmetic
 * - http://www.samiam.org/key-schedule.html
 *
 */

// use this for c++ code when input- output streams are used.
// Otherwise, fread/fwrite will be used
#define use_cin_cout
#define text_mode_output

#ifdef use_cin_cout
#include <iostream>
#endif
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "aes_crypt.h"

#define PAGES 32 // The number of pages to allocate -- tune this for performance
#define PAGE_SIZE 4096 // The page size in Intel systems (and some solaris -- some use 8kB pages)
#define BUFFER_BLOCK_SIZE PAGES*PAGE_SIZE   // Always allocate entire pages
#define BLOCK_BYTE_SIZE 16

void printBytes2(unsigned char* pBytes, unsigned long dLength, int textWidth=16)
{	
	int bytecount=0;
	for(unsigned long i=0;i<dLength;i++)
	{
		printf("%x ",pBytes[i]);
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
	printf("\n\nAES test program -- linked version\n\n");

	printf("Version: ");
	#ifdef __ARDUINO__DUEMILANOVE__
	printf("Arduino");
    #endif
	#ifdef __INTEL_32_LINUX__
	printf("LINUX");
	#endif
	#ifdef __INTEL32_BSD__
	printf("BSD");
	#endif
	printf("\n\n");

	// Only support 128 bit keys and 10 rounds at this time.

	#ifdef verbose
	printf("\n\nAES ENCRYPTION\n\n");
	#if defined(t_box_transform) && defined(t_table_pregenerated)	
	printf("Using t-table transforms and pre-generated tables\n");
	#elif defined(t_box_transform) && defined(t_table_generate)
	printf("Using t-table transforms and generating tables\n");
	#else
	printf("Using the good-old 8-bit version\n");
	#endif
	#endif

	// Initialize the t-boxes
	#if defined(t_box_transform) && defined(t_table_generate)
	initializeTboxes();
	#endif

	// Read the 16 keybytes from stdin
	unsigned int pKey[4];
	#ifdef use_cin_cout
	std::cin.read( (char*)pKey,16);
	if(std::cin.fail()) 
	{
		#ifdef verbose_errors
		printf("Error reading key from stdin. Quitting.\n");
		#endif
		return -1;
	}
	assert(std::cin.gcount()==16);	
	#else
	assert( fread((char *)pKey,sizeof(char),16,stdin) == 16 );
	#endif

	//printBytes2((unsigned char *)pKey,16);

	// Allocate memory and generate the key schedule
	unsigned char pKeys[KEY_BYTES*12];
	KeyExpansion(pKey,pKeys);
//	#ifdef verbose_debug
	printf("\nKey schedule:\n");
	printBytes2((unsigned char *)pKeys,16*11);
	printf("\n\n");
//	#endif

	// The allocated buffer for plaintext. A fixed BUFFER_BLOCK_SIZE = PAGES*PAGE_SIZE is reserved.
	// Make sure only entire pages are allocated!
	unsigned int dTextLen = 0;        // The acutal length in bytes of the plaintext	
	unsigned int dBlockWords = 0;     // The number of blocks to process
	unsigned int i;
	unsigned int *pText = (unsigned int*)malloc(BUFFER_BLOCK_SIZE); // slightly faster than calloc

	// Read blocks into the buffer, process and output.
	// Note cin/cout or fread/fwrite can be used for input/output as controlled by the
	// appropriate defines.
	do
	{
		#ifdef use_cin_cout
		std::cin.read((char*)pText,BUFFER_BLOCK_SIZE);
		dTextLen = std::cin.gcount();
		#else
		dTextLen = fread((char *)pText,sizeof(char),BUFFER_BLOCK_SIZE,stdin);
		#endif

		dBlockWords=dTextLen/4;
		for( i=0; i < dBlockWords; i+=4 ) {
			//printBytes2((unsigned char*)pText,16);
			encryptBlock(pText+i, (const u_int32_ard*)pKeys);
			//encryptBlock(pText+i, (unsigned int*)pKeys);
		}

		#ifndef verbose
		#ifdef use_cin_cout
		#ifndef text_mode_output
		std::cout.write((const char*)pText,dTextLen);
		#else
		printf("\nOutput:\n");
		printBytes2((unsigned char *)pText,dTextLen);
		#endif
		#else
		fwrite(pText,sizeof(int),dBlockWords,stdout);
		#endif
		#else
		printf("\nOutput:\n");
		printBytes2((unsigned char *)pText,dTextLen);
		#endif
	}
	#ifdef use_cin_cout
	while( !std::cin.eof() );
	#else
	while( !feof(stdin) );
	#endif
	// Free the allocated text buffer
	free(pText);

	return 0; // Normal return
}



