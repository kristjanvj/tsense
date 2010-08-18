/*
 * File name: cmac_test.cpp
 * Date:      2010-07-12 13:24
 * Author:    Kristj�n R�narsson
 */

#include <iostream>
#include <string>
#include <stdio.h>
#include "aes_crypt.h"
#include "aes_cmac.h"

#define PAGES 32 // The number of pages to allocate -- tune this for performance
#define PAGE_SIZE 4096 // The page size in Intel systems (and some solaris -- some use 8kB pages)
#define BUFFER_BLOCK_SIZE PAGES*PAGE_SIZE

using namespace std;

// printBytes2 KVJ
void printBytes2(unsigned char* pBytes, unsigned long dLength, int textWidth =16) {
    int bytecount=0;
    for(unsigned long i=0;i<dLength;i++) {
      printf ("%.2x ",pBytes[i]);
        if ( ++bytecount == textWidth ) {
            printf("\n");
            bytecount=0;
        }
    }

    if ( bytecount != 0 ){
        printf("\n");
    }
}


byte_ard CMAC0[] =
	{0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28,
	 0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46};
byte_ard CMAC16[] =
	{0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,
	 0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c};
byte_ard CMAC40[] =
	{0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30,
	 0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27};
byte_ard CMAC64[] =
	{0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92,
	 0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c, 0xfe};

byte_ard Key[] = 
	{0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
	 0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};

byte_ard M[] = {
	  0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
	  0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
	  0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
	  0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
	  0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
	  0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
	  0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
	  0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};

int main() {
	cout << "----------------------------------------" << endl;
	cout << "RFC-4494 test cases for cmac generation:" << endl;
	cout << "----------------------------------------" << endl;

	byte_ard CMAC[] =
        {0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
         0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0};

    byte_ard KS[BLOCK_BYTE_SIZE*11];
    KeyExpansion(Key,KS);
	aesCMac((const u_int32_ard*)KS, M, 0,  CMAC);
	printf("CMAC   0: "); printBytes2((byte_ard*)CMAC0, 16);
	printf("CMAC'  0: "); printBytes2((byte_ard*)CMAC, 16);

	aesCMac((const u_int32_ard*)KS, M, 16,  CMAC);
	printf("CMAC  16: "); printBytes2((byte_ard*)CMAC16, 16);
	printf("CMAC' 16: "); printBytes2((byte_ard*)CMAC, 16);

	aesCMac((const u_int32_ard*)KS, M, 40,  CMAC);
	printf("CMAC  40: "); printBytes2((byte_ard*)CMAC40, 16);
	printf("CMAC' 40: "); printBytes2((byte_ard*)CMAC, 16);
	
	aesCMac((const u_int32_ard*)KS, M, 64,  CMAC);
	printf("CMAC  64: "); printBytes2((byte_ard*)CMAC64, 16);
	printf("CMAC' 64: "); printBytes2((byte_ard*)CMAC, 16);
	

	printf("Verify (expected: 1): %d\n", verifyAesCMac(Key, M, 64,  CMAC));
	printf("Verify (expected: 0): %d\n", verifyAesCMac(Key, M, 64,  CMAC40));

    return 0;
} // end main()