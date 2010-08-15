/*
 * File name: cmac_test.cpp
 * Date:      2010-07-12 13:24
 * Author:    Kristján Rúnarsson
 */

#include <iostream>
#include <string>
#include "aes_crypt.h"
#include "aes_cmac.h"

#define PAGES 32 // The number of pages to allocate -- tune this for performance
#define PAGE_SIZE 4096 // The page size in Intel systems (and some solaris -- some use 8kB pages)
#define BUFFER_BLOCK_SIZE PAGES*PAGE_SIZE

using namespace std;

byte_ard constZero[] = 
    {0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0};
// The encryption key from the RFC-4494 key expansion test case.
byte_ard macK[] = 
	{0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
// The expected output from the RFC-4494 key expansion test case.
byte_ard macL[] = 
	{0x7d,0xf7,0x6b,0x0c,0x1a,0xb8,0x99,0xb3,0x3e,0x42,0xf0,0x47,0xb9,0x1b,0x54,0x6f};
byte_ard macK1[] = 
	{0xfb,0xee,0xd6,0x18,0x35,0x71,0x33,0x66,0x7c,0x85,0xe0,0x8f,0x72,0x36,0xa8,0xde};
byte_ard macK2[] = 
	{0xf7,0xdd,0xac,0x30,0x6a,0xe2,0x66,0xcc,0xf9,0x0b,0xc1,0x1e,0xe4,0x6d,0x51,0x3b};

void printBytes2(unsigned char* pBytes, unsigned long dLength, int textWidth=16) {
	int bytecount=0;    
	for(unsigned long i=0;i<dLength;i++) {
		printf("%.2x ",pBytes[i]);
		if ( ++bytecount == textWidth ) {
			printf("\n");
			bytecount=0;
		}
	}

	if ( bytecount != 0 ){
		printf("\n");
	}
}

int main() {
	
	cout << "-------------------------------------" << endl;
	cout << "RFC-4494 test case for key expansion:" << endl;
	cout << "-------------------------------------" << endl;
	printf("K   : "); printBytes2(macK, 16);
	// Expanded from L.
	printf("K1  : "); printBytes2(macK1, 16);
	// Expanded from K1.
	printf("K2  : "); printBytes2(macK2, 16);
	// Initially an array with value 0x0 for each element. This is then 
	// encrypted  with the key K to yield L.
	printf("L   : "); printBytes2(constZero, 16);
	// Used in key expansion if the MSB of the key being expanded is zero.
	printf("CRB : "); printBytes2((byte_ard*)constRb, 16);
	cout << endl;

	byte_ard pKeys[KEY_BYTES*12];
	KeyExpansion(pKey,pKeys);

	byte_ard L[16] = 
		{0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0};

	cout << "Generating L, L: <expected>, L': <generated>" << endl;
	encryptBlock((char*)L, (const u_int32_ard*)pKeys);

	printf("CZ  : "); printBytes2((byte_ard*) constZero, 16);
	printf("L   : "); printBytes2((byte_ard*) macL, 16);
	printf("L'  : "); printBytes2((byte_ard*) L,16);
	cout << endl;

	byte_ard k1[16];
	expandMacKey(L,k1);

	cout << "Generating K1, K1: <expected>, K1': <generated>" << endl;
	printf("K1  : "); printBytes2((byte_ard*)macK1, 16);
	printf("K1' : "); printBytes2((byte_ard*)k1,16);
	cout << endl;

	byte_ard k2[16];
	expandMacKey(k1,k2);

	cout << "Generating K2, K2: <expected>, K2': <generated>" << endl;
	printf("K2  : "); printBytes2((byte_ard *)macK2, 16);
	printf("K2' : "); printBytes2((byte_ard *)k2,16);
    return 0;
} // end main()
