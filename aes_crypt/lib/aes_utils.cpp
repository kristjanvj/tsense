/*
 * aes_utils.cpp
 *
 * A basket for various utility methods used in the Tsense project
 * regarding the AES crypto functions.  NOTE: Not part of the AES
 * library and some methods are platform dependent. 
 *
 */

#include "aes_utils.h"

int generateKey(byte_ard *newKey) {
	generateKeyOfLength(newKey, KEY_BYTES);
}

int generateKeyOfLength(byte_ard *newKey, int length) {
	byte_ard res = 0;
    u_int32_ard f;
	FILE * urandom = fopen("/dev/urandom","r");

	if(urandom)
    {
		for(u_int32_ard i=0; i<length; i++)
        {
			f = fread(&res, 1, sizeof(res), urandom);
			newKey[i] = res;
		}
		fclose(urandom);
		return 1;
	}
	return res;
}

void printByteArd(unsigned char* pBytes, unsigned long dLength, 
						int textWidth = 16)
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

