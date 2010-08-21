/*
   File name: tsense_keystore.h
   Date:      2010-08-21 11:23
   Author:    Kristján Rúnarsson
*/

#ifndef __TSENSE_KEYSTORE_H__
#define __TSENSE_KEYSTORE_H__

#include <iostream>
#include "aes_crypt.h"
#include "aes_cmac.h"

class TSenseKeyPair {
private:
	byte_ard cryptoKey[BLOCK_BYTE_SIZE];
	byte_ard cryptoKeySched[BLOCK_BYTE_SIZE*11];
	byte_ard macKey[BLOCK_BYTE_SIZE];
	byte_ard macKeySched[BLOCK_BYTE_SIZE*11];

public:
	TSenseKeyPair(byte_ard * key, byte_ard *constant);
	byte_ard * getCryptoKey();
	byte_ard * getCryptoKeySched();
	byte_ard * getMacKey();
	byte_ard * getMacKeySched();
};



#endif
