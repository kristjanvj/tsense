/*
 * File name: tsense_keystore.cpp
 * Date:      2010-08-21 11:22
 * Author:    Kristjan Runarsson, Kristjan V. Jonsson
 */

#include "tsense_keypair.h"

/* A class that models a key pair as used in the TSense sytem. These 
 * keys always come in pairs:
 *  - An encryption key such as for example K_AT.
 *  - A corresponding CMAC key which in the case of K_AT would be 
 *    K_AT,a. The key K_AT,a is derived from K_AT using CMAC and a consant
 *    which in this case is called alpha.
 * This constructor takes as it's argument K_AT and alpha, derives
 * K_AT,a and then expands they key schedules for K_AT and K_AT,a.
 */
TSenseKeyPair::TSenseKeyPair(byte_ard *key, byte_ard *constant){

	memcpy(cryptoKey, (void*) key, BLOCK_BYTE_SIZE);

	// Expand crypto key schedule.
	KeyExpansion(key, cryptoKeySched);

	// Expand constant key schedule which we will need to generate the mac key.
	byte_ard constKeySched[BLOCK_BYTE_SIZE*11];
	KeyExpansion(constant, constKeySched);

	// Derive the mac key using AES cMAC. The constant is the key and the 
	// key is the message M that will be cMAC'ed.
	aesCMac((u_int32_ard*) constKeySched,
		cryptoKey,
		BLOCK_BYTE_SIZE,
		macKey);

	//Key schedule for the mac key
	KeyExpansion(macKey, macKeySched);
}

byte_ard * TSenseKeyPair::getCryptoKey(){
	return cryptoKey;
};

byte_ard * TSenseKeyPair::getCryptoKeySched(){
	return cryptoKeySched;
};

byte_ard * TSenseKeyPair::getMacKey(){
	return macKey;
};

byte_ard * TSenseKeyPair::getMacKeySched(){
	return macKeySched;
};
