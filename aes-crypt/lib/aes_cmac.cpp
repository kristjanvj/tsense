/*
 * File name: aes_cmac.cpp
 * Date:      2010-07-19 11:00
 * Author:    Kristjan Runarsson
 */

#include "aes_cmac.h"

// Left shifts every element of an array of length BLOCK_BYTE_SIZE. This
// is equivalent to left shifting the entire 128 bit binary string the array
// represents. The first bit of each left shifted element becomes the last 
// bit of the preceeding one.
void leftShiftKey(byte_ard *orig, byte_ard *shifted){
    byte_ard overFlow =  0x0;

    int32_ard i;
    for(i = BLOCK_BYTE_SIZE - 1; i >= 0; i--){
        shifted[i] = (orig[i] << 1);
        shifted[i] = shifted[i] | overFlow;
        overFlow = (orig[i] & 0x80) ? 0x1 : 0x0;
    }
}

// Performs (p XOR q) on every element of an array of length BLOCK_BYTE_SIZE
// and copies the result into r.
void xorToLength(byte_ard *p, byte_ard *q, byte_ard *r){
    int32_ard i;
    for(i = 0; i < BLOCK_BYTE_SIZE; i++){
        r[i] = p[i] ^ q[i];
    }
}

/* A not quite literal implementation of the Generate_Subkey psuedocode
 * algorithm in section 2.4 of RFC 4493. This function expands a single
 * AES encryption key into one expanded key of the type of key needed 
 * for MAC generation rather than two like the psuedo code in the RFC.
 * Call this twice to get K1 and K2.
 */
void expandMacKey(byte_ard *origKey, byte_ard *newKey){
    leftShiftKey(origKey, newKey);
    // FIXME: Is there an endian issue here?
    if((origKey[0] & 0x80) != 0x0){
        xorToLength(newKey, (byte_ard*)constRb, newKey);
    }
}


// Pads a message with a single '1' followed by the minimum number
// of '0' such that the string's total lenght is 128 bits.
void padding ( byte_ard *lastb, byte_ard *pad, u_int32_ard length ) {
    u_int32_ard i;

    for (i=0; i<BLOCK_BYTE_SIZE; i++) {
        if (i < length) {
            pad[i] = lastb[i];
        } else if (i == length) {
            pad[i] = 0x80;
        } else {
            pad[i] = 0x00;
        }
    }
}

// Initialize an AES block with zeros.
void initBlockZero(byte_ard *block){
    int32_ard i;
    for(i=0; i < BLOCK_BYTE_SIZE; i++){
        block[i] = 0x0;
    }
}

/* This is a more or less literal implementation of the AES-CMAC psuedo 
 * code algorithm in section 2.4 of RFC 4493.
 * 
 * +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * +                   Algorithm AES-CMAC                              +
 * +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * +                                                                   +
 * +   Input    : KS        Rijandel key schedule                      +
 * +            : M,        Message that key will be generated from.   +
 * +            : M_length, Message length in bytes (len in the RFC)   +
 * +   Output   : CMAC,     The resulting cMAC authentication          +
 * +                        code (T in the RFC)                        +
 * +                                                                   +
 * +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 */
void aesCMac(const u_int32_ard* KS, byte_ard *M, u_int32_ard M_length, byte_ard *CMAC){

    byte_ard K1[BLOCK_BYTE_SIZE], K2[BLOCK_BYTE_SIZE],
             L[BLOCK_BYTE_SIZE], M_last[BLOCK_BYTE_SIZE];

    initBlockZero(K1); initBlockZero(K2);
    initBlockZero(L); initBlockZero(M_last);

    u_int32_ard blockCount = 0;

    bool isComplete = true;

    /*byte_ard pKeys[KEY_BYTES * 12];
      KeyExpansion(pKey, pKeys);*/

    // Step 1.
    //EncryptBlock((char*)L, (const u_int32_ard*) pKeys);
    EncryptBlock((void*)L, KS);

    expandMacKey(L, K1);
    expandMacKey(K1, K2);

    // Step 2. determine the needed number of blocks of lenght BLOCK_BYTE_SIZE.
    //blockCount = (u_int32_ard)ceil((double) M_length/(double) BLOCK_BYTE_SIZE);
    //blockCount = neededblocks(M_length);
    blockCount = ceilf((float32_ard) M_length / (float32_ard)BLOCK_BYTE_SIZE);
    //blockCount = 1;

    // Step 3. Check whether M needs padding or not.
    if(blockCount == 0){
        blockCount = 1;
        isComplete = false;
    } else {
        if ((M_length % BLOCK_BYTE_SIZE) == 0) { // The last block needs no padding.
            isComplete = true;
        } else {
            isComplete = false;
        }
    }

    // Step 4. Handle messages depending whether they are an integer multiple
    // of BLOCK_BYTE_SIZE or not.
    byte_ard M_lastPad[BLOCK_BYTE_SIZE];

    if (isComplete) { // the last block does not need padding.
        xorToLength(&M[BLOCK_BYTE_SIZE * (blockCount - 1)], K1, M_last);
    } else { // No padding needed.
        initBlockZero(M_lastPad);
        padding(&M[BLOCK_BYTE_SIZE * (blockCount - 1)], M_lastPad,
                (M_length % BLOCK_BYTE_SIZE));
        xorToLength(M_lastPad, K2, M_last);
    }

    // Step 5. Perfrom the CBC encryption chain up to (M_length - 1) 
    byte_ard X[BLOCK_BYTE_SIZE], Y[BLOCK_BYTE_SIZE];
    initBlockZero(X);
    initBlockZero(Y);

    // Step 6.
    u_int32_ard i, j;
    for(i = 0; i < blockCount-1; i++){
        //Y := X XOR M_i;
        xorToLength(X, &M[BLOCK_BYTE_SIZE * i], Y);

        //AES-128(K,Y);
        //EncryptBlock((char*) Y, (const u_int32_ard*) KS);
        EncryptBlock((void*) Y, KS);

        // X:= AES-128(K,Y); Necessary because encryptBlock does not copy the
        // encrypted text into a new target vector.
        for(j = 0; j < BLOCK_BYTE_SIZE; j++){
            X[j] = Y[j];
        }
    }

    // XOR and encrypt the last block of M to produce the CMAC.
    xorToLength(X, M_last, Y);
    //EncryptBlock((char*) Y, (const u_int32_ard*) K);
    EncryptBlock((void*) Y, KS);

    // Step 7. T := AES-128(K,Y); where in our case T == CMAC
    for(i = 0; i < BLOCK_BYTE_SIZE; i++){
        CMAC[i] = Y[i];
    }
}

/* Implementation of the verify_MAC psuedo code algorithm in section 2.5 
 * of RFC 4493.
 * 
 * +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * +                      Algorithm Verify_MAC                         +
 * +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * +                                                                   +
 * +   Input    : K         AES Key.                                   +
 * +            : M         Message to be verified.                    +
 * +            : M_length  Length of the message in octets.           +
 * +            : CMACm     The received MAC to be verified.           +
 * +   Output   : INVALID or VALID                                     +
 * +                                                                   +
 * +-------------------------------------------------------------------+
 */

int32_ard verifyAesCMac(byte_ard *K, byte_ard *M, u_int32_ard M_length,
                          byte_ard* CMACm){
    byte_ard CMAC[BLOCK_BYTE_SIZE];
    byte_ard keys[BLOCK_BYTE_SIZE*11];

    KeyExpansion(K, keys);

    aesCMac((const u_int32_ard*)keys, M, M_length, CMAC);

    int32_ard i;
    for(i = 0; i<BLOCK_BYTE_SIZE; i++){
        if(CMAC[i] != CMACm[i]){
            return 0;
        }
    }

    return 1;
}

