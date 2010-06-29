/**
 *
 * Kristjan Valur Jonsson
 *
 * AES Encryption Implementation. Ported quick-and-dirty to the Arduino 
 * from the aes Intel platform implementation
 *
 *
 */
#include "aes_crypt.h"

/**
 *  keyExpansion
 *
 *  Implements the AES key expansion algorithm.
 *  Note: only supports 128 bit keys and 10 rounds.
 *  See FIPS-197 and http://en.wikipedia.org/wiki/Rijndael_key_schedule on the algorithm.
 *  The Rcon table used in the algorithm copied from (but verified!) the wikipedia article.
 */
inline void KeyExpansion(const void *key, void *keys) 
{
	memcpy(keys,key,16); // Copy the first key unmodified

        #ifdef verbose_debug
        Serial.println("Starting key expansion");
        Serial.println("Initial key:");
        printBytes((unsigned char *)key,16,16);
        #endif

	unsigned char *ckeys = (unsigned char*)keys;
//        unsigned char *ckey = (unsigned char*)key;

/*        for( int i=0; i<16; i++)
        {
                ckeys[i] = ckey[i];
        }  */

	int r=1; // The Rcon counter
        int i;
	for(i=16; i<176; i+=4)
	{
		// The SubWord and RotWord methods described in Section 5.2 of FIPS-197 are replaced
		// here by their inlined equivalents. The algorithm is also simplifyed by not supporting 
		// the longer key lengths. Several steps are combined to be able to compute keys in-place
		// without temporary variables.
		if (i % 16 == 0)
		{
			// Copy the previous four bytes with rotate. 
			// Apply the AES Sbox to the four bytes of the key only.
			// Multiply the first byte with the Rcon.
			ckeys[i] = ckeys[i-16] ^ sbox[ckeys[i-3]] ^ Rcon[r++];
			ckeys[i+1] = ckeys[i-15] ^ sbox[ckeys[i-2]];
			ckeys[i+2] = ckeys[i-14] ^ sbox[ckeys[i-1]];
			ckeys[i+3] = ckeys[i-13] ^ sbox[ckeys[i-4]];
		}
		else
		{
			// Straight copy and rotate of the previous key bytes.
			ckeys[i] = ckeys[i-16] ^ ckeys[i-4];
			ckeys[i+1] = ckeys[i-15] ^ ckeys[i-3];
			ckeys[i+2] = ckeys[i-14] ^ ckeys[i-2];
			ckeys[i+3] = ckeys[i-13] ^ ckeys[i-1];
		}
	} 
        #ifdef verbose_debug
        printBytes((unsigned char *)keys,160,16);
        #endif
}

/**
 *  addRoundKey
 *
 *  Adds a key from the schedule (for the specified round) to the current state.
 *  Loop unrolled for a bit of performance gain.
 */
inline void addRoundKey(void *pText, const unsigned long *pKeys, int round)
{
	int roundOffset=round*4;
	unsigned long *pState = (unsigned long *)pText;

	pState[0] ^= pKeys[roundOffset];
	pState[1] ^= pKeys[roundOffset+1];
	pState[2] ^= pKeys[roundOffset+2];
	pState[3] ^= pKeys[roundOffset+3];

	#ifdef verbose_debug
	Serial.print("Adding round key at round:");
        Serial.println(round);
	printBytes((unsigned char*)(pKeys+4*round),16);
	Serial.println("State after:");
	printBytes((unsigned char*)pText,16,16);
	#endif
}

/**
 *  subAndShift
 *
 *  Implementation of the AES subBytes and shiftRows operations. 
 *
 *  The AES sbox is applied to each byte as the shift is performed
 *  Loop unrolled for a bit of preformance gain.
 *
 *  See: FIPS-197.
 *  See: http://en.wikipedia.org/wiki/Rijndael_S-box
 */
#ifndef t_box_transform
inline void subAndShift(void *pText)
{
	unsigned char *pState = (unsigned char*)pText;
	unsigned char temp;

	// Only sbox for first row
	state(pState,0,0) = sbox[state(pState,0,0)];
	state(pState,0,1) = sbox[state(pState,0,1)];
	state(pState,0,2) = sbox[state(pState,0,2)];
	state(pState,0,3) = sbox[state(pState,0,3)];

	// Shift and sbox the second row
	temp=state(pState,1,0);
	state(pState,1,0)=sbox[state(pState,1,1)];
	state(pState,1,1)=sbox[state(pState,1,2)];
	state(pState,1,2)=sbox[state(pState,1,3)];
	state(pState,1,3)=sbox[temp];
	// Shift and sbox the third row
	temp = state(pState,2,0);
	state(pState,2,0)=sbox[state(pState,2,2)];
	state(pState,2,2)=sbox[temp];
	temp = state(pState,2,1); 
	state(pState,2,1)=sbox[state(pState,2,3)];
	state(pState,2,3)=sbox[temp];
	// Shift and sbox the fourth row
	temp = state(pState,3,3);
	state(pState,3,3) = sbox[state(pState,3,2)];
	state(pState,3,2) = sbox[state(pState,3,1)];
	state(pState,3,1) = sbox[state(pState,3,0)];
	state(pState,3,0) = sbox[temp];

	#ifdef verbose_debug
	Serial.println("State after subAndShift:");
	printBytes((unsigned char *)pText,16,16);
	#endif 
}
#endif

/**
 *  mixColumns
 * 
 * The mixColumns function is the trickiest to implement efficiently since it contains a lot of 
 * expensive operations if implemented literally as stated in FIPS-197.
 *
 * Considerable experimentation, trial, error and literature search lead to the present form.
 * A fuller discussion and the sources used are cited in the body of the function.
 *
 */
#ifndef t_box_transform
inline void mixColumns(void *pText)
{
	// The sub bytes operation is as follows (see 5.1.3 in the FIPS-197 document):
	//
	// s'_0,c = ({02} * s_0,c ) XOR ({03} * s_1,c ) XOR s_2,c XOR s_3,c
	// s'_1,c = s_0,c XOR ({02} * s_1,c ) XOR ({03} * s_2,c ) XOR s_3,c
	// s'_2,c = s_0,c XOR s_1,c XOR ({02} * s_2,c ) XOR ({03} * s_3,c )  ′
	// s'_3,c = ({03} * s_0,c ) XOR s_1,c XOR s_2,c XOR ({02} * s_3,c )
	//
	// The * operation is here multiplication in the AES (Rijndael) finite field. See section
	// 4.2.1 in FIPS-197 on the multiplication and the xtime function.
	// A much clearer description can be found in 
	//           http://www.usenix.org/event/cardis02/full_papers/valverde/valverde_html/node12.html
	//
	// The xtime function is as follows:
	// xtime(a) = a<<1 if x7==0 (the eight bit is 0)
	// xtime(a) = a<<1 XOR Ox1 if x7==1

	// see also:
	// * http://en.wikipedia.org/wiki/Rijndael_mix_columns
	// * http://en.wikipedia.org/wiki/Rijndael_Galois_field
	// * http://www.usenix.org/event/cardis02/full_papers/valverde/valverde_html/node12.html

	unsigned char *pState = (unsigned char *)pText;
	unsigned char a, s0;

        int c;
	for(c = 0; c < 4; c++)
	{	
		// This algorithm is adapted from the paper
		// "Efficient AES Implementations for ARM Based Platforms" by Atasu, Breveglieri and Macchetti (2004)
		// Note: This is in essence identical to the code from Daemen and Rijmen (sec. 5.1).
		//
		// temp[0] = xtime(pState[0][c] ^ pState[1][c]) ^ pState[1][c] ^ pState[2][c] ^ pState[3][c];
		// temp[1] = xtime(pState[1][c] ^ pState[2][c]) ^ pState[2][c] ^ pState[3][c] ^ pState[0][c];
		// temp[2] = xtime(pState[2][c] ^ pState[3][c]) ^ pState[3][c] ^ pState[0][c] ^ pState[1][c];
		// temp[3] = xtime(pstate[3][c] ^ pstate[0][c]) ^ pState[0][c] ^ pState[1][c] ^ pState[2][c];
		//
		// The code below is a variation of the pseudocode in the document by Daemen and Rijmen (sec. 5.1)
		// and allows us to dispense with the temporary variable: a single initial XOR A of all four 
		// states is computed. Then, temporary variables can be avoided by XORing A with the xtime calculation
		// and the target field itself. This self-XOR nullifies the corresponding term from A, avoiding
		// the temporary variable. The use of the a variable also saves quite a few XORs. 
		// This is reimplemented as follows:
		a = state(pState,0,c) ^ state(pState,1,c) ^ state(pState,2,c) ^ state(pState,3,c);
		s0 = state(pState,0,c); // This is the only temporary variable needed
		state(pState,0,c) ^= xtime((state(pState,0,c) ^ state(pState,1,c))) ^ a; 
		state(pState,1,c) ^= xtime((state(pState,1,c) ^ state(pState,2,c))) ^ a;
		state(pState,2,c) ^= xtime((state(pState,2,c) ^ state(pState,3,c))) ^ a;
		state(pState,3,c) ^= xtime((state(pState,3,c) ^ s0)) ^ a; 
			// Here, we need to use a temp, since the contents of s0c have been modified

	}

	#ifdef verbose_debug
	Serial.println("State after mixColumns:");
	printBytes((unsigned char*)pText,16,16);
	#endif 
}
#endif

/**
 *  ttransform
 *
 *  The function implements the efficient 32-bit transformation suggested by Daemen and Rijmen
 *  (sec. 5.2). Pre-computed t-tables combine the subBytes, shiftRows and mixColumns operations.
 *  In addition, the round key is applied.
 */
#ifdef t_box_transform
inline void ttransform(void *pText, const unsigned int *pKeys, int round)
{    
	unsigned char *pState = (unsigned char *)pText;

	unsigned int e[4];
	e[0] = t0[pState[0]]  ^ t1[pState[5]]  ^ t2[pState[10]] ^ t3[pState[15]] ^ pKeys[round*4];
	e[1] = t0[pState[4]]  ^ t1[pState[9]]  ^ t2[pState[14]] ^ t3[pState[3]]  ^ pKeys[round*4+1];
	e[2] = t0[pState[8]]  ^ t1[pState[13]] ^ t2[pState[2]]  ^ t3[pState[7]]  ^ pKeys[round*4+2];
	e[3] = t0[pState[12]] ^ t1[pState[1]]  ^ t2[pState[6]]  ^ t3[pState[11]] ^ pKeys[round*4+3]; 
	memcpy(pText,e,16); // Blast the temporary buffer to the state
}
#endif

/**
 *  lttransform
 *
 *  This is the last round transform -- a variation of the ttransform function that is only applied
 *  in the last round. subBytes, shiftRows and addRoundKey are combined to produce the last state
 *  update.
 */
#ifdef t_box_transform
inline void lttransform(void *pText, const unsigned int *pKeys, int round)
{
	unsigned char *pState = (unsigned char *)pText;

	unsigned int e[4];
	e[0] = ( sbox[pState[0]]  | ( sbox[pState[5]]  << 8 ) | ( sbox[pState[10]] << 16 ) | ( sbox[pState[15]] << 24 ) ) ^ pKeys[round*4];
	e[1] = ( sbox[pState[4]]  | ( sbox[pState[9]]  << 8 ) | ( sbox[pState[14]] << 16 ) | ( sbox[pState[3]]  << 24 ) ) ^ pKeys[round*4+1];
	e[2] = ( sbox[pState[8]]  | ( sbox[pState[13]] << 8 ) | ( sbox[pState[2]]  << 16 ) | ( sbox[pState[7]]  << 24 ) ) ^ pKeys[round*4+2];
	e[3] = ( sbox[pState[12]] | ( sbox[pState[1]]  << 8 ) | ( sbox[pState[6]]  << 16 ) | ( sbox[pState[11]] << 24 ) ) ^ pKeys[round*4+3]; 
	memcpy(pText,e,16);
}
#endif

//
// ntransform -- normal transform macro to help with the loop unrolling
//
#define ntransform(text,keys,round) subAndShift(text);mixColumns(text);addRoundKey(text,keys,round);

/**
 *  encryptBlock
 *
 *  Encrypt a single block, stored in the buffer text. The buffer MUST be 16 bytes in length!
 *  pKeys stores a complete key schedule for the round.
 *  The algorithm, call order and function names, follows the reference of FIPS-197, section 5.1.
 *
 *  The encryption loop can be unrolled or left as is by using the unroll_encrypt_loop define.
 *  t-box transforms or regular (textbook) algorithm can be selected by the proper defines
 *  as can be seen in the code.
 *
 *  The encrypted data is returned in the text buffer.
 *
 *  Note: Only 10 rounds and 128 bit keys are supported in this implementation.
 */
inline void encryptBlock(void *pText, const unsigned long *pKeys) {

        #ifdef verbose_debug
        Serial.println("\n\nStarting encrypt, plaintext is");
        printBytes((unsigned char *)pText,16,16);
        #endif 
  
	// Add the first round key from the schedule
	addRoundKey(pText, pKeys, 0);

	// Do the bulk of the encryption by calling the standard sequence of operations several times.
	#if defined(unroll_encrypt_loop)
	#if defined(t_box_transform)
	ttransform(pText,(unsigned int *)pKeys,1);
	ttransform(pText,(unsigned int *)pKeys,2);
	ttransform(pText,(unsigned int *)pKeys,3);
	ttransform(pText,(unsigned int *)pKeys,4);
	ttransform(pText,(unsigned int *)pKeys,5);
	ttransform(pText,(unsigned int *)pKeys,6);
	ttransform(pText,(unsigned int *)pKeys,7);
	ttransform(pText,(unsigned int *)pKeys,8);
	ttransform(pText,(unsigned int *)pKeys,9);
	#else
	ntransform(pText, pKeys, 1);
	ntransform(pText, pKeys, 2);
	ntransform(pText, pKeys, 3);
	ntransform(pText, pKeys, 4);
	ntransform(pText, pKeys, 5);
	ntransform(pText, pKeys, 6);
	ntransform(pText, pKeys, 7);
	ntransform(pText, pKeys, 8);
	ntransform(pText, pKeys, 9);
	#endif
	#else
        
        int round;
	for (round=1; round<ROUNDS; round++)
	{
                #ifdef verbose_debug
                Serial.print("Encryption round ");
                Serial.println(round);
                #endif
  
		#ifdef t_box_transform
		ttransform(pText,(unsigned int *)pKeys,round);
		#else
		subAndShift(pText); // Execute the combined subBytes and shiftRows
		mixColumns(pText);  // mixColumns is separate since we need to skip it in the final round
		addRoundKey(pText, pKeys, round); // Add a key from the schedule */
		#endif
	}
	#endif

        #ifdef verbose_debug
        Serial.println("Encryption round 10");
        #endif


	// Now, do the final round of encryption
	#ifdef t_box_transform
	lttransform(pText,(unsigned int *)pKeys,10);
	#else
	subAndShift(pText);
	addRoundKey(pText, pKeys, 10);  // add the last round key from the schedule
	#endif
}

/**
 *  initializeTboxes
 *
 *  Initializes the t-boxes if t-box transformations are used. See Daemen and Rijmen (sec. 5.2)
 *  on the code.
 */
#if defined(t_box_transform) && defined(t_table_generate)
inline void initializeTboxes()
{
	#ifdef debug_print_tbox_construction
	printf("\nGenerating the t-boxes\n\n");
	#endif
	unsigned int w,s;
	for( int i=0;i<256;i++)
	{
		// Get the sbox value for i
		s = sbox[i];

		// Assemble a word as described by Daemen and Rijmen (sec. 5.2.1)
		w = (twotimes(s)) | (s << 8) | (s << 16) | (threetimes(s)<<24);
		// This is the entry for i in the first tbox table.
		// We exploit symmetry for the rest by rotating the word to the right
		t0[i]=w;
		t1[i]=brl(w,1);
		t2[i]=brl(w,2);
		t3[i]=brl(w,3); 

		#ifdef debug_print_tbox_construction
		printf( "%d: s: %.2x, 2x: %.2x, 3x: %.2x. :%.8x -- 1:%.8x -- 2:%.8x -- 3:%.8x\n", 
                i, s, twotimes(s), threetimes(s), t0[i], t1[i], t2[i], t3[i] );
		#endif
	}
}
#endif

