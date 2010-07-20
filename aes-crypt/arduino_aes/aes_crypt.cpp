/**
 *
 * Kristjan Valur Jonsson
 * Benedikt Kristinsson
 *
 * AES Encryption Implementation. Ported quick-and-dirty to the Arduino 
 * from the aes Intel platform implementation
 *
 *
 */
#include "aes_crypt.h"
//
// The xtime macro is used in the mixColumns transformation. It implements the left shift and 
// conditional XOR operations described in FIPS-197, section 4.2.1. This can be implemented by a
// procedure and a conditional statement, but the macro is a much more compact form.
// This macro is similar to one in the PolarSSL library
// http://www.polarssl.org/?page=show_source&file=aes.
// The twotimes and threetimes macros are based on the description by Daemen and Rijmen.
#define xtime(a)  (a<<1) ^ ((a & 0x80) ? 0x1b : 0x00)
// See the paper by Daemen and Rijmen (sec 2.1.3) on the 2x and 3x multiplication. 
#define twotimes(a)  (((a<<1) ^ (((a>>7) & 1) * 0x1b)) & 0xFF)     
#define threetimes(a) (a^twotimes(a))  

#define four(a) twotimes(twotimes(a))
#define eight(a) twotimes(four(a))
#define sexteen(a) four(four(a))


// byte rotate left and right
#define brl(w,n) ( ( w << (8*n) | w >> (32-8*n) ) & 0xFFFFFFFF )
#define brr(w,n) ( ( w >> (8*n) | w << (32-8*n) ) & 0xFFFFFFFF )

// Access an element i,j from a linear char array, indexed for convenience as the AES state.
#define state(p,i,j) (p[i+4*j])


// AES inverse SBox lookup table
// http://en.wikipedia.org/wiki/Rijndael_S-box#Inverse_S-box
// Only used for decrypt
byte_ard isbox[256] = {
   0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 
   0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 
   0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 
   0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 
   0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 
   0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 
   0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 
   0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 
   0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 
   0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 
   0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 
   0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 
   0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 
   0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 
   0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 
   0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// The AES sbox lookup table. 
// http://en.wikipedia.org/wiki/Rijndael_S-box#Forward_S-box

byte_ard sbox[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};


// The Rcon operation (Rijandel Key Schdeule Operation) lookup table.
// Note: borrowed from http://en.wikipedia.org/wiki/Rijndael_key_schedule.

byte_ard Rcon[255] = {
	0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 
	0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 
	0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 
	0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 
	0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 
	0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 
	0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 
	0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 
	0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 
	0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 
	0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 
	0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 
	0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 
	0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 
	0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 
	0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb };


// Allocate memory for the expanded keys
// byte_ard pKeys[KEY_BYTES*12];

/**
 *  KeyExpansion()
 *
 *  Implements the AES key expansion algorithm.
 *  Note: only supports 128 bit keys and 10 rounds.
 *  See FIPS-197 and http://en.wikipedia.org/wiki/Rijndael_key_schedule on the algorithm.
 *  The Rcon table used in the algorithm copied from (but verified!) the wikipedia article.
 *  key is the ecryption key, whereas keys are the derived expansion keys. 
 */
void KeyExpansion(const void *key, void *keys) 
{
	memcpy(keys,key,16); // Copy the first key

    // fixme
	#ifdef verbose_debug  
	Serial.println("Starting key expansion");
	Serial.println("Initial key:");
	printBytes((byte_ard *)key,16,16);
	#endif

	byte_ard *ckeys = (byte_ard*)keys;

	int r=1; // The Rcon counter
	for(int i=16; i<176; i+=4)
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
    printBytes((byte_ard*)keys,160,16);
    #endif
}

/**
 *  AddRoundKey
 *
 *  Adds a key from the schedule (for the specified round) to the current state.
 *  Loop unrolled for a bit of performance gain
 *  The key is XOR-ed to the state
 */
void AddRoundKey(void *pText, const u_int32_ard *pKeys, int round)
{
	int roundOffset=round*4;
	u_int32_ard *pState = (u_int32_ard *)pText;

	pState[0] ^= pKeys[roundOffset];
	pState[1] ^= pKeys[roundOffset+1];
	pState[2] ^= pKeys[roundOffset+2];
	pState[3] ^= pKeys[roundOffset+3];

	// FIXME -- use non-arduino-specific debug code
	#ifdef verbose_debug
	Serial.print("Adding round key at round:");
	Serial.println(round);
	printBytes((unsigned char*)(pKeys+4*round),16);
	Serial.println("State after:");
	printBytes((unsigned char*)pText,16,16);
	#endif
}

/**
 *  SubAndShift
 *
 *  Implementation of the AES subBytes and shiftRows operations. 
 *
 *  The AES sbox is applied to each byte as the shift is performed
 *  Loop unrolled for a bit of preformance gain.
 *
 *  See: FIPS-197.
 *  See: http://en.wikipedia.org/wiki/Rijndael_S-box
 */
void SubAndShift(void *pText)
{
	byte_ard *pState = (byte_ard*)pText;
	byte_ard temp;

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

	// FIXME -- Use non-arduino-specific debug
	#ifdef verbose_debug
	Serial.println("State after subAndShift:");
	printBytes((unsigned char *)pText,16,16);
	#endif 
} // SubAndShift

// InvSubAndShift()
//
// Implements the inverse of the AES operations SubBytes and ShiftRows. 
// Applies the inverted SBox to the bytes while and shifts the
// rows backwards. 
void InvSubAndShift(void *pText)
{
  byte_ard *pState = (byte_ard*)pText;
  byte_ard temp;

  // Loop unrolled for a bit of performance gain 

  // The first row isnt rotataed, only isboxed
  state(pState,0,0) = isbox[state(pState,0,0)];
  state(pState,0,1) = isbox[state(pState,0,1)];
  state(pState,0,2) = isbox[state(pState,0,2)];
  state(pState,0,3) = isbox[state(pState,0,3)];
  
  // Second row is shifted one byte to the left
  temp = state(pState,1,3);
  state(pState,1,3) = isbox[state(pState,1,2)];
  state(pState,1,2) = isbox[state(pState,1,1)];
  state(pState,1,1) = isbox[state(pState,1,0)];
  state(pState,1,0) = isbox[temp];

  // Third row is shifted two bytes to the left
  temp = state(pState,2,2);
  state(pState,2,2) = isbox[state(pState,2,0)];
  state(pState,2,0) = isbox[temp];
  temp = state(pState,2,1);
  state(pState,2,1) = isbox[state(pState,2,3)];
  state(pState,2,3) = isbox[temp];

  // The fourth row is shifted three bytes to the left
  temp = state(pState,3,0);
  state(pState,3,0) = isbox[state(pState,3,1)];
  state(pState,3,1) = isbox[state(pState,3,2)];
  state(pState,3,2) = isbox[state(pState,3,3)];
  state(pState,3,3) = isbox[temp];

  // FIXME -- Use non-arduino-specific debug
  #ifdef verbose_debug
  Serial.println("State after subAndShift:");
  printBytes((unsigned char *)pText,16,16);
  #endif 

} // InvSubAndShift()


/**
 *  MixColumns
 * 
 * The MixColumns function is the trickiest to implement efficiently since it contains a lot of 
 * expensive operations if implemented literally as stated in FIPS-197.
 *
 * Considerable experimentation, trial, error and literature search lead to the present form.
 * A fuller discussion and the sources used are cited in the body of the function.
 *
 */
void MixColumns(void *pText)
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

	byte_ard *pState = (byte_ard *)pText;
	byte_ard a, s0;

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

	// FIXME -- Use non-arduino-specific debug
	#ifdef verbose_debug
	Serial.println("State after mixColumns:");
	printBytes((unsigned char*)pText,16,16);
	#endif 
} // MixColumns()


// InvMixColumns
// http://en.wikipedia.org/wiki/Rijndael_mix_columns

void InvMixColumns(void *pText)
{
  byte_ard *pState = (byte_ard *)pText;
  byte_ard s0, s1, s2, s3;

  int c;
  for (c = 0; c < 4; c++)
  {
    s0 = state(pState,0,c); // S_0,0
    s1 = state(pState,1,c); // S_1,0
    s2 = state(pState,2,c); // S_2,0
    s3 = state(pState,3,c); // S_3,0

    // * is multiplication is GF(2^8)
    // s'_0,c = (0x0e * s0) xor (0x0b * s1) xor (0x0d * s2) xor (0x09 * s3)
    state(pState,0,c) = (eight(s0)^four(s0)^xtime(s0)) ^ (eight(s1)^xtime(s1)^s1) ^ (eight(s2)^four(s2)^s2) ^ (eight(s3) ^ s3);

    // s'_1,c = (0x09 * s0) xor (0x0e * s1) xor (0x0b * s2) xor (0x0d * s3)
    state(pState,1,c) = (eight(s0)^s0) ^ (eight(s1)^four(s1)^xtime(s1)) ^ (eight(s2)^xtime(s2)^s2) ^ (eight(s3)^four(s3)^s3);

    // s'_2,c = (0x0d * s0) xor (0x09 * s1) xor (0x0e * s2) xor (0x0b * s3)
    state(pState,2,c) = (eight(s0)^four(s0)^s0) ^ (eight(s1)^s1) ^ (eight(s2)^four(s2)^xtime(s2)) ^ (eight(s3)^xtime(s3)^s3);

    // s'_3,c = (0x0b * s0) xor (0x0d * s1) xor (0x09 * s2) xor (0x0e * s3)
    state(pState,3,c) = (eight(s0)^xtime(s0)^s0) ^ (eight(s1)^four(s1)^s1) ^ (eight(s2)^s2) ^ (eight(s3)^four(s3)^xtime(s3));
  }

  // arduino specific debug
  #ifdef verbose_debig
  Serial.println("state after InvMixColumns(): ");
  printBytes((unsigned char*)pText, 16, 16);
  #endif
} // InvMixColumns()



// ntransform -- normal transform macro to help with the loop unrolling
#define ntransform(text,keys,round) subAndShift(text);mixColumns(text);addRoundKey(text,keys,round);

/**
 *  EncryptBlock
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
void EncryptBlock(void *pText, const u_int32_ard *pKeys) {

	// FIXME -- Use non-arduino-specific debug
	#ifdef verbose_debug
	Serial.println("\n\nStarting encrypt, plaintext is");
	printBytes((byte_ard*)pText,16,16);
	#endif 
  
    // Add the first round key from the schedule
	AddRoundKey(pText, pKeys, 0);
    
    #if defined(unroll_encrypt_loop)
    ntransform(pText, pKeys, 1);
    ntransform(pText, pKeys, 2);
    ntransform(pText, pKeys, 3);
    ntransform(pText, pKeys, 4);
    ntransform(pText, pKeys, 5);
    ntransform(pText, pKeys, 6);
    ntransform(pText, pKeys, 7);
    ntransform(pText, pKeys, 8);
    ntransform(pText, pKeys, 9);
    #else

	int round;
	for (round=1; round<ROUNDS; round++)
	{
		// Fixme: Use non-arduino-specific debug
		#ifdef verbose_debug
		Serial.print("Encryption round ");
		Serial.println(round);
		#endif
  
		SubAndShift(pText); 
		MixColumns(pText);  
		AddRoundKey(pText, pKeys, round); 
	}
    #endif

	// Fixme: Use non-arduino-specific debug
	#ifdef verbose_debug
	Serial.println("Encryption round 10");
	#endif

	// Now, do the final round of encryption
	SubAndShift(pText);
	AddRoundKey(pText, pKeys, 10);  // add the last round key from the schedule
} //EncryptBlock()


// DecryptBlock()
// 
// Decrypt a single block, stored in the buffer, take a pointer to the buffer.
// The buffer _MUST_ be 16 bytes in length!
// pKeys stores a complete key schedule for the round. 
//
// Follows the references of FIPS-197, Section 5.3 (Inverse Cipher)

void DecryptBlock(void* pEncrypted, const u_int32_ard *pKeys)
{
  // Add the first round key before starting the rounds
  AddRoundKey(pEncrypted, pKeys, ROUNDS);

  int round;
  for(round=ROUNDS-1; round>0; round--)
  {
    // FIXME: use non-arduino specific debug
    #ifdef verbose_debug
    Serial.print("Encryption round " );
    Serial.println(round);
    #endif

    InvSubAndShift(pEncrypted);
    AddRoundKey(pEncrypted, pKeys, round);
    InvMixColumns(pEncrypted);
  }

  // The last round is different -- there is no MixColumns.
  InvSubAndShift(pEncrypted);
  AddRoundKey(pEncrypted, pKeys, 0);


} // DecryptBlock()
