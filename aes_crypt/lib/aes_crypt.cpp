/**
 *
 * Kristjan Valur Jonsson
 * Benedikt Kristinsson
 *
 * AES Encryption Implementation. Ported to the Arduino 
 * from the aes Intel platform implementation. The code compiles on
 * both the Arduino platform and Intel i386/amd64
 * 
 *    This file is part of the Trusted Sensors Research Project (TSense).
 *
 *  TSense is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  TSense is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with the TSense code.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
 
#include "aes_crypt.h"
  
#ifdef _ARDUINO_DUEMILANOVE
  #include <EEPROM.h>     // The EEPROM access library
  #include <WProgram.h>   // Needed for Serial.print debugging
  #include "edevdata.h"   // The EEPROM memory layout
#endif /* _ARDUINO_DUEMILANOVE */

//
// The xtime macro is used in the mixColumns transformation. It implements the 
// left shift and conditional XOR operations described in FIPS-197, section 4.2.1. 
// This can be implemented by a procedure and a conditional statement, but the 
// macro is a much more compact form.
// 
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

// The AES related lookup tables are stored in the EEPROM on the Arduino platform
#ifndef _ARDUINO_DUEMILANOVE
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
#endif

/**
 *  KeyExpansion()
 *
 *  Implements the AES key expansion algorithm.
 *  Note: only supports 128 bit keys and 10 rounds.
 *  See FIPS-197 and http://en.wikipedia.org/wiki/Rijndael_key_schedule on the algorithm.
 *  The Rcon table used in the algorithm copied from (but not verified!) the wikipedia
 *  article.
 *  key is the ecryption key, whereas keys are the derived expansion keys. 
 */
void KeyExpansion(const void *key, void *keys) 
{
	memcpy(keys,key,16); // Copy the first key

	#ifdef verbose_debug  
	Serial.println("Starting key expansion");
	Serial.println("Initial key:");
	printBytes((byte_ard *)key,16,16);
	#endif

	byte_ard *ckeys = (byte_ard*)keys;

	int r=1; // The Rcon counter
	for(int i=16; i<176; i+=4)
	{
		// The SubWord and RotWord methods described in Section 5.2 of FIPS-197 are 
        // replaced here by their inlined equivalents. The algorithm is also simplifyed
        // by not supporting the longer key lengths. Several steps are combined to be
        // able to compute keys in-place without temporary variables.
        if (i % 16 == 0)  // Dividable by 16, the first key
		{
			// Copy the previous four bytes with rotate. 
			// Apply the AES Sbox to the four bytes of the key only.
			// Multiply the first byte with the Rcon.
			ckeys[i] = ckeys[i-16] ^ getSboxValue(ckeys[i-3]) ^ getRconValue(r++);
			ckeys[i+1] = ckeys[i-15] ^ getSboxValue(ckeys[i-2]);
			ckeys[i+2] = ckeys[i-14] ^ getSboxValue(ckeys[i-1]);
			ckeys[i+3] = ckeys[i-13] ^ getSboxValue(ckeys[i-4]);
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
	state(pState,0,0) = getSboxValue(state(pState,0,0));
	state(pState,0,1) = getSboxValue(state(pState,0,1));
	state(pState,0,2) = getSboxValue(state(pState,0,2));
	state(pState,0,3) = getSboxValue(state(pState,0,3));

	// Shift and sbox the second row
	temp=state(pState,1,0);
	state(pState,1,0)=getSboxValue(state(pState,1,1));
	state(pState,1,1)=getSboxValue(state(pState,1,2));
	state(pState,1,2)=getSboxValue(state(pState,1,3));
	state(pState,1,3)=getSboxValue(temp);
	// Shift and sbox the third row
	temp = state(pState,2,0);
	state(pState,2,0)=getSboxValue(state(pState,2,2));
	state(pState,2,2)=getSboxValue(temp);
	temp = state(pState,2,1); 
	state(pState,2,1)=getSboxValue(state(pState,2,3));
	state(pState,2,3)=getSboxValue(temp);
	// Shift and sbox the fourth row
	temp = state(pState,3,3);
	state(pState,3,3) = getSboxValue(state(pState,3,2));
	state(pState,3,2) = getSboxValue(state(pState,3,1));
	state(pState,3,1) = getSboxValue(state(pState,3,0));
	state(pState,3,0) = getSboxValue(temp);

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
  state(pState,0,0) = getISboxValue(state(pState,0,0));
  state(pState,0,1) = getISboxValue(state(pState,0,1));
  state(pState,0,2) = getISboxValue(state(pState,0,2));
  state(pState,0,3) = getISboxValue(state(pState,0,3));
  
  // Second row is shifted one byte to the left
  temp = state(pState,1,3);
  state(pState,1,3) = getISboxValue(state(pState,1,2));
  state(pState,1,2) = getISboxValue(state(pState,1,1));
  state(pState,1,1) = getISboxValue(state(pState,1,0));
  state(pState,1,0) = getISboxValue(temp);

  // Third row is shifted two bytes to the left
  temp = state(pState,2,2);
  state(pState,2,2) = getISboxValue(state(pState,2,0));
  state(pState,2,0) = getISboxValue(temp);
  temp = state(pState,2,1);
  state(pState,2,1) = getISboxValue(state(pState,2,3));
  state(pState,2,3) = getISboxValue(temp);

  // The fourth row is shifted three bytes to the left
  temp = state(pState,3,0);
  state(pState,3,0) = getISboxValue(state(pState,3,1));
  state(pState,3,1) = getISboxValue(state(pState,3,2));
  state(pState,3,2) = getISboxValue(state(pState,3,3));
  state(pState,3,3) = getISboxValue(temp);

  // FIXME -- Use non-arduino-specific debug
  #ifdef verbose_debug
  Serial.println("State after subAndShift:");
  printBytes((unsigned char *)pText,16,16);
  #endif 

} // InvSubAndShift()


/**
 *  MixColumns
 * 
 * The MixColumns function is the trickiest to implement efficiently since it 
 * contains a lot of expensive operations if implemented literally as stated 
 * in FIPS-197.
 *
 * Considerable experimentation, trial, error and literature search lead to 
 * the present form. A fuller discussion and the sources used are cited in the 
 * body of the function.
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
#define ntransform(text,keys,round) SubAndShift(text);MixColumns(text);AddRoundKey(text,keys,round);

/**
 *  EncryptBlock
 *
 *  Encrypt a single block, stored in the buffer text. The buffer MUST be 16 
 *  bytes in length!
 *  pKeys stores a complete key schedule for the round.
 *  The algorithm, call order and function names, follows the reference of 
 *  FIPS-197, section 5.1.
 *
 *  The encryption loop can be unrolled or left as is by using the 
 *  unroll_encrypt_loop define.
 *
 *  The encrypted data is returned in the text buffer.
 *
 *  Note: Only 10 rounds and 128 bit keys are supported in this implementation.
 */
void EncryptBlock(void *pBlock, const u_int32_ard *pKeys) 
{
	// FIXME -- Use non-arduino-specific debug
	#ifdef verbose_debug
	Serial.println("\n\nStarting encrypt, plaintext is");
	printBytes((byte_ard*)pBlock,16,16);
	#endif 
  
    // XOR the first key to the first state
	AddRoundKey(pBlock, pKeys, 0);
    
    #if defined(unroll_encrypt_loop)
    ntransform(pBlock, pKeys, 1);
    ntransform(pBlock, pKeys, 2);
    ntransform(pBlock, pKeys, 3);
    ntransform(pBlock, pKeys, 4);
    ntransform(pBlock, pKeys, 5);
    ntransform(pBlock, pKeys, 6);
    ntransform(pBlock, pKeys, 7);
    ntransform(pBlock, pKeys, 8);
    ntransform(pBlock, pKeys, 9);
    #else

	int round;
	for (round=1; round<ROUNDS; round++)
	{
		// Fixme: Use non-arduino-specific debug
		#ifdef verbose_debug
		Serial.print("Encryption round ");
		Serial.println(round);
		#endif
  
		SubAndShift(pBlock); 
		MixColumns(pBlock);  
		AddRoundKey(pBlock, pKeys, round); 
	}
    #endif

	// Fixme: Use non-arduino-specific debug
	#ifdef verbose_debug
	Serial.println("Encryption round 10");
	#endif

	// Now, do the final round of encryption
	SubAndShift(pBlock);
	AddRoundKey(pBlock, pKeys, 10);  // add the last round key from the schedule
} //EncryptBlock()


// DecryptBlock()
// 
// Decrypt a single block, stored in the buffer, take a pointer to the buffer.
// The buffer _MUST_ be 16 bytes in length!
// pKeys stores a complete key schedule for the round. 
//
// Follows the references of FIPS-197, Section 5.3 (Inverse Cipher)

// dtransform - help with the loop unrolling
#define dtransform(cipher,keys,round) InvSubAndShift(cipher);AddRoundKey(cipher,keys,round);InvMixColumns(cipher);
void DecryptBlock(void* pEncrypted, const u_int32_ard *pKeys)
{
  // XOR the first key to the first state. 
  AddRoundKey(pEncrypted, pKeys, ROUNDS);

  #if defined(unroll_decrypt_loop)
  dtransform(pEncrypted, pKeys, 9);
  dtransform(pEncrypted, pKeys, 8);
  dtransform(pEncrypted, pKeys, 7);
  dtransform(pEncrypted, pKeys, 6);
  dtransform(pEncrypted, pKeys, 5);
  dtransform(pEncrypted, pKeys, 4);
  dtransform(pEncrypted, pKeys, 3);
  dtransform(pEncrypted, pKeys, 2);
  dtransform(pEncrypted, pKeys, 1);
  #else
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
  #endif

  // The last round is different (Round 0) -- there is no MixColumns.
  InvSubAndShift(pEncrypted);
  AddRoundKey(pEncrypted, pKeys, 0);


} // DecryptBlock()

 /**
  *  CBC - The cipher-block chaining mode of operation
  *  Mode of operation
  *  http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation
  *       C_0 = IV
  *       C_i = E_k(P_i XOR C_{i-1})
  *       C_1 = E_k(P_1 XOR C_0) = E_k(P_1 XOR IV)
  *       C_2 = E_k(P_2 XOR C_1) 
  *
  * In order to use the CBC Mode of Operation the following has to be declared
  *  - A unsigned char (byte_ard) array containing the cleartext/ciphertext.
  *  - A buffer of length (blocks*BLOCK_BYTE_SIZE) for post-CBC data.
  *  - The length of the char array. (Decryption: must be mod 16 == 0)
  *  - The number of chars needed to 'pad' the array. (Encryption only)
  *      (if the integer is BLOCK_BYTE_SIZE+1 then CBCEncrypt will calc. the padding itself.) 
  *  - Initialization vector
  *  - Rijandel Key schedule
  */


// CBCEncrypt()
void CBCEncrypt(void *pTextIn, void* pBuffer, u_int32_ard length,
                u_int32_ard padding, const u_int32_ard *pKeys,
                const u_int16_ard *pIV)
{
  byte_ard *pText = (byte_ard*)pTextIn;
  byte_ard *cBuffer = (byte_ard*)pBuffer;
  byte_ard lastblock[BLOCK_BYTE_SIZE];
  byte_ard currblock[BLOCK_BYTE_SIZE];
  u_int32_ard blocks = (length + padding) / BLOCK_BYTE_SIZE;

  memcpy(lastblock,pIV,BLOCK_BYTE_SIZE);

  if (padding == (BLOCK_BYTE_SIZE +1) )
  {
    // Decide on the padding
    if ((length % BLOCK_BYTE_SIZE) == 0)
      padding = 0;
    else
      padding = BLOCK_BYTE_SIZE - (length % BLOCK_BYTE_SIZE);  
  }

  
  // Copy and pad the 
  for (u_int32_ard i = 0; i<(length + padding); i++)
  {
    if (i < length)
    {
      // Copy the string
      cBuffer[i] = pText[i];
    }
    else
    {
      cBuffer[i] = 0x80;
    }
     
  }
  

  // C_i = E_k(P_i XOR C_{i-1})
  for (u_int32_ard i = 0; i < blocks; i++) 
  {
    #if defined(unroll_cbc_loop)
    currblock[0] = cBuffer[(i*BLOCK_BYTE_SIZE)+0] ^ lastblock[0];
    currblock[1] = cBuffer[(i*BLOCK_BYTE_SIZE)+1] ^ lastblock[1];
    currblock[2] = cBuffer[(i*BLOCK_BYTE_SIZE)+2] ^ lastblock[2];
    currblock[3] = cBuffer[(i*BLOCK_BYTE_SIZE)+3] ^ lastblock[3];
    currblock[4] = cBuffer[(i*BLOCK_BYTE_SIZE)+4] ^ lastblock[4];
    currblock[5] = cBuffer[(i*BLOCK_BYTE_SIZE)+5] ^ lastblock[5];
    currblock[6] = cBuffer[(i*BLOCK_BYTE_SIZE)+6] ^ lastblock[6];
    currblock[7] = cBuffer[(i*BLOCK_BYTE_SIZE)+7] ^ lastblock[7];
    currblock[8] = cBuffer[(i*BLOCK_BYTE_SIZE)+8] ^ lastblock[8];
    currblock[9] = cBuffer[(i*BLOCK_BYTE_SIZE)+9] ^ lastblock[9];
    currblock[10] = cBuffer[(i*BLOCK_BYTE_SIZE)+10] ^ lastblock[10];
    currblock[11] = cBuffer[(i*BLOCK_BYTE_SIZE)+11] ^ lastblock[11];
    currblock[12] = cBuffer[(i*BLOCK_BYTE_SIZE)+12] ^ lastblock[12];
    currblock[13] = cBuffer[(i*BLOCK_BYTE_SIZE)+13] ^ lastblock[13];
    currblock[14] = cBuffer[(i*BLOCK_BYTE_SIZE)+14] ^ lastblock[14];
    currblock[15] = cBuffer[(i*BLOCK_BYTE_SIZE)+15] ^ lastblock[15];

    EncryptBlock((void*)currblock, pKeys);

    cBuffer[(i*BLOCK_BYTE_SIZE)+0] = currblock[0];
    cBuffer[(i*BLOCK_BYTE_SIZE)+1] = currblock[1];
    cBuffer[(i*BLOCK_BYTE_SIZE)+2] = currblock[2];
    cBuffer[(i*BLOCK_BYTE_SIZE)+3] = currblock[3];
    cBuffer[(i*BLOCK_BYTE_SIZE)+4] = currblock[4];
    cBuffer[(i*BLOCK_BYTE_SIZE)+5] = currblock[5];
    cBuffer[(i*BLOCK_BYTE_SIZE)+6] = currblock[6];
    cBuffer[(i*BLOCK_BYTE_SIZE)+7] = currblock[7];
    cBuffer[(i*BLOCK_BYTE_SIZE)+8] = currblock[8];
    cBuffer[(i*BLOCK_BYTE_SIZE)+9] = currblock[9];
    cBuffer[(i*BLOCK_BYTE_SIZE)+10] = currblock[10];
    cBuffer[(i*BLOCK_BYTE_SIZE)+11] = currblock[11];
    cBuffer[(i*BLOCK_BYTE_SIZE)+12] = currblock[12];
    cBuffer[(i*BLOCK_BYTE_SIZE)+13] = currblock[13];
    cBuffer[(i*BLOCK_BYTE_SIZE)+14] = currblock[14];
    cBuffer[(i*BLOCK_BYTE_SIZE)+15] = currblock[15];
    
    #else

    for (u_int16_ard j = 0; j < BLOCK_BYTE_SIZE; j++)
    {
      currblock[j] = cBuffer[(i*BLOCK_BYTE_SIZE)+j] ^ lastblock[j];
    }
    
    EncryptBlock((void*)currblock, pKeys);

    // Copy the ciphered block into the buffer again. 
    for (u_int16_ard j = 0; j < BLOCK_BYTE_SIZE; j++)
    {
      cBuffer[(i*BLOCK_BYTE_SIZE)+j] = currblock[j];
    }

    #endif
//    lastblock = currblock;
	memcpy(lastblock,currblock,BLOCK_BYTE_SIZE);

  } // for (blocks)
} // CBCEncrypt()

// CBCDecrypt()
//
// C_0 = IV
// P_i = D_k(C_i) XOR C_{i-1} 
//
// Removing the padding probably isnt neccesary, since the CBC
// leaves the null char intact at the end of the cstring. But what 
// about binary files and etc?
void CBCDecrypt(void* pText, void* pBuffer, u_int32_ard length,
                const u_int32_ard *pKeys, const u_int16_ard *pIV)
{
  byte_ard *cText = (byte_ard*)pText;
  byte_ard *cBuffer = (byte_ard*)pBuffer;
  byte_ard lastblock[BLOCK_BYTE_SIZE];
  byte_ard tempblock[BLOCK_BYTE_SIZE];
  byte_ard currblock[BLOCK_BYTE_SIZE];
  u_int32_ard blocks = length/BLOCK_BYTE_SIZE;
  
  memcpy(lastblock,pIV,BLOCK_BYTE_SIZE);

  for (u_int32_ard i = 0; i < blocks; i++)
  {
    #if defined(unroll_cbc_loop) 
    // This loop unrolled would be really ugly. 
    #else

    // copy the data to 'currblock', to be deciphered. 
    for (u_int16_ard j = 0; j < BLOCK_BYTE_SIZE; j++)
    {
      currblock[j] = cText[(i*BLOCK_BYTE_SIZE)+j];
      tempblock[j] = currblock[j];
    }

    DecryptBlock((void*)currblock, pKeys);

    // xor the decphered block with last latest cipherblock, C_{i-1} 
    for (u_int16_ard j = 0; j < BLOCK_BYTE_SIZE; j++)
    {
      cBuffer[(i*BLOCK_BYTE_SIZE)+j] = currblock[j]  ^ lastblock[j];
      lastblock[j] = tempblock[j];
    }

    #endif
  }
  
} // CBCDecrypt()

/**
 *  getSboxValue
 *
 *  Accessor for the SBOX lookup table. Arduino systems look into the EEPROM
 *  while other platforms use in-memory tables.
 */
byte_ard getSboxValue(int index)
{
  #ifdef _ARDUINO_DUEMILANOVE
    if( (S_TABLE_START+index) >= EEPROM_SIZE )
      return 0x00;
    return EEPROM.read(S_TABLE_START+index);
  #else
    return sbox[index];
  #endif
}

/**
 *  getISboxValue
 *
 *  Accessor for the ISBOX lookup table. Arduino systems look into the EEPROM
 *  while other platforms use in-memory tables.
 */
byte_ard getISboxValue(int index)
{
  #ifdef _ARDUINO_DUEMILANOVE
    if( (IS_TABLE_START+index) >= EEPROM_SIZE )
      return 0x00;
    return EEPROM.read(IS_TABLE_START+index);
  #else
    return isbox[index];
  #endif 
}

/**
 *  getRconValue
 *
 *  Accessor for the Rcon lookup table. Arduino systems look into the EEPROM
 *  while other platforms use in-memory tables.
 */
byte_ard getRconValue(int index)
{
  #ifdef _ARDUINO_DUEMILANOVE
    if( (RCON_TABLE_START+index) >= EEPROM_SIZE )
      return 0x00;
    return EEPROM.read(RCON_TABLE_START+index);
  #else
    return Rcon[index];
  #endif   
}

int generateKey(byte_ard *newKey){
	byte_ard res = 0;

	FILE * urandom = fopen("/dev/urandom","r");

	if(urandom) {
		for(int i=0; i<BLOCK_BYTE_SIZE; i++){
			fread(&res, 1, sizeof(res), urandom);
			newKey[i] = res;
		}
		fclose(urandom);
		return 1;
	}

	return res;
}
