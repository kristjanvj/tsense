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
 *  printBytes
 */
void printBytes(unsigned char* pBytes, unsigned long dLength, int textWidth=16)
{	
	int bytecount=0;
	for(unsigned long i=0;i<dLength;i++)
	{
		Serial.print(pBytes[i],HEX);
                Serial.print(" ");
		if ( ++bytecount == textWidth )
		{
			Serial.print("\n");
			bytecount=0;
		}
	}
	if ( bytecount != 0 )
		Serial.print("\n");
}

void setup(void)
{
  Serial.begin(9600);  
 
  delay(1000);
  
  // Initialize the t-boxes
  #if defined(t_box_transform) && defined(t_table_generate)
  initializeTboxes();
  #endif  
  
  Serial.println("Initial key is");
  printBytes(pKey,16,16);
  
  Serial.println("Expanding keys");
  KeyExpansion(pKey,pKeys);
  Serial.println("Key expansion done -- starting main loop (new code #4)");
}


void loop(void) { 
  char pStr[] = {0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34}; // FIPS test vector
  unsigned char pText[128];
  strncpy((char*)pText,pStr,16);
  encryptBlock((void*)pText,(unsigned long *)pKeys);  
  printBytes((unsigned char*)pStr,16,16);
  printBytes(pText,16,16); // Print to serial in more or less readable format
  Serial.print("\n\n");
  delay(10000);
}
