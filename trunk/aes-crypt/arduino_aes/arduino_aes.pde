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

int counter = 0;

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
  
  // Test code to print the version def'd in the envrionment.h file
  Serial.print("\n\nVersion:");
  #ifdef _ARDUINO_DUEMILANOVE
  Serial.println("Arduino");
  #endif
  #ifdef  _INTEL_32
  Serial.println("_INTEL_32");
  #endif
  #ifdef  _INTEL_64
  Serial.println("_INTEL_64");
  #endif

  // Doublecheck the actual size of int16 and int32
  Serial.print("Size of int16: ");  
  Serial.println(sizeof(int16_ard));
  Serial.print("Size of int32: ");
  Serial.println(sizeof(int32_ard));  
      
  // Initialize the t-boxes
  #if defined(t_box_transform) && defined(t_table_generate)
  initializeTboxes();
  #endif  
  
  Serial.println("Initial key is");
  printBytes(pKey,16,16);
  
  Serial.println("Expanding keys");
  KeyExpansion(pKey,pKeys);
  Serial.println("Key expansion done -- starting main loop (new code #11)");
  Serial.print("\n");
}

void doCount(void) {
  
  unsigned char pText[16];
  sprintf((char*)pText, "%.016d", counter);
  Serial.print("pText (before): ");
  Serial.print((char*)pText);
  Serial.print("\n");
  
  encryptBlock((void*)pText,(u_int32_ard *)pKeys);  

  Serial.print("printBytes(counter): ");
  printBytes((unsigned char*)counter,16,16);
  Serial.print("pText (after): ");
  printBytes(pText,16,16); // Print to serial in more or less readable format

  Serial.print("\n\n");
  delay(10000);

  counter ++;
}

void doFips197Test(void) { 
  char pStr[] = {0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,
  				 0xe0,0x37,0x07,0x34}; // FIPS test vector
  unsigned char pText[128];
  strncpy((char*)pText,pStr,16);
  encryptBlock((void*)pText,(u_int32_ard *)pKeys);  
  printBytes((unsigned char*)pStr,16,16);
  printBytes(pText,16,16); // Print to serial in more or less readable format
  Serial.print("\n\n");
  delay(10000);
}

void loop(void) {
  doRfc4493test(); 
  //doFips197Test();
  //doCount();  
}

int doRfc4493test() {
  
  delay(5000);
  
  Serial.println("----------------------------------------");
  Serial.println("RFC-4494 test cases for cmac generation:");
  Serial.println("----------------------------------------");
  
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

  byte_ard K[] = 
    {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
     0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};

  byte_ard M[] = 
    {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
     0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
     0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
     0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
     0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
     0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
     0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
     0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};
     
  byte_ard CMAC[] =
    {0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
     0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0};

  aesCMac(K, M, 0,  CMAC);
  Serial.print("CMAC   0: "); printBytes((byte_ard*)CMAC0, 16);
  Serial.print("CMAC'  0: "); printBytes((byte_ard*)CMAC, 16);

  aesCMac(K, M, 16,  CMAC);
  Serial.print("CMAC  16: "); printBytes((byte_ard*)CMAC16, 16);
  Serial.print("CMAC' 16: "); printBytes((byte_ard*)CMAC, 16);

  aesCMac(K, M, 40,  CMAC);
  Serial.print("CMAC  40: "); printBytes((byte_ard*)CMAC40, 16);
  Serial.print("CMAC' 40: "); printBytes((byte_ard*)CMAC, 16);
	
  aesCMac(K, M, 64,  CMAC);
  Serial.print("CMAC  64: "); printBytes((byte_ard*)CMAC64, 16);
  Serial.print("CMAC' 64: "); printBytes((byte_ard*)CMAC, 16);
	

  Serial.print("Verify (expected: 1): "); Serial.println(verifyAesCMac(K, M, 64,  CMAC));
  Serial.print("Verify (expected: 0): "); Serial.println(verifyAesCMac(K, M, 64,  CMAC40));
}

