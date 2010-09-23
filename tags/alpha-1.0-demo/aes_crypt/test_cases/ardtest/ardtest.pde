
/**
 *  @file ardtest.pde
 *
 *  @brief AES tests for Arduino Duemilanove
 *
 *  @author Kristjan V. Jonsson
 *  @date 2010
 */
 
#include <stdlib.h>
#include <EEPROM.h>
#include "aes_cmac.h"
#include "aes_crypt.h"
#include "protocol.h"
#include "tstypes.h"

void* operator new(size_t size) { return malloc(size); }
void operator delete(void* ptr) { free(ptr); }

//
// The debug defines
//
//#define verbose   // Verbose output to the serial interface.
//#define debug     // Debug output to the serial interface.
//#define testcounters // Counters used to generate the measurements rather than analog input

// Defines for the digital output pins
#define LED_STATUS          13
#define LED_SIGNAL_1        3
#define LED_SIGNAL_2        4
#define LED_SIGNAL_3        5
#define LED_SIGNAL_4        6


/**
 *  setup
 *
 *  The Arduino setup function.
 */
void setup(void)
{   
  // Set pinMode of digital pins to output
  pinMode(LED_STATUS,OUTPUT); 
  pinMode(LED_SIGNAL_1,OUTPUT);
  pinMode(LED_SIGNAL_2,OUTPUT);
  pinMode(LED_SIGNAL_3,OUTPUT);
  pinMode(LED_SIGNAL_4,OUTPUT);
  digitalWrite(LED_STATUS,LOW);
   
  // Initialize the serial port
  Serial.begin(9600);
  Serial.flush();
  
  delay(5000);
  
  Serial.println("\n\nStarting tests");

  int reps=1000; // Repetitions for timed test

  fipsTest();
  encrypt_decrypt_single_test();
  encrypt_decrypt_cbc_test();
  int bufsize=16;
  for( int i = 0; i<4; i++ )
  {
    encrypt_cbc_timed_test(bufsize,reps);
    bufsize = bufsize+bufsize;
  }
  bufsize=16;
  for( int i = 0; i<4; i++ )
  {
    encrypt_decrypt_cbc_timed_test(bufsize,reps);  
    bufsize = bufsize+bufsize;    
  } 
  //mac_test();
  //pack_unpack_test();
  
  Serial.println("\n\n\nTests done.\n\n");
}

/**
 *  loop
 *
 *  The Arduino loop function
 */
void loop(void) 
{
  static bool blinkState=false;
  blinkState = !blinkState;  
  digitalWrite(LED_STATUS,blinkState);
  delay(1000);
}

/**
 *  printBytes
 *
 *  For debug only. Pretty print an array of bytes.
 *  Can be safely removed from "production" builds.
 */
void printBytes(byte_ard* pBytes, int dLength)
{	 
  int byteLen=0;
  for(int i=0; i<dLength;i++)
  {
    if(pBytes[i]<0x10) Serial.print("0");
    Serial.print(pBytes[i],HEX);
    Serial.print(" ");
    if(++byteLen%16==0)
      Serial.print("\n");
  }
  Serial.print("\n");
}

void fipsTest()
{
  Serial.println("\n\nFIPS (appendix B) test begins\n");
  
  byte_ard pFipsStr[] = {0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34}; // FIPS test vector
  byte_ard pFipsKey[] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c}; // FIPS key
    
  Serial.print("KEY: ");
  printBytes(pFipsKey,16);
  Serial.print("P: ");
  printBytes(pFipsStr,16);

  byte_ard pKeys[KEY_BYTES*11];  
  memset(pKeys,0,KEY_BYTES*11);  
  KeyExpansion(pFipsKey,pKeys);

  EncryptBlock((void*)pFipsStr, (u_int32_ard *)pKeys);  
  Serial.print("C: ");
  printBytes(pFipsStr,16);

  DecryptBlock((void*)pFipsStr, (u_int32_ard *)pKeys);
  Serial.print("P': ");
  printBytes(pFipsStr,16);
}

void encrypt_decrypt_single_test()
{
  Serial.println("\n\nSingle block encrypt/decrypt test begins");
   
  byte_ard P[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x01};
  byte_ard PP[16];
  memcpy(PP,P,16);  
    
  byte_ard K[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
  byte_ard IV[16] = {0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,  0x30, 0x30};

  byte_ard KS[16*11];
  KeyExpansion(K,KS);  

  EncryptBlock(P,(const u_int32_ard*)KS);
  DecryptBlock(P,(const u_int32_ard*)KS);

  printBytes(P,16);
  printBytes(PP,16);
  if ( strncmp((const char *)P,(const char *)PP,16)==0 )
   Serial.println("PASSED");
  else
   Serial.println("FAILED"); 
}

void encrypt_decrypt_cbc_test()
{
  Serial.println("\n\nCBC-mode encrypt/decrypt test begins");  
    
  byte_ard P[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x01};
  byte_ard C[16];  
  byte_ard PP[16];
  memset(C,0,16);
  memset(PP,0,16);
    
  byte_ard K[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
  byte_ard IV[16] = {0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,  0x30, 0x30};

  byte_ard KS[16*11];
  KeyExpansion(K,KS);  

  CBCEncrypt((void *) P, (void *) C, 16, 0,  (const u_int32_ard*)KS, (const u_int16_ard*)IV);
  CBCDecrypt((void *) C, (void *) PP, 16, (const u_int32_ard*)KS, (const u_int16_ard*)IV);
  printBytes(P,16);  
  printBytes(C,16);
  printBytes(PP,16);
  if ( strncmp((const char *)P,(const char *)PP,16)==0 )
   Serial.println("PASSED");
  else
   Serial.println("FAILED"); 
}

void encrypt_cbc_timed_test(int bufsize, int reps)
{
  Serial.println("\n\nTimed CBC-mode encrypt test begins");
  
  randomSeed(analogRead(5));  // Unconnected analog pin
  
  byte_ard P[bufsize];              // Bufsize is in bytes, not blocks
  for ( int i=0; i<bufsize; i++ )
    P[i] = random(256);
  byte_ard C[bufsize];  
    
  byte_ard K[16];
  byte_ard IV[16];
  
  for ( int i=0; i<16; i++ )
    K[i] = random(256);    
  for ( int i=0; i<16; i++ )
    IV[i] = random(256);
    
  byte_ard KS[16*11];
  KeyExpansion(K,KS);  

  long starttime;
  long endtime;
        
  starttime=micros();
  for( int i=0; i<reps; i++ )
    CBCEncrypt((void*)P, (void*)C, bufsize, 0, (const u_int32_ard*)KS, (const u_int16_ard*)IV);
  endtime=micros();

  double diff = (double)(endtime-starttime);
  double t = (diff/reps);

  int blockCount = bufsize/16; // 16 bytes per block for AES

  Serial.print(bufsize); Serial.print(";");          // Bytes
  Serial.print(reps); Serial.print(";");             // # of repetitions
  Serial.print(starttime); Serial.print(";");        // micro secs
  Serial.print(endtime); Serial.print(";");          // micro secs
  Serial.print(t); Serial.print(";");                // ave time per operation in micro secs
  Serial.print(t/blockCount); Serial.print("\n");    // time per block in micro secs
}

void encrypt_decrypt_cbc_timed_test(int bufsize, int reps)
{
  Serial.println("\n\nTimed CBC-mode encrypt/decrypt test begins");
    
  randomSeed(analogRead(5));  // Unconnected analog pin
  
  byte_ard P[bufsize];
  for ( int i=0; i<bufsize; i++ )
    P[i] = random(256);
  byte_ard C[bufsize];  
  byte_ard PP[bufsize];  
    
  byte_ard K[16];
  byte_ard IV[16];
  
  for ( int i=0; i<16; i++ )
    K[i] = random(256);    
  for ( int i=0; i<16; i++ )
    IV[i] = random(256);
    
  byte_ard KS[16*11];
  KeyExpansion(K,KS);  

  long starttime;
  long endtime;

  starttime=micros();
  for( int i=0; i<reps; i++ )
  {
    CBCEncrypt((void *) P, (void *) C, bufsize, 0,  (const u_int32_ard*)KS, (const u_int16_ard*)IV);
    CBCDecrypt((void *) C, (void *) PP, bufsize, (const u_int32_ard*)KS, (const u_int16_ard*)IV);
  }
  endtime=micros();

  if ( strncmp((const char *)P,(const char *)PP,bufsize)!=0 )
  {
   Serial.println("FAILED"); 
   Serial.print("P: ");
   printBytes(P,bufsize);
   Serial.print("PP: ");
   printBytes(PP,bufsize);
  }
  else
  {
    double diff = (double)(endtime-starttime);
    double t = (diff/reps);
    int blockCount = bufsize/16;
  
    Serial.print(bufsize); Serial.print(";");          // Bytes
    Serial.print(reps); Serial.print(";");             // # of repetitions 
    Serial.print(starttime); Serial.print(";");        // micro secs
    Serial.print(endtime); Serial.print(";");          // micro secs
    Serial.print(t); Serial.print(";");                // Ave time per operation in micro secs
    Serial.print(t/blockCount); Serial.print("\n");   // Time per block in micro secs
  }
}

void mac_test()
{
  // TODO
}

void pack_unpack_test()
{
  // TODO
}

