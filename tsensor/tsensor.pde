/**
 *
 *  TSensor
 *
 *  Kristjan Valur Jonsson, Kristján Rúnarsson, Benedikt Kristinsson
 *  2010
 *
 *  Trusted sensor implementation for the Arduino platform.
 *  Written for the Arduino ATMega328 board.
 * 
 *  This file is part of the Trusted Sensors Research Project (TSense).
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

//
// There is a bunch of Serial.print stuff here for debug purposes. Use this very
// carefully since the debug strings seem to eat up all of the available RAM very
// quickly. Use #define to include only debug code for testing and be careful to
// remove for "production" builds.
//

#include <EEPROM.h>
#include "aes_cmac.h"
#include "aes_crypt.h"
#include "protocol.h"
#include "tstypes.h"
#include "devinfo.h"    // TODO: REMOVE -- INTEGRATE WITH PROTOCOL INFO AND OTHER HEADERS
#include "edevdata.h"   // The EEPROM data layout
#include "memoryFree.h"

//#define verbose   // Verbose output to the serial interface.
//#define debug     // Debug output to the serial interface.

#define COMMAND_BUFFER_SIZE 36

// Test counters
u_int16_ard counter1 = 100;
u_int16_ard counter2 = 200;

byte_ard state=0x00;            // The state bits -- 0: initialized, 1: error, 4 MSB: error code
u_int32_ard currentTime;        // The current update time
byte_ard samplingInterval = 1;  // The sampling interval in seconds
byte_ard *measBuffer=NULL;      // The measurement buffer (includes header for easier encrypt/MAC)
byte_ard measBufferSize = 10;   // The size of the measurement buffer -- values stored per interface
byte_ard measBufferCount = 0;   // The current position in the measurement buffer (stored values per interface)
byte_ard *valBase=NULL;         // The start of the values array in measBuffer
u_int32_ard *pMsgTime=NULL;     // Pointer to the time field in the measBuffer header
byte_ard headerByteSize=0;      // The size of the header portion of measBuffer
byte_ard recordByteSize;        // The size of a single record in measBuffer -- one record is one sample per interface

byte_ard *pSessionKey=NULL;
byte_ard *pCryptoKey=NULL;
u_int16_ard rekeyTimer=0;
u_int16_ard rekeyInterval=0;

u_int16_ard idNonce=0;
u_int16_ard rekeyNonce=0;

byte_ard commandBuffer[COMMAND_BUFFER_SIZE]; // Buffer to receive serial input

// Defines for the digital output bits
#define LED_STATUS 13

//
// Temporary defines for protocol messages -- include in the protocol itself eventually.
// Some of these are strictly T <-> C messages -- can consider these a separate sensor/client
// protocol.
//
#define MSG_T_GET_ID_Q           0x40
#define MSG_T_FREE_MEM_Q         0x50
#define MSG_T_FREE_MEM_R         0x51
#define MSG_T_STATE_Q            0x52
#define MSG_T_STATE_R            0x53
//
#define MSG_T_START_CMD          0x71 
#define MSG_T_STOP_CMD           0x72
#define MSG_T_RUN_TEST_CMD       0x73
//
#define MSG_ACK_NORMAL           0x00 
#define MSG_ACK_UNKNOWN_MESSAGE  0x01

//
// See protocol.h for these message types
//
#define MSG_T_GET_ID_R           0x10  
#define MSG_T_ID_RESPONSE_ERROR  0x1F
#define MSG_T_REKEY_REQUEST      0x30
#define MSG_T_KEY_TO_SENSE       0x31
#define MSG_T_REKEY_RESPONSE     0x32
#define MSG_T_ACK                0x4F
// TODO: NOT CLEAR ON 0x11 and 0x1F from the protocol definition

//
// The state word bit definitions
//
#define STATE_BIT_RUNNING 0   // Set to 1 when capture running -- sensor fully initialized
#define STATE_BIT_ERROR   1   // Set to 1 if error occurs
// State but 2 is reserved
#define STATE_BIT_BLINK   3   // Utility bit to blink status led in standby mode
#define STATE_BIT_MASK    0x07
#define STATE_ERR_CODE_OFFSET 4

//
// Error code definitions -- max 4 bits
//
#define ERR_CODE_NONE            0x00
#define ERR_CODE_BUF_ALLOCATION  0x01
#define ERR_CODE_STALE_MESSAGE   0x02
#define ERR_CODE_MAC_FAILED      0x03

//
// Protocol/policy related defines
//
#define MIN_NONCE_OFFSET  3    // The maximum staleness of nonce received back from authentication server.


/**
 *  setup
 *
 *  The Arduino setup function.
 */
void setup(void)
{
  state = 0x00;
  randomSeed(analogRead(5));  // Unconnected analog pin
  idNonce = random(32000); 
  rekeyNonce = random(32000);
 
  pinMode(LED_STATUS,OUTPUT); // Set the pinMode for pin 13 to output
  digitalWrite(LED_STATUS,LOW);
 
  Serial.begin(9600);    
  Serial.flush();
    
  #ifdef verbose    
  // Delay for a bit and blink the status led
  for(int i=0; i<5; i++)
  {
    digitalWrite(LED_STATUS,HIGH);
    delay(500);
    digitalWrite(LED_STATUS,LOW);
    delay(500);
  } 
  // Print the initial greeting
  Serial.println("\n\n------------------------");
  Serial.println("Initializing Tsensor");
  Serial.print("Free memory = ");
  Serial.println(freeMemory());
  Serial.println("------------------------\n\n");  
  #endif
}

/**
 *  loop
 *
 *  The Arduino loop function
 */
void loop(void) 
{      
  if( Serial.available() ) 
  {
    // First, check if there is a pending command
    // TODO: THe protocol needs to be coded into the getCommand function
    getCommand();  
  }
        
  if ( getRunState() ) // Bit 0 is the running bit
  {
    // Running state
    digitalWrite(LED_STATUS,HIGH);
    sampleAndReport(); 
  }
  else
  {    
    // Delay for a while
    delay(100);  
    if( getErrorState() ) 
    {  
      // Error state. Turn off the status LED
      digitalWrite(LED_STATUS,LOW);
    }
    else
    {
      // Standby state -- Blink the status LED
      if( bitRead(state,STATE_BIT_BLINK)==0 )
        digitalWrite(LED_STATUS,HIGH);
      else
        digitalWrite(LED_STATUS,LOW);
      bitWrite(state,STATE_BIT_BLINK,!bitRead(state,STATE_BIT_BLINK)); // Toggle led -- bit 3 is the blink bit
    }
  } 
}

/**
 *  getCommand
 *
 *  Check if there is a pending command from the host. Commands are defined in the protocol definition --
 *  see protocol.h. Some commands are C <-> T only, for example ones which query the memory state and
 *  status of the sensor. The format of the command is a single byte defining the type of message,
 *  followed by a number of fields, further defined in the protocol definitions.
 */
void getCommand() 
{   
  int endPos=0;
  while ( Serial.available() > 0 && endPos<COMMAND_BUFFER_SIZE )
  {
    // Read some bytes off the serial port
    commandBuffer[endPos++] = Serial.read();
  }
  
  // TODO: Patch in the rest of the protocol here
  // TODO: Use pack/unpack functions from the protocol library
   
  if(endPos>0)
  {    
    byte_ard cmdCode = commandBuffer[0]; // The first byte identifies the message

    // Handle all possible protocol messages that the sensor can receive here      
    switch(cmdCode)
    {
      case MSG_T_GET_ID_Q:  // ID query received from client C
        sendDeviceId();
        break;
      case MSG_T_ID_RESPONSE_ERROR:
        handleIdResponseError();
        break;
      case MSG_T_KEY_TO_SENSE:           // New (encrypted) session key package received from authentication server                                
        handleKeyToSense(commandBuffer); // via S and C.
        break;
      case MSG_T_REKEY_RESPONSE:
        handleRekeyResponse(commandBuffer);
        break;
      case MSG_T_START_CMD:
        doStart(commandBuffer); // The start and stop commands are only temporary for debug. TODO: REMOVE EVENTUALLY.
        break;
      case MSG_T_STOP_CMD:      // The start and stop commands are only temporary for debug. TODO: REMOVE EVENTUALLY.
        doStop();
        break;
      case MSG_T_FREE_MEM_Q:
        sendFreeMemory();
        break;
      case MSG_T_STATE_Q:
        sendCurrentState();
        break;    
      case MSG_T_RUN_TEST_CMD:
        doEncryptDecryptTest();     
        break;
      default:
        sendAck(MSG_ACK_UNKNOWN_MESSAGE);
        break;
      // TODO: Other possible messages include:
      //  -  update current time
    }
  }
}

/**
 *  sendDeviceId
 *
 *  Handler for device id query message. The sensor reports its public device ID in plaintext and
 *  additionally encrypts and MACs the ID with a nonce to identify itself to an authentication server.
 *  The private ID (master encryption key) is used for this message.
 */
void sendDeviceId()
{
  byte_ard pBuffer[41 /*IDMSG_FULLSIZE*/]; // TODO: CONST TOO SMALL! FIX IN protocol.h
  
  byte_ard key[KEY_BYTES];
  getPrivateKeyFromEEPROM(key);  // Get the private key from the EEPROM
  byte_ard keys[KEY_BYTES*11];
  KeyExpansion(key,keys);

  byte_ard idbuf[DEV_ID_LEN];  // Get the id from EEPROM
  getPublicIdFromEEPROM(idbuf);
  
  // Increment the nonce
  idNonce++;
  idNonce %= 65536; // Wrap around

  // Create the input struct and populate  
  message msg;
  msg.msgtype=0x10;  // TODO: USE CONST!
  msg.pID=idbuf;
  msg.nonce=idNonce;  
  msg.key=key;
    
  // Call the pack function to construct the message
  pack_idresponse(&msg,(const u_int32_ard*)keys,(void *)pBuffer);
  
  Serial.write(pBuffer,41); // TODO: USE CONST FROR LENGTH
  Serial.flush();
}

/**
 *  handleIdResponseError
 *
 *  Handle error from the identification procecss
 */
void handleIdResponseError()
{
  // TODO 
}

/** 
 *  handleKeyToSense
 *
 *  Utility function to handle a received key-to-sense message. This message carries the
 *  session key for the device. The session key is used for subsequent re-keying operations.
 */
void handleKeyToSense(byte_ard *pCommandBuffer)
{
  message msg;
  
  byte_ard key[KEY_BYTES];
  getPrivateKeyFromEEPROM(key);  // Get the private key from the EEPROM
  byte_ard keys[KEY_BYTES*11];
  KeyExpansion(key,keys);  
  
  unpack_keytosens(pCommandBuffer,(const u_int32_ard *)keys,&msg);
  
  // Check nonce
  // Check if the nonce is too old. A certain range must be allowed to account for the client 
  // fetching multiple ID packages.
  if ( msg.nonce < (idNonce-MIN_NONCE_OFFSET) || msg.nonce > idNonce )
  {
    setErrorState(ERR_CODE_STALE_MESSAGE);
    return;     
  }
  
  // Check the MAC
  // TODO: SHOULD UNPACK HANDLE MAC VERIFICATION????
  byte_ard cmac_buff[BLOCK_BYTE_SIZE];
  byte_ard authKeys[KEY_BYTES*11];
  KeyExpansion(key,authKeys);     // TODO: NEED THE AUTHENTICATION KEY!!
  aesCMac((const u_int32_ard*)authKeys, msg.ciphertext, 32, cmac_buff);
 
  if (strncmp((const char*)msg.cmac, (const char*)cmac_buff, BLOCK_BYTE_SIZE) != 0)
  {
    setErrorState(ERR_CODE_MAC_FAILED);
    return;     
  }
        
  // Save the session key
  if ( pSessionKey!=NULL )
    free(pSessionKey);
  pSessionKey = (byte_ard*)malloc(KEY_BYTES);
  memcpy(pSessionKey,msg.key,KEY_BYTES);
  // Set the rekey counter and interval. Use default if t=0
  rekeyTimer=0;
  rekeyInterval=msg.timer;
    
  sendRekeyRequest();  // Send a rekey request to the associated S
}

/**
 *  sendRekeyRequest
 *
 *  Constructs and sends a re-key message to the associated S
 */
void sendRekeyRequest()
{
  if (pSessionKey==NULL)
    return; // Should not happen! TODO: HANDLE BETTER
    
  // Increment the nonce
  rekeyNonce++;
  rekeyNonce %= 65536; // Wrap around
  
  byte_ard idbuf[DEV_ID_LEN];  // Get the id from EEPROM
  getPublicIdFromEEPROM(idbuf);
    
  message msg;
  msg.nonce=rekeyNonce;
  msg.pID = idbuf;
  
  byte_ard *keys = (byte_ard *)malloc(KEY_BYTES*11);
  KeyExpansion(pSessionKey,keys);

  byte_ard *buffer = (byte_ard *)malloc(REKEY_FULLSIZE);
  pack_rekey(&msg, (const u_int32_ard *)keys, buffer);  
  
  Serial.write(buffer,REKEY_FULLSIZE);
  
  free(buffer);
  free(keys);
}

/**
 *  handleRekeyResponse
 *
 *  TODO: IMPLEMENT
 */
void handleRekeyResponse(byte_ard *pCommandBuffer)
{
  // SAVE THE CRYPTO KEY HERE
  
  rekeyTimer=0; // Reset the rekey counter since we have a fresh key
  
  // Set running state to start producing encrypted messages
}
 
/**
 *  sendFreeMemory
 *
 *  Handler for the send free memory utility command. Returns (an estimate?) of the
 *  free RAM on the device.
 */
void sendFreeMemory()
{
  u_int16_ard freemem = freeMemory();  
  Serial.write(MSG_T_FREE_MEM_R);
  Serial.write(lowByte(freemem));
  Serial.write(highByte(freemem));  
  Serial.flush();
}

/**
 *  sendCurrentState
 *
 *  Handler for the get current state utility command. Returns the state bits and
 *  error code of the device.
 */
void sendCurrentState()
{
  Serial.write(MSG_T_STATE_R);
  Serial.write((state & STATE_BIT_MASK));
  Serial.write(((state >> STATE_ERR_CODE_OFFSET) & 0x0F));
  Serial.flush();
}

/**
 *  sendAck
 *
 *  Utility function to construct and send an ack packet.
 */
void sendAck(byte_ard code)
{
  Serial.write(MSG_T_ACK);
  Serial.write(code);
  Serial.flush();
}

/**
 *  sampleAndReport
 *
 *  This is the main measure loop, executed once the device is enabled.
 *  Values are stored in the measurement section of the allocated buffer. Note that
 *  the 10-bit arduino analog values are truncated by cutting off the 2 LSBs in order
 *  to fit into a byte. The rationale for this is that the 2 LSBs are probably mostly 
 *  measurement noise. This must of course be interpreted at the receiving end by right
 *  shifting to a 10 bit value, but of course we loose the two LSBs permanently.
 */
void sampleAndReport()
{
  // TODO: Hook in the actual analog measurements here eventually.
  *(valBase+measBufferCount++) = counter1++ >> 2; // Cut off 2 LSBs
  *(valBase+measBufferCount++) = counter2++ >> 2; // TODO: Use a constant for this 
  /* Stick other interfaces in here */

  // These are just demo counters -- replace with actual measured values
  counter1 %= 1024;  
  counter2 %= 1024;
  
  // Update the current time. Note that we rely on the delay command to keep
  // reasonably accurate time. The currentTime and samplingInterval are in seconds.
  currentTime+=samplingInterval; 
    
  // Check if the buffer is full. If so, dump to the serial interface.
  // TODO: Add some handling for the case when the serial port is not connected.
  if ( measBufferCount >= measBufferSize*INTERFACE_COUNT )
  {
    *pMsgTime = currentTime;  // Update the time part of the buffer header.
    //reportValues(measBuffer);  // TODO: DISABLED FOR INTEGRATION
    measBufferCount=0;
  } 

  delay(samplingInterval*1000); // Delay for the sampling interval (in msec)
}

/**
 *  doStart
 *
 *  Handle a start command received from the host. Takes a character buffer of parameters.
 */
void doStart(byte_ard *pCommandBuffer)
{
#ifdef debug
  Serial.println("\n-----------------------");
  Serial.println("Data acquisition begins");
  Serial.println("-----------------------\n");
  Serial.print("Set time: ");
  Serial.println(valBuffer);
  Serial.println("Push mode");      // The default (currently only) mode of operatioin
  Serial.print("Sampling interval: ");
  Serial.print(samplingInterval);
  Serial.println(" sec");
  Serial.print("Buffer size: ");
  Serial.println(measBufferSize);
  Serial.print("\n");
#endif
  if ( !allocateMeasBuffer() )
  {
    setErrorState(ERR_CODE_BUF_ALLOCATION);
    return;
  }
  setRunState();
  currentTime = 0; // TODO: Use the current time submitted from the client
  measBufferCount = 0; // Zero the current buffer size
  sendAck(MSG_ACK_NORMAL);
}

/**
 *  doStop
 *
 *  Handle a stop command received from the host. Stops the capture.
 *
 *  TODO: Perhaps flush the buffer to the host before deallocating?
 */
void doStop()
{
  #ifdef debug
  Serial.println("\n------------------------");
  Serial.println("Data acquisition stopped");
  Serial.println("------------------------\n");  
  #endif
  deallocateMeasBuffer();
  clearRunState();
  sendAck(MSG_ACK_NORMAL);  
}

/**
 *  allocateMeasBuffer
 *  
 *  Allocates a measurement buffer. 
 *  Computes the header and data segment sizes and initializes the fixed header fields.
 *
 *  Fields:
 *
 *  ID -- 6 bytes
 *  Update time -- 4 bytes (unix time)
 *  Sampling interval -- 1 byte
 *  Measurement buffer size -- 1 byte (#samples per interface)
 *  Interface count -- 4 bits
 *  Analog measurement bit len (ABITL) -- 4 bits
 *  Interface type -- 4 bits (each)
 *  Data values -- ABITL (list: buffer length*interface count)
 * 
 *  TODO: Coordinate with the protocol definition -- see protocol.h.
 */
bool allocateMeasBuffer()
{ 
  int headerBitSize = ID_BIT_SIZE + TIME_BIT_SIZE + SINT_BIT_SIZE + LEN_BIT_SIZE + 
                      ICNT_BIT_SIZE + ABITL_BIT_SIZE + INTERFACE_COUNT*ITYPE_BIT_SIZE;
  headerByteSize = headerBitSize/8;
  if ( headerBitSize % 8 != 0 )
    headerByteSize += 1;
   
  recordByteSize = (INTERFACE_COUNT*VAL_BIT_SIZE)/8;

  // Try to allocate the buffer
  measBuffer = (byte_ard*)malloc(headerByteSize+measBufferSize*recordByteSize);
  if ( measBuffer == NULL )
    return false;
  
  // Zero the buffer
  memset(measBuffer,0,headerByteSize+measBufferSize*recordByteSize);
     
  //
  // Construct the buffer header. This can be constant for the duration of the capture,
  // except for the timestamp of course.
  //
  
  // Set the id
  int p=0;
  getPublicIdFromEEPROM(measBuffer+p);
  // Set the time
  p+=ID_BIT_SIZE/8;
  pMsgTime = (u_int32_ard*)(measBuffer+p); // Store a pointer to the time field
  *(measBuffer+p) = currentTime;
  // Set the sampling interval (seconds)
  p+=TIME_BIT_SIZE/8;
  *(measBuffer+p) = (byte_ard)(samplingInterval) & 0xFF;
  // Set the buffer length
  p+=SINT_BIT_SIZE/8;
  *(measBuffer+p) = (byte_ard)measBufferSize & 0xFF;
  // Set the interface count and the analog value bit length -- 
  p+=LEN_BIT_SIZE/8;
  *(measBuffer+p) = INTERFACE_COUNT | ABITL << ICNT_BIT_SIZE;
  p+=(ICNT_BIT_SIZE+ABITL_BIT_SIZE)/8;
  /*  // TODO: add interfaces later
  // Set the interface types
  for( int i=0; i<INTERFACE_COUNT; i+=2 )
  {
    *(measBuffer+p+i) = interface_types[i] & 0x0F;
    if ( INTERFACE_COUNT>i)
      *(measBuffer+p+i) |= interface_types[i+1] <<  ITYPE_BIT_SIZE;
  }
  */

  // Store a pointer for the beginning of the data segment of the buffer
  valBase = measBuffer+headerByteSize;
    
  return true;
}

/**
 *  deallocateMeasBuffer
 *
 *  free the measurement buffer
 */
void deallocateMeasBuffer()
{
  if (measBuffer==NULL)
    return;
  free(measBuffer); 
  measBuffer=NULL;
}

/**
 *  getIdStr
 *
 *  Produces the public id of the device as a string. Outputs to the serial interface.
 *  The ID is part of the device data kept in the EEPROM.  
 *  TODO: This funciton can be safely removed from "production" builds.
 */
void getIdStr()
{
  for( int i=0; i<DEV_ID_MAN_LEN; i++ )
    Serial.print(EEPROM.read(DEV_DATA_START+DEV_ID_START+i),HEX);
  Serial.print("-");
  for( int i=0; i<DEV_ID_DEV_LEN; i++ )
    Serial.print(EEPROM.read(DEV_DATA_START+DEV_ID_START+DEV_ID_MAN_LEN+i),HEX);
}

/**
 *  reportValues
 *
 *  Prints the current buffer to the serial interface.
 *  TODO: Remove or define out for "production" builds.
 */
void reportValues(byte_ard *measBuffer)
{
  Serial.print("Device ID: ");
  getIdStr();
  
  int p=0;
  p+=ID_BIT_SIZE/8;
  Serial.println(*pMsgTime);
    
  p+=TIME_BIT_SIZE/8;
  Serial.print((u_int16_ard)(*(measBuffer+p)));

  p+=SINT_BIT_SIZE/8;
  Serial.println((u_int16_ard)(*(measBuffer+p)));
  
  p+=LEN_BIT_SIZE/8;
  Serial.println((u_int16_ard)(*(measBuffer+p)>>ICNT_BIT_SIZE) & 0x0F);
  Serial.println((u_int16_ard)(*(measBuffer+p)) & 0x0F);

  p+=(ICNT_BIT_SIZE+ABITL_BIT_SIZE)/8;
  for( int i=0; i<INTERFACE_COUNT; i+=2 )
  {
    Serial.print((u_int16_ard)(*(measBuffer+p+i) & 0x0F),HEX);
    Serial.print(" ");
    if ( INTERFACE_COUNT>i)
    {
      Serial.print((u_int16_ard)(*(measBuffer+p+i)>>ITYPE_BIT_SIZE & 0x0F),HEX);
      Serial.print(" ");
    }
  }
  
  byte_ard *valBase = measBuffer+headerByteSize; 
  for( int i=0; i<measBufferCount; i++ )
    Serial.println((u_int16_ard)(*(valBase+i))<<2); // Shift up to convert to 10 bits
}

/**
 *  reportValuesLong
 *
 *  Prints the current buffer to the serial interface. Verbose format, useful for debugging.
 *  TODO: Remove or define out for "production" builds.
 */
void reportValuesLong(byte_ard *measBuffer)
{
  Serial.println("\n----------------------------------------");
  int p=0;
  Serial.print("Device ID: ");
  getIdStr();
  Serial.print("\n");
  
  p+=ID_BIT_SIZE/8;
  Serial.print("Update time: ");
  Serial.println(*pMsgTime);
    
  p+=TIME_BIT_SIZE/8;
  Serial.print("Sampling interval: ");
  Serial.print((u_int16_ard)(*(measBuffer+p)));
  Serial.println("*100 msec");

  p+=SINT_BIT_SIZE/8;
  Serial.print("Measurement buffer size: ");
  Serial.println((u_int16_ard)(*(measBuffer+p)));
  
  p+=LEN_BIT_SIZE/8;
  Serial.print("Analog bit size: ");
  Serial.println((u_int16_ard)(*(measBuffer+p)>>ICNT_BIT_SIZE) & 0x0F);
  Serial.print("Interface count: ");
  Serial.println((u_int16_ard)(*(measBuffer+p)) & 0x0F);

  Serial.print("Interface types: ");  
  p+=(ICNT_BIT_SIZE+ABITL_BIT_SIZE)/8;
  for( int i=0; i<INTERFACE_COUNT; i+=2 )
  {
    Serial.print((u_int16_ard)(*(measBuffer+p+i) & 0x0F),HEX);
    Serial.print(" ");
    if ( INTERFACE_COUNT>i)
    {
      Serial.print((u_int16_ard)(*(measBuffer+p+i)>>ITYPE_BIT_SIZE & 0x0F),HEX);
      Serial.print(" ");
    }
  }
   
  Serial.println("\n----------------------------------------"); 
  byte_ard *valBase = measBuffer+headerByteSize; 
  Serial.println("Values:");
  Serial.println("----------------------------------------");
  for( int i=0; i<measBufferCount; i++ )
    Serial.println((u_int16_ard)(*(valBase+i))<<2); // Shift up to convert to 10 bits
  Serial.println("----------------------------------------");
}

//
// TODO: Add a function to pack and send the update message
//

/**
 *  doEncryptDecryptTest
 *
 *  Do the FIPS encryption test (appendix B) followed by a decryption.
 *  TODO: Remove or define out for "production" builds.
 */
void doEncryptDecryptTest()
{
  byte_ard pFipsStr[] = {0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34}; // FIPS test vector
  byte_ard pFipsKey[] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c}; // FIPS key
    
  Serial.write(pFipsKey,16);
  Serial.write(pFipsStr,16);

  byte_ard pKeys[KEY_BYTES*11];  
  memset(pKeys,0,KEY_BYTES*11);  
  KeyExpansion(pFipsKey,pKeys);

  EncryptBlock((void*)pFipsStr, (u_int32_ard *)pKeys);  
  Serial.write(pFipsStr,16);

  DecryptBlock((void*)pFipsStr, (u_int32_ard *)pKeys);
  Serial.write(pFipsStr,16);
}

/**
 *  copyEEPROM2mem
 *
 *  Utility funciton to copy a number of bytes from the EEPROM memory into a RAM buffer
 */
void copyEEPROM2mem(byte_ard *buf, int start, int len)
{
  for( int i=0; i<len; i++ )
    buf[i]=EEPROM.read(start+i);  
}

/**
 *  getPrivateKeyFromEEPROM
 *
 *  Utility function to copy the private key of the device (master key) into a
 *  RAM buffer
 */
void getPrivateKeyFromEEPROM( byte_ard *key )
{
  copyEEPROM2mem(key,DEV_DATA_START+DEV_KEY_START,DEV_KEY_LEN);
}

/**
 *  getPublicIdFromEEPROM
 *
 *  Utility funtion to copy the public id of the device into a 
 *  RAM buffer.
 */
void getPublicIdFromEEPROM( byte_ard *idbuf )
{
  copyEEPROM2mem(idbuf,DEV_DATA_START+DEV_ID_START,DEV_ID_LEN);
}

/**
 *  printBytes
 *
 *  For debug only. Pretty print an array of bytes
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

/**
 *  printEEPROMBytes
 *
 *  Dump an EEPROM buffer
 */
void printEEPROMBytes(int start, int dLength)
{
  int byteLen=0;
  byte_ard b;
  for(int i=0; i<dLength;i++)
  {
    if( start+1 > EEPROM_SIZE )
      return;
    b = EEPROM.read(start+i);
    if(b<0x10) Serial.print("0");
    Serial.print(b,HEX);
    Serial.print(" ");
    if(++byteLen%16==0)
      Serial.print("\n");
  }
  Serial.print("\n");
}

void setRunState()
{
  bitSet(state,STATE_BIT_RUNNING);
}

void clearRunState()
{
  bitClear(state,STATE_BIT_RUNNING);
}

bool getRunState()
{
  return (bitRead(state,STATE_BIT_RUNNING)==1); 
}

bool getErrorState()
{
  return (bitRead(state,STATE_BIT_ERROR)==1);
}

void setErrorState( byte_ard errorCode )
{
  bitSet(state,STATE_BIT_ERROR);
  state &= 0xF0;
  state |= errorCode << STATE_ERR_CODE_OFFSET; 
}
