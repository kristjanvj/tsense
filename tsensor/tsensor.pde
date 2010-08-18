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

#include <EEPROM.h>
#include "aes_cmac.h"
#include "aes_crypt.h"
#include "protocol.h"
#include "tstypes.h"
#include "devinfo.h"  // TODO: REMOVE -- INTEGRATE WITH PROTOCOL INFO AND OTHER HEADERS
#include "edevdata.h" // The EEPROM data layout
#include "memoryFree.h"

//#define verbose   // Verbose output to the serial interface.
//#define debug     // Debug output to the serial interface.

#define COMMAND_BUFFER_SIZE 36
//#define VAL_BUFFER_SIZE 16

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

u_int16_ard idNonce=0;

char commandBuffer[COMMAND_BUFFER_SIZE];
//char valBuffer[VAL_BUFFER_SIZE];   

byte_ard pEncKeys[KEY_BYTES*11];
byte_ard pAuthKeys[KEY_BYTES*11];

// TODO: Declare keys and test vectors as PROGMEM to save space
//byte_ard pFipsStr[] = {0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34}; // FIPS test vector
//byte_ard pFipsKey[] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c}; // FIPS key

byte_ard pEncKey[KEY_BYTES] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
byte_ard pAuthKey[KEY_BYTES] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

#define LED_STATUS 13

//
// Temporary defines for protocol messages -- include in the protocol itself eventually
#define MSG_T_GET_ID_Q           0x40
#define MSG_T_GET_ID_R           0x10
#define MSG_T_FREE_MEM_Q         0x50
#define MSG_T_FREE_MEM_R         0x51
#define MSG_T_STATE_Q            0x52
#define MSG_T_STATE_R            0x53

#define MSG_T_ACK                0x4F

#define MSG_T_START_CMD          0x71 
#define MSG_T_STOP_CMD           0x72
#define MSG_T_RUN_TEST_CMD       0x73

#define MSG_ACK_NORMAL           0x00 
#define MSG_ACK_UNKNOWN_MESSAGE  0x01

/**
 *  setup
 *
 *  The Arduino setup function.
 */
void setup(void)
{
  state = 0x00;
  randomSeed(analogRead(5));  // Unconnected analog pin
  idNonce = random(65536);
 
  pinMode(LED_STATUS,OUTPUT); // Set the pinMode for pin 13 to output
  digitalWrite(LED_STATUS,LOW);
 
  Serial.begin(9600);    
  Serial.flush();
  
  /*
  for(int i=0; i<5; i++)
  {
    digitalWrite(LED_STATUS,HIGH);
    delay(500);
    digitalWrite(LED_STATUS,LOW);
    delay(500);
  } 
  */ 
  
  #ifdef verbose    
  Serial.println("\n\n------------------------");
  Serial.println("Initializing Tsensor");
  Serial.print("Free memory = ");
  Serial.println(freeMemory());
  Serial.println("------------------------\n\n");  
  #endif
//  copyEEPROM2mem(pEncKey,DEV_KEY_START,DEV_KEY_LEN);
//  doEncryptDecryptTest(pEncKey,pFipsStr);
  
//  Serial.println("\n\n------------------");
//  Serial.println("Starting main loop");
//  Serial.println("------------------\n\n");  
//  Serial.flush();
     
//  allocateMeasBuffer();
//  Serial.print("Free memory = ");
//  Serial.println(freeMemory());
//  deallocateMeasBuffer();
  
//  digitalWrite(LED_SIGNAL_PIN,HIGH);
//  Serial.println(freeMemory());
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
    getCommand();  // First, check if there is a pending command
//    Serial.print("State: ");
//    Serial.println(state & 0x07,BIN); 
  }
  
  byte_ard stateLow = state & 0x07; // 3 lowest bits used for status
      
  if (stateLow==0x01) // Bit 0 is the running bit
  {
    // Running state
    digitalWrite(LED_STATUS,HIGH);
    sampleAndReport(); 
  }
  else
  {    
    // Delay for a while
    delay(100);  
    if( stateLow == 0x02 ) // Bit 1 is the error bit
    {  
      // Error state
      digitalWrite(LED_STATUS,LOW);
    }
    else
    {
      // Standby state
      if( bitRead(state,3)==0 )
        digitalWrite(LED_STATUS,HIGH);
      else
        digitalWrite(LED_STATUS,LOW);
      bitWrite(state,3,!bitRead(state,3)); // Toggle led -- bit 3 is the blink bit
    }
  } 
}

/**
 *  getCommand
 *
 *  Check if there is a pending command from the host. The command is a string (up to 32 characters) 
 *  and optional 32 character parameter string. The command and parameter strings are separated by
 *  a space character.
 */
void getCommand() 
{   
  int endPos=0;
  while ( Serial.available() > 0 && endPos<COMMAND_BUFFER_SIZE )
  {
    commandBuffer[endPos++] = Serial.read();
  }
  
  // TODO: Patch in the rest of the protocol here
  // TODO: Use pack/unpack functions from the protocol library
   
  if(endPos>0)
  {    
    byte_ard cmdCode = commandBuffer[0];
    u_int32_ard param = 0;
/*    Serial.write(cmdCode);
    Serial.write("\n");
    Serial.flush();
    return; */
      
    switch(cmdCode)
    {
      case MSG_T_GET_ID_Q:
        sendDeviceId();
        break;
      case MSG_T_START_CMD:
        doStart(param);
        break;
      case MSG_T_STOP_CMD: 
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
    }
  }
}

void sendDeviceId()
{
  byte_ard pBuffer[41 /*IDMSG_FULLSIZE*/]; // TODO: CONST TOO SMALL!
  
  byte_ard key[KEY_BYTES];
  copyEEPROM2mem(key,DEV_DATA_START+DEV_KEY_START,DEV_KEY_LEN);
  byte_ard keys[KEY_BYTES*11];
  KeyExpansion(key,keys);

  byte_ard idbuf[DEV_ID_LEN];  // Get the id from EEPROM
  copyEEPROM2mem(idbuf,DEV_DATA_START+DEV_ID_START,DEV_ID_LEN);
  
  idNonce++;
  idNonce %= 65536; // Wrap around
  
  message msg;
  msg.msgtype=0x10;  // TODO: USE CONST!
  msg.pID=idbuf;
  msg.nonce=idNonce;  
  msg.key=key;
    
  pack_idresponse(&msg,(const u_int32_ard*)keys,(void *)pBuffer);
  
  Serial.write(pBuffer,41);
  Serial.flush();
}

void sendFreeMemory()
{
  u_int16_ard freemem = freeMemory();  
  Serial.write(MSG_T_FREE_MEM_R);
  Serial.write(lowByte(freemem));
  Serial.write(highByte(freemem));  
  Serial.flush();
}

void sendCurrentState()
{
  Serial.write(MSG_T_STATE_R);
  Serial.write((state & 0x07));
  Serial.write(((state >> 4) & 0x0F));
  Serial.flush();
}

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
  *(valBase+measBufferCount++) = counter1++ >> 2; // Cut off 2 LSBs
  *(valBase+measBufferCount++) = counter2++ >> 2; // TODO: Use a constant for this 
  // Stick other interfaces in here
  
  // Update the current time. Note that we rely on the delay command to keep
  // reasonably accurate time.
  // The currentTime is in seconds
  currentTime+=samplingInterval; 
    
  // These are just demo counters -- replace with actual measured values
  counter1 %= 1024;  
  counter2 %= 1024;

  // Check if the buffer is full. If so, dump to the serial interface.
  // TODO: Add some handling for the case when the client cannot receive values.
  if ( measBufferCount >= measBufferSize*INTERFACE_COUNT )
  {
    *pMsgTime = currentTime;  // Update the time part of the buffer header.
    //reportValues(measBuffer);  // TODO: DISABLED FOR INTEGRATION
    measBufferCount=0;
//    Serial.println(freeMemory());
  } 

  delay(samplingInterval*1000); // Delay for the sampling interval (in msec)
}

/**
 *  doReportId
 *
 *  Handler for host command. Produces the public device id as an ascii string in response to a query.
 */
void doReportId()
{
#ifdef debug
  Serial.println("\n------------------");
  Serial.println("TSensor Device ID:");
  Serial.println("------------------");  
#endif
  getIdStr();
  Serial.print("\n");  
}

/**
 *  doReportInfo
 *
 *  Handler for host command. Produces the public device info as an ascii string to the serial interface
 *  in response to a host query.
 */
 /*
void doReportInfo()
{ 
  // TODO: Fill in text device data and interface types. This info is per-device and should be read from EEPROM
  Serial.println("\n------------------");  
  Serial.println("TSensor Device Data");  
  Serial.println("-------------------\n");  
  Serial.print("Device id: ");
  getIdStr();
  Serial.print("\n");
  Serial.print("Manufacturer: ");
  Serial.println("TSG");
  Serial.print("Model: ");
  Serial.println("ALPHA");
  Serial.print("Serial number: ");
  Serial.println("SERIAL");
  Serial.print("Manufacture date: ");  
  Serial.println("DATE");
  
//  Serial.println("Interfaces:");
//  for(int i=0; i<INTERFACE_COUNT; i++)
//  {
//    Serial.print("Interface ");
//    Serial.print(i);
//    Serial.print(": Type=0x");
//    if (interface_types[i]<0x10)
//      Serial.print("0");
//    Serial.print(interface_types[i],HEX);
//    Serial.print(": NAME=");
//    Serial.print(interface_names[i]);
//    Serial.print("\n");
//  }
}
*/

/**
 *  doStart
 *
 *  Handle a start command received from the host. Takes a character buffer of parameters.
 */
void doStart(u_int32_ard time /*char *valBuffer*/)
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
//    Serial.println("ERROR: Cannot start -- buffer problems!");
    bitSet(state,1);
    state |= 0x01<<4; // TODO: USE LED
    return;
  }
  currentTime = time;
  /*
  if (strlen(valBuffer)>0)         // TODO: Handle conversion errors 
    currentTime = atol(valBuffer);  // Currently, the only expected parameter is the current (unix) time
  else
    currentTime = 0; */
  measBufferCount = 0; // Zero the current buffer size
  //initialized = true;  // OK to start collecting measurements
  bitSet(state,0);
  sendAck(MSG_ACK_NORMAL);
//  Serial.println(freeMemory());
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
//  initialized = false; 
  bitClear(state,0);
  // Serial.println(freeMemory());  
  sendAck(MSG_ACK_NORMAL);  
}

/**
 *  doGetLastError
 *
 *  Handle a get last error command from the host.
 *  Returns a numerical error code.
 */
 /*
void doGetLastError()
{
  Serial.println("\n------------");
  Serial.println("Error report");
  Serial.println("------------");  
  if ( bitRead(state,1)==0 )
  {
    Serial.println("NONE");
  }
  else
  {
    Serial.print("ERROR. CODE:");
    Serial.println(state>>4,HEX);
  } 
}
*/

/**
 *  doSetTime
 *
 *  Handle a set time command from the host. Simply set the current time to the newly provided (unix) time.
 */
void doSetTime(char *val)
{
  #ifdef debug
  Serial.println("\n--------------------");
  Serial.println("Setting current time");
  Serial.println("--------------------");
  Serial.print("New time: ");
  Serial.println(val);
  Serial.print("\n");
  #endif
  currentTime = atol(val); // TODO: Handle conversion errors
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
 */
bool allocateMeasBuffer()
{ 
  int headerBitSize = ID_BIT_SIZE + TIME_BIT_SIZE + SINT_BIT_SIZE + LEN_BIT_SIZE + 
                      ICNT_BIT_SIZE + ABITL_BIT_SIZE + INTERFACE_COUNT*ITYPE_BIT_SIZE;
  headerByteSize = headerBitSize/8;
  if ( headerBitSize % 8 != 0 )
    headerByteSize += 1;
   
  recordByteSize = (INTERFACE_COUNT*VAL_BIT_SIZE)/8;

/*
  Serial.print("header size: ");
  Serial.println(headerByteSize);
  Serial.print("record size: ");
  Serial.println(recordByteSize);
*/

  // Try to allocate the buffer
  measBuffer = (byte_ard*)malloc(headerByteSize+measBufferSize*recordByteSize);
  if ( measBuffer == NULL )
  {
  //    Serial.println("ERROR: CANNOT ALLOCATE BUFFER");
    // TODO: Use a LED for this 
    //errorState=true;
    return false;
  }
  
  // Zero the buffer
  memset(measBuffer,0,headerByteSize+measBufferSize*recordByteSize);
     
  // Set the id
  int p=0;
//  copyEEPROM2mem(measBuffer+p,DEV_ID_START,DEV_ID_LEN);
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
 *  The ID is part of the device data kept in the EEPROM
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
 */
void reportValues(byte_ard *measBuffer)
{
/*
  Serial.print("Device ID: ");
  getIdStr();
  
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
*/   
  byte_ard *valBase = measBuffer+headerByteSize; 
  for( int i=0; i<measBufferCount; i++ )
    Serial.println((u_int16_ard)(*(valBase+i))<<2); // Shift up to convert to 10 bits
}

/**
 *  reportValuesLong
 *
 *  Prints the current buffer to the serial interface. Verbose format, useful for debugging.
 */
/* 
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
*/

/**
 *  doEncryptDecryptTest
 *
 *  Do the FIPS encryption test (appendix B) followed by a decryption.
 */
void doEncryptDecryptTest()
{
  byte_ard pFipsStr[] = {0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34}; // FIPS test vector
  byte_ard pFipsKey[] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c}; // FIPS key
    
  Serial.write(pFipsKey,16);
  Serial.write(pFipsStr,16);
  
  memset(pEncKeys,0,KEY_BYTES*11);  
  KeyExpansion(pFipsKey,pEncKeys);

  EncryptBlock((void*)pFipsStr, (u_int32_ard *)pEncKeys);  
  Serial.write(pFipsStr,16);

  DecryptBlock((void*)pFipsStr, (u_int32_ard *)pEncKeys);
  Serial.write(pFipsStr,16);
}

void copyEEPROM2mem(byte_ard *buf, int start, int len)
{
  for( int i=0; i<len; i++ )
    buf[i]=EEPROM.read(start+i);  
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
