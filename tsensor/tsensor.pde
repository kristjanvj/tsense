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

#include "aes_cmac.h"
#include "aes_crypt.h"
#include "devinfo.h"

#define verbose   // Verbose output to the serial interface.
#define debug     // Debug output to the serial interface.
//#define ENABLE_FIPS_197_TEST
//#define ENABLE_RFC_4493_TEST

#define COMMAND_BUFFER_SIZE 64
#define VAL_BUFFER_SIZE 32

// Test counters
u_int16_ard counter1 = 100;
u_int16_ard counter2 = 200;

bool errorState = false;      // Board in error state
int errorCode = 0;            // The error code
bool initialized = false;     // Measurements are not collected until the initialized variable has been set. 
                              // This happens once the authentication protocol has been successfully completed.
u_int32_ard currentTime;      // The current update time
int samplingInterval = 1000;  // The sampling rate.
byte_ard *measBuffer=NULL;    // The measurement buffer (includes header for easier encrypt/MAC)
int measBufferSize = 10;      // The size of the measurement buffer -- values stored per interface
int measBufferCount = 0;      // The current position in the measurement buffer (stored values per interface)
byte_ard *valBase=NULL;       // The start of the values array in measBuffer
u_int32_ard *pMsgTime=NULL;   // Pointer to the time field in the measBuffer header
int headerByteSize=0;         // The size of the header portion of measBuffer
int recordByteSize;           // The size of a single record in measBuffer -- one record is one sample per interface
u_int16_ard heapAddr, stackAddr;

char commandBuffer[COMMAND_BUFFER_SIZE];
char valBuffer[VAL_BUFFER_SIZE];   

byte_ard pKeys[KEY_BYTES*12];
// TODO: Declare keys and test vectors as PROGMEM to save space
byte_ard pFipsStr[] = {0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34}; // FIPS test vector
byte_ard pFipsKey[] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c}; // FIPS key

PROGMEM prog_uchar pDummyKey[] = {0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34}; // A test key


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
 *  printProgmemBytes
 *
 *  Dump a PROGMEM buffer
 */
void printProgmemBytes(prog_uchar *buf, int dLength)
{
  int byteLen=0;
  byte_ard b;
  for(int i=0; i<dLength;i++)
  {
    b = (byte_ard)pgm_read_byte_near(buf+i);
    if(b<0x10) Serial.print("0");
    Serial.print(b,HEX);
    Serial.print(" ");
    if(++byteLen%16==0)
      Serial.print("\n");
  }
  Serial.print("\n");
}

void doEncryptDecryptTest()
{
  Serial.println("\n\n----------------------------------------------------------------------------");
  Serial.println("Execute an encrypt/decrypt test using the FIPS 197 (appendix B) test vectors");
  Serial.println("----------------------------------------------------------------------------\n\n");  

  Serial.println("Expand keys:");    
  memset(pKeys,0,KEY_BYTES*11);  
  KeyExpansion(pFipsKey,pKeys);
  printBytes(pKeys,KEY_BYTES*11);
    
  Serial.println("Plaintext");
  printBytes(pFipsStr,16);  

  EncryptBlock((void*)pFipsStr, (u_int32_ard *)pKeys);  
  Serial.println("Ciphertext");  
  printBytes(pFipsStr,16);

  DecryptBlock((void*)pFipsStr, (u_int32_ard *)pKeys);
  Serial.println("Plaintext (decrypted)");
  printBytes(pFipsStr,16);  
    
  Serial.flush();
}

/**
 *  setup
 *
 *  The Arduino setup function.
 */
void setup(void)
{
  Serial.begin(9600);    
  Serial.flush();
  
  delay(10000);
    
  Serial.println("\n\n------------------------");
  Serial.println("Initializing Tsensor");
  Serial.println("------------------------\n\n");  
  
  doEncryptDecryptTest();
/*  
  memset(pKeys,0,KEY_BYTES*11);  
  KeyExpansion(pFipsKey,pKeys);
  printBytes(pKeys,KEY_BYTES*11);
  
  Serial.println("A key from PROGMEM:");
  printProgmemBytes(pDummyKey,16);  */
  
  initialized = false;
 
  Serial.println("\n\n------------------");
  Serial.println("Starting main loop");
  Serial.println("------------------\n\n");  
  Serial.flush();
  
  delay(1000);
}

/**
 *  loop
 *
 *  The Arduino loop function
 */
void loop(void) 
{     
  return;
  
  getCommand();  // First, check if there is a pending command
   
  if (initialized && !errorState)
  {
    // Run the measurement funciton if initialized and not in error state
    sampleAndReport(); 
  }
  else
  {
    // Delay for a while
    delay(100);  
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
  commandBuffer[endPos]=0;
  
  if(endPos>0)
  {   
    Serial.print("COMMAND: ");
    Serial.println(commandBuffer);

    int p = strchr(commandBuffer,' ')-commandBuffer;
    if ( p > 0 )
    {
      memset(valBuffer,0,32);
      strncpy(valBuffer,commandBuffer+p+1,endPos-p-1);
      commandBuffer[p]=0; 
    }
         
    if(strcmp(commandBuffer,"get_id")==0)
      doReportId();
    else if (strcmp(commandBuffer,"get_device_info")==0)
      doReportInfo();      
    else if (strcmp(commandBuffer,"start")==0)
      doStart(valBuffer);
    else if (strcmp(commandBuffer,"stop")==0)
      doStop();
    else if (strcmp(commandBuffer,"reset")==0)
      doReset();
    else if (strcmp(commandBuffer,"get_last_error")==0)
      doGetLastError();
    else if (strcmp(commandBuffer,"set_time")==0)
      doSetTime(valBuffer);
//    #ifdef ENABLE_FIPS_197_TEST
//    else if (strcmp(commandBuffer,"fips197test")==0)
//      doFips197Test();
//    #endif
//    #ifdef ENABLE RFC_4493_TEST
//    else if (strcmp(commandBuffer,"rfc4493test")==0)
//      doRfc4493test(); 
//    #endif
  }
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
  *(valBase+measBufferCount++) = counter2++ >> 2;
  // Stick other interfaces in here
  
  // Update the current time. Note that we rely on the delay command to keep
  // reasonably accurate time.
  // The currentTime is in seconds, sampling interval in msec.
  currentTime+=samplingInterval/1000; 
    
  // These are just demo counters -- replace with actual measured values
  counter1 %= 1024;  
  counter2 %= 1024;

  // Check if the buffer is full. If so, dump to the serial interface.
  // TODO: Add some handling for the case when the client cannot receive values.
  if ( measBufferCount >= measBufferSize*INTERFACE_COUNT )
  {
    *pMsgTime = currentTime;  // Update the time part of the buffer header.
    reportValuesLong(measBuffer);
    measBufferCount=0;
  } 

  delay(samplingInterval); // Delay for the sampling interval.
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
  idStr(devId);
  Serial.print("\n");  
}

/**
 *  doReportInfo
 *
 *  Handler for host command. Produces the public device info as an ascii string to the serial interface
 *  in response to a host query.
 */
void doReportInfo()
{ 
  Serial.println("\n------------------");  
  Serial.println("TSensor Device Data");  
  Serial.println("-------------------\n");  
  Serial.print("Device id: ");
  idStr(devId);
  Serial.print("\n");
  Serial.print("Manufacturer: ");
  Serial.println(manName);
  Serial.print("Model: ");
  Serial.println(modelName);
  Serial.print("Serial number: ");
  Serial.println(serialNo);
  Serial.print("Manufacture date: ");  
  Serial.println(manDate);
  
  Serial.println("Interfaces:");
  for(int i=0; i<INTERFACE_COUNT; i++)
  {
    Serial.print("Interface ");
    Serial.print(i);
    Serial.print(": Type=0x");
    if (interface_types[i]<0x10)
      Serial.print("0");
    Serial.print(interface_types[i],HEX);
    Serial.print(": NAME=");
    Serial.print(interface_names[i]);
    Serial.print("\n");
  }
}

/**
 *  doStart
 *
 *  Handle a start command received from the host. Takes a character buffer of parameters.
 */
void doStart(char *valBuffer)
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
  Serial.println(" msec");
  Serial.print("Buffer size: ");
  Serial.println(measBufferSize);
  Serial.print("\n");
#endif
  if ( !allocateMeasBuffer() )
  {
    Serial.println("ERROR: Cannot start -- buffer problems!");
    return;
  }
  if (strlen(valBuffer)>0)         // TODO: Handle conversion errors 
    currentTime = atol(valBuffer);  // Currently, the only expected parameter is the current (unix) time
  else
    currentTime = 0;
  measBufferCount = 0; // Zero the current buffer size
  initialized = true;  // OK to start collecting measurements
#ifdef debug  
  // Show the memory usage after buffer allocation
  // Stackptr must always be greater than the heapptr
  u_int16_ard heapAddr, stackAddr;
  getArdMem(heapAddr,stackAddr);
  Serial.println("\nFree memory after buffer allocation: ");
  Serial.print("Stackpointer: 0x");
  Serial.println(stackAddr,HEX);
  Serial.print("Heappointer: 0x");
  Serial.println(heapAddr,HEX);
  Serial.print("Difference: ");
  Serial.print(stackAddr-heapAddr,DEC);
  Serial.print(" bytes\n\n");
#endif
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
  initialized = false; 
#ifdef debug  
  // Show the memory usage after buffer deallocation
  // Stackptr must always be greater than the heapptr
  u_int16_ard heapAddr, stackAddr;
  getArdMem(heapAddr,stackAddr);
  Serial.println("\nFree memory after buffer allocation: ");
  Serial.print("Stackpointer: 0x");
  Serial.println(stackAddr,HEX);
  Serial.print("Heappointer: 0x");
  Serial.println(heapAddr,HEX);
  Serial.print("Difference: ");
  Serial.print(stackAddr-heapAddr,DEC);
  Serial.print(" bytes\n\n");
#endif  
}

/**
 *  doReset
 *  
 *  Handle a command from host. Reset the sensor from error state
 */ 
void doReset()
{
  #ifdef debug
  Serial.println("\n--------------------");
  Serial.println("Resetting the sensor");
  Serial.println("--------------------\n");  
  #endif
  errorState = false;
  errorCode = 0; 
}

/**
 *  doGetLastError
 *
 *  Handle a get last error command from the host.
 *  Returns a numerical error code.
 */
void doGetLastError()
{
  Serial.println("\n------------");
  Serial.println("Error report");
  Serial.println("------------");  
  if ( errorState==false )
  {
    Serial.println("NONE");
  }
  else
  {
    Serial.print("ERROR. CODE:");
    Serial.println(errorCode);
  } 
}

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

  Serial.print("header size: ");
  Serial.println(headerByteSize);
  Serial.print("record size: ");
  Serial.println(recordByteSize);
  
  // Try to allocate the buffer
  measBuffer = (byte_ard*)malloc(headerByteSize+measBufferSize*recordByteSize);
  if ( measBuffer == NULL )
  {
    Serial.println("ERROR: CANNOT ALLOCATE BUFFER");
    // TODO: Use a LED for this 
    errorState=true;
    errorCode=1;
    return false;
  }
  
  // Zero the buffer
  memset(measBuffer,0,headerByteSize+measBufferSize*recordByteSize);
    
  // Set the id
  int p=0;
  memcpy((measBuffer+p),(void*)devId,ID_BIT_SIZE/8);
  // Set the time
  p+=ID_BIT_SIZE/8;
  pMsgTime = (u_int32_ard*)(measBuffer+p); // Store a pointer to the time field
  *(measBuffer+p) = currentTime;
  // Set the sampling interval
  p+=TIME_BIT_SIZE/8;
  *(measBuffer+p) = (byte_ard)(samplingInterval/100) & 0xFF;
  // Set the buffer length
  p+=SINT_BIT_SIZE/8;
  *(measBuffer+p) = (byte_ard)measBufferSize & 0xFF;
  // Set the interface count and the analog value bit length -- 
  p+=LEN_BIT_SIZE/8;
  *(measBuffer+p) = INTERFACE_COUNT | ABITL << ICNT_BIT_SIZE;
  p+=(ICNT_BIT_SIZE+ABITL_BIT_SIZE)/8;
  // Set the interface types
  for( int i=0; i<INTERFACE_COUNT; i+=2 )
  {
    *(measBuffer+p+i) = interface_types[i] & 0x0F;
    if ( INTERFACE_COUNT>i)
      *(measBuffer+p+i) |= interface_types[i+1] <<  ITYPE_BIT_SIZE;
  }

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
 *  idStr
 *
 *  Produces the public id of the device as a string. Outputs to the serial interface.
 */
void idStr(byte_ard *devId)
{
  Serial.print(devId[0],HEX);
  Serial.print(devId[1],HEX);
  Serial.print("-");
  Serial.print(devId[2],HEX);
  Serial.print(devId[3],HEX);
  Serial.print(devId[4],HEX);
  Serial.print(devId[5],HEX);  
}

/**
 *  reportValuesLong
 *
 *  Prints the current buffer to the serial interface. Verbose format, useful for debugging.
 */
void reportValuesLong(byte_ard *measBuffer)
{
  Serial.println("\n----------------------------------------");
  int p=0;
  Serial.print("Device ID: ");
  idStr(measBuffer+p);
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

/**
 *  getArdMem
 *
 *  Gets the position of the heap and stack pointers. Modified from check_mem by 
 *  Julian Gall on the Arduino forum.
 */
void getArdMem(u_int16_ard &heapAddr, u_int16_ard &stackAddr) 
{
  uint8_t *heapptr, *stackptr;
  stackptr = (uint8_t *)malloc(4);  // use stackptr temporarily
  heapptr = stackptr;               // save value of heap pointer
  free(stackptr);                   // free up the memory again (sets stackptr to 0)
  stackptr =  (uint8_t *)(SP);      // save value of stack pointer
  heapAddr = (u_int16_ard)heapptr;
  stackAddr = (u_int16_ard)stackptr;
}


