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

/*
 *  UNFINISHED:
 *   - Test authentication protocol w. rest of the chain
 *   - Add key derivation for MAC keys
 *   - Code the data transfer protocol message -- crypted data transfer
 *   - Check if heap allocation of expanded keys is more efficient than stack allocation on Arduino
 *   - Use re-key counter to periodically refresh crypto keys
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
//#define testcounters // Counters used to generate the measurements rather than analog input

// Defines for the digital output pins
#define LED_STATUS          2
#define LED_SIGNAL_1        3
#define LED_SIGNAL_2        4
#define LED_SIGNAL_3        5
#define LED_SIGNAL_4        6
#define LED_SIGNAL_ERROR    LED_SIGNAL_1
#define LED_SIGNAL_SAMPLE   LED_SIGNAL_1
#define LED_SIGNAL_TX       LED_SIGNAL_2
// Defines for the analog input pins
#define AI_LUM          0
#define AI_TEMP         2
#define AI_UNCONNECTED  5  // This pin is used to create randomness -- do not connect!
#define AI_CUT_BITS     2  // The number of LSBs cut off the 10 bit value for more efficient packing

//
// T <-> C protocol messages. Common protocol message definitons are included in protocol.h
//
#define MSG_T_ACK                0x4F
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
#define MSG_ACK_RUN_ERROR        0x10

//
// The sensor state word bit definitions
//
#define STATE_BIT_RUNNING 0   // Set to 1 when capture running -- sensor fully initialized
#define STATE_BIT_ERROR   1   // Set to 1 if error occurs
// State but 2 is reserved
#define STATE_BIT_BLINK   3   // Utility bit to blink status led in standby mode
#define STATE_BIT_MASK    0x07
#define STATE_ERR_CODE_OFFSET 4

//
// The protocol state word bit definitions
//
#define PROT_STATE_STANDBY         0x00
#define PROT_STATE_ID_DELIVERED    0x01
#define PROT_STATE_SESSION_KEY_SET 0x02
#define PROT_STATE_REKEY_PENDING   0x03
#define PROT_STATE_KEY_READY       0x10

//
// Error code definitions -- max 4 bits. Kept in the upper 4 bits of the state byte
//
#define ERR_CODE_NONE                      0x00
#define ERR_CODE_BUF_ALLOCATION            0x01
#define ERR_CODE_STALE_MESSAGE             0x02
#define ERR_CODE_MAC_FAILED                0x03
#define ERR_CODE_ID_RESPONSE_ERROR         0x04
#define ERR_CODE_UNEXPECTED_KEY_TO_SENSE   0x05
#define ERR_CODE_UNEXPECTED_REKEY_MESSAGE  0x06

//
// Protocol/policy related defines
//
#define MIN_NONCE_OFFSET  3        // The maximum staleness of nonce received back from authentication server.
#define NONCE_INIT_MAX    10000    // The maximum value of the nonces in the beginning
#define TIMEOUT_INTERVAL  60000    // timeout interval in msec
#define NONCE_MAX_VALUE   65536    // The max for a 16 bit nonce

//
// Sensor state variables
//
byte_ard state=0x00;                        // The state bits -- 0: initialized, 1: error, 4 MSB: error code
byte_ard protocolState=PROT_STATE_STANDBY;  // The protocol state bits
u_int32_ard currentTime;                    // The current update time
byte_ard samplingInterval = 1;              // The sampling interval in seconds
byte_ard *measBuffer=NULL;                  // The measurement buffer (includes header for easier encrypt/MAC)
byte_ard measBufferSize = 10;               // The size of the measurement buffer -- values stored per interface
byte_ard measBufferCount = 0;               // The current position in the measurement buffer (stored values per interface)
byte_ard *valBase=NULL;                     // The start of the values array in measBuffer
u_int32_ard *pMsgTime=NULL;                 // Pointer to the time field in the measBuffer header
byte_ard headerByteSize=0;                  // The size of the header portion of measBuffer
byte_ard recordByteSize;                    // The size of a single record in measBuffer -- one record is one sample per interface

byte_ard *pSessionKey=NULL;    // The session key delivered from the authentication service
byte_ard *pCryptoKey=NULL;     // The crypto key delivered upon re-keying from sink server.
u_int16_ard rekeyCounter=0;    // The re-keying counter
u_int16_ard rekeyInterval=0;   // The re-keying interval -- delivered in message from sink server.

u_int16_ard idNonce=0;         // Use separate nonces for each message type. The nonces are counters w. wrap around
u_int16_ard rekeyNonce=0;      // and start at some randomly chosen initial value.

u_int16_ard timeout; // Soft state timeout for the communications protocol


/**
 *  setup
 *
 *  The Arduino setup function.
 */
void setup(void)
{
  // Initialize sensor state
  state = 0x00;
  // Initialize nonces
  randomSeed(analogRead(AI_UNCONNECTED));  // Unconnected analog pin
  // Initialize the nonces to a random value. An unconnected analog pin is considered a
  // good enough source of initial randomness.
  idNonce = random(NONCE_INIT_MAX);     
  rekeyNonce = random(NONCE_INIT_MAX);
 
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
  // static int blinkcounter=0; // Only for fun!
  
  // Check on protocol timeouts
  if ( timeout > 0 )
  {
    if( timeout <= millis() )
    {
      // millis returns the number of msecs since the program began executing
      setProtocolState(PROT_STATE_STANDBY);
    }  
  }
  
  if( Serial.available() ) 
  {
    // First, check if there is a pending command
    // TODO: THe protocol needs to be coded into the getCommand function
    getCommand();  
  }

  // Set all LEDs in default state
  digitalWrite(LED_SIGNAL_1,LOW);
  digitalWrite(LED_SIGNAL_2,LOW);
  digitalWrite(LED_SIGNAL_3,LOW);
  digitalWrite(LED_SIGNAL_4,LOW);
        
  if ( getRunState() ) // Bit 0 is the running bit
  {
    // Running state
    digitalWrite(LED_STATUS,HIGH);
    
    sampleAndReport();  // This function delays for at least a second
  }
  else
  {        
    delay(100);   // Delay for a while
    if( getErrorState() ) 
    {  
      // Error state. Turn off the status LED
      digitalWrite(LED_STATUS,LOW);
      digitalWrite(LED_SIGNAL_ERROR,HIGH);
    }
    else
    {
      // Standby state -- Blink the status LED
      if( bitRead(state,STATE_BIT_BLINK)==0 )
        digitalWrite(LED_STATUS,HIGH);
      else
        digitalWrite(LED_STATUS,LOW);
      bitWrite(state,STATE_BIT_BLINK,!bitRead(state,STATE_BIT_BLINK)); // Toggle led -- bit 3 is the blink bit
      
      // Set the status leds to reflect the protocol state
      switch( protocolState )
      {
        case PROT_STATE_STANDBY:
          break; // all off
        case PROT_STATE_ID_DELIVERED:
          digitalWrite(LED_SIGNAL_1,HIGH);
          break;
        case PROT_STATE_SESSION_KEY_SET:
          digitalWrite(LED_SIGNAL_2,HIGH);
          break;
        case PROT_STATE_REKEY_PENDING:
          digitalWrite(LED_SIGNAL_3,HIGH);
          break;        
        case PROT_STATE_KEY_READY:
          digitalWrite(LED_SIGNAL_4,HIGH);
          break;        
      }      
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
  // TODO: Patch in the rest of the protocol here
  // TODO: Use pack/unpack functions from the protocol library
   
  // Check if there is waiting data.
  if ( Serial.available() > 0 )
  {    
    // Read the first byte -- the message identifier
    byte_ard cmdCode = Serial.read(); // Read one byte

    // Handle all possible protocol messages that the sensor can receive here based on the 1 byte message ID.
    // Note: Handlers read the bytes expected by the protocol from the serial port.    
    switch( cmdCode )
    {
      case MSG_T_GET_ID_Q:  // ID query received from client C
        handleDeviceIdQuery();
        break;
      case MSG_T_ID_RESPONSE_ERROR:
        handleIdResponseError();
        break;
      case MSG_T_KEY_TO_SENSE:           // New (encrypted) session key package received from authentication server                                
        handleKeyToSense();              // via S and C.
        break;
      case MSG_T_REKEY_RESPONSE:
        handleRekeyResponse();
        break;
      case MSG_T_START_CMD:
        doStart(); // The start and stop commands are only temporary for debug. TODO: REMOVE EVENTUALLY.
        break;
      case MSG_T_STOP_CMD: // The start and stop commands are only temporary for debug. TODO: REMOVE EVENTUALLY.
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
        Serial.flush(); // Crear the crud
        sendAck(MSG_ACK_UNKNOWN_MESSAGE);
        break;
      // TODO: Other possible messages include:
      //  -  update current time
    }
  }
}

/**
 *  handleDeviceIdQuery
 *
 *  Handler for device id query message. The sensor reports its public device ID in plaintext and
 *  additionally encrypts and MACs the ID with a nonce to identify itself to an authentication server.
 *  The private ID (master encryption key) is used for this message.
 */
void handleDeviceIdQuery()
{
  // Only handle if the sensor is in standby mode
  if ( protocolState != PROT_STATE_STANDBY )
  {
    Serial.flush(); // Get rid of crud
    return;  
  }
  
  byte_ard pBuffer[IDMSG_FULLSIZE];
  
  byte_ard key[KEY_BYTES];
  getPrivateKeyFromEEPROM(key);  // Get the private key from the EEPROM
  // Expand crypto key schedule
  byte_ard keys[KEY_BYTES*11];
  KeyExpansion(key,keys);
  // Expand authentication key schedule -- key derivation of MAC key missing at the moment
  byte_ard macKeys[KEY_BYTES*11];
  KeyExpansion(key,macKeys);

  byte_ard idbuf[DEV_ID_LEN];  // Get the id from EEPROM
  getPublicIdFromEEPROM(idbuf);
  
  // Increment the nonce
  idNonce++;
  idNonce %= NONCE_MAX_VALUE; // Wrap around

  // Create the input struct and populate  
  message msg;
  msg.pID=idbuf;
  msg.nonce=idNonce;  
  msg.key=key;
    
  // Call the pack function to construct the message
  // See protocol.cpp for details. Encrypts and MACs the message and returns in pBuffer.
  pack_idresponse(&msg,(const u_int32_ard *)keys,(const u_int32_ard *)macKeys,(void *)pBuffer);
  
  // Write the crypto buffer to the serial port
  Serial.write(pBuffer,IDMSG_FULLSIZE);
  Serial.flush();
  
  setProtocolState(PROT_STATE_ID_DELIVERED);
}

/**
 *  handleIdResponseError
 *
 *  Handle error from the identification procecss
 */
void handleIdResponseError()
{
  // TODO 
  setProtocolState(PROT_STATE_STANDBY);
  setErrorState(ERR_CODE_ID_RESPONSE_ERROR);
  
  Serial.flush();
}

/** 
 *  handleKeyToSense
 *
 *  Utility function to handle a received key-to-sense message. This message carries the
 *  session key for the device. The session key is used for subsequent re-keying operations.
 */
void handleKeyToSense()
{  
  // Only handle if the sensor is in correct protocol stage
  if ( protocolState != PROT_STATE_ID_DELIVERED )
  {
    setProtocolState(PROT_STATE_STANDBY);
    setErrorState(ERR_CODE_UNEXPECTED_KEY_TO_SENSE);
    Serial.flush(); // Get rid of crud
    return;  
  }
  
  byte_ard key[KEY_BYTES];
  getPrivateKeyFromEEPROM(key);  // Get the private key from the EEPROM
  byte_ard keys[KEY_BYTES*11];
  KeyExpansion(key,keys);  
 
  // The struct to hold unpacked results
  message msg;
 
  // The raw command buffer -- unpack into the message struct to process
  byte_ard *pCommandBuffer = (byte_ard *)malloc(KEYTOSENS_FULLSIZE); 
  readFromSerial(pCommandBuffer,KEYTOSENS_FULLSIZE);
  
  // First, check the MAC
  // TODO: SHOULD UNPACK HANDLE MAC VERIFICATION????
  byte_ard cmac_buff[BLOCK_BYTE_SIZE];
  byte_ard authKeys[KEY_BYTES*11];
  KeyExpansion(key,authKeys);     // TODO: NEED THE AUTHENTICATION KEY!!
  aesCMac((const u_int32_ard*)authKeys, msg.ciphertext, KEYTOSINK_CRYPTSIZE, cmac_buff);  // TODO: CHECK LENGHT
  if (strncmp((const char*)msg.cmac, (const char*)cmac_buff, BLOCK_BYTE_SIZE) != 0)
  {
    setErrorState(ERR_CODE_MAC_FAILED);
    setProtocolState(PROT_STATE_STANDBY);
    return;     
  }
    
  unpack_keytosens(pCommandBuffer,(const u_int32_ard *)keys,&msg);
  free(pCommandBuffer);
  
  // Check nonce
  // Check if the nonce is too old. A certain range must be allowed to account for the client 
  // fetching multiple ID packages.
  if ( msg.nonce < (idNonce-MIN_NONCE_OFFSET) || msg.nonce > idNonce )
  {
    setErrorState(ERR_CODE_STALE_MESSAGE);
    return;     
  }
  
  // TODO: CHECK OTHER PARAMS
          
  // Save the session key
  if ( pSessionKey!=NULL )
    free(pSessionKey);
  pSessionKey = (byte_ard*)malloc(KEY_BYTES);
  memcpy(pSessionKey,msg.key,KEY_BYTES);
  // Set the rekey counter and interval. Use default if t=0
  rekeyCounter=0;
  rekeyInterval=msg.timer;
    
  setProtocolState(PROT_STATE_SESSION_KEY_SET);  
    
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
  rekeyNonce %= NONCE_MAX_VALUE; // Wrap around
  
  byte_ard idbuf[DEV_ID_LEN];  // Get the id from EEPROM
  getPublicIdFromEEPROM(idbuf);
    
  message msg;
  msg.nonce=rekeyNonce;
  msg.pID = idbuf;
  
  // TODO: Check stack vs heap allocation of encryption key schedules
  // Expand crypto key schedule
  byte_ard *keys = (byte_ard *)malloc(KEY_BYTES*11);
  KeyExpansion(pSessionKey,keys);
  // Expand authentication key schedule
  byte_ard *macKeys = (byte_ard *)malloc(KEY_BYTES*11);
  KeyExpansion(pSessionKey,macKeys); // TODO: MAC key derivation missing at the moment

  byte_ard *buffer = (byte_ard *)malloc(REKEY_FULLSIZE);
  pack_rekey(&msg, (const u_int32_ard *)keys, (const u_int32_ard *)macKeys, buffer);  
  
  Serial.write(buffer,REKEY_FULLSIZE);
  
  free(buffer);
  free(keys);
  free(macKeys);

  setProtocolState(PROT_STATE_REKEY_PENDING);
}

/**
 *  handleRekeyResponse
 *
 *  Handles a rekey message. This message delivers a fresh crypto key to the sensor. 
 *  The crypto key and a derived authentication key are used for the data transfer.
 */
void handleRekeyResponse()
{
  // Only handle if the sensor is in correct protocol stage
  if ( protocolState != PROT_STATE_REKEY_PENDING )
  {
    setProtocolState(PROT_STATE_STANDBY);
    setErrorState(ERR_CODE_UNEXPECTED_REKEY_MESSAGE);
    Serial.flush(); // Get rid of crud
    return;  
  }

  if ( pSessionKey == NULL )
    return; // TODO: CHECK HANDLING
 
  message msg; // A message struct to hold unpacked message
  
  // Expand keys
  byte_ard *keys = (byte_ard *)malloc(KEY_BYTES*11);
  KeyExpansion(pSessionKey,keys);

  // Allocate a receive buffer and read from the serial port
  byte_ard *pCommandBuffer = (byte_ard *)malloc(REKEY_FULLSIZE);  // TODO: CHECK THE BUFFER SIZE
  readFromSerial(pCommandBuffer,REKEY_FULLSIZE);
  
  // First, check the MAC
  byte_ard cmac_buff[BLOCK_BYTE_SIZE];
  byte_ard authKeys[KEY_BYTES*11];
  KeyExpansion(pSessionKey,authKeys);     // TODO: NEED THE AUTHENTICATION KEY!!
  aesCMac((const u_int32_ard*)authKeys, msg.ciphertext, REKEY_CRYPTSIZE, cmac_buff);  // TODO: CHECK LENGHT
  if (strncmp((const char*)msg.cmac, (const char*)cmac_buff, BLOCK_BYTE_SIZE) != 0)
  {
    setErrorState(ERR_CODE_MAC_FAILED);
    setProtocolState(PROT_STATE_STANDBY);
    return;     
  }
    
  unpack_rekey(pCommandBuffer,(const u_int32_ard *)keys,&msg);
  free(pCommandBuffer);

  // Save the crypto key
  if ( pCryptoKey!=NULL )
    free(pCryptoKey);
  pCryptoKey = (byte_ard*)malloc(KEY_BYTES);
  memcpy(pCryptoKey,msg.key,KEY_BYTES);

  // Reset the rekey counter since we have a fresh key
  rekeyCounter=0; 
  
  setProtocolState(PROT_STATE_KEY_READY);
  doStart(); // Start the capture
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
  // Update the current time. Note that we rely on the delay command to keep
  // reasonably accurate time. The currentTime and samplingInterval are in seconds.
  currentTime+=samplingInterval; 

  #ifdef testcounters 
  // Use the test counters -- this is only used for testing to get predictable
  // measurement results. Helps to determine if data is garbled in buffer manipulation,
  // transit or on reception.  
  static u_int16_ard counter1 = 100;
  static u_int16_ard counter2 = 100;
  *(valBase+measBufferCount++) = (counter1++ >> AI_CUT_BITS) & 0xFF; // Cut off 2 LSBs
  *(valBase+measBufferCount++) = (counter2++ >> AI_CUT_BITS) & 0xFF;
  counter1 %= 1024;  // Make sure the counters are within the AI range
  counter2 %= 1024;
  #else
  *(valBase+measBufferCount++) = (analogRead(AI_LUM) >> AI_CUT_BITS) & 0xFF; // Cut off 2 LSBs
  *(valBase+measBufferCount++) = (analogRead(AI_TEMP) >> AI_CUT_BITS) & 0xFF;
  /* Stick other interfaces in here */
  #endif  
      
  digitalWrite(LED_SIGNAL_SAMPLE,HIGH);
  
  // Check if the buffer is full. If so, dump to the serial interface.
  // TODO: Add some handling for the case when the serial port is not connected.
  if ( measBufferCount >= measBufferSize*INTERFACE_COUNT )
  {
    *pMsgTime = currentTime;  // Update the time part of the buffer header.
    reportValues(measBuffer); 
    measBufferCount=0;
    digitalWrite(LED_SIGNAL_TX,HIGH);
  } 

  delay(samplingInterval*1000); // Delay for the sampling interval (in msec)
  digitalWrite(LED_SIGNAL_SAMPLE,LOW);
  digitalWrite(LED_SIGNAL_TX,LOW);  
}

/**
 *  doStart
 *
 *  Handle a start command received from the host. Takes a character buffer of parameters.
 */
void doStart()
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
  // We expect the sampling rate as a byte, followed by the current time (4 bytes ll to hh)
  // Set the sampling parameters of the board
  samplingInterval = Serial.read();
  byte_ard samples = Serial.read(); // The size of the measurement buffer in bytes per interface
  byte_ard t_ll = Serial.read();
  byte_ard t_lh = Serial.read();
  byte_ard t_hl = Serial.read();
  byte_ard t_hh = Serial.read();
  currentTime = t_ll + t_lh<<8 + t_hl<<16 + t_hh << 24;
  
  // Allocate the measurement buffer -- use the samples specified in the start message.
  if ( !allocateMeasBuffer(samples) )
  {
    setErrorState(ERR_CODE_BUF_ALLOCATION);
    sendAck(MSG_ACK_RUN_ERROR); // Error
    return;
  }
  measBufferCount = 0; // Zero the current buffer size
  
  // set the board in run state and return an ok ack
  setRunState();
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
bool allocateMeasBuffer(byte_ard size)
{ 
  measBufferSize = size;
  
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
/*  
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
*/  
  Serial.write(0xAB);  // Dummy code for update message -- TODO: REPLACE
  Serial.write(measBufferCount);
  byte_ard *valBase = measBuffer+headerByteSize; 
//  for( int i=0; i<measBufferCount; i++ )
//    Serial.write( valBase[i] ); // Report the byte format -- remember to shift up at receiving end!
  Serial.write(valBase,measBufferCount);
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
    Serial.println((u_int16_ard)(*(valBase+i))<<AI_CUT_BITS); // Shift up to convert to 10 bits
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

void readFromSerial(byte_ard *buf, u_int16_ard length)
{
  for(int i=0; i<length; i++)
    buf[i] = Serial.read(); 
}

void setProtocolState(byte_ard state)
{
  protocolState = state;

  if ( protocolState == PROT_STATE_STANDBY || 
       protocolState == PROT_STATE_KEY_READY )
    timeout = 0;
  else
    timeout = millis() + TIMEOUT_INTERVAL;   
}
