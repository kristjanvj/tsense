/**
 *
 *  @file tsensor.pde
 *
 *  @brief TSensor
 *
 *  Trusted sensor implementation for the Arduino platform.
 *  Written for the Arduino ATMega328 board.
 *  This component is part of the Trusted sensors research project (TSense)
 * 
 *  @author Kristjan Valur Jonsson, Kristján Rúnarsson, Benedikt Kristinsson
 *  @date 2010
 *
 *  @todo Check if heap allocation of expanded keys is more efficient than stack allocation on Arduino
 *  @todo Use re-key counter to periodically refresh crypto keys. Code this in conjunction with data transfer protocol. 
 *  @todo Read the key derivation constants from EEPROM rather than allocating in RAM
 */

/*  This file is part of the Trusted Sensors Research Project (TSense).
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
 */

//
// There is a bunch of Serial.print stuff here for debug purposes. Use this very
// carefully since the debug strings seem to eat up all of the available RAM very
// quickly. Use #define to include only debug code for testing and be careful to
// remove for "production" builds.
//
// Two interface commands intentionally leak the secret key (private ID) of the
// device. One fetches the private key bytes, the other dumps the EEPROM. Both are useful
// for diagnostics and debugging while developing but should be removed from "production" devices.
//

//
// Version of sensor software. This is used for compatibility checking with the client software to
// help prevent weird bugs due to out of date sensor software.
// CHANGE THIS AT LEAST WHEN MODIFYING THE PROTOCOL.
//
#define MAJOR_VERSION   0
#define MINOR_VERSION   2
#define REVISION       42

#include <EEPROM.h>
#include <stdlib.h>
#include "aes_cmac.h"
#include "aes_crypt.h"
#include "protocol.h"
#include "tstypes.h"
#include "edevdata.h"       // The EEPROM data layout
#include "memoryFree.h"
#include "tsense_keypair.h"
#include "aes_constants.h"

void* operator new(size_t size) { return malloc(size); }
void operator delete(void* ptr) { free(ptr); }

//
// The debug defines
//
//#define verbose   // Verbose output to the serial interface.
//#define debug     // Debug output to the serial interface.
#define testcounters // Counters used to generate the measurements rather than analog input

// Defines for the digital output pins
#define LED_STATUS          2
#define LED_SIGNAL_1        3
#define LED_SIGNAL_2        4
#define LED_SIGNAL_3        5
#define LED_SIGNAL_4        6
// #define LED_SIGNAL_ERROR    LED_SIGNAL_1 // Not used at this time
#define LED_SIGNAL_SAMPLE   LED_SIGNAL_1
#define LED_SIGNAL_TX       LED_SIGNAL_2
// Defines for the analog input pins
#define AI_LUM          0
#define AI_TEMP         2
#define AI_UNCONNECTED  5  // This pin is used to create randomness -- do not connect!
#define AI_CUT_BITS     2  // The number of LSBs cut off the 10 bit value for more efficient packing

#define INTERFACE_COUNT 2   // The number of sampled interfaces
#define VAL_BYTE_SIZE   1   // The number of bytes allocated per sample. Must be an integer.

//
// T <-> C protocol messages. Common protocol message definitons are included in protocol.h
// See the protocol definition wiki page for details
//
#define MSG_T_ACK                0x4F
//
#define MSG_T_GET_ID_Q           0x40
#define MSG_T_FREE_MEM_Q         0x50
#define MSG_T_FREE_MEM_R         0x51
#define MSG_T_STATE_Q            0x52
#define MSG_T_STATE_R            0x53
#define MSG_T_VERSION_Q          0x54
#define MSG_T_VERSION_R          0x55
#define MSG_T_STARTUP_ID_Q       0x56         
#define MSG_T_CUR_TIME_Q         0x57
#define MSG_T_CUR_TIME_R         0x58
#define MSG_T_PRIVATE_KEY_Q      0x5A  // NOTE: These four message types violate the
#define MSG_T_PRIVATE_KEY_R      0x5B  // basic security premise of the tsensor device
#define MSG_T_EEPROM_DUMP_Q      0x5C  // and should not be included in a 
#define MSG_T_EEPROM_DUMP_R      0x5D  // production device. For development only!
//
#define MSG_T_RUN_TEST_CMD             0x73  // Run a crypto test using the FIPS test vectors
#define MSG_T_SET_TIME_CMD             0x74  // Set the current time
#define MSG_T_SET_SAMLPLE_INTERVAL_CMD 0x75
#define MSG_T_SET_SAMPLE_BUF_SIZE_CMD  0x76
#define MSG_T_DEBUG_PACKET             0x77
//
#define MSG_ACK_NORMAL           0x00
#define MSG_ACK_UNKNOWN_MESSAGE  0x01
#define MSG_ACK_RUN_ERROR        0x10

//
// Error code definitions
//
#define ERR_CODE_OK                      		0x00
#define ERR_CODE_TIMEOUT                                0x01
//
#define ERR_CODE_ID_RESPONSE_ERROR         		0x04
//
#define ERR_CODE_NO_DATA_READ                           0x05
#define ERR_CODE_INSUFFICIENT_DATA_READ                 0x06
//
#define ERR_CODE_IDQUERY_UNEXPECTED                     0x10
//
#define ERR_CODE_KEYTOSENSE_UNEXPECTED			0x20
#define ERR_CODE_KEYTOSENSE_MAC_FAILED			0x21
#define ERR_CODE_KEYTOSENSE_NONCE_FAILED	        0x22
//
#define ERR_CODE_REKEY_REQ_SKEY_ERROR                   0x30
//
#define ERR_CODE_REKEYRESPONSE_UNEXPECTED		0x40
#define ERR_CODE_REKEYRESPONSE_MAC_FAILED		0x41
#define ERR_CODE_REKEYRESPONSE_ID_FAILED		0x42
#define ERR_CODE_REKEYRESPNSE_NONCE_FAILED		0x43
//
#define ERR_CODE_BUF_ALLOCATION            		0xA0
//
#define ERR_CODE_GEN_PROTOCOL_ERROR        		0xFF

//
// The protocol state word definitions
//
#define PROT_STATE_STANDBY         0x00
#define PROT_STATE_ID_DELIVERED    0x01
#define PROT_STATE_SESSION_KEY_SET 0x02
#define PROT_STATE_REKEY_PENDING   0x03
#define PROT_STATE_KEY_READY       0x10
#define PROT_STATE_ERROR           0xFF
#define PROT_STATE_RUNNING         PROT_STATE_KEY_READY

//
// Protocol/policy related defines
//
#define MIN_NONCE_OFFSET  3        // The maximum staleness of nonce received back from authentication server.
#define NONCE_INIT_MAX    10000    // The maximum value of the nonces in the beginning
#define TIMEOUT_INTERVAL  10000    // timeout interval in msec. For intermediary protocol states.
#define NONCE_MAX_VALUE   65536    // The max for a 16 bit nonce
#define DEFAULT_REKEY_INTERVAL 0   // The default re-keying interval. Used if t=0 delivered from sink. 0: no key expiration.


#define SHORT_DELAY 100  // The short delay used when the sensor is not in sampling mode.

//
// Sensor state variables
//
byte_ard protocolState=PROT_STATE_STANDBY;  // The protocol state word
byte_ard errorCode=0;                       // The protocol error code
u_int32_ard currentTime;                    // The current update time
byte_ard samplingInterval = 1;              // The sampling interval in seconds
byte_ard *measBuffer=NULL;                  // The measurement buffer (includes header for easier encrypt/MAC)
byte_ard measBufferSize = 10;               // The size of the measurement buffer -- values stored per interface
byte_ard measBufferCount = 0;               // The current position in the measurement buffer (stored values per interface)
u_int32_ard *pMsgTime=NULL;                 // Pointer to the time field in the measBuffer header
byte_ard headerByteSize=0;                  // The size of the header portion of measBuffer
byte_ard recordByteSize;                    // The size of a single record in measBuffer -- one record is one sample per interface

u_int16_ard idNonce=0;         // Use separate nonces for each message type. The nonces are counters w. wrap around
u_int16_ard rekeyNonce=0;      // and start at some randomly chosen initial value.

u_int32_ard timeout;           // Soft state timeout for the communications protocol

TSenseKeyPair *sessionKeys=NULL;         // The session key delivered from the authentication service
TSenseKeyPair *transportKeys=NULL;       // The crypto key delivered upon re-keying from sink server.
u_int16_ard sessionKeyUseCounter=0;      // Session keys usage counter
u_int16_ard transportKeyUseCounter=0;    // Transport key usage counter
u_int16_ard sessionRekeyInterval=DEFAULT_REKEY_INTERVAL; // The re-keying interval for the session key
u_int16_ard transportRekeyInterval=DEFAULT_REKEY_INTERVAL; // The re-keying interval for the transport key

/**
 *  setup
 *
 *  The Arduino setup function.
 */
void setup(void)
{
  // Initialize sensor state
  protocolState = PROT_STATE_STANDBY;
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
  delay(1000);
}

/**
 *  loop
 *
 *  The Arduino loop function
 */
void loop(void) 
{      
  static byte_ard timeUpdateCounter=0;
  static bool blinkStateFast=false;
  static bool blinkStateSlow=false;
  static byte_ard blinkCounter=0;
  
  // Maintain the blink counter and state
  blinkCounter++;
  blinkCounter%=100; // wrap at 100 ticks
  if (blinkCounter%2==0)
    blinkStateFast=!blinkStateFast;
  if (blinkCounter%10==0)
    blinkStateSlow=!blinkStateSlow; 
   
  // Check on protocol timeouts
  if ( timeout > 0 )
  {
    if( timeout <= millis() ) 
    {
      // millis returns the number of msecs since the program began executing
      // If the timeout set equals the current time then reset
      errorCode=0;
      setProtocolState(PROT_STATE_STANDBY);
      sendAck(ERR_CODE_TIMEOUT);
    }  
  }  
  
  // Handle any waiting commands on the serial line
  getCommand();  

  if ( protocolState == PROT_STATE_RUNNING )
  {
    // Running state
    digitalWrite(LED_STATUS,HIGH);    
    sampleAndReport();  // This function delays for at least a second
    // Update the current time. Note that we rely on the delay command to keep
    // reasonably accurate time. The currentTime and samplingInterval are in seconds.
    currentTime += samplingInterval; 
  }
  else
  {        
    delay(SHORT_DELAY);   // Delay for a while
    switch(protocolState)
    {
      case PROT_STATE_ERROR: 
        digitalWrite(LED_STATUS,LOW);
        break;
      case PROT_STATE_STANDBY:
        digitalWrite(LED_STATUS,blinkStateSlow);
        break;
      default: 
        digitalWrite(LED_STATUS,blinkStateFast);
        break;
    }
    
    // Update the clock (about) every second
    if ( ++timeUpdateCounter >= 1000/SHORT_DELAY )
    {
      currentTime++;
      timeUpdateCounter=0;
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
  // Read the first byte -- the message identifier.
  byte_ard cmdCode = Serial.read();
  if ( cmdCode==0xFF )
    return;   // -1 (0xFF) means no data available.

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
    case MSG_T_KEY_TO_SENSE:       // New (encrypted) session key package received from authentication server                                
      handleKeyToSense();          // via S and C.
      break;
    case MSG_T_REKEY_RESPONSE:
      handleRekeyResponse();
      break;
    case MSG_T_FINISH:
      handleFinish();
      break;
    case MSG_T_ERROR:
      handleGeneralProtocolError();
      break;
    case MSG_T_FREE_MEM_Q:
      sendFreeMemory();
      break;
    case MSG_T_STATE_Q:
      sendCurrentState();
      break;    
    case MSG_T_VERSION_Q:
      handleVersionQuery();
      break;
    case MSG_T_STARTUP_ID_Q:
      handleStartupIdQuery();
      break;
    case MSG_T_CUR_TIME_Q:
      handleCurTimeQuery();
      break;
    case MSG_T_RUN_TEST_CMD:
      doEncryptDecryptTest();     
      break;
    case MSG_T_SET_TIME_CMD:
      handleSetTimeCmd();
      break;
    case MSG_T_SET_SAMLPLE_INTERVAL_CMD:
      handleSetSamplingRateCmd();
      break;
    case MSG_T_SET_SAMPLE_BUF_SIZE_CMD:        
      handleSetSampleBufferSizeCmd();
      break;
    case MSG_T_PRIVATE_KEY_Q:
      handlePrivateKeyQuery();
      break;
    case MSG_T_EEPROM_DUMP_Q:
      handleEepromDumpQuery();
      return;        
    default:
      Serial.flush(); // Crear the crud
      sendAck(MSG_ACK_UNKNOWN_MESSAGE);
      break;
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
  // Only handle if the sensor is in standby mode or id delivered mode. We dont want the sensor
  // state to be messed up by spurious device id queries.
  if ( protocolState != PROT_STATE_STANDBY )
  {
    setWarningState(ERR_CODE_IDQUERY_UNEXPECTED);
    Serial.flush(); // Get rid of crud
    sendAck(errorCode);
    return;  
  }
  
  byte_ard pBuffer[IDMSG_FULLSIZE];
    
  // Get the private key from the EEPROM
  byte_ard masterKeyBuf[KEY_BYTES];
  getPrivateKeyFromEEPROM(masterKeyBuf);  
  // Expand the masterkey (temporarily) to get encryption and authentication schedules.
  // Use the public constant for derivation of authentication key.
  TSenseKeyPair masterKeys(masterKeyBuf,cAlpha);

  // Get the public id from EEPROM
  byte_ard idbuf[DEV_ID_LEN];  
  getPublicIdFromEEPROM(idbuf);
  
  // Increment the nonce
  idNonce++;
  idNonce %= NONCE_MAX_VALUE;
  
  // Create the input struct and populate  
  message msg;
  msg.pID=idbuf;
  msg.nonce=idNonce;   
    
  // Call the pack function to construct the message
  // See protocol.cpp for details. Encrypts and MACs the message and returns in pBuffer.
  pack_idresponse( &msg, (const u_int32_ard *)masterKeys.getCryptoKeySched(),
                   (const u_int32_ard *)masterKeys.getMacKeySched(), (void *)pBuffer);
     
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
  // TODO: CHECK HANDLING
  setWarningState(ERR_CODE_ID_RESPONSE_ERROR); 
  Serial.flush();
  sendAck(errorCode);
}

/** 
 *  handleKeyToSense
 *
 *  Utility function to handle a received key-to-sense message. This message carries the
 *  session key for the device. The session key is used for subsequent re-keying operations.
 */
void handleKeyToSense()
{  
  errorCode = 0x00;
  
  // Only handle if the sensor is in correct protocol stage
  if ( protocolState != PROT_STATE_ID_DELIVERED )
  {
    setWarningState(ERR_CODE_KEYTOSENSE_UNEXPECTED);
    Serial.flush(); // Get rid of crud
    sendAck(errorCode);
    return;  
  }
   
  // Get the private key from the EEPROM
  byte_ard masterKeyBuf[KEY_BYTES];
  getPrivateKeyFromEEPROM(masterKeyBuf);  
  // Expand the masterkey (temporarily) to get encryption and authentication schedules.
  // Use the public constant for derivation of authentication key.
  TSenseKeyPair masterKeys(masterKeyBuf,cAlpha);
    
  // Allocate the raw command buffer and read the expected number of bytes
  byte_ard pCommandBuffer[KEYTOSENS_FULLSIZE];
  memset(pCommandBuffer,0,KEYTOSENS_FULLSIZE);
  pCommandBuffer[0]=MSG_T_KEY_TO_SENSE;
  int readlen = readFromSerial(pCommandBuffer+1,KEYTOSENS_FULLSIZE-1);
  if (readlen==-1)
  {
    sendAck(ERR_CODE_NO_DATA_READ);
    return;    
  }
  if (readlen<KEYTOSENS_FULLSIZE-1)
  {
    sendAck(ERR_CODE_INSUFFICIENT_DATA_READ);
    return; 
  }
   
  // Allocate memory for the unpacked message
  struct message senserecv;
  senserecv.key = (byte_ard*)malloc(KEY_BYTES);
  senserecv.ciphertext = (byte_ard*)malloc(KEYTOSINK_CRYPTSIZE);
  // Unpack
  unpack_keytosens((void*)pCommandBuffer, (const u_int32_ard *)masterKeys.getCryptoKeySched(), &senserecv);

  // Validate the MAC  
  int validMac = verifyAesCMac( (const u_int32_ard *)masterKeys.getMacKeySched(), 
                                senserecv.ciphertext, KEYTOSINK_CRYPTSIZE, senserecv.cmac );
  if ( validMac==0 )                                                              
  {
    setWarningState(ERR_CODE_KEYTOSENSE_MAC_FAILED);
    sendAck(errorCode);
    return;     
  }

  // Validate the nonce
  if ( senserecv.nonce != idNonce ) // TODO: Use some allowable range for nonces
  {
    setWarningState( ERR_CODE_KEYTOSENSE_NONCE_FAILED );
    sendAck(errorCode);
    return;  
  }

  // TODO: Validate the ID -- requires protocol changes
  
  // Store the session key in a keypair object
  if (sessionKeys!=NULL)
    delete sessionKeys;
  sessionKeys = new TSenseKeyPair(senserecv.key,cBeta);  // Use the key derivation constant
  if ( senserecv.renewal_timer=0 )
    sessionRekeyInterval=DEFAULT_REKEY_INTERVAL;
  else
    sessionRekeyInterval=senserecv.renewal_timer;
  sessionKeyUseCounter=0; // Set the session key use counter to zero since we have a fresh key
      
  // Cleanup
  free(senserecv.ciphertext);
  // When you don't need the key anymore
  free(senserecv.key);            
      
  // Update the protocol state and ack to indicate to client that all is OK.
  setProtocolState(PROT_STATE_SESSION_KEY_SET);        
  sendAck(ERR_CODE_OK);

/**  sendDebugPacket("SCKEY",sessionKeys->getCryptoKey(),16);  // TESTING ONLY */
/**  sendDebugPacket("SMKEY",sessionKeys->getMacKey(),16);  // TESTING ONLY  **/

/*  
  byte_ard tempBuf[10];

  tempBuf[0] = lowByte(idNonce);
  tempBuf[1] = highByte(idNonce);
  tempBuf[2] = lowByte(senserecv.nonce);
  tempBuf[3] = highByte(senserecv.nonce);
  sendDebugPacket("NONCES",tempBuf,4);  
*/

  // Send a rekey request to the associated S
  sendRekeyRequest();                                   
}

/**
 *  sendRekeyRequest
 *
 *  Constructs and sends a re-key message to the associated S
 */
void sendRekeyRequest()
{
  if ( sessionKeys == NULL )
  {
    setErrorState(ERR_CODE_REKEY_REQ_SKEY_ERROR);
    Serial.flush(); // Get rid of crud
    sendAck(errorCode);
    return;  
  }
    
  // Increment the nonce
  rekeyNonce++;
  rekeyNonce %= NONCE_MAX_VALUE; // Wrap around
  
  // Get the public devie id from EEPROM
  byte_ard idbuf[DEV_ID_LEN]; 
  getPublicIdFromEEPROM(idbuf);
    
  // Construct the message struct and fill in the needed fields.
  message msg;
  msg.msgtype = MSG_T_REKEY_HANDSHAKE;
  msg.nonce=rekeyNonce;
  msg.pID = idbuf;

  // Pack, encrypt and MAC the message using the session key.
  byte_ard buffer[REKEY_FULLSIZE];
  pack_rekey( &msg, (const u_int32_ard *)sessionKeys->getCryptoKeySched(), 
              (const u_int32_ard *)sessionKeys->getMacKeySched(), buffer );  
  sessionKeyUseCounter++;  // Keep track of how often the key has been used

  /****  
  sendDebugPacket("REKEY-HANDSH",buffer,REKEY_FULLSIZE);
  return;
  ****/
  
  // Write the buffer to serial and free
  Serial.write(buffer,REKEY_FULLSIZE);  

  // Update the protocol state
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
    setWarningState(ERR_CODE_REKEYRESPONSE_UNEXPECTED);
    Serial.flush(); // Get rid of crud
    sendAck(errorCode);
    return;  
  }
   
  // Allocate a receive buffer and read the expected number of bytes from the serial port
  byte_ard pCommandBuffer[NEWKEY_FULLSIZE]; // = (byte_ard *)malloc(NEWKEY_FULLSIZE);  // TODO: CHECK THE BUFFER SIZE
  pCommandBuffer[0]=MSG_T_REKEY_RESPONSE;
  readFromSerial(pCommandBuffer+1,NEWKEY_FULLSIZE);

  // Unpack the raw buffer into a message struct
  message msg; 
  msg.ciphertext = (byte_ard*)malloc(NEWKEY_CRYPTSIZE);
  msg.pID = (byte_ard*)malloc(ID_SIZE);
  
  unpack_newkey(pCommandBuffer,(const u_int32_ard *)sessionKeys->getCryptoKeySched(),&msg);

  byte_ard tempmac[16];
  aesCMac((const u_int32_ard*)sessionKeys->getMacKeySched(), msg.ciphertext, NEWKEY_CRYPTSIZE, tempmac);

  // Check the MAC against the encrypted data
  int validMac = verifyAesCMac( (const u_int32_ard *)sessionKeys->getMacKeySched(), msg.ciphertext, NEWKEY_CRYPTSIZE, msg.cmac );
  if ( validMac==0 )
  {
    setWarningState(ERR_CODE_REKEYRESPONSE_MAC_FAILED);
    sendAck(errorCode);
    /****    
    sendDebugPacket("BUF",pCommandBuffer,NEWKEY_FULLSIZE);
    sendDebugPacket("CIPHER",msg.ciphertext,NEWKEY_CRYPTSIZE);
    sendDebugPacket("SMKEY",sessionKeys->getMacKey(),16);    
    sendDebugPacket("MAC",msg.cmac,16);
    sendDebugPacket("TMAC",tempmac,16);  
    ****/
    return;     
  }

  //
  // Get the data available from the rekey message
  //  
  
  // Get the device id in the message and compare with my own
  byte_ard rID[ID_SIZE];
  memcpy(rID,msg.pID,ID_SIZE);
  byte_ard mID[ID_SIZE];
  getPublicIdFromEEPROM(mID);
  if ( strncmp((const char *)rID,(const char *)mID,ID_SIZE) != 0 )
  {
    setWarningState(ERR_CODE_REKEYRESPONSE_ID_FAILED);
    sendAck(errorCode);
    return;         
  }

  // Compare the nonce with my current one
  if ( msg.nonce != rekeyNonce )
  {
    setWarningState(ERR_CODE_REKEYRESPNSE_NONCE_FAILED);
    sendAck(errorCode);
    return;         
  }

  // Get the random number R delivered by sink and derive transport encryption and authentication keys
  byte_ard pTransportKey[KEY_BYTES];  
  // Allocate temporary buffer for the transport encryption key
  byte_ard* pGammaKeySched[KEY_BYTES*11]; 
  // Expand the derivation key schedule for random -> K_STe
  KeyExpansion(cGamma,pGammaKeySched);      
  // CMAC the random number to get K_STe
  aesCMac((const u_int32_ard *)pGammaKeySched,msg.rand,KEY_BYTES,pTransportKey); 

  // Save the transport key -- cEpsilon is the constant for authentication key derivation    
  if ( transportKeys != NULL )
    delete transportKeys;
  transportKeys = new TSenseKeyPair(pTransportKey,cEpsilon);
  // Reset the rekey counter since we have a fresh key
  transportKeyUseCounter=0; 

  // Set the re-key interval as specified by sink (delivered in t (timer) field in protocol)
  if ( msg.renewal_timer == 0 )
    transportRekeyInterval = DEFAULT_REKEY_INTERVAL;
  else
    transportRekeyInterval = msg.renewal_timer; // Set the re-key interval for the transport key
  
  // Update the protocol state and start the capture
  allocateMeasBuffer();
  setProtocolState(PROT_STATE_KEY_READY);
  sendAck(ERR_CODE_OK);

  // Debug stuff follows -- can be removed later
  /****  
  sendDebugPacket("SCKEY",sessionKeys->getCryptoKey(),16);
  sendDebugPacket("CID",msg.pID,6);  
  sendDebugPacket("RAND",msg.rand,16);
  sendDebugPacket("TEKEY",transportKeys->getCryptoKeySched(),16);
  sendDebugPacket("TMKEY",transportKeys->getMacKeySched(),16);  

  byte_ard temp[20];
  temp[0]=lowByte(rekeyNonce);
  temp[1]=highByte(rekeyNonce);
  temp[2]=lowByte(msg.nonce);
  temp[3]=highByte(msg.nonce);
  sendDebugPacket("NONCES",temp,4);
  ****/
  
  free(msg.ciphertext);  // TODO: CHECK free on abnormal returns
  free(msg.pID);  
}
 
void sendData()
{
  //
  // NOTE: This completely bypasses the pack function in the protocol which caused weird crashes
  // probably due to memory issues. Rewrite when time allows.
  //
  
  u_int16_ard plainsize = ID_SIZE + MSGTIME_SIZE + 1 + measBufferCount;
  u_int16_ard cipher_len = plainsize;
  if ( plainsize%16!=0 )  
    cipher_len = (1+(cipher_len/16))*16;
  u_int16_ard bufsize = MSGTYPE_SIZE + 1 + ID_SIZE + cipher_len + 16;
  byte_ard* transmitBuffer = (byte_ard*)malloc(bufsize);
  memset(transmitBuffer,0,bufsize);

  // Insert the message identifier  
  transmitBuffer[0]=0x01;
  // Insert the cipher buffer length in bytes.
  // Must be a multiple of blocklenght (16 bytes per block)
  transmitBuffer[1]=cipher_len;
  // Insert the public device id -- once for plaintext, once for ciphertext
  getPublicIdFromEEPROM(transmitBuffer+2);
  memcpy(transmitBuffer+8,transmitBuffer+2,6);
  // Insert the curren ttime
  for( int i=0; i<4; i++ )
    transmitBuffer[14+i] = ( currentTime >> (8*i) ) & 0xFF;
  // Insert the data size
  transmitBuffer[18]=measBufferCount;
  // Insert the data
  memcpy(transmitBuffer+19,measBuffer,measBufferCount);

  /***  
  sendDebugPacket("BUF",transmitBuffer,bufsize);
  ***/
    
  // This is a dummy IV -- REPLACE!
  byte_ard IV[] = {
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30 
  };
  
  // Allocate a cipher buffer -- TODO: DO IN PLACE TO SAVE MEM!!
  byte_ard *cipherbuff = (byte_ard*)malloc(cipher_len);
  // Encrypt the data to the temporary cipher buffer
  CBCEncrypt((void*)(transmitBuffer+8), (void*)cipherbuff, plainsize, AUTOPAD,
             (const u_int32_ard*)transportKeys->getCryptoKeySched(), (const u_int16_ard*)IV);  
  // Copy the temporary cipherbuffer into the transmit buffer -- after the plaintext header
  memcpy(transmitBuffer+8,cipherbuff,cipher_len);  
  // Mac the cipherbuffer and insert directly into the last 16 bytes of the transmit buffer
  aesCMac((const u_int32_ard*)transportKeys->getMacKeySched(), cipherbuff, cipher_len, transmitBuffer+8+cipher_len);  
  // Now we can safely get rid of the cipherbuffer
  free(cipherbuff);

  /***  
  sendDebugPacket("BUF",transmitBuffer,bufsize);  
  ***/
  
  // Send on the wire and free the transmit buffer
  Serial.write(transmitBuffer,bufsize); 
  free(transmitBuffer);
  
  // Reset for the next round
  measBufferCount=0;
}
  
/**
 *  handleFinish
 *
 *  Handle a received finish message.
 */
void handleFinish()
{
  // Stop data acquisition, if running, and reset the protocol state to standby.
  deallocateMeasBuffer();
  setProtocolState(PROT_STATE_STANDBY);
  sendAck(MSG_ACK_NORMAL);
  errorCode = 0x00;
  // TODO: Other cleanup?? 
}

/**
 *  handleGeneralProtocolError
 *
 *  Handle a received protocol error message. Set error state on the sensor.
 */
void handleGeneralProtocolError()
{
  setErrorState(ERR_CODE_GEN_PROTOCOL_ERROR);  
  sendAck(errorCode);  
  // TODO: Other cleanup;
}

/**
 *  handleSetTimeCmd
 *
 *  Set the current time as unix time, Expected byte order is lowest to highest.
 *  Replies with an ACK message.
 */
void handleSetTimeCmd()
{
  // Read four bytes off the serial port
  byte_ard t_ll = Serial.read();
  byte_ard t_lh = Serial.read();
  byte_ard t_hl = Serial.read();
  byte_ard t_hh = Serial.read();
  // Calculate the 32-bit time value.
  currentTime = long(t_ll) + (long(t_lh)<<8) + (long(t_hl)<<16) + (long(t_hh)<<24);   
  // Send an ACK back.
  sendAck(MSG_ACK_NORMAL);
}

/**
 *  handleSetSamplingIntervalCmd
 *
 *  Set the sampling interval (in seconds) for the sensor. Expects one byte of data.
 *  Replies with an ACK message.
 */
void handleSetSamplingRateCmd()
{
   samplingInterval = Serial.read(); 
   sendAck(MSG_ACK_NORMAL);
}
  
/**
 *  handleSetSampleBufferSizeCmd
 *
 *  Sets the sampling buffer size -- the number of samples held per interface.
 *  Expects one byte of data. Replies with an ACK message.
 */
void handleSetSampleBufferSizeCmd()
{
  measBufferSize = Serial.read();
  sendAck(MSG_ACK_NORMAL);
  // Reallocate the buffer if already allocated. Otherwise, simply store the new size
  if ( measBuffer != NULL )
  {
     deallocateMeasBuffer();
     allocateMeasBuffer();
  }
} 
  
/**
 *  sendFreeMemory
 *
 *  Handler for the send free memory utility command. Returns (an estimate?) of the
 *  free RAM on the device in bytes, encoded in two bytes. Byte order is low to high.
 *  Message code and two additional bytes written.
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
 *  sendDebugPacket
 *
 *  Send a debug packet to the attached host. The format of the packet is 
 *  message id: 1 byte
 *  text label len: 1 byte
 *  Text label (human readable tag): char[] of size text label len
 *  Data len: 2 bytes (low,high)
 *  data: unsinged char[] of length data len
 */
void sendDebugPacket(char szText[], byte_ard *buf, u_int16_ard len)
{
  Serial.write(MSG_T_DEBUG_PACKET);
  byte_ard tlen = strlen(szText);
  Serial.write(tlen);
  for( int i=0; i<tlen; i++ )
    Serial.write(szText[i]);
  Serial.write(lowByte(len));
  Serial.write(highByte(len));
  for( int i=0; i<len; i++ )
    Serial.write(buf[i]);
}

/**
 *  sendCurrentState
 *
 *  Handler for the get current state utility command. Returns the state bits and
 *  error code of the device. Message code and two additional bytes written.
 */
void sendCurrentState()
{
  Serial.write(MSG_T_STATE_R);
  Serial.write(protocolState);
  Serial.write(errorCode);
  Serial.flush();
}

/**
 *  handleVersionQuery
 *
 *  Return the sensor version major.minor.revision. Message code and three additional bytes
 *  written.
 */
void handleVersionQuery()
{
  Serial.write(MSG_T_VERSION_R);  
  Serial.write((byte_ard)MAJOR_VERSION);
  Serial.write((byte_ard)MINOR_VERSION);
  Serial.write((byte_ard)REVISION);
  Serial.flush();
}

/**
 *  handleStartupIdQuery
 *
 *  This message should only be returned once at the first connection to a sensor. It returns a random-looking
 *  string of bytes. The purpose of this step in the connection process is simply to rule out an accidental 
 *  and non-malicious connection to a USB device other than a sensor. This is the only message that does not return
 *  a message identifier in the first byte.
 */
void handleStartupIdQuery()
{
  byte_ard buf[] = {0xAB, 0x2E, 0x12, 0xF1, 0xC3, 0x13, 0xD9, 0x01, 0x39, 0xBA, 0x2E, 0x51, 0xC3, 0x81, 0xFF, 0x0A};
  Serial.write(buf,16);
  Serial.flush();
}

/**
 *  handleCurTimeQuery
 *
 *  Returns the current sensor time in four bytes, ordered lowest to highest.
 */
void handleCurTimeQuery()
{
  Serial.write(MSG_T_CUR_TIME_R);
  Serial.write(currentTime & 0xFF);
  Serial.write((currentTime>>8) & 0xFF);
  Serial.write((currentTime>>16) & 0xFF);    
  Serial.write((currentTime>>24) & 0xFF);
  Serial.flush();
}

/**
 *  handlePrivateKeyQuery
 *
 *  Return the private key of the device.
 *
 *  NOTE: This function breaks the basic security premise of the tsensor device -- that the private key cannot
 *  be extracted from the device. This function is only indended for debug/development and should never be
 *  implemented on a production device.
 */
void handlePrivateKeyQuery()
{
  Serial.write(MSG_T_PRIVATE_KEY_R);
  byte_ard PK[16];
  getPrivateKeyFromEEPROM(PK);
  for( int i=0; i<16; i++ )
    Serial.write(PK[i]);
}

/**
 *  handlePrivateKeyQuery
 *
 *  Dump the entire EEPROM memory of the device. This is 1K on the Duemilanove with ATmega328.
 *
 *  NOTE: This function breaks the basic security premise of the tsensor device -- that the private key cannot
 *  be extracted from the device. This function is only indended for debug/development and should never be
 *  implemented on a production device.
 */
void handleEepromDumpQuery()
{
  Serial.write(MSG_T_EEPROM_DUMP_R);
  for( int i=0; i<1024; i++ )
    Serial.write(EEPROM.read(i));
}

/**
 *  sendAck
 *
 *  Utility function to construct and send an ACK packet. Message code and one additional 
 *  byte written.
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
  #ifdef testcounters 
  // Use the test counters -- this is only used for testing to get predictable
  // measurement results. Helps to determine if data is garbled in buffer manipulation,
  // transit or on reception.  
  static u_int16_ard counter1 = 0;
  static u_int16_ard counter2 = 10;
  measBuffer[measBufferCount++] = counter1++;
  measBuffer[measBufferCount++] = counter2++;
  counter1 %= 0xFF;  // Make sure the counters are within the AI range
  counter2 %= 0xFF;
  #else
  measBuffer[measBufferCount++] = (analogRead(AI_LUM) >> AI_CUT_BITS) & 0xFF; // Cut off 2 LSBs
  measBuffer[measBufferCount++] = (analogRead(AI_TEMP) >> AI_CUT_BITS) & 0xFF;
  /* Stick other interfaces in here */
  #endif  
      
  digitalWrite(LED_SIGNAL_SAMPLE,HIGH);
  
  // Check if the buffer is full. If so, dump to the serial interface.
  // TODO: Add some handling for the case when the serial port is not connected.
  if ( measBufferCount >= measBufferSize*INTERFACE_COUNT )
  {
    sendData();
    digitalWrite(LED_SIGNAL_TX,HIGH);
  } 

  // Delay for the sampling interval (in msec)  
  // Split in two for nicer LED control.
  delay(samplingInterval*200); 
  digitalWrite(LED_SIGNAL_SAMPLE,LOW);
  digitalWrite(LED_SIGNAL_TX,LOW);  
  delay(samplingInterval*800); 
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
  // Free an already allocated buffer
  if( measBuffer!=NULL )
    deallocateMeasBuffer();
  // Try to allocate the buffer
  recordByteSize = (INTERFACE_COUNT*VAL_BYTE_SIZE);
  measBuffer = (byte_ard*)malloc(measBufferSize*recordByteSize);
  if ( measBuffer == NULL )
    return false;
  
  // Zero the buffer
  memset(measBuffer,0,headerByteSize+measBufferSize*recordByteSize);

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
 *  setWarningState
 *
 *  Soft error. Sets the sensor to standby and cancels ongoing capture.
 */
void setWarningState( byte_ard code )
{
  errorCode = code;  
//  setProtocolState( PROT_STATE_STANDBY );
  setProtocolState( PROT_STATE_ERROR ); // TODO: CHECK HANDLING
}


/**
 *  setErrorState
 *
 *  Hard error -- full stop. Sets the protocol state to error which needs a sensor reset to clear.
 */
void setErrorState( byte_ard code )
{
  errorCode = code;
  setProtocolState( PROT_STATE_ERROR );
}

/**
 *  readFromSerial
 *
 *  Utility function to read an array of bytes from the serial port.
 *  Returns the read bytes in the buffer buf.
 */
int readFromSerial(byte_ard *buf, u_int16_ard length)
{
  if ( Serial.available() < 1 )
    return -1;
  int tries=0;
  int pos=0;
  do
  {
    if ( Serial.available() > 0 )
    {
      buf[pos++] = Serial.read();     
      tries=0;
    }
    else
    {
      if( tries++ > 3 ) // Dont delay forever
        return pos;
      delay(50); // Delay a bit
    }
  }
  while(pos < length);
  return pos;
}

/**
 *  setProtocolState
 *
 *  Sets the sensor protocol state. The authentication protocol proceeds in several stages
 *  as discussed in the protocol description. The state codes help to keep track of the stages.
 *  Soft states are used for intermediary stages. The four signal LEDs on the prototype board
 *  are used to indicate the current stage for easier debugging.
 */
void setProtocolState(byte_ard state)
{
  protocolState = state;

  // Set the timeout
  if ( protocolState == PROT_STATE_STANDBY || 
       protocolState == PROT_STATE_KEY_READY )
    timeout = 0; // No timeout
  else
    timeout = millis() + TIMEOUT_INTERVAL;  // Some timeout for the intermediary states    
            
  // Set all LEDs in default state
  digitalWrite(LED_SIGNAL_1,LOW);
  digitalWrite(LED_SIGNAL_2,LOW);
  digitalWrite(LED_SIGNAL_3,LOW);
  digitalWrite(LED_SIGNAL_4,LOW);
 
  // Set the status leds to reflect the protocol state
  switch( protocolState )
  {
    case PROT_STATE_STANDBY:
      break;  // Clear all LEDs on standby
    case PROT_STATE_ERROR:
      if ( errorCode!=0 )
      {
        digitalWrite(LED_SIGNAL_1,errorCode & 0x01); // Set the error code
        digitalWrite(LED_SIGNAL_2,errorCode & 0x02);
        digitalWrite(LED_SIGNAL_3,errorCode & 0x04);
        digitalWrite(LED_SIGNAL_4,errorCode & 0x08);      
      }
      break;
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

// TODO: DEFINE OUT
/**s
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

// TODO: DEFINE OUT
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

// TODO: DEFINE OUT
/**
 *  printEEPROMBytes
 *
 *  Dump an EEPROM buffer -- similar to the printBytes method.
 *  Can be safely removed from "production" builds. 
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

