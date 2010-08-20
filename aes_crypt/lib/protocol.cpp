/**
   Benedikt Kristinsson, 2010

   (GPL here)

   Tsense Protocol methods. Written in C++ to ensure comptability with Arduino
   Wiring, but made to be compilable with gcc and g++.

 */

#include "protocol.h"

/*
  TODO: Don't use a hardcoded IV
 */
byte_ard IV[] = {
  0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30 
};

/*
  Authentication
 */
void pack_idresponse(struct message* msg, const u_int32_ard* pKeys, void *pBuffer)
{
  byte_ard crypt_buff[IDMSG_CRYPTSIZE];
  byte_ard cmac_buff[IDMSG_CRYPTSIZE];
  byte_ard temp[ID_SIZE + NONCE_SIZE];
  byte_ard* pNonce = (byte_ard*)&msg->nonce;
  
  for (u_int32_ard i = 0; i < ID_SIZE; i++)
  {
    temp[i] = msg->pID[i];
  }
  for(u_int32_ard i = 0; i < NONCE_SIZE; i++)
  {
    temp[ID_SIZE + i] = pNonce[i];
  }

  // Encrypt-then-MAC (Bellare and Namprempre)
  CBCEncrypt((void*)temp, (void*) crypt_buff, (ID_SIZE+NONCE_SIZE),
             AUTOPAD, pKeys, (const u_int16_ard*)IV);

  // CMac the crypted ID and Nonce. 
  aesCMac(pKeys, crypt_buff, IDMSG_CRYPTSIZE, cmac_buff);

  byte_ard* cBuffer = (byte_ard*)pBuffer;
  
  // First byte is the msg type. If longer than one byte, add loop.
  //cBuffer[0] = msg->msgtype;
  cBuffer[0] = MSG_T_GET_ID_R;
  msg->msgtype = MSG_T_GET_ID_R;

  // This will strip off the null char wich isn't crypted.
  for (u_int16_ard i = 0; i < ID_SIZE; i++)
  {
    cBuffer[i + MSGTYPE_SIZE] = msg->pID[i];
  }
  // Add the ciphertext behind the msgtype and plaintext id
  for (u_int32_ard i = 0; i <  IDMSG_CRYPTSIZE; i++)
  {
    cBuffer[MSGTYPE_SIZE + ID_SIZE + i] = crypt_buff[i];
  }

  // Add the CMac behind the msgtype, plaintext id and E(Public ID, Nonce)
  for (u_int32_ard j = 0; j < IDMSG_CRYPTSIZE; j++)
  {
    cBuffer[MSGTYPE_SIZE + ID_SIZE + IDMSG_CRYPTSIZE + j] = cmac_buff[j];
  }
}
void unpack_idresponse(void* pStream, const u_int32_ard* pKeys,
                       struct message* msg)
{
  byte_ard* cStream = (byte_ard*)pStream;
  
  // First MSGTYPE_SIZE (1) bytes is msgcode. Assumes one byte, no loop.
  msg->msgtype = cStream[0];

  byte_ard plain_buff[IDMSG_CRYPTSIZE];

  // Get the ciphertext. 
  for(u_int16_ard i = 0; i < IDMSG_CRYPTSIZE; i++)
  {
    msg->ciphertext[i] = cStream[MSGTYPE_SIZE + ID_SIZE + i];
  }

  // Decipher
  CBCDecrypt((void*)msg->ciphertext, (void*)plain_buff, IDMSG_CRYPTSIZE, pKeys,
             (const u_int16_ard*)IV);

  // Get the ciphered public id (now deciphered) into the stuct and append \0
  for(u_int16_ard i = 0; i < ID_SIZE; i++)
  {
    msg->pID[i] = plain_buff[i];
  }
  msg->pID[ID_SIZE] = '\0';

  // Get the nonce into the struct, cast to int again. 
  byte_ard* temp = (byte_ard*)malloc(NONCE_SIZE);
  for (u_int16_ard i = 0; i < NONCE_SIZE; i++)
  {
    temp[i] = plain_buff[ID_SIZE+i];
  }
  msg->nonce = (u_int16_ard)*temp;
  free(temp);

  // Get the cmac into the struct.
  for (u_int16_ard i = 0; i < BLOCK_BYTE_SIZE; i++)
  {
    //msg->cmac[i] = plain_buff[ID_SIZE+NONCE_SIZE+i];
    msg->cmac[i] = cStream[MSGTYPE_SIZE + ID_SIZE + IDMSG_CRYPTSIZE + i];
  }
}

/*
  Key exchange
 */

void pack_keytosink(struct message* msg, const u_int32_ard* pKeys, void *pBuffer)
{
  byte_ard* cBuffer = (byte_ard*)pBuffer;
  msg->msgtype = MSG_T_KEY_TO_SINK;
  cBuffer[0] = MSG_T_KEY_TO_SINK;

  // Place the key in the "plaintext" to the sink. (SSLed)
  for (u_int16_ard i = 0; i < KEY_BYTES; i++)
  {
    cBuffer[MSGTYPE_SIZE+i] = msg->key[i];
  }

  // t_ST, expiration time. u_int32
  byte_ard* pTimer = (byte_ard*)&msg->timer;
  for (u_int16_ard i = 0; i < TIMER_SIZE; i++)
  {
    cBuffer[MSGTYPE_SIZE+KEY_BYTES+i] = pTimer[i];
  }

  // Create the buffer that is to be ciphered
  byte_ard temp[NONCE_SIZE+KEY_BYTES+TIMER_SIZE];
  byte_ard cipher_buff[KEYTOSINK_CRYPTSIZE];

  byte_ard* pNonce = (byte_ard*)&msg->nonce;
  // N_T
  for (u_int16_ard i = 0; i < NONCE_SIZE; i++)
  {
    temp[i] = pNonce[i];
  }
  
  // Key
  for (u_int16_ard i = 0; i < KEY_BYTES; i++)
  {
    temp[NONCE_SIZE+i] = msg->key[i];
  }
  //Timer (pointer declartion above)
  for (u_int16_ard i = 0; i < TIMER_SIZE; i++)
  {
    temp[NONCE_SIZE+KEY_BYTES+i] = pTimer[i];
  }

  // Cipher
  CBCEncrypt((void*)temp, (void*)cipher_buff, (NONCE_SIZE + KEY_BYTES + TIMER_SIZE),
             KEYTOSINK_PADLEN, pKeys, (const u_int16_ard*)IV);
  aesCMac(pKeys, cipher_buff, KEYTOSINK_CRYPTSIZE, msg->cmac);

  // Put the cipherstuff into the buffer
  for (u_int16_ard i = 0; i < KEYTOSINK_CRYPTSIZE; i++)
  {
    cBuffer[MSGTYPE_SIZE + KEY_BYTES + TIMER_SIZE + i] = cipher_buff[i];
  }

  // Hash
  for (u_int16_ard i = 0; i < BLOCK_BYTE_SIZE; i++)
  {
    cBuffer[MSGTYPE_SIZE+KEY_BYTES+TIMER_SIZE+KEYTOSINK_CRYPTSIZE+i] = msg->cmac[i];
  }
}

void unpack_keytosink(void *pStream, struct message* msg)
{
  byte_ard* cStream = (byte_ard*)pStream;
  // Assumes one byte for msgtype
  msg->msgtype = cStream[0];

  // Key
  for (u_int16_ard i = 0; i < KEY_BYTES; i++)
  {
    msg->key[i] = cStream[MSGTYPE_SIZE+i];
  }

  // Timer
  byte_ard* temp = (byte_ard*)malloc(TIMER_SIZE);
  for (u_int16_ard i = 0; i < TIMER_SIZE; i++)
  {
    temp[i] = cStream[MSGTYPE_SIZE + KEY_BYTES + i];
  }
  msg->timer = (u_int32_ard)*temp;
  free(temp);

  // Since this method unpacks the stream on the Sink, it cannot decipher
  // the ciphertext. (Thus, it is missing the pKey pointer) The Ciphertext
  // will be stored in the struct and will be forwarded to the client and
  // sensor. The Hash is also useless for the sink and is forwarded.

  for(u_int16_ard i = 0; i < KEYTOSINK_CRYPTSIZE; i++)
  {
    msg->ciphertext[i] = cStream[MSGTYPE_SIZE + KEY_BYTES + TIMER_SIZE + i];
  }
  for(u_int16_ard i = 0; i < BLOCK_BYTE_SIZE; i++)
  {
    msg->cmac[i] = cStream[MSGTYPE_SIZE + KEY_BYTES + TIMER_SIZE + KEYTOSINK_CRYPTSIZE + i];
  }
  
}

void pack_keytosens(struct message* msg, void *pBuffer)
{
  byte_ard* cBuffer = (byte_ard*)pBuffer;
  cBuffer[0] = MSG_T_KEY_TO_SENSE;
  msg->msgtype = MSG_T_KEY_TO_SENSE;

  // The ciphertext containing the Nonce, key and Timer. 
  for (u_int16_ard i = 0; i < KEYTOSINK_CRYPTSIZE; i++)
  {
    cBuffer[MSGTYPE_SIZE + i] = msg->ciphertext[i];
  }
  // The hash
  for (u_int16_ard i = 0; i < BLOCK_BYTE_SIZE; i++)
  {
    cBuffer[MSGTYPE_SIZE + KEYTOSINK_CRYPTSIZE + i] = msg->cmac[i];
  }
}

void unpack_keytosens(void *pStream, const u_int32_ard* pKeys, struct message* msg)
{
  byte_ard* cStream = (byte_ard*)pStream;
  msg->msgtype = cStream[0];

  // Extract the ciphertext
  for (u_int16_ard i = 0; i < KEYTOSINK_CRYPTSIZE; i++)
  {
    msg->ciphertext[i] = cStream[MSGTYPE_SIZE + i];
  }
  //Extract the hash
  for(u_int16_ard i = 0; i < BLOCK_BYTE_SIZE; i++)
  {
    msg->cmac[i] = cStream[MSGTYPE_SIZE + (KEYTOSINK_CRYPTSIZE) + i];
  }
  byte_ard plainbuff[KEYTOSINK_CRYPTSIZE];
    
  CBCDecrypt((void*)msg->ciphertext, plainbuff, KEYTOSINK_CRYPTSIZE,
             pKeys, (const u_int16_ard*)IV);

  // 1 - nonce
  byte_ard noncetemp[NONCE_SIZE];
  for (u_int16_ard i = 0; i < NONCE_SIZE; i++)
  {
    noncetemp[i] = plainbuff[i];
  }
  msg->nonce = (u_int16_ard)*noncetemp;

  // 2 - key
  for (u_int16_ard i = 0; i < KEY_BYTES; i++)
  {
    msg->key[i] = plainbuff[NONCE_SIZE + i];
  }
  
  // 3 - timer
  byte_ard timertemp[TIMER_SIZE];
  for (u_int16_ard i = 0; i < TIMER_SIZE; i++)
  {
    timertemp[i] = plainbuff[NONCE_SIZE + KEY_BYTES + i];
  }
  msg->timer = (u_int32_ard)*timertemp;
}

/*
  Re-keying
 */
void pack_rekey(struct message* msg, const u_int32_ard* pKeys, void* pBuffer)
{
  byte_ard* cBuffer = (byte_ard*) pBuffer;
  // MSGTYPE
  if (msg->msgtype == MSG_T_REKEY_HANDSHAKE)
  {
    cBuffer[0] = msg->msgtype;
  }
  else
  {
    msg->msgtype = MSG_T_REKEY_REQUEST;
  }
  
  // T (Public ID)
  for (u_int16_ard i = 0; i < ID_SIZE; i ++)
  {
    cBuffer[MSGTYPE_SIZE + i] = msg->pID[i];
  }

  // Create the ciphered packet
  // ID
  byte_ard temp[ID_SIZE + NONCE_SIZE];
  for (u_int16_ard i = 0; i < ID_SIZE; i++)
  {
    temp[i] = msg->pID[i];
  }
  // Nonce
  byte_ard* pNonce = (byte_ard*)&msg->nonce;
  for(u_int16_ard i = 0; i < NONCE_SIZE; i++)
  {
    temp[ID_SIZE + i] = pNonce[i];
  }
  byte_ard cipher_buff[REKEY_CRYPTSIZE];

  // Cipher
  CBCEncrypt((void*)temp, (void*)cipher_buff, (ID_SIZE + NONCE_SIZE), AUTOPAD,
             pKeys, (const u_int16_ard*)IV);

  // Stick it in the buffer
  for (u_int16_ard i = 0; i < REKEY_CRYPTSIZE; i++)
  {
    cBuffer[MSGTYPE_SIZE + ID_SIZE + i] = cipher_buff[i];
  }

  // CMac
  aesCMac(pKeys, cipher_buff, REKEY_CRYPTSIZE, msg->cmac);
  // Stick it in the buffer
  for (u_int16_ard i = 0; i < BLOCK_BYTE_SIZE; i++)
  {
    cBuffer[MSGTYPE_SIZE + ID_SIZE + REKEY_CRYPTSIZE + i] = msg->cmac[i];
  }
  
}
void unpack_rekey(void* pStream, const u_int32_ard* pKeys, struct message* msg)
{
  byte_ard* cStream = (byte_ard*)pStream;
  msg->msgtype = cStream[0];

  // The ID is only extacted from the ciphertext

  // Extract the ciphertext
  for (u_int16_ard i = 0; i < REKEY_CRYPTSIZE; i ++)
  {
    msg->ciphertext[i] = cStream[MSGTYPE_SIZE + ID_SIZE + i];
  }
  // Extract the cmac
  for (u_int16_ard i = 0; i < BLOCK_BYTE_SIZE; i++)
  {
    msg->cmac[i] = cStream[MSGTYPE_SIZE + ID_SIZE + REKEY_CRYPTSIZE + i];
  }

  // Decipher
  byte_ard plainbuff[REKEY_CRYPTSIZE];
  CBCDecrypt((void*)msg->ciphertext, plainbuff, REKEY_CRYPTSIZE,
             pKeys, (const u_int16_ard*)IV);

  // Extract the ID for the ciphertext
  for (u_int16_ard i = 0; i < ID_SIZE; i ++)
  {
    msg->pID[i] = plainbuff[i];
  }
  msg->pID[ID_SIZE] = '\0';

  // Extract the Nonce from the ciphertext
  byte_ard* temp_nonce = (byte_ard*)malloc(NONCE_SIZE);
  for (u_int16_ard i = 0; i < ID_SIZE; i++)
  {
    temp_nonce[i] = plainbuff[ID_SIZE + i];
  }
  msg->nonce = (u_int16_ard)*temp_nonce;
  free(temp_nonce);
}
void pack_newkey(struct messsage* msg, const u_int32_ard* pKeys, void* pBuffer)
{
  /*
  byte_ard* cBuffer = (byte_ard*)pBuffer;
  cBuffer[0] = 0x31;
  msg->msgtype = 0x31;

  for(u_int16_ard i = 0; i < ID_SIZE; i++)
  {
    cBuffer[MSGTYPE_SIZE + i] = msg->pID[i];
  }

  // Construct the ciphertext
  byte_ard temp[ID_SIZE + NONCE_SIZE + RAND_SIZE + TIMER_SIZE];
  for (u_int16_ard i = 0; i < ID_SIZE; i++)
  {
    temp[i] = msg->pID[i];
  }
  byte_ard* temp_nonce = (byte_ard*)&msg->nonce;
  for (u_int16_ard i = 0; i < NONCE_SIZE: i++)
  {
    temp[ID_SIZE + i] = temp_nonce[i];
  }
  byte_ard* temp_rand = (byte_ard*)&msg->rand;
  for(u_int16_ard i = 0; i < RAND_SIZE; i++)
  {
    temp[ID_SIZE + NONCE_SIZE + i] = temp_rand[i];
  }
  byte_ard* temp_timer = (byte_ard*)&msg->timer;
  for(u_int16_ard i = 0; i < TIMER_SIZE; i++)
  {
    temp[ID_SIZE + NONCE_SIZE + RAND_SIZE + i] = temp_timer[i];
  }

  byte_ard cipher_buff[NEWKEY_CRYPTSIZE];

  // Cipher
  CBCEncrypt((void*)temp, (void*)cipher_buff,
             (ID_SIZE+NONCE_SIZE+RAND_SIZE+TIMER_SIZE), AUTOPAD,
             pKeys, (const u_int16_ard*)IV);
  // Stick it in the buffer
  for (u_int16_ard i = 0; i < NEWKEY_CRYPTSIZE; i++)
  {
    cBuffer[MSGTYPE_SIZE + ID_SIZE + i] = temp[i];
  }

  // CMac
  aesCMac(pKeys, cipher_buff, NEWKEY_CRYPTSIZE, msg->cmac);

  for (u_int16_ard i = 0; i < BLOCK_BYTE_SIZE; i++)
  {
    cBuffer[MSGTYPE_SIZE + ID_SIZE + NEWKEY_CRYPTSIZE + i] = msg->cmac[i];
  }
*/
  
}
void unpack_newkey(void* pStream, const u_int32_ard* pKeys, struct message* msg)
{
}
