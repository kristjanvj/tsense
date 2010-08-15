/**
   Benedikt Kristinsson, 2010

   (GPL here)

   Tsense Protocol methods. Written in C++ to ensure comptability with Arduino
   Wiring, but made to be compilable with gcc and g++.

 */

#include "protocol.h"

byte_ard IV[] = {
  0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30 
};

void pack_idresponse(struct message* msg, const u_int32_ard* pKeys, void *pBuffer)
{
  byte_ard crypt_buff[IDMSG_CRYPTSIZE];
  byte_ard cmac_buff[IDMSG_CRYPTSIZE];
  byte_ard temp[ID_SIZE + NOUNCE_SIZE];
  byte_ard* pNounce = (byte_ard*)&msg->nounce;
  
  for (u_int32_ard i = 0; i < ID_SIZE; i++)
  {
    temp[i] = msg->pID[i];
  }
  for(u_int32_ard i = 0; i < NOUNCE_SIZE; i++)
  {
    temp[ID_SIZE + i] = pNounce[i];
  }

  // Encrypt-then-MAC (Bellare and Namprempre)
  CBCEncrypt((void*)temp, (void*) crypt_buff, (ID_SIZE+NOUNCE_SIZE),
             AUTOPAD, pKeys, (const u_int16_ard*)IV);

  // CMac the crypted ID and Nounce. 
  aesCMac(pKeys, crypt_buff, IDMSG_CRYPTSIZE, cmac_buff);

  byte_ard* cBuffer = (byte_ard*)pBuffer;
  
  // First byte is the msg type. If longer than one byte, add loop.
  //cBuffer[0] = msg->msgtype;
  cBuffer[0] = 0x10;
  msg->msgtype = 0x10;

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

  // Add the CMac behind the msgtype, plaintext id and E(Public ID, Nounce)
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

  // ID_SIZE (6) bytes of public id. 
  for (u_int16_ard i = 0; i < ID_SIZE; i++)
  {
    msg->pID[i] = cStream[i + MSGTYPE_SIZE];
  }
  // append \0, pack_idresponse() strips it off.
  msg->pID[ID_SIZE] = '\0';

  // blocks_count * BLOCK_BYTE_SIZE bytes of encrypted block.

  byte_ard crypt_buff[IDMSG_CRYPTSIZE];
  byte_ard plain_buff[IDMSG_CRYPTSIZE];
  // ↑ Needed because CBC Decrypt doesnt de-pad. 

  // Get the ciphertext. 
  for(u_int16_ard i = 0; i < IDMSG_CRYPTSIZE; i++)
  {
    crypt_buff[i] = cStream[MSGTYPE_SIZE + ID_SIZE + i];
  }

  // Decipher
  CBCDecrypt((void*)crypt_buff, (void*)plain_buff, IDMSG_CRYPTSIZE, pKeys,
             (const u_int16_ard*)IV);

  // Get the ciphered public id (now deciphered) into the stuct and append \0
  for(u_int16_ard i = 0; i < ID_SIZE; i++)
  {
    msg->pCipherID[i] = plain_buff[i];
  }
  msg->pCipherID[ID_SIZE] = '\0';

  // Get the nounce into the struct, cast to int again. 
  byte_ard* temp = (byte_ard*)malloc(NOUNCE_SIZE);
  for (u_int16_ard i = 0; i < NOUNCE_SIZE; i++)
  {
    temp[i] = plain_buff[ID_SIZE+i];
  }
  msg->nounce = (u_int32_ard)*temp;
  free(temp);

  // Get the cmac into the struct.
  for (u_int16_ard i = 0; i < BLOCK_BYTE_SIZE; i++)
  {
    //msg->cmac[i] = plain_buff[ID_SIZE+NOUNCE_SIZE+i];
    msg->cmac[i] = cStream[MSGTYPE_SIZE + ID_SIZE + IDMSG_CRYPTSIZE + i];
  }
}

void pack_keytosink(struct message* msg, const u_int32_ard* pKeys, void *pBuffer)
{
  byte_ard* cBuffer = (byte_ard*)pBuffer;
  msg->msgtype = 0x11;
  cBuffer[0] = 0x11;

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
  byte_ard temp[NOUNCE_SIZE+KEY_BYTES+TIMER_SIZE];
  byte_ard cipher_buff[KEYTOSINK_CRYPTSIZE];

  byte_ard* pNounce = (byte_ard*)&msg->nounce;
  // N_T
  for (u_int16_ard i = 0; i < NOUNCE_SIZE; i++)
  {
    temp[i] = pNounce[i];
  }
  
  // Key
  for (u_int16_ard i = 0; i < KEY_BYTES; i++)
  {
    temp[NOUNCE_SIZE+i] = msg->key[i];
  }
  //Timer (pointer declartion above)
  for (u_int16_ard i = 0; i < TIMER_SIZE; i++)
  {
    temp[NOUNCE_SIZE+KEY_BYTES+i] = pTimer[i];
  }

  // Cipher
  CBCEncrypt((void*)temp, (void*)cipher_buff, (NOUNCE_SIZE + KEY_BYTES + TIMER_SIZE),
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
  cBuffer[0] = 0x11;
  msg->msgtype = 0x11;

  // The ciphertext containing the Nounce, key and Timer. 
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

  // 1 - nounce
  byte_ard nouncetemp[NOUNCE_SIZE];
  for (u_int16_ard i = 0; i < NOUNCE_SIZE; i++)
  {
    nouncetemp[i] = plainbuff[i];
  }
  msg->nounce = (u_int32_ard)*nouncetemp;

  // 2 - key
  for (u_int16_ard i = 0; i < KEY_BYTES; i++)
  {
    msg->key[i] = plainbuff[NOUNCE_SIZE + i];
  }
  
  // 3 - timer
  byte_ard timertemp[TIMER_SIZE];
  for (u_int16_ard i = 0; i < TIMER_SIZE; i++)
  {
    timertemp[i] = plainbuff[NOUNCE_SIZE + KEY_BYTES + i];
  }
  msg->timer = (u_int32_ard)*timertemp;


}
