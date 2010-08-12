/**
   Benedikt Kristinsson, 2010

   (GPL here)

   Tsense Protocol methods. Written in C++ to ensure comptability with Arduino
   Wiring, but made to be compilable with gcc and g++.

 */

#include "protocol.h"


byte_ard IV[] = {
  0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,  0x30, 0x30 
};

void pack_idresponse(struct message* msg, const u_int32_ard* pKeys, void *pBuffer)
{
  byte_ard crypt_buff[IDMSG_CRYPTSIZE];
  byte_ard cmac_buff[IDMSG_CRYPTSIZE];
  byte_ard temp[ID_SIZE + NOUNCE_SIZE];
  byte_ard* pNounce = (byte_ard*)&msg->nounce;
  
  for (u_int32_ard i = 0; i < (ID_SIZE + NOUNCE_SIZE); i++)
  {
    if (i < ID_SIZE) 
    {
      temp[i] = msg->pID[i];
    }
    else if (i >= ID_SIZE)
    {
      temp[i] = pNounce[i-ID_SIZE];
    }
  }

  // Encrypt-then-MAC (Bellare and Namprempre)
  CBCEncrypt((void*)temp, (void*) crypt_buff, (ID_SIZE+NOUNCE_SIZE),
             IDMSG_PADLEN,pKeys, (const u_int16_ard*)IV);

  // CMac the crypted ID and Nounce. 
  aesCMac(pKeys, crypt_buff, IDMSG_CRYPTSIZE, cmac_buff);

  byte_ard* cBuffer = (byte_ard*)pBuffer;
  
  // First byte is the msg type. If longer than one byte, add loop.
  //cBuffer[0] = msg->msgtype;
  cBuffer[0] = 0x10;

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



 /* TODO: Move to tsense_common or similar.  */
u_int16_ard neededblocks(u_int32_ard len)
{
  /*u_int32_ard count = 0;
  while (pText[count] != '\0')
    count++;
  */
  
  u_int32_ard i = 0;
  while ( i >= 0 )
  {
    if (len <= (i*BLOCK_BYTE_SIZE))
    {
      break;
    }
    else
    {
      i++;
    }
  }
  return i;
}

u_int32_ard padding(u_int32_ard strlen)
{
  // Decide on the padding
  if ((strlen % BLOCK_BYTE_SIZE) == 0)
    return 0;
  else
    return  BLOCK_BYTE_SIZE - (strlen % BLOCK_BYTE_SIZE);  

}

