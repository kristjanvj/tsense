// Benedikt Kristinsson
// Test the protocol methods. 

#include <stdio.h>
#include <stdlib.h>  // malloc()

#include "protocol.h"


// printBytes2 KVJ
void printBytes2(unsigned char* pBytes, unsigned long dLength, int textWidth=16)
{	
	int bytecount=0;
	for(unsigned long i=0;i<dLength;i++)
	{
		printf("%.2x ",pBytes[i]);
		if ( ++bytecount == textWidth )
		{
			printf("\n");
			bytecount=0;
		}
	}
	if ( bytecount != 0 )
		printf("\n");
}



/* strncpy borrowed from the OpenBSD project */

byte_ard* strncpy2(byte_ard* dst, const byte_ard* src, u_int32_ard n)
{
  if (n != 0) {
    byte_ard* d = dst;
    const byte_ard* s = src;

    do {
      if ((*d++ = *s++) == 0) {
        /* NUL pad the remaining n-1 bytes */
        while (--n != 0)
          *d++ = 0;
        break;
      }
    } while (--n != 0);
  }
  return (dst);
}


 byte_ard Keys[BLOCK_BYTE_SIZE*11];

 
int idmsgtest(byte_ard* id, unsigned int n)
{

  // Create the buffer to write the packet into.
  // Needs to hold, MSGTYPE, IDSIZE, E(IDSIZE + NOUNCE) + MAC
  byte_ard buff[IDMSG_FULLSIZE];
  
  // Construct the packet
  struct message idmsg;
  idmsg.msgtype = 0x10;
  idmsg.pID = id;
  idmsg.nounce = n;

  
  pack_idresponse(&idmsg, (const u_int32_ard*)Keys, (void*)buff);

  // Unpack
  struct message recv_id;
  // Allocate memory for the ID
  recv_id.pID = (byte_ard*)malloc(ID_SIZE+1);
  recv_id.pCipherID = (byte_ard*)malloc(ID_SIZE+1);
  byte_ard cmac[IDMSG_CRYPTSIZE];
  byte_ard idandnounce[ID_SIZE+NOUNCE_SIZE];
  byte_ard pre_cmac[IDMSG_CRYPTSIZE];
  unpack_idresponse((void*)buff, (const u_int32_ard*)Keys, &recv_id);

  // fill the buffer with ID and Nounce to find the cmac
  byte_ard* pNounceUnPack = (byte_ard*)&recv_id.nounce;
  for (u_int16_ard i = 0; i < ID_SIZE; i++)
  {
    idandnounce[i] = idmsg.pID[i];
  }
  for (u_int16_ard i = 0; i < NOUNCE_SIZE; i++)
  {
    idandnounce[ID_SIZE+i] = pNounceUnPack[i];
  }
  byte_ard IVector[] = {
  0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,  0x30, 0x30 
  };

  CBCEncrypt((void*)idandnounce, (void*)pre_cmac, (ID_SIZE+NOUNCE_SIZE),
             IDMSG_PADLEN, (const u_int32_ard*)Keys,
             (const u_int16_ard*)IVector);
  aesCMac((const u_int32_ard*)Keys, pre_cmac, IDMSG_CRYPTSIZE, cmac);
  
  printf("idresponse: ");
  //printf("ID: %s, Nounce: %d\n", idmsg.pID, recv_id.nounce);
  // 0 == match.
  int retval = 1;
  if (strcmp((char*)recv_id.pID, (char*)recv_id.pCipherID) == 0)
  {
    if (strcmp((char*)recv_id.pCipherID, (char*)idmsg.pID) == 0)
    {
      if((n + recv_id.nounce) == (n + idmsg.nounce))
      {
        if(strncmp((char*)recv_id.cmac, (char*)cmac, BLOCK_BYTE_SIZE) == 0)
        {
          if (recv_id.msgtype == 0x10)
          {
            printf("Checks out! (ID: %s)\n", recv_id.pCipherID);
            retval = 0;
          }
          else
          {
            printf("Failed: msgtype.\n");
          }
        }
        else
        {
          printf("Failed: The hash doesn't match!\n");
        }
      }
      else
      {
        printf("Failed: nounce\n");
      }
    }
    else
    {
      printf("Failed: recv_id.CipherID does not match idmsg.pID\n");
    }
  }
  else
  {
    printf("Failed: the plaintext id does not match the ciphered ID\n");
  }

  free(recv_id.pID);
  free(recv_id.pCipherID);
  return retval;
}

int keytosinktest(unsigned int n, unsigned int t, byte_ard* id)
{
  printf("keytosink: ");
  int retval = 1;

  byte_ard newkey[] = {
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x36, 0x37, 0x38, 0x39, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25
  };

  struct message sendmsg;
  sendmsg.pID = id;
  sendmsg.timer = t;
  sendmsg.nounce = n;
  sendmsg.key = (byte_ard*)newkey;
  
  byte_ard buff[KEYTOSINK_FULLSIZE];
  
  pack_keytosink(&sendmsg, (const u_int32_ard*)Keys, buff);

  struct message recvmsg;
  recvmsg.key = (byte_ard*)malloc(KEY_BYTES);
  recvmsg.ciphertext = (byte_ard*)malloc(KEYTOSINK_CRYPTSIZE);

  // UNPACK
  unpack_keytosink((void*)buff, &recvmsg);
  /*
  // To verify the ciphered stream (that the Sink is unable to decipher, and
  // that is why unpack_keytosink() doesnt take in the pointer to the key schedule.
  byte_ard temp[NOUNCE_SIZE + KEY_BYTES + TIMER_SIZE];
  byte_ard ctext[KEYTOSINK_CRYPTSIZE];

  byte_ard* pNounce = (byte_ard*)&n; // recvmsg doesnt contain the nounce because its
                                     // only sent ciphered
  byte_ard* pTimer = (byte_ard*)&recvmsg.timer;
  for (u_int16_ard i = 0; i < NOUNCE_SIZE; i++)
  {
    temp[i] = pNounce[i];
  }
  for(u_int16_ard i = 0; i < KEY_BYTES; i++)
  {
    temp[NOUNCE_SIZE + i] = recvmsg.key[i];
  }
  for(u_int16_ard i = 0; i < TIMER_SIZE; i++)
  {
    temp[NOUNCE_SIZE + KEY_BYTES + i] = pTimer[i];
  }

  byte_ard IV[] = {
  0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,  0x30, 0x30 
};
h
  CBCEncrypt((void*)temp, (void*)ctext, 24,
             8, (const u_int32_ard*)Keys, (const u_int16_ard*)IV);

 
  printf("\nplaintext bytes: \n");
  printBytes2((byte_ard*)temp, 24);
  printf("\n protocol_tests.cpp:\n");
  printBytes2((byte_ard*)ctext, KEYTOSINK_CRYPTSIZE, 16);
  printf("recvmsg.ciphertext:\n ");
  printBytes2((byte_ard*)recvmsg.ciphertext, KEYTOSINK_CRYPTSIZE, 16);
  */

  if (recvmsg.msgtype == 0x11)
  {
    if (strcmp((const char*)recvmsg.key, (const char*)newkey) == 0)
    {
      if (recvmsg.timer == t)
      {
        printf("Checks out! (Timer: %d)\n", recvmsg.timer);
        retval = 0;
      }
      else
      {
        printf("Failed: timer\n");
      }
    }
    else
    {
      printf("Failed: plaintext key!\n");
    }
  }
  else
  {
    printf("Failed: msgtype\n");
  }
  

  //free(recvmsg.pCipherID);
  free(recvmsg.key);
  free(recvmsg.ciphertext);

  return retval;
}

int main(int argc, char* argv[])
{

  // Sample key. 
  byte_ard Key[] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c 
  };
  
 KeyExpansion(Key, Keys);
 

  // Sample id: 000:001 (including null char)
  byte_ard id[ID_SIZE+1] = {0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x00};
  
  int test1 = idmsgtest((byte_ard*)id, 3);
  int test2 = keytosinktest(5, 18, (byte_ard*)id);

  if ((test1+test2) == 0) // SUM
  {
    printf("\nAll OK!\n");
  }
  
}
