// Benedikt Kristinsson
// Test the protocol methods. 

#include "protocol.h"
#include <stdio.h>
#include <stdlib.h>  // malloc()

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


int main(int argc, char* argv[])
{
  // Sample id: 000:001 (including null char)
  byte_ard id[ID_SIZE+1] = {0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x00};

  // Sample key. 
  byte_ard Key[] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c 
  };

  byte_ard Keys[BLOCK_BYTE_SIZE*11];
  KeyExpansion(Key, Keys);

  // Create the buffer to write the packet into.
  // Needs to hold, MSGTYPE, IDSIZE, E(IDSIZE + NOUNCE) + MAC
  byte_ard buff[IDMSG_FULLSIZE];
  
  // Construct the packet
  struct message idmsg;
  idmsg.msgtype = 0x10;
  idmsg.pID = (byte_ard*)malloc(ID_SIZE+1);   // +1 for \0, else buffer overflow
  idmsg.pID = (byte_ard*)id;
  idmsg.nounce = 3;

  
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
  
  printf("\nidresponse\n");
  //printf("ID: %s, Nounce: %d\n", idmsg.pID, recv_id.nounce);
  // 0 == match.
  if (strcmp((char*)recv_id.pID, (char*)recv_id.pCipherID) == 0)
  {
    if (strcmp((char*)recv_id.pCipherID, (char*)idmsg.pID) == 0)
    {
      if(recv_id.nounce == idmsg.nounce)
      {
        if(strncmp((char*)recv_id.cmac, (char*)cmac, BLOCK_BYTE_SIZE) == 0)
        {
          printf("Checks out!\n");
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
      printf("Failed: recv_id.CipherID does not match idmsg.pID");
    }
  }
  else
  {
    printf("Failed: the plaintext id does not match the ciphered ID");
  }
  
  return 0;
}

