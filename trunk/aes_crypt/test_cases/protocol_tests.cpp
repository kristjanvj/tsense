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

byte_ard Keys[BLOCK_BYTE_SIZE*11];
byte_ard CmacKeys[BLOCK_BYTE_SIZE*11];
 
int idmsgtest(byte_ard* id, u_int16_ard n)
{

  // Create the buffer to write the packet into.
  // Needs to hold, MSGTYPE, IDSIZE, E(IDSIZE + NONCE) + MAC
  byte_ard buff[IDMSG_FULLSIZE];
  
  // Construct the packet
  struct message idmsg;
  idmsg.msgtype = MSG_T_GET_ID_R;
  idmsg.pID = id;
  idmsg.nonce = n;

  
  pack_idresponse(&idmsg, (const u_int32_ard*)Keys, (const u_int32_ard*)CmacKeys, (void*)buff);

  // Unpack
  struct message recv_id;
  // Allocate memory for the ID
  recv_id.pID = (byte_ard*)malloc(ID_SIZE+1);
  recv_id.ciphertext = (byte_ard*)malloc(IDMSG_CRYPTSIZE);
  byte_ard cmac[IDMSG_CRYPTSIZE];

  unpack_idresponse((void*)buff, (const u_int32_ard*)Keys, &recv_id);
  // add null char
  recv_id.pID[ID_SIZE] = '\0';

  // addpend null char
  //recv_id.pID[ID_SIZE] = '\0';
  aesCMac((const u_int32_ard*)CmacKeys, recv_id.ciphertext, IDMSG_CRYPTSIZE, cmac);
  
  printf("idresponse: ");
  //printf("ID: %s, Nonce: %d\n", idmsg.pID, recv_id.nonce);
  // 0 == match.
  int retval = 1;
  if (strcmp((char*)recv_id.pID, (char*)id) == 0)
  {
    if (n == recv_id.nonce)
    {
      if(strncmp((char*)recv_id.cmac, (char*)cmac, BLOCK_BYTE_SIZE) == 0)
      {
        if (recv_id.msgtype == MSG_T_GET_ID_R)
        {
          printf("Checks out! (ID: %s)\n", recv_id.pID);
          retval = 0;
        }
        else
        {
          printf("Failed: msgtype doesnt match! (0x%x)\n", recv_id.msgtype);
        }
      }
      else
      {
        fprintf(stderr, "Failed The mac doesnt match!\n");
      }
    }
    else
    {
      fprintf(stderr, "Failed nonce doesnt match!\n");
    }
  }
  else
  {
    fprintf(stderr, "Failed id doesnt match!\n");
  }

  free(recv_id.pID);
  free(recv_id.ciphertext);
  return retval;
}

int keytosinktest(u_int16_ard n, unsigned int t, byte_ard* id)
{
  printf("keytosink: ");
  int retval = 1;

  byte_ard newkey[] = {
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x36, 0x37, 0x38, 0x39, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25
  };

  struct message sendmsg;
  sendmsg.pID = id;
  sendmsg.timer = t;
  sendmsg.nonce = n;
  sendmsg.key = (byte_ard*)newkey;
  
  byte_ard buff[KEYTOSINK_FULLSIZE];
  
  pack_keytosink(&sendmsg, (const u_int32_ard*)Keys, (const u_int32_ard*)CmacKeys, buff);

  struct message recvmsg;
  recvmsg.pID = (byte_ard*)malloc(ID_SIZE);
  recvmsg.key = (byte_ard*)malloc(KEY_BYTES);
  recvmsg.ciphertext = (byte_ard*)malloc(KEYTOSINK_CRYPTSIZE);

  // UNPACK
  unpack_keytosink((void*)buff, &recvmsg);

  if (recvmsg.msgtype == 0x11)
  {
    if (strncmp((const char*)recvmsg.key, (const char*)newkey, KEY_BYTES) == 0)
    {
      if (recvmsg.timer == t)
      {
        if (strncmp((const char*)recvmsg.pID, (const char*)id, ID_SIZE) == 0)
        {
          printf("Checks out! (Timer : %d)\n", recvmsg.timer);
          retval = 0;
        }
        else
        {
          fprintf(stderr, "Failed: ID!\n");
        }
      }
      else
      {
        fprintf(stderr, "Failed timer\n");
      }
    }
    else
    {
      fprintf(stderr, "Failed plaintext key!\n");
    }
  }
  else
  {
    fprintf(stderr, "Failed msgtype\n");
  }

  //byte_ard* pNewkey = recvmsg.key;
  //printBytes2(pNewkey, KEY_BYTES);

  //free(recvmsg.pCipherID);
  free(recvmsg.key);
  free(recvmsg.ciphertext);
  free(recvmsg.pID);


  return retval;
}

int keytosensetest(u_int16_ard n, unsigned int t, byte_ard* id) 
{
  // Because pack_keytosens() is designed to forward the ciphertext from
  // keytosink, we will first create the keytosink package.

  int retval = 1;

  byte_ard newkey[] = {
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36
  };

  struct message sendmsg;
  sendmsg.pID = id;
  sendmsg.timer = t;
  sendmsg.nonce = n;
  sendmsg.key = (byte_ard*)newkey;

  byte_ard sinkbuff[KEYTOSINK_FULLSIZE];

  pack_keytosink(&sendmsg, (const u_int32_ard*)Keys, (const u_int32_ard*)CmacKeys, sinkbuff);

  // Now we will unpack that message in order to grab the ciphertext. The appropiate
  // memeory still has to be allocated to prevent buffer overflows.
  struct message sink_recv;
  sink_recv.pID = (byte_ard*)malloc(ID_SIZE);
  sink_recv.key = (byte_ard*)malloc(KEY_BYTES);
  sink_recv.ciphertext = (byte_ard*)malloc(KEYTOSINK_CRYPTSIZE);
  // the cmac memory is staticly allocated. Maybe that was a stupid move that leads
  // only to inconsistency?

  unpack_keytosink((void*)sinkbuff, &sink_recv);
  
  // sink_recv now contains the packet that the sink recieves and can only partly read.
  // Now recvmsg.ciphertext and recvmsg.cmac contains the values we are interested in.

  // Allocate memory for the buffer, conating msgtype, the ciphered part and the cmac
  byte_ard tosensebuffer[KEYTOSENS_FULLSIZE];

  // Pack the data recived in unpack_keytosink
  pack_keytosens(&sink_recv, tosensebuffer);

  free (sink_recv.ciphertext);
  free (sink_recv.key);
  free (sink_recv.pID);


  // Now read the message packed by pack_keytosense
  struct message senserecv;
  senserecv.key = (byte_ard*)malloc(KEY_BYTES);
  senserecv.ciphertext = (byte_ard*)malloc(KEYTOSINK_CRYPTSIZE);

  unpack_keytosens((void*)tosensebuffer, (const u_int32_ard*)Keys, &senserecv);

  byte_ard cmac_buff[BLOCK_BYTE_SIZE];
  aesCMac((const u_int32_ard*)CmacKeys, senserecv.ciphertext, 32, cmac_buff);
  
  printf("keytosense: ");
  if (senserecv.nonce == n)
  {
    if (senserecv.timer == t)
    {
      if (strncmp((const char*)newkey, (const char*)senserecv.key, KEY_BYTES) == 0)
      {
        if (strncmp((const char*)senserecv.cmac, (const char*)cmac_buff, BLOCK_BYTE_SIZE) == 0)
        {
          printf("Checks out! (Nonce: %d)\n", senserecv.nonce);
          retval = 0;
        }
        else
        {
          fprintf(stderr, "Failed the cmac doesn't match!\n");
          printf("  Cmac from stream:      ");
          printBytes2(senserecv.cmac, BLOCK_BYTE_SIZE);
          printf("  Ciphertext on stream:  ");
          printBytes2(senserecv.ciphertext, BLOCK_BYTE_SIZE);
          printf("  Cmaced in test:        ");
          printBytes2(cmac_buff, BLOCK_BYTE_SIZE);
        }
      }
      else
      {
        fprintf(stderr, "Failed the key doesnt match!\n");
      }
    }
    else
    {
      fprintf(stderr, "Failed timer doesnt match!\n");
    }
  }
  else
  {
    fprintf(stderr, "Failed nonce!\n");
  }
  
  free (senserecv.key);
  free (senserecv.ciphertext);
  return retval;
} 


int rekeytest(u_int16_ard n, byte_ard* id)
{
  int retval = 1;

  printf("rekey: ");

  struct message sendmsg;
  sendmsg.pID = id;
  sendmsg.nonce = n;

  byte_ard buffer[REKEY_FULLSIZE];
  pack_rekey(&sendmsg, (const u_int32_ard*)Keys, (const u_int32_ard*)CmacKeys, buffer);

  struct message recvmsg;
  recvmsg.pID = (byte_ard*)malloc(ID_SIZE+1);  // Null term.
  recvmsg.ciphertext = (byte_ard*)malloc(REKEY_CRYPTSIZE);

  unpack_rekey(buffer, (const u_int32_ard*)Keys, &recvmsg);

  // Get a new cmac for verification purposes
  byte_ard cmac_buff[BLOCK_BYTE_SIZE];
  aesCMac((const u_int32_ard*)CmacKeys, recvmsg.ciphertext, REKEY_CRYPTSIZE, cmac_buff);
  
  if (recvmsg.nonce == n)
  {
    if (strncmp((const char*)recvmsg.cmac, (const char*)cmac_buff, BLOCK_BYTE_SIZE) == 0)
    {
      if (strncmp((const char*) recvmsg.pID, (const char*)id, ID_SIZE) == 0)
      {
        printf("Checks out! (Public ID: %s)\n", recvmsg.pID);
        retval = 0;
      }
      else
      {
        fprintf(stderr, "Failed ID.\n");
      }
    }
    else
    {
      fprintf(stderr, "Failed Cmac.\n");
    }
  }
  else 
  {
    fprintf(stderr, "Failed nounce.\n");
  }

  free (recvmsg.pID);
  free (recvmsg.ciphertext);
 
  return retval;
}

int newkeytest(byte_ard* id, u_int16_ard n, u_int16_ard r, u_int16_ard t)
{
  int retval = 1;
  printf("newkey: ");
  
  struct message sendmsg;
  sendmsg.pID = id;
  sendmsg.nonce = n;
  sendmsg.rand = r;
  sendmsg.timer = t;

  byte_ard buffer[NEWKEY_FULLSIZE];

  pack_newkey(&sendmsg, (const u_int32_ard*)Keys, (const u_int32_ard*)CmacKeys,
              (void*)buffer);

  
  struct message recvmsg;
  recvmsg.pID = (byte_ard*)malloc(ID_SIZE+1);
  recvmsg.ciphertext = (byte_ard*)malloc(NEWKEY_CRYPTSIZE);

  unpack_newkey((void*)buffer, (const u_int32_ard*)Keys, &recvmsg);
  recvmsg.pID[ID_SIZE] = '\0';

  // verify cmac
  byte_ard cmac_temp[BLOCK_BYTE_SIZE];
  aesCMac((const u_int32_ard*)CmacKeys, recvmsg.ciphertext,
          NEWKEY_CRYPTSIZE, cmac_temp);
  if(strncmp((const char*)recvmsg.cmac, (const char*)cmac_temp, BLOCK_BYTE_SIZE) == 0)
  {
    if (strncmp((const char*)recvmsg.pID, (const char*)id, ID_SIZE) == 0)
    {
      if (recvmsg.nonce == n)
      {
        if (recvmsg.timer == t)
        {
          if (recvmsg.rand == r)
          {
            printf("Checks out! (Nonce: %d)\n", recvmsg.nonce);
            retval = 0;
          }
          else
          {
            fprintf(stderr, "Failed: random\n");
          }
        }
        else
        {
          fprintf(stderr, "Failed: timer\n");
        }
      }
      else
      {
        fprintf(stderr, "Failed: nonce\n");
      }
    }
    else
    {
      fprintf(stderr, "Failed: ID\n");
    }
  }
  else
  {
    fprintf(stderr, "Failed: cmac \n");
  }
  
  free(recvmsg.pID);
  free(recvmsg.ciphertext);
  return retval;
}

int main(int argc, char* argv[])
{

  // Sample key. 
  byte_ard Key[] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c 
  };
  
  KeyExpansion(Key, Keys);

  // Cmac key. Only 4 bits changed. 
  byte_ard CmacKey[] = {
    0x2c, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c  
  };
  KeyExpansion(CmacKey, CmacKeys);

  // Sample id: 000:001 (including null char)
  byte_ard id[ID_SIZE+1] = {0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x00};

  printf("TSense protocol tests\n");
  printf("\n  The values in paranthesis are read from the ciphertext and are printed to \n  make it easier for humans to make sure garbage isn't being read and compared\n\n");

  int test1 = idmsgtest((byte_ard*)id, 3);
  int test2 = keytosinktest(5, 18, (byte_ard*)id);
  int test3 = keytosensetest(1, 2, (byte_ard*)id);
  printf("\n");
  int test4 = rekeytest(9, (byte_ard*)id);
  int test5 = newkeytest((byte_ard*)id, 2, 3, 4);


  if ((test1+test2+test3+test4+test5) == 0) // SUM
  {
    printf("\nAll OK!\n");
  }
  else
  {
    printf("\nSome test(s) failed!\n");
  }

  //printf("IDMSG_FULLSIZE: %d\n", IDMSG_FULLSIZE);
}
