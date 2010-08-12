/**
   Benedikt Kristinsson, 2010

   (GPL here)

   Tsense Protocol methods. Written in C++ to ensure comptability with Arduino
   wiring, but made to be compilable with gcc and g++.

 */

#ifndef __PROTOCOL_H__
#define __PROTOCOL_H__

#include "aes_crypt.h"
#include "aes_cmac.h"
#include <stdlib.h>
#include <string.h>

/* Some defines - Please take care if you change them. */
#define ID_SIZE 6
#define MSGTYPE_SIZE 1
#define NOUNCE_SIZE 4

/* Some macros to calculate the various lengths of various things. */
//#define IDMSG_SIZE ID_SIZE+NOUNCE_SIZE
#define IDMSG_PADLEN BLOCK_SIZE - (ID_SIZE+NOUNCE_SIZE)
#define IDMSG_CRYPTSIZE ID_SIZE + NOUNCE_SIZE + IDMSG_PADLEN
#define IDMSG_FULLSIZE MSGTYPE_SIZE + ID_SIZE + IDMSG_CRYPTSIZE + BLOCK_BYTE_SIZE

/* Structs */
struct message
{
  byte_ard msgtype;
  byte_ard* pID;
  byte_ard* pCipherID;
  u_int32_ard nounce;
  byte_ard cmac[BLOCK_BYTE_SIZE];
};

void pack_idresponse(struct message* msg, const u_int32_ard* pKeys,
                     void *pBuffer);
void unpack_idresponse(void *pStream, const u_int32_ard* pKeys,
                       struct message* msg);

/* Cannot define IV here for some reason. Investigate */

/* Misc methods to simplify code - will be moved */
u_int32_ard padding (u_int32_ard strlen);
u_int16_ard neededblocks(u_int32_ard len);

#endif
