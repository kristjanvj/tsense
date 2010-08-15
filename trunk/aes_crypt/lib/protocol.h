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

/*
  Some defines - Please take care if you change them.

  The macros below depend on these sizes for easy calculation. If you ahvenge
  NOUNCE_SIZE, TIMER_SIZE, MSGTYPE_SIZE, IDSIZE - please fix the macros below
  accordingly. As is, this applies to the _PADLEN macros, since they use the
  BLOCK_BYTE_SIZE without a dynamic multiplicator and will return minus values
  if the _SIZE defines get larger. 
*/
#define ID_SIZE 6
#define MSGTYPE_SIZE 1
#define NOUNCE_SIZE 4
#define TIMER_SIZE 4

/*
  Some macros to calculate the various lengths of various things.

  Please thread carefully if changing something. 
*/
#define IDMSG_PADLEN BLOCK_BYTE_SIZE - (ID_SIZE+NOUNCE_SIZE)
#define IDMSG_CRYPTSIZE ID_SIZE + NOUNCE_SIZE + (IDMSG_PADLEN)
#define IDMSG_FULLSIZE MSGTYPE_SIZE + ID_SIZE + IDMSG_CRYPTSIZE + BLOCK_BYTE_SIZE

#define KEYTOSINK_PADLEN (BLOCK_BYTE_SIZE - (NOUNCE_SIZE + TIMER_SIZE))
#define KEYTOSINK_CRYPTSIZE (NOUNCE_SIZE + KEY_BYTES + TIMER_SIZE + KEYTOSINK_PADLEN)
#define KEYTOSINK_FULLSIZE MSGTYPE_SIZE + KEY_BYTES + TIMER_SIZE + KEYTOSINK_CRYPTSIZE + BLOCK_BYTE_SIZE

#define KEYTOSENS_FULLSIZE MSGTYPE_SIZE + KEYTOSINK_CRYPTSIZE + BLOCK_BYTE_SIZE
/* Struct */
struct message
{
  byte_ard msgtype;
  byte_ard* pID;
  byte_ard* pCipherID;
  u_int32_ard nounce;
  byte_ard cmac[BLOCK_BYTE_SIZE];
  byte_ard* key;
  byte_ard* ciphertext;
  u_int32_ard timer;
};

void pack_idresponse(struct message* msg, const u_int32_ard* pKeys, void *pBuffer);
void unpack_idresponse(void *pStream, const u_int32_ard* pKeys, struct message* msg);

void pack_keytosink(struct message* msg, const u_int32_ard* pKeys, void *pBuffer);
void unpack_keytosink(void *pStream, struct message* msg);

void pack_keytosens(struct message* msg, void *pBuffer);
void unpack_keytosens(void *pStream, const u_int32_ard* pKeys, struct message* msg);

/* Cannot define IV here for some reason. Investigate */


#endif
