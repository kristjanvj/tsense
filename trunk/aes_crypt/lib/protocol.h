/**
   Benedikt Kristinsson, 2010

   (GPL here)

   Tsense Protocol methods. Written in C++ to ensure comptability with Arduino
   wiring, but made to be compilable with gcc and g++.

**/

#ifndef __PROTOCOL_H__
#define __PROTOCOL_H__

#include "aes_crypt.h"
#include "aes_cmac.h"
#include <stdlib.h>
#include <string.h>

/*
  Some defines - Please take care if you change them.

  The macros below depend on these sizes for easy calculation. If you ahvenge
  NONCE_SIZE, TIMER_SIZE, MSGTYPE_SIZE, IDSIZE - please fix the macros below
  accordingly. As is, this applies to the _PADLEN macros, since they use the
  BLOCK_BYTE_SIZE without a dynamic multiplicator and will return minus values
  if the _SIZE defines get larger. 
 */
#define ID_SIZE 6
#define MSGTYPE_SIZE 1
#define NONCE_SIZE 2
#define TIMER_SIZE 2
#define RAND_SIZE 2

/*
  Some macros to calculate the various lengths of various things.

  Please thread carefully if changing something. The general rule here is
    _PADLEN = Number of characters needed to pad the block. <16 chars.
    _CRYPTSIZE = The length of the crypted size. Divisable by 16.
    _FULLSIZE = The length of the full packet, everthing included.

  The _PADLEN macros are sensetive to change. 
*/
#define IDMSG_PADLEN BLOCK_BYTE_SIZE - (ID_SIZE+NONCE_SIZE)
#define IDMSG_CRYPTSIZE ID_SIZE + NONCE_SIZE + (IDMSG_PADLEN)
#define IDMSG_FULLSIZE MSGTYPE_SIZE + ID_SIZE + IDMSG_CRYPTSIZE + BLOCK_BYTE_SIZE

#define KEYTOSINK_PADLEN (BLOCK_BYTE_SIZE - (NONCE_SIZE + TIMER_SIZE+ ID_SIZE))
#define KEYTOSINK_CRYPTSIZE (NONCE_SIZE + ID_SIZE + KEY_BYTES + TIMER_SIZE + KEYTOSINK_PADLEN)
#define KEYTOSINK_FULLSIZE MSGTYPE_SIZE + ID_SIZE + KEY_BYTES + TIMER_SIZE + KEYTOSINK_CRYPTSIZE + BLOCK_BYTE_SIZE

#define KEYTOSENS_FULLSIZE MSGTYPE_SIZE + KEYTOSINK_CRYPTSIZE + BLOCK_BYTE_SIZE

#define REKEY_PADLEN BLOCK_BYTE_SIZE - (NONCE_SIZE + ID_SIZE)
#define REKEY_CRYPTSIZE (ID_SIZE + NONCE_SIZE + REKEY_PADLEN)
#define REKEY_FULLSIZE MSGTYPE_SIZE + ID_SIZE + REKEY_CRYPTSIZE + BLOCK_BYTE_SIZE

#define NEWKEY_PADLEN  BLOCK_BYTE_SIZE - (ID_SIZE + NONCE_SIZE + RAND_SIZE + TIMER_SIZE)
#define NEWKEY_CRYPTSIZE ID_SIZE + NONCE_SIZE + RAND_SIZE + TIMER_SIZE + (NEWKEY_PADLEN)
#define NEWKEY_FULLSIZE MSGTYPE_SIZE + ID_SIZE + NEWKEY_CRYPTSIZE + BLOCK_BYTE_SIZE

/*
 Defines for message identifiers  
 */
#define MSG_T_GET_ID_R           0x10
#define MSG_T_KEY_TO_SINK        0x11
#define MSG_T_KEY_TO_SENSE       0x12
#define MSG_T_ID_RESPONSE_ERROR  0x1F
#define MSG_T_REKEY_REQUEST      0x30
#define MSG_T_REKEY_HANDSHAKE    0x31
#define MSG_T_REKEY_RESPONSE     0x32
#define MSG_T_FINISH             0x90
#define MSG_T_ERROR              0xff

/*
  Struct
 */
struct message
{
  byte_ard msgtype;                // The hex code declaring what type of message (see wiki)
  byte_ard* pID;                   // Pointer to the ID sent in plaintext
  u_int16_ard nonce;               // The nonce
  byte_ard cmac[BLOCK_BYTE_SIZE];  // The cmac of the ciphertext
  byte_ard* key;                   // The key sent in key exchange and re-keying
  byte_ard* ciphertext;            // When forwarding ciphertext
  u_int16_ard renewal_timer;       // re-keying timer
  u_int16_ard rand;                // Random number (the new key-material)
};

/*
  Key exchange and Authentication 
 */
void pack_idresponse(struct message* msg, const u_int32_ard* pKeys, const u_int32_ard* pCmacKeys, void *pBuffer);
void unpack_idresponse(void *pStream, const u_int32_ard* pKeys, struct message* msg);

void pack_keytosink(struct message* msg, const u_int32_ard* pKeys, const u_int32_ard* pCmacKeys, void *pBuffer);
void unpack_keytosink(void *pStream, struct message* msg);

void pack_keytosens(struct message* msg, void *pBuffer);
void unpack_keytosens(void *pStream, const u_int32_ard* pKeys, struct message* msg);

/*
  Re-keying
 */

void pack_rekey(struct message* msg, const u_int32_ard* pKeys,  const u_int32_ard* pCmacKeys, void* pBuffer);
void unpack_rekey(void* pStream, const u_int32_ard* pKeys, struct message* msg);

void pack_newkey(struct message* msg, const u_int32_ard* pKeys, const u_int32_ard* pCmacKeys, void* pBuffer);
void unpack_newkey(void* pStream, const u_int32_ard* pKeys, struct message* msg);

/* Cannot define IV here for some reason. Investigate */


#endif
