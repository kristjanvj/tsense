/*
 * File name: TlsClientBIO.c
 * Date:      2010-08-14 10:53
 * Author:    Kristján Rúnarsson
 */

#include "common.h"
#include "tsense_keypair.h"
#include "aes_constants.h"
#include "aes_utils.h"
#include <iostream>

#define I_BUF_LEN 80
#define O_BUF_LEN 80

using namespace std;

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

byte_ard key[] = {  0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
					0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

TSenseKeyPair *K_at;
TSenseKeyPair *K_st;

void do_client_loop(BIO *conn){
    int err;

	// Pack idresponse message -------------------------------------------------

	printf("Packing and sending idresponse message\n");

	byte_ard pBuffer[IDMSG_FULLSIZE];

	// Get the private key from the EEPROM
	byte_ard masterKeyBuf[KEY_BYTES] = 
		{ 0x09, 0xd2, 0x0c, 0x10, 0xa5, 0xd1, 0x33, 0x1d, 
		  0x15, 0xc6, 0x20, 0x1a, 0x92, 0x9e, 0x83, 0xaf };

	// Expand the masterkey (temporarily) to get encryption and authentication 
	// schedules. Use the public constant for derivation of authentication key.
	TSenseKeyPair masterKeys(masterKeyBuf,cAlpha);

	// Get the public id from EEPROM
	byte_ard idbuf[6] = {0x00,0x01,0x00,0x00,0x00,0x02};

	u_int16_ard idNonce = 518;

	// Create the input struct and populate  
	message msg;
	msg.msgtype=0x10;
	msg.pID=idbuf;
	msg.nonce=idNonce;   

	byte_ard idResponseBuf[IDMSG_FULLSIZE];

	// Pack ID response. See protocol.cpp for details. Encrypts and MACs the 
	// message and returns in pBuffer.
	pack_idresponse( &msg, 
					(const u_int32_ard *)masterKeys.getCryptoKeySched(),
					(const u_int32_ard *)masterKeys.getMacKeySched(),
					(void *)idResponseBuf);

	// Done packing idresponse message -----------------------------------------

	// Write idresponse messsage to sink server
    err = BIO_write(conn, (void*)idResponseBuf, IDMSG_FULLSIZE);

    printf("Done writing idresponse packet\n");

    byte_ard keyToSensBuf[KEYTOSENS_FULLSIZE];

	// Read keytosense message from sink server.
    err = BIO_read(conn, (void*)keyToSensBuf, KEYTOSENS_FULLSIZE);

	printf("\n");

	// Unpack keytosens message ------------------------------------------------
    
	printf("Unpacking a keytosens message\n");

	// Allocate memory for the unpacked message
	struct message senserecv;
	senserecv.key = (byte_ard*)malloc(KEY_BYTES);
	senserecv.ciphertext = (byte_ard*)malloc(KEYTOSINK_CRYPTSIZE);

	// Unpack
	unpack_keytosens((void*)keyToSensBuf,
					 (const u_int32_ard *)masterKeys.getCryptoKeySched(), 
					 &senserecv);

	// Validate the MAC  
	int validMac = verifyAesCMac( 
						(const u_int32_ard *)masterKeys.getMacKeySched(), 
						senserecv.ciphertext, 
						KEYTOSINK_CRYPTSIZE, 
						senserecv.cmac );

	if ( validMac==0 ) {
		printf("MAC failed");
		return;     
	} else {
		printf("MAC OK\n");
	}

	// Validate the nonce
	if ( senserecv.nonce != idNonce ) {
		printf("Nonce failed");
		return;  
	} else {
		printf("Nonce %d matches", idNonce);
	}

	printf("Recieved an encrypted keytoens package:\n");
	printf("---------------------------------------\n");
	printf("senserecv.msgtype: %x\n", senserecv.msgtype);
	printf("senserecv.nonce: %x\n", senserecv.nonce);
	printf("senserecv.key:\n");
	printBytes2(senserecv.key, KEY_BYTES); 
	printf("senserecv.cmac:\n");
	printBytes2(senserecv.cmac, KEY_BYTES); 

	K_st = new TSenseKeyPair(senserecv.key, cBeta);

	free(senserecv.ciphertext);
	free(senserecv.key);

	// Done unpacking keytosens message ----------------------------------------

	// The server disconnects after each request so we reconnect.
	conn = BIO_new_connect((char*)"sink.tsense.sudo.is:6002");

	// Pack rekey message ------------------------------------------------------

	u_int16_ard rekeyNonce = 765;

	printf("\n");
	printf("Packing rekey message:\n");
	printf("----------------------\n");

	struct message rekeymsg;
	rekeymsg.pID = idbuf;
	rekeymsg.nonce = rekeyNonce;

	// Set the correct MSG type if you are doing a handshake
	rekeymsg.msgtype = MSG_T_REKEY_HANDSHAKE;

    // Generate the buffer to write the packet into
    byte_ard reKeyBuf[REKEY_FULLSIZE];
	pack_rekey(	&rekeymsg, 
				(const u_int32_ard*) (K_st->getCryptoKeySched()),
				(const u_int32_ard*) (K_st->getMacKeySched()),
				reKeyBuf);

	printf("K_st crypto key schedule:\n");
	printByteArd(K_st->getCryptoKeySched(), KEY_BYTES*11, 16);
	printf("\n");
	
	printf("K_st MAC key schedule:\n");
	printByteArd(K_st->getMacKeySched(), KEY_BYTES*11, 16);
	printf("\n");

	printf("Rekey buffer:\n");
	printByteArd(reKeyBuf, REKEY_FULLSIZE, 16);

	// Done packing rekey message ----------------------------------------------

    err = BIO_write(conn, (void*)reKeyBuf, REKEY_FULLSIZE);

    printf("Done writing rekey packet: %d\n", err);

	// unpacking newkey  message -----------------------------------------------

	printf("\n");
	printf("Read newkey packet\n");
	printf("-------------------\n\n");

	byte_ard newkeybuf[NEWKEY_FULLSIZE];
	err = BIO_read(conn, (void*)newkeybuf, NEWKEY_FULLSIZE);

	// Unpack the raw buffer into a message struct
	message newkeyresp; 
	newkeyresp.ciphertext = (byte_ard*)malloc(NEWKEY_CRYPTSIZE);
	newkeyresp.pID = (byte_ard*)malloc(6);
  
  	unpack_newkey(newkeybuf,
				  (const u_int32_ard *)K_st->getCryptoKeySched(),
				  &newkeyresp);

	// Check the MAC against the encrypted data

	validMac = verifyAesCMac((const u_int32_ard *)K_st->getMacKeySched(),
							 newkeyresp.ciphertext, 
							 NEWKEY_CRYPTSIZE,
							 newkeyresp.cmac );

	if ( validMac = 0) {
		printf("MAC failed\n");
		return;     
	} else {
		printf("MAC OK\n");
	}
    
	// Get the data available from the rekey message
  
	// Get the device id in the message and compare with my own
	if (strncmp((const char *)newkeyresp.pID,
		(const char *)idbuf,ID_SIZE) != 0 )
	{
		printf("ID mismatch in rekey\n");
		return;         
	} else {
		printf("ID %d%d-%d%d%d%d matches\n",
				newkeyresp.pID[0],newkeyresp.pID[1],newkeyresp.pID[2],
				newkeyresp.pID[3],newkeyresp.pID[4],newkeyresp.pID[5]);
	}

	// Compare the nonce with my current one
	if ( newkeyresp.nonce != rekeyNonce ) {
		printf("Nonce mismatch on rekey");
		return;         
	} else {
		printf("Nonce %d matches\n", rekeyNonce);
	}

	printf("Random number (key material):\n");
	printBytes2(newkeyresp.rand,16);
  
	free(newkeyresp.ciphertext);
	free(newkeyresp.pID);

	printf("Done handling newkey message from sink\n\n");
}

void senddata(BIO *conn)
{
  data msg;  // Struct to hold the data messages
  byte_ard tmpid[] = {0x00,0x01,0x00,0x00,0x00,0x02};
  memcpy(msg.id,tmpid,6);
  msg.msgtime = 1234;
  msg.data_len = 20;
  msg.data = (byte_ard*)malloc(msg.data_len);

  byte_ard measBuffer[20];
  for (int i=0; i<20; i++)
	measBuffer[i] = 0x01;

  memcpy(msg.data,measBuffer,msg.data_len);
  
//  u_int16_ard bufsize = 1+1+msg.data_len+16;

  u_int16_ard plainsize = ID_SIZE + MSGTIME_SIZE + 1 + (u_int16_ard)msg.data_len;

  // Since cipher_len is always going to be congruent to 16 in modulus 16, we can
  // use it to indicate much larger ciphertext then 127 if we use that fact. 
  u_int16_ard cipher_len = (1 + (plainsize/BLOCK_BYTE_SIZE)) * BLOCK_BYTE_SIZE;
  u_int16_ard bufsize = cipher_len+2+16; // 2 plaintext bytes + cmac
  byte_ard* databuf = (byte_ard*)malloc(bufsize);

	// Get the private key from the EEPROM
	byte_ard keybuf[KEY_BYTES] = 
		{ 0x09, 0xd2, 0x0c, 0x10, 0xa5, 0xd1, 0x33, 0x1d, 
		  0x15, 0xc6, 0x20, 0x1a, 0x92, 0x9e, 0x83, 0xaf };

	// Expand the masterkey (temporarily) to get encryption and authentication 
	// schedules. Use the public constant for derivation of authentication key.
	TSenseKeyPair KSte(keybuf,cEpsilon);
    
  pack_data( &msg, (const u_int32_ard*)KSte.getCryptoKeySched(), 
             (const u_int32_ard*)KSte.getMacKeySched(), databuf );
 
	printByteArd(databuf,bufsize,16);

/*
	// The server disconnects after each request so we reconnect.
	conn = BIO_new_connect((char*)"sink.tsense.sudo.is:6002");

     err = BIO_write(conn, (void*)databuf, bufsize);

    BIO_free(conn);
  
*/  

  // Free
//  free(databuf);
//  free(msg.data);

	// -----------

	byte_ard readBuf[2048];
	memcpy(readBuf,databuf,bufsize);
	
/*
    TsDbSinkSensorProfile *tssp;

    try {
        tssp = new TsDbSinkSensorProfile(tmpID, dbcd);

    } catch(runtime_error rex) {
        log_err_exit(rex.what());
    }
*/

    struct data sensorData;

    unpack_data(readBuf,
                (const u_int32_ard*) KSte.getCryptoKeySched(),
                &sensorData);

	printByteArd(readBuf,100,16);

    printf( "msg_type:     %x\n", sensorData.msgtype);
    printf( "cipher_len:   %x\n", sensorData.cipher_len);
	printByteArd(sensorData.id,ID_SIZE,6);
    printf( "msg_time:     %u\n", sensorData.msgtime);
    printf( "data_len:     %x\n", sensorData.data_len);
	printf("cipher data:\n");
	printByteArd(sensorData.ciphertext,sensorData.cipher_len,16);
	printf("data:\n");
	printByteArd(sensorData.data,sensorData.data_len,16);

    // data
    // ciphertext
	printByteArd(sensorData.cmac,16,16);

	free(sensorData.ciphertext);
	free(sensorData.data);
}


int main(int argc, char *argv[]){

    BIO *conn;
/*
	printf("NEWKEY_FULLSIZE: %d", NEWKEY_FULLSIZE);

	byte_ard K_AT[] = { 0x09, 0xd2, 0x0c, 0x10, 0xa5, 0xd1, 0x33, 0x1d, 
                        0x15, 0xc6, 0x20, 0x1a, 0x92, 0x9e, 0x83, 0xaf };

    byte_ard alpha[] = { 0x65, 0xa4, 0x56, 0x5d, 0x09, 0xd6, 0x7e, 0xfa, 
                         0xb5, 0x9d, 0x6f, 0x1c, 0xc1, 0xc5, 0x79, 0x9d };

	K_at = new TSenseKeyPair(K_AT, alpha);

    init_OpenSSL();
	
	conn = BIO_new_connect((char*)"sink.tsense.sudo.is:6002");

    if(!conn){
        int_error("Error createing connection BIO");
    }

    if(BIO_do_connect(conn) <= 0){
        int_error("Error connecting to remote machine");
    }

    fprintf(stderr, "Connection opened\n");
    do_client_loop(conn);
    fprintf(stderr, "Connection closed\n");

    BIO_free(conn);
*/
	senddata(conn);

    return 0;
}

