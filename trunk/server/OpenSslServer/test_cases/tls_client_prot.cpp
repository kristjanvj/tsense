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

    byte_ard idResponseBuf[IDMSG_FULLSIZE];

	// id_response packet sent as response to a get ID request from the
	// proxy client.

	// Sample id: 000:001 (including null char)
	byte_ard id[ID_SIZE+1] = {0x30, 0x30, 0x30, 0x30, 0x31, 0x31, 0x00};

	// Create the struct, allocate neccesary memory and write sample data.
	struct message idmsg;
	idmsg.msgtype = 0x10;   // This line is optional. pack_idresponse() will
							// set the proper msgtype. It can be useful for 
							// verification purposes to declare it.
	idmsg.pID = (byte_ard*)id;
	idmsg.nonce = 3;

	printf("\n");

	//printf("Constructed an encrypted idresponse package:\n");
	//printf("--------------------------------------------\n");
	//printf("idmsg.msgtype:          %x\n", idmsg.msgtype);
	//printf("idmsg.nonce:           %x\n", idmsg.nonce);
	//printf("\n");

	
	pack_idresponse(&idmsg, (const u_int32_ard*) (K_at->getCryptoKeySched()),
							(const u_int32_ard*) (K_at->getMacKeySched()),
							(void*)idResponseBuf);

	// Done packing idresponse message -----------------------------------------

	// Write idresponse messsage to sink server
    err = BIO_write(conn, (void*)idResponseBuf, IDMSG_FULLSIZE);

    //printf("Done writing idresponse packet\n");

    byte_ard keyToSensBuf[KEYTOSENS_FULLSIZE];

	// Read keytosense message from sink server.
    err = BIO_read(conn, (void*)keyToSensBuf, KEYTOSENS_FULLSIZE);

	//printf("\n");

	// Unpack keytosens message ------------------------------------------------

	struct message senserecv;
	senserecv.key = (byte_ard*)malloc(KEY_BYTES);
	senserecv.ciphertext = (byte_ard*)malloc(KEYTOSINK_CRYPTSIZE);

	
	unpack_keytosens((void*)keyToSensBuf, 
					 (const u_int32_ard*) (K_at->getCryptoKeySched()),
					 &senserecv);
	
	//byte_ard cmac_buff[BLOCK_BYTE_SIZE];
	//aesCMac((const u_int32_ard*)Keys, senserecv.ciphertext, 32, cmac_buff);

 	printf("Verifying CMAC on keytosens message.\n");
	int validMac = verifyAesCMac((const u_int32_ard*) (K_at->getMacKeySched()),
									senserecv.ciphertext,
									KEYTOSINK_CRYPTSIZE,
									senserecv.cmac);

	if(validMac == 0){
		int_error("Mac of incoming keytosens message did not match");
	}

	printf("Recieved an encrypted keytoens package:\n");
	printf("---------------------------------------\n");
	printf("senserecv.msgtype: %x\n", senserecv.msgtype);
	printf("senserecv.nonce: %x\n", senserecv.nonce);
	printf("senserecv.key:\n");
	printBytes2(senserecv.key, KEY_BYTES); 
	printf("senserecv.cmac:\n");
	printBytes2(senserecv.cmac, KEY_BYTES); 


    //byte_ard beta[] = {	0x10, 0x9b, 0x58, 0xba, 0x59, 0xe0, 0xd6, 0x6e,
	//					0xe9, 0xf7, 0x35, 0xab, 0x6a, 0x99, 0xe3, 0x61 };

	K_st = new TSenseKeyPair(senserecv.key, cBeta);

	free(senserecv.ciphertext);
	free(senserecv.key);

	// Done unpacking keytosens message ----------------------------------------

	// The server disconnects after each request so we reconnect.
	conn = BIO_new_connect((char*)"sink.tsense.sudo.is:6002");

	// Pack rekey message ------------------------------------------------------

	printf("\nPacking rekey message:\n");
	printf("----------------------\n");
	struct message rekeymsg;
	rekeymsg.pID = id;
	rekeymsg.nonce = 0xff;

	// Set the correct MSG type if you are doing a handshake
	rekeymsg.msgtype = MSG_T_REKEY_HANDSHAKE;

    // Generate the buffer to write the packet into
    byte_ard reKeyBuf[REKEY_FULLSIZE];
	pack_rekey(	&rekeymsg, 
				(const u_int32_ard*) (K_st->getCryptoKeySched()),
				(const u_int32_ard*) (K_st->getMacKeySched()),
				reKeyBuf);


	printByteArd(K_st->getCryptoKeySched(), KEY_BYTES*11, 16);

	printf("\n");

	printByteArd(K_st->getMacKeySched(), KEY_BYTES*11, 16);

	printf("\n");

	printByteArd(reKeyBuf, REKEY_FULLSIZE, 16);


    err = BIO_write(conn, (void*)reKeyBuf, REKEY_FULLSIZE);

    printf("Done writing rekey pakcet: %d\n", err);
}

int main(int argc, char *argv[]){

    BIO *conn;

	byte_ard K_AT[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };

    byte_ard alpha[] = { 0xc7, 0x46, 0xe9, 0x64, 0x72, 0x3a, 0x21, 0x47,
                         0xa2, 0x47, 0x30, 0x1a, 0xb9, 0x6b, 0x54, 0xde };

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

    return 0;
}

