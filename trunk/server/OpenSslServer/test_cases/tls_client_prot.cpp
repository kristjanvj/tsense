/*
 * File name: TlsClientBIO.c
 * Date:      2010-08-14 10:53
 * Author:    Kristján Rúnarsson
 */

#include "common.h"
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

void do_client_loop(BIO *conn){
    int err;

	printf("do_client_loop(0)\n");

    byte_ard outBuf[IDMSG_FULLSIZE];
    byte_ard inBuf[IDMSG_FULLSIZE];

	byte_ard Key[] = {	0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 
						0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

	printf("do_client_loop(1)\n");
    
	byte_ard Keys[BLOCK_BYTE_SIZE*11];
	KeyExpansion(Key, Keys);

 	// Sample id: 000:001 (including null char)
 	byte_ard id[ID_SIZE+1] = {0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x00};
  
  	// Create the buffer to write the packet into.
  	// Needs to hold, MSGTYPE, IDSIZE, E(IDSIZE + NOUNCE) + MAC
  	byte_ard packetBuff[IDMSG_FULLSIZE];

	printf("IDMSG_FULLSIZE: %d\n", IDMSG_FULLSIZE);
   
	// Create the struct, allocate neccesary memory and write sample data.
	struct message idmsg;
	idmsg.msgtype = 0x10;	// This line is optional. pack_idresponse() will
							// set the proper msgtype. It can be useful for 
							// verification purposes to declare it.
	idmsg.pID = (byte_ard*)id;
	idmsg.nounce = 3;

	printf("idmsg.msgtype:          %x\n", idmsg.msgtype);
	printf("idmsg.nounce:           %x\n", idmsg.nounce);
	printf("\n");

	pack_idresponse(&idmsg, (const u_int32_ard*)Keys, (void*)packetBuff);

    printf("sending encrypted packet, printing buffer to be written:\n");

	printBytes2(packetBuff, IDMSG_FULLSIZE);

	printf("\n");

    err = BIO_write(conn, (void*)packetBuff, IDMSG_FULLSIZE);

    printf("Done writing encrypted packet\n");

    err = BIO_read(conn, (void*)inBuf, IDMSG_FULLSIZE);

    inBuf[err] = 0x0;
    printf("Done reading encrypted packet, printing what was recieved:\n");
	printBytes2(inBuf, IDMSG_FULLSIZE);

	printf("\n");

	//----------------------------------------------------------

	struct message recv_id;
	// Allocate memory for the ID and '\0'
	recv_id.pID = (byte_ard*)malloc(ID_SIZE+1);
	recv_id.pCipherID = (byte_ard*)malloc(ID_SIZE+1);

	unpack_idresponse((void*)inBuf, (const u_int32_ard*)Keys, &recv_id);

    printf("Done unpacking encrypted packet:\n");

	printf("recv_id.msgtype:          %x\n", recv_id.msgtype);
	printf("recv_id.nounce:           %x\n", recv_id.nounce);
	printf("recv_id.public id:        %x\n", (unsigned int) *recv_id.pID);
	printf("recv_id.public cypher id: %x\n", (unsigned int) *recv_id.pCipherID);
	//printf("public cmac:      %x\n", (unsigned int) *recv_id.cmac);

	// Cleanup
	free(recv_id.pID);
	free(recv_id.pCipherID);

	//----------------------------------------------------------


}

int main(int argc, char *argv[]){

    BIO *conn;

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

