/*
 * File name: TlsAuthServer.cpp
 * Date:      2010-08-03 16:10
 * Author:    Kristjan Runarsson
 */

#include "tls_authserver.h"
#include <syslog.h>
#include <string.h>

using namespace std;

#define BUFSIZE 2048

/* This class implements a simple authorization server for TSense. It 
 * constructs a set of profiles for each authorized sensor. Arguments
 * are:
 *   - sinkServerAddr, the FQDN of the sink server.
 *   - serverAddr, the authorization servers own FQDN.
 *   - serverListenPort, the port on which the authorization server listens.
 */
TlsAuthServer::TlsAuthServer( 	const char* sinkServerAddr,
				const char *serverAddr,
				const char *serverListenPort) : 
				TlsBaseServer(	SERVER_MODE,
						serverAddr, 
						serverListenPort)
{
	_sinkServerAddr = sinkServerAddr;
}

TlsAuthServer::~TlsAuthServer(){
	delete K_at;
}

/* A simple generic messge handling method that calls a specialized message 
 * routine after examining the first byte of an incoming message packet that
 * should contain the message ID.
 */
void TlsAuthServer::handleMessage(SSL *ssl) {
	int readLen;
	byte_ard readBuf[BUFSIZE];

	// FIXME: What if messageSize > bufsize?
 	// Read from the sink because we need the message id.
	readLen = readFromSink(ssl, readBuf, BUFSIZE);

	// Now call the appropriate handler.
	if(readBuf[0] == 0x10){
		handleIdResponse(ssl, readBuf, readLen);
	}else{
		log_err_exit("Error, unsupported protocol message.");
	}
}

void TlsAuthServer::handleIdResponse(SSL *ssl, byte_ard *idResponseBuf, 
										int readLen) 
{
	// Start sensor identification -----------------------------------------

	byte_ard sensorId[ID_SIZE];
	memcpy(sensorId,idResponseBuf+1,ID_SIZE);

	char szSensorId[20];
	sprintf(szSensorId,"%d%d-%d%d%d%d",
				sensorId[0],sensorId[1],sensorId[2],
				sensorId[3],sensorId[4],sensorId[5]);

	// This is the plaintext sensor id. Now, lets see if we know the 
	// corresponding secret key
	syslog(LOG_NOTICE,"Received id message from tsensor %s",szSensorId); 

	byte_ard K_AT[KEY_BYTES];

	// This is the alpha for deriving the MAC key.
	// FIXME Can be removed once the key derivation header has been included.
	byte_ard alpha[] = {0x65, 0xa4, 0x56, 0x5d, 0x09, 0xd6, 0x7e, 0xfa, 
						0xb5, 0x9d, 0x6f, 0x1c, 0xc1, 0xc5, 0x79, 0x9d };

	//
	// Here are some hardcoded encryption keys -- private sensor IDs.
	// FIXME Eventually read from file or database. 
	//

	// Device 01-0002
	byte_ard K_AT_0002[] = {0x09, 0xd2, 0x0c, 0x10, 0xa5, 0xd1, 0x33, 0x1d, 
							0x15, 0xc6, 0x20, 0x1a, 0x92, 0x9e, 0x83, 0xaf };
	byte_ard K_AT_0004[] = {0xcf, 0xb5, 0x08, 0x8d, 0xc6, 0x11, 0x06, 0x24, 
							0xc1, 0x38, 0x62, 0x41, 0x6f, 0xc0, 0x13, 0xaa };
	byte_ard K_AT_000A[] = {0x0c, 0xbb, 0x0a, 0x6f, 0xe8, 0x1b, 0x20, 0x17, 
							0x14, 0xa1, 0xae, 0x4b, 0xb2, 0xea, 0x5e, 0x00 };

	// For now, using the last byte as unique sensor identifier does the trick.
	switch(sensorId[5])
	{
		case 0x02:
			syslog(LOG_NOTICE,"Using keyset 2");
			memcpy(K_AT,K_AT_0002,KEY_BYTES);
			break;
		case 0x04:
			syslog(LOG_NOTICE,"Using keyset 4");
			memcpy(K_AT,K_AT_0004,KEY_BYTES);
			break;
		case 0x0A:
			syslog(LOG_NOTICE,"Using keyset A");
			memcpy(K_AT,K_AT_000A,KEY_BYTES);
			break;
		default:
			syslog(LOG_ERR,"UNKNOWN TSENSOR");
			return; // TODO: Handle better
	}

	// Construct the encryption and MAC key pair.
	K_at = new TSenseKeyPair(K_AT, alpha);
	
	// Start unpack idresponse -------------------------------------------------
	
	// Allocate memory for the ID and '\0'	
	struct message recv_id;
	recv_id.pID = (byte_ard*)malloc(ID_SIZE+1);
	recv_id.ciphertext = (byte_ard*)malloc(IDMSG_CRYPTSIZE);
	// Unpack and decrypt the message
	unpack_idresponse((void*) idResponseBuf,
			  (const u_int32_ard*) (K_at->getCryptoKeySched()),
			  &recv_id);

	// Check the cMAC on the incoming idresponse
	int validMac = verifyAesCMac((const u_int32_ard*) (K_at->getMacKeySched()),
								recv_id.ciphertext,
								IDMSG_CRYPTSIZE,
								recv_id.cmac);

	if(validMac != 1){
		syslog(LOG_ERR, "%s", "The idresponse cmac did not check out!");

		// FIXME: When the error message is ready one should be packed here,
		// sent to T, and the method should shut down the SSL connection and 
		// return.

		//int status = (SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN)? 1 : 0;

		//if(status){
		//	SSL_shutdown(ssl);
		//} else {
		//	SSL_clear(ssl);
		//}
	}
	else {
		syslog(LOG_NOTICE, "%s", "The idresponse cmac checked out ok!");
	}


	// End unpack idresponse ---------------------------------------------------

	
	// Check the nonce and id --------------------------------------------------

	syslog(LOG_NOTICE,"Nonce received from %s: %d", szSensorId, recv_id.nonce);
	// TODO: Store the nonce along with sensor profile and check for 
	// consistency, replays etc.
	// Also keep track of the last authentication time etc.

	// Quit if the ciphered and plain sensor IDs do not match. This indicates
	// either an error in the protocol or that the sender does not have the
	// proper key to encrypt the message.
	if ( strncmp( (char *)sensorId, (char *)recv_id.pID, 6 ) != 0 ) {
		log_err_exit("Plaintext and ciphered IDs did not match!");
	}

	// Generate the session key ------------------------------------------------

	// TODO: Use /dev/urandom

	// Generate K_ST.
	byte_ard K_ST[BLOCK_BYTE_SIZE];
	generateKey(K_ST);	// Call the key generation function in aes_utils

	char szKeyStr[50];
	sprintf(szKeyStr,
			"%.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x "
			"%.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x",
			K_ST[0], K_ST[1], K_ST[2], K_ST[3], 
			K_ST[4], K_ST[5], K_ST[6], K_ST[7],
			K_ST[8], K_ST[9], K_ST[10], K_ST[11], 
			K_ST[12], K_ST[13], K_ST[14], K_ST[15] );

	syslog(LOG_NOTICE,"Session key for %s: %s", szSensorId, szKeyStr);

	// Pack the keytosink message ----------------------------------------------

	struct message sendmsg;
	sendmsg.renewal_timer = 0; 				// Not using this at present.
	sendmsg.nonce = recv_id.nonce;	// Pass on the nonce from T.
        sendmsg.pID = (byte_ard*)malloc(ID_SIZE);

	memcpy(sendmsg.pID,recv_id.pID,ID_SIZE);

	sendmsg.key =  K_ST;

	byte_ard keyToSinkBuf[KEYTOSINK_FULLSIZE];

	pack_keytosink(	&sendmsg,
					(const u_int32_ard*) (K_at->getCryptoKeySched()),
					(const u_int32_ard*) (K_at->getMacKeySched()), 
					keyToSinkBuf);

   	free(recv_id.ciphertext); // Remember to clean up all malloced
	free(recv_id.pID);

	// Done packing the keytosink message --------------------------------------

	// Dispatch ketosink message to sink.
	writeToSink(ssl, keyToSinkBuf, KEYTOSINK_FULLSIZE);

	syslog(LOG_NOTICE,
			"Session key package for sensor %s dispatched to sink", szSensorId);

	int status = (SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN)? 1 : 0;

	if(status){
		SSL_shutdown(ssl);
	} else { 
		SSL_clear(ssl);
	}
}

/* Writes a message to the sink server over SSL/TLS and returns the number of
 * bytes written or 0 if the call was not sucessuful. Returns <0 if an error 
 * occurred.
 */
int TlsAuthServer::writeToSink(SSL *ssl, byte_ard* writeBuf, int len){

	int err = SSL_write(ssl, writeBuf, len);
	
	if(err <= 0){
		log_err_exit("Error writing to auth-server.");
	}

   return err;
}

/* Reads a message from the sink server over SSL/TLS and returns the number of
 * bytes read. Returns 0 if the call was not sucessuful or <0 if an error 
 * occurred.
 */
int TlsAuthServer::readFromSink(SSL *ssl, byte_ard* readBuf, int len){
	int err = SSL_read(ssl, readBuf, len);

	if(err <= 0){
		log_err_exit("Error reading from sink-server.");
	}

	return err;
}

/* Forks a child process to handle an incoming message from the sink. The 
 * child exits after the message has been processed, the parent renturns
 * immediately after forking to wait for another incoming message.
 */
void TlsAuthServer::serverFork(void *arg, BIO* proxyClientRequestBio){
	SSL *ssl = (SSL*) arg;
	
	if(SSL_accept(ssl) <= 0){
		log_err_exit("Error accepting SSL connection.");
	}

    // Post connection verification, does things like:
	//  - Compare url,name,address  of originator with same in certificate.
	//  - Checks revocation status.
	//  - Chekcs usage fields in certificate.
	doVerify(ssl, _sinkServerAddr);

	syslog(LOG_NOTICE, "SSL Connection opened.\n");

    // Fork a child process that should be an exact copy of the parent.
	// it will continue servicing the proxy client's request while the.
	// parent exits and waits for a new request.
	int pid = fork();
	if(pid < 0){ //Fork a child process.
		log_err_exit("Unable to fork TLS server process.");
		throw runtime_error("A call to fork() failed.");
		exit(0);
	} else if(pid!=0){ // The parent exits here.
		return;
	}

	// Contacts sink-server.
	handleMessage(ssl);

	syslog(LOG_NOTICE, "SSL Connection closed.\n");

	SSL_free(ssl);
	ERR_remove_state(0);

	//BIO_free(proxyClientRequestBio);
	//ERR_remove_state(0);

	if(pid ==  0){ // the child exits here.
		exit(0);
	}
}

/* Main server loop, just sits and waits for incoming messages, as soon as one
 * arrives a child process is forked an the loop returns to waiting for another
 * connection attempt to accept.
 */
void TlsAuthServer::serverMain(){
    BIO *sinkServerAcceptBio, *sinkServerRequestBio;
	SSL *ssl;
	//SSL_CTX *ctx;

	// Creates a BIO object and returns it as an accept BIO object.
	sinkServerAcceptBio = BIO_new_accept((char*) _serverListenPort);

	//ctx = setupServerCtx(SERVER_MODE);
	
	if(!sinkServerAcceptBio){
		log_err_exit("Error creating server socket.");
	}

	
	// The first call to BIO_do_accept binds the socket to the correct port...
	if(BIO_do_accept(sinkServerAcceptBio) <= 0){
		log_err_exit("Error binding server socket.");
	}

	pid_t   pid;
	while(true){

		// ... subsequent calls to BIO_do_accept cause the program to stop and
		// wait for an incoming connection from a client.
		if(BIO_do_accept(sinkServerAcceptBio) <= 0){
			log_err_exit("Error accepting connection");
		}

		// Pop a BIO channel for an incoming connection off the accept BIO.
		sinkServerRequestBio = BIO_pop(sinkServerAcceptBio);

		// Get a new SSL structure for this auth-server connection.
		if(!(ssl = SSL_new(ctx))){
			log_err_exit("Error creating SSL context.");
		}
		
		// Connect the SSL server with the BIOs it will use.
		SSL_set_bio(ssl, sinkServerRequestBio, sinkServerRequestBio);

		serverFork(ssl, sinkServerRequestBio);
	}
	
	SSL_CTX_free(ctx);
	BIO_free(sinkServerAcceptBio);
}
