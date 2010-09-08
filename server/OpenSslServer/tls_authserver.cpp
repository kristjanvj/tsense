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
TlsAuthServer::TlsAuthServer(	const char* sinkServerAddr,
								const char *serverAddr,
								const char *serverListenPort) : 
							TlsBaseServer(	SERVER_MODE,
											serverAddr, 
											serverListenPort)
{
	
	// FIXME, At the moment this only allows for the handling of a single 
	// sensor whose keys and constants are hardcoded here. This infromation
	// should be read from a file or a database and there should be a map
	// container or a database table that contains the sesnor profiles.

	_sinkServerAddr = sinkServerAddr;

	// Hardcode a  profile for test sensor -------------------------------------

	byte_ard K_AT[] = { 0x09, 0xd2, 0x0c, 0x10, 0xa5, 0xd1, 0x33, 0x1d, 0x15, 0xc6, 0x20, 0x1a, 0x92, 0x9e, 0x83, 0xaf }; // #2
	//byte_ard K_AT[] = {0xcf, 0xb5, 0x08, 0x8d, 0xc6, 0x11, 0x06, 0x24, 0xc1, 0x38, 0x62, 0x41, 0x6f, 0xc0, 0x13, 0xaa }; // #4

	// Does this vary from T to T?
	byte_ard alpha[] = { 0x65, 0xa4, 0x56, 0x5d, 0x09, 0xd6, 0x7e, 0xfa, 0xb5, 0x9d, 0x6f, 0x1c, 0xc1, 0xc5, 0x79, 0x9d };

	K_at = new TSenseKeyPair(K_AT, alpha);

	for ( int i=0; i<16; i++ )
		syslog(LOG_NOTICE, "crypto: 0x%.2x", K_at->getCryptoKey()[i]);
	for ( int i=0; i<16; i++)
		syslog(LOG_NOTICE, "mac: 0x%.2x", K_at->getMacKey()[i]);
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
	// Start unpack idresponse -------------------------------------------------

	struct message recv_id;

    // Allocate memory for the ID and '\0'
    recv_id.pID = (byte_ard*)malloc(ID_SIZE+1);
    recv_id.ciphertext = (byte_ard*)malloc(IDMSG_CRYPTSIZE);

    unpack_idresponse(	(void*) idResponseBuf,
						(const u_int32_ard*) (K_at->getCryptoKeySched()),
						&recv_id);

    syslog(LOG_NOTICE,"Received id message from: %d%d-%d%d%d%d", recv_id.pID[0],recv_id.pID[1],recv_id.pID[2],recv_id.pID[3],recv_id.pID[4],recv_id.pID[5]);
    syslog(LOG_NOTICE,"Nonce: %d", recv_id.nonce);

    printf("Done unpacking encrypted packet:\n");

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

//    free(recv_id.pID);
    free(recv_id.ciphertext);

	// End unpack idresponse ---------------------------------------------------

	// TODO: Use /dev/urandom

	// Generate K_ST.
	srand((unsigned)time(0));

	byte_ard K_ST[BLOCK_BYTE_SIZE];
	for(int i=0; i<BLOCK_BYTE_SIZE; i++){
		K_ST[i] = (rand() % 0x1ff);
		syslog(LOG_NOTICE, "KS_T %x", K_ST[i]);
	}

	// Pack the keytosink message ----------------------------------------------

	struct message sendmsg;
	sendmsg.renewal_timer = 0; 				// Not using this at present.
	sendmsg.nonce = recv_id.nonce;	// Pass on the nonce from T.
        sendmsg.pID = recv_id.pID;

	sendmsg.key =  K_ST;

	byte_ard keyToSinkBuf[KEYTOSINK_FULLSIZE];

	pack_keytosink(	&sendmsg,
					(const u_int32_ard*) (K_at->getCryptoKeySched()),
					(const u_int32_ard*) (K_at->getMacKeySched()), 
					keyToSinkBuf);

	free(recv_id.pID);

	// Done packing the keytosikn message --------------------------------------

	// Dispatch ketosink message to sink.
	writeToSink(ssl, keyToSinkBuf, KEYTOSINK_FULLSIZE);

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
