/*
 * File name: TlsAuthServer.cpp
 * Date:      2010-08-03 16:10
 * Author:    Kristjan Runarsson
 */

#include "TlsAuthServer.h"
#include <syslog.h>
#include <string.h>

using namespace std;

TlsAuthServer::TlsAuthServer(const char *serverAddr, const char *serverListenPort) : 
							TlsBaseServer(serverAddr, serverListenPort) {
}

int TlsAuthServer::doEcho(SSL *ssl){
	int err;
	char readBuf[80];

	err = readFromSink(ssl, readBuf, 80);
			
	//sleep(20);

	char writeBuf[80] = "AuthServer <-> ";
		
	strcat(writeBuf, readBuf);

	writeToSink(ssl, writeBuf, strlen(writeBuf));

	return (SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN)? 1 : 0;
}

int TlsAuthServer::writeToSink(SSL *ssl, char* writeBuf, int len){
	syslog(LOG_ERR, "Auth wrote to Sink: %s", writeBuf);

	int err = SSL_write(ssl, writeBuf, len);

	if(err <= 0){
		log_err_exit("Error writing to auth-server.");
	}

   return err;
}

int TlsAuthServer::readFromSink(SSL *ssl, char* readBuf, int len){
	int  err = SSL_read(ssl, readBuf, len);

	if(err <= 0){
		log_err_exit("Error reading from sink-server.");
	}

	// Null terminate string for syslog.
	readBuf[err] = 0x0;

	syslog(LOG_ERR, "Auth read from Sink: %s", readBuf);

	return err;
}


void TlsAuthServer::serverFork(void *arg){
	SSL *ssl = (SSL*) arg;
	
	if(SSL_accept(ssl) <= 0){
		log_err_exit("Error accepting SSL connection.");
	}

    // Post connection verification, does things like:
	//  - Compare url,name,address  of originator with same in certificate.
	//  - Checks revocation status.
	//  - Chekcs usage fields in certificate.
	doVerify(ssl);

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
	if(doEcho(ssl)){
		SSL_shutdown(ssl);
	} else { 
		SSL_clear(ssl);
	}

	fprintf(stderr, "SSL Connection closed.\n");

	SSL_free(ssl);
	ERR_remove_state(0);

	if(pid ==  0){ // the child exits here.
		exit(0);
	}
}

void TlsAuthServer::serverMain(){
    BIO *sinkServerAcceptBio, *sinkServerRequestBio;
	SSL *ssl;
	SSL_CTX *ctx;

	// Creates a BIO object and returns it as an accept BIO object.
	sinkServerAcceptBio = BIO_new_accept((char*) _serverListenPort);

	ctx = setupServerCtx(SERVER_MODE);
	
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

		serverFork(ssl);
	}
	
	SSL_CTX_free(ctx);
	BIO_free(sinkServerAcceptBio);
}
