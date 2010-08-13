/*
 * File name: tls_anon_server.c
 * Date:      2010-06-15 12:22
 * Author:    Kristján Rúnarsson
 */

#include "TlsSinkServer.h"
#include <syslog.h>
#include <string.h>

#include "TlsSinkServer.h"


using namespace std;

/* Parameters:
 *  - authServerAddr, IP/FQDN for the authentication server.
 *  - authServerPort,  The port the Auth server listens on.
 *  - serverAddr, Our own IP/FQDN.
 *  - serverListenPort, The port this server listens for connections
 *                      from the proxy client.
 */
TlsSinkServer::TlsSinkServer(	const char *authServerAddr,
								const char *authServerPort, 
					 			const char *serverAddr,
								const char *serverListenPort) :
						TlsBaseServer(CLIENT_MODE, serverAddr, serverListenPort)
{
	_authServerAddr = authServerAddr;
	_authServerPort = authServerPort;

	syslog(LOG_NOTICE, "_authServerAddr: %s", _authServerAddr);
	syslog(LOG_NOTICE, "_authServerPort: %s", _authServerPort);
	syslog(LOG_NOTICE, "_serverAddr: %s", _serverAddr);
	syslog(LOG_NOTICE, "_authServerPort: %s", _serverListenPort);
}

int TlsSinkServer::sendEcho(SSL *ssl, char* readBuf, char* writeBuf){

	int err;

	// Write what came in from the proxy client to our auth-server.
	writeToAuth(ssl, writeBuf, (int) strlen(writeBuf));

	// Retrieve the tagged response from the auth-server.
	err = readFromAuth(ssl, readBuf, 80);
	
	//sleep(20);

    return (SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN)? 1 : 0;
}

int TlsSinkServer::writeToAuth(SSL *ssl, char* writeBuf, int len){
	syslog(LOG_NOTICE, "Sink wWrote to Auth: %s", writeBuf);

	int err = SSL_write(ssl, writeBuf, len);

	if(err <= 0){
        log_err_exit("Error writing to auth-server.");
	}

	return err;
}

int TlsSinkServer::readFromAuth(SSL *ssl, char* readBuf, int len){
	int err = SSL_read(ssl, readBuf, len);

	if(err <= 0){
        log_err_exit("Error reading from auth-server.");
	}

	// Null terminate string for syslog.
	readBuf[err] = 0x0;

	syslog(LOG_NOTICE, "Sink read from Auth: %s", readBuf);

	return err;
}

void TlsSinkServer::serverFork(BIO *proxyClientReqestBio, void *arg, 
								char* readBuf, char* writeBuf){
    SSL *ssl = (SSL*) arg;

	if(SSL_connect(ssl) <= 0){
        log_err_exit("Error connecting SSL object.");
    }		

	// Post connection verification, does things like:
	//  - Compare url,name,address  of originator with same in certificate.
	//  - Checks revocation status.
	//  - Chekcs usage fields in certificate.
    doVerify(ssl, _authServerAddr);

    syslog(LOG_NOTICE, "SSL Connection opened.");

	// Fork a child process that should be an exact copy of the parent.
	// it will continue servicing the proxy client's request while the.
	// parent exits and waits for a new request.
	pid_t pid = fork();
    if(pid < 0){ //Fork a child process.
        log_err_exit("Unable to fork TLS server process.");
        throw runtime_error("A call to fork() failed.");
        exit(0);
    } else if(pid!=0){ // The parent exits method here.
        return;
    }

	// Contact the Auth server.
    if(sendEcho(ssl, readBuf, writeBuf)){
        SSL_shutdown(ssl);
    } else {
        SSL_clear(ssl);
    }

    syslog(LOG_NOTICE, "SSL Connection to auth-server closed.\n");

    SSL_free(ssl);
    ERR_remove_state(0);

	// Write what came in from the auth-server back to our proxy client.
	writeToProxyClient(proxyClientReqestBio, readBuf);

	// Close connection to proxy client.
	BIO_free(proxyClientReqestBio);
	ERR_remove_state(0);

    if(pid ==  0){ // The child terminates execution here.
		syslog(LOG_ERR, "Child is exiting.");
        exit(0);
    }
}

int  TlsSinkServer::readFromProxyClient(BIO *proxyClientReqestBio, char *readBuf){
	int err = BIO_read(proxyClientReqestBio, readBuf, 80);

	// Null terminate string for syslog.
	readBuf[err] = 0x0;
        
	if(err <= 0){
		syslog(LOG_ERR, "Read error: %d", err);
	}

	return err;
}

int TlsSinkServer::writeToProxyClient(BIO *proxyClientReqestBio, char *writeBuf){

	int err = BIO_write(proxyClientReqestBio, writeBuf, strlen(writeBuf));

	if(err <= 0){
		syslog(LOG_ERR, "Write error: %d", err);
	}

	return err;
}

void TlsSinkServer::serverMain(){
    BIO *authServerBio, *proxyClientAcceptBio, *proxyClientReqestBio;
    SSL *ssl;
    //SSL_CTX *ctx;

	// Set up the the SSL context for connecting to the auth-server.
    //ctx = setupServerCtx(CLIENT_MODE);

	// Connection string to connect to auth-server.
	string hostPort = _authServerAddr;
	hostPort.append(":");
	hostPort.append(_authServerPort);

	syslog(LOG_NOTICE, "Connecting to authServer on: %s", hostPort.c_str());

	initOpenSsl();

	// Creates a BIO object and returns it as an accept BIO object.
    proxyClientAcceptBio = BIO_new_accept((char*) _serverListenPort);

    if(!proxyClientAcceptBio){
        log_err_exit("Error creating client proxy listener socket.");
    }

	// The first call to BIO_do_accept binds the socket to the correct port...
    if(BIO_do_accept(proxyClientAcceptBio) <= 0){
        log_err_exit("Error binding client proxy listener socket.");
    }

	syslog(LOG_NOTICE, "Listening for Proxy Client requests on %s", _serverListenPort);

	int err;
	while(true){

		char readBuf[80];
		char writeBuf[80] = "SinkServer <-> ";

		// ... subsequent calls to BIO_do_accept cause the program to stop and
		// wait for an incoming connection from a client.
		if(BIO_do_accept(proxyClientAcceptBio) <= 0){
			log_err_exit("Error accepting proxy cilent connection");
		}

		// Pop a BIO channel for an incoming connection off the accept BIO.
		proxyClientReqestBio = BIO_pop(proxyClientAcceptBio);

		readFromProxyClient(proxyClientReqestBio, readBuf);

        syslog(LOG_NOTICE, "Sink read from Client: %s", readBuf);

		// Obtain a BIO for connecting to the auth-server.
		syslog(LOG_NOTICE, "Connecting to authServer: %s", hostPort.c_str());
		authServerBio = BIO_new_connect((char*)hostPort.c_str());

		if(!authServerBio){
			log_err_exit("Error createing connection BIO");
		}

		// Connect the auth-server BIO channe.
		if(BIO_do_connect(authServerBio) <= 0){
			log_err_exit("Error connecting to remote machine");
		}

		// Get a new SSL structure for this auth-server connection.
		if(!(ssl = SSL_new(ctx))){
			log_err_exit("Error creating an SSL context.");
		}

		// Connect the SSL server with the BIOs it will use.
		SSL_set_bio(ssl, authServerBio, authServerBio);

		// Append what came in from the proxy client to our write buffer.
		strcat(writeBuf, readBuf); 

		// Fork a clild that uses our auth-server bio channel to get a 
		// tagged response from the auth-server.
		serverFork(proxyClientReqestBio, ssl, readBuf, writeBuf);
		
		syslog(LOG_NOTICE, "-------------");

	}

    //SSL_CTX_free(ctx);
    //BIO_free(conn);
}

