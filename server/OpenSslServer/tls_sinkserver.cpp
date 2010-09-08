/*
 * File name: tls_anon_server.c
 * Date:      2010-06-15 12:22
 * Author:    Kristj�n R�narsson
 */

#include <syslog.h>
#include <string.h>

#include "tls_sinkserver.h"


using namespace std;

#define BUFSIZE 2048

// The constant used to derive K_STa from K_ST.
byte_ard cBeta[KEY_BYTES] = { 0x10, 0x9b, 0x58, 0xba, 0x59, 0xe0, 0xd6, 0x6e,
							  0xe9, 0xf7, 0x35, 0xab, 0x6a, 0x99, 0xe3, 0x61 };

// The constant used to derive K_STe from K_ST.
byte_ard cGamma[KEY_BYTES] = { 0xf1, 0x15, 0x3e, 0xb6, 0xb0, 0x1f, 0xa8, 0xc7,
							   0xa2, 0x3b, 0x9f, 0x9b, 0x95, 0x2d, 0xcc, 0x06 };

// The constant  used to derive K_STea from K_STe.
byte_ard cEpsilon[KEY_BYTES] = { 0x3c, 0xdd, 0x2d, 0x67, 0xdf, 0x88, 0xef, 0xb2,
					           0xe1, 0x31, 0x33, 0xe7, 0xc9, 0x3a, 0x63, 0xeb };

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

	//R = (byte_ard*)malloc(KEY_BYTES);  // REM?

	dbcd.hostName ="localhost";
	dbcd.userName = "tssink";
	dbcd.passWord = "pass";
	dbcd.dbName = "tsense";
}

/* Writes a message to the auth server over SSL/TLS and returns the number of
 * byter written or 0 if the call was not sucessuful. Returns <0 if an error 
 * occurred.
 */
int TlsSinkServer::writeToAuth(SSL *ssl, byte_ard* writeBuf, int len){

	int err = SSL_write(ssl, writeBuf, len);

	if(err <= 0){
        log_err_exit("Error writing to auth-server.");
	}

	return err;
}

/* Reads a message from the auth server over SSL/TLS and returns the number of
 * byter read. Returns 0 if the call was not sucessuful or <0 if an error 
 * occurred.
 */
int TlsSinkServer::readFromAuth(SSL *ssl, byte_ard* readBuf, int len){
	int err = SSL_read(ssl, readBuf, len);

	if(err <= 0){
        log_err_exit("Error reading from auth-server.");
	}

	return err;
}

/* A simple generic messge handling method that calls a specialized message 
 * routine after examining the first byte of an incoming message packet that
 * should contain the message ID.
 */
int TlsSinkServer::handleMessage(SSL *ssl, BIO* proxyClientRequestBio,
								 byte_ard *readBuf, int readLen)
{
	
	syslog(LOG_NOTICE, "%x", readBuf[0]);

	if(readBuf[0] == 0x10){
		handleIdResponse(ssl, proxyClientRequestBio, readBuf, readLen);
	}else if(readBuf[0] == 0x31){ 
		// Handshake message, regular rekey is ox30.
		handleRekey(ssl, proxyClientRequestBio, readBuf, readLen);
	}else{
        log_err_exit("Error, unsupported protocol message.");
	}
}

/* Recieves a buffer containin a message fromt the prxy client and forwards
 * this to the authorization server. The method then waits for a reply.
 * After verifying that he reply from the auth server is indeed a keytosink 
 * message the message is unpacked. The session key K_ST is stored locally. 
 * The encrypted palyoad is then sent on to the proxy client.
 */
void  TlsSinkServer::handleIdResponse(SSL *ssl, BIO* proxyClientRequestBio, 
									  byte_ard* readBuf, int readLen)
{

	byte_ard keyToSinkBuf[KEYTOSINK_FULLSIZE];

	// Forward the idresponse to the auth server.
	// ------------------------------------------
	writeToAuth(ssl, readBuf, readLen);

	// Read the response from the auth server.
	// ---------------------------------------
	int err = readFromAuth(ssl, keyToSinkBuf, KEYTOSINK_FULLSIZE);

    int status = (SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN)? 1 : 0;

    if(status){
        SSL_shutdown(ssl);
    } else {
        SSL_clear(ssl);
	}

	// Unpack the key to sink message ------------------------------------------

	struct message keyToSinkMsg;
	keyToSinkMsg.key = (byte_ard*)malloc(KEY_BYTES);
	keyToSinkMsg.ciphertext = (byte_ard*)malloc(KEYTOSINK_CRYPTSIZE);
 
	unpack_keytosink((void*)keyToSinkBuf, &keyToSinkMsg);

	if (keyToSinkMsg.msgtype != 0x11) {
		log_err_exit("Authentication server didn't accept the ID/Cipher!");
	}

	// Done unpacking the keytosink message ------------------------------------

	//byte_ard tmpID[] = { 0x30, 0x30, 0x30, 0x30, 0x31, 0x31, 0x00 };

	byte_ard tmpID[10]; 
	memcpy(tmpID, readBuf+1, 6);

/*
	syslog(LOG_NOTICE, "tmpID #1:");
	for(int i = 0; i < 6; i++){
		syslog(LOG_NOTICE, "%x", tmpID[i]);
	}											
*/

	//TsDbSinkSensorProfile(keyToSinkMsg.pPID, keyToSinkMsg.key,dbcd);
	TsDbSinkSensorProfile tssp(keyToSinkMsg.key, tmpID, dbcd);

	//-----------------------------------

/**/
	syslog(LOG_NOTICE, "KST1");
	for(int i = 0; i < KEY_BYTES*11; i++){
		syslog(LOG_NOTICE, "%x", tssp.getKstSched()[i]);
	}

	syslog(LOG_NOTICE, "KST1a");
	for(int i = 0; i < KEY_BYTES*11; i++){
		syslog(LOG_NOTICE, "%x", tssp.getKstaSched()[i]);
	}

	syslog(LOG_NOTICE, "KST1e");
	for(int i = 0; i < KEY_BYTES*11; i++){
		syslog(LOG_NOTICE, "%x", tssp.getKsteSched()[i]);
	}

	syslog(LOG_NOTICE, "KST1ea");
	for(int i = 0; i < KEY_BYTES*11; i++){
		syslog(LOG_NOTICE, "%x", tssp.getKsteaSched()[i]);
	}
/**/
	//-----------------------------------

	tssp.persist();

	// Pack keytosense message -------------------------------------------------

	byte_ard keyToSenseBuf[KEYTOSENS_FULLSIZE];

	pack_keytosens(&keyToSinkMsg, keyToSenseBuf);

	// Send keytosense message to sensor.
	// ----------------------------------
	writeToProxyClient(proxyClientRequestBio, keyToSenseBuf, 
		KEYTOSENS_FULLSIZE);

	free (keyToSinkMsg.ciphertext);
	free (keyToSinkMsg.key);

	// Done packing key to sense message ---------------------------------------

	// Close connection to proxy client.
	BIO_free(proxyClientRequestBio);
	ERR_remove_state(0);
}

void TlsSinkServer::handleRekey(SSL *ssl, BIO* proxyClientRequestBio,
                                      byte_ard* readBuf, int readLen)
{
	
	byte_ard tmpID[10]; 
	memcpy(tmpID, readBuf+1, 6);

/*
	syslog(LOG_NOTICE, "tmpID #2:");
	for(int i = 0; i < 6; i++){
		syslog(LOG_NOTICE, "%x", tmpID[i]);
	}											
*/

	try {
		TsDbSinkSensorProfile *tssp = new TsDbSinkSensorProfile(tmpID, dbcd);

/*
		syslog(LOG_NOTICE, "KST2");
		for(int i = 0; i < KEY_BYTES*11; i++){
			syslog(LOG_NOTICE, "%x", tssp->getKstSched()[i]);
		}

		syslog(LOG_NOTICE, "KST2a");
		for(int i = 0; i < KEY_BYTES*11; i++){
			syslog(LOG_NOTICE, "%x", tssp->getKstaSched()[i]);
		}

		syslog(LOG_NOTICE, "KST2e");
		for(int i = 0; i < KEY_BYTES*11; i++){
			syslog(LOG_NOTICE, "%x", tssp->getKsteSched()[i]);
		}

		syslog(LOG_NOTICE, "KST2ea");
		for(int i = 0; i < KEY_BYTES*11; i++){
			syslog(LOG_NOTICE, "%x", tssp->getKsteaSched()[i]);
		}

		syslog(LOG_NOTICE, "readBuf");
		for(int i = 0; i < REKEY_FULLSIZE; i++){
			syslog(LOG_NOTICE, "%x", readBuf[i]);
		}
*/

		// Unpack newkey message -----------------------------------------------

		// Create the struct the recieve the packet to and malloc memory.
		struct message newkeymsg;
		newkeymsg.pID = (byte_ard*)malloc(ID_SIZE+1);  // Null term.
		newkeymsg.ciphertext = (byte_ard*)malloc(REKEY_CRYPTSIZE);

		// Put the data in the struct
		unpack_rekey(readBuf, (const u_int32_ard*) (tssp->getKstSched()), 
						&newkeymsg);


		int validMac = verifyAesCMac((const u_int32_ard*)(tssp->getKstaSched()),
										newkeymsg.ciphertext,
										REKEY_CRYPTSIZE,
										newkeymsg.cmac);

		syslog(LOG_NOTICE, "nonce:  %x", newkeymsg.nonce);

		if(validMac == 0){
			log_err_exit("Mac of incoming keytosens message did not match");
		}

		// Done unpacking newkey message ---------------------------------------


		// Pack rekey ----------------------------------------------------------

		// Done packing rekey --------------------------------------------------

		free (newkeymsg.pID);
		free (newkeymsg.ciphertext);

		// Close connection to proxy client.
		BIO_free(proxyClientRequestBio);
		ERR_remove_state(0);

		delete tssp;

	} catch(runtime_error rex) {
		syslog(LOG_ERR, "%s", rex.what());
	}
}

/* This method is called after a BIO channel connection from the proxy client 
 * has been accepted. What follows is:
 *    - The incoming message from the client is read
 *    - A BIO channel to the authorization server is created and tied to 
 *      an SSL object.
 *    - Post connection SSL verifications are performed.
 *    - Achild process is forked. 
 * The parent then returns to wait for another proxy client connection. The 
 * child calls a generic message handler metod which in turn calls the 
 * appropriate specialist handler method for the message in question.
 */
void TlsSinkServer::serverFork(BIO *proxyClientRequestBio, BIO* authServerBio){
	byte_ard readBuf[BUFSIZE];
    SSL *ssl;

	// Read theincoming message from the proxy client.
	int readLen = readFromProxyClient(proxyClientRequestBio, readBuf, BUFSIZE);

	// Construct connection string to connect to auth-server.
	string hostPort = _authServerAddr;
	hostPort.append(":");
	hostPort.append(_authServerPort);

	syslog(LOG_NOTICE, "Connecting to authServer on: %s", hostPort.c_str());

	// Obtain a BIO channel for connecting to the auth-server.
	syslog(LOG_NOTICE, "Connecting to authServer: %s", hostPort.c_str());
	authServerBio = BIO_new_connect((char*)hostPort.c_str());

	if(!authServerBio){
		log_err_exit("Error createing connection BIO");
	}

	// Connect the auth-server BIO channel.
	if(BIO_do_connect(authServerBio) <= 0){
		log_err_exit("Error connecting to remote machine");
	}

	// Get a new SSL structure for this auth-server connection.
	if(!(ssl = SSL_new(ctx))){
		log_err_exit("Error creating an SSL context.");
	}

	// Connect the SSL server with the BIOs it will use.
	SSL_set_bio(ssl, authServerBio, authServerBio);

	if(SSL_connect(ssl) <= 0){
        log_err_exit("Error connecting SSL object.");
    }		

	// Post connection verification, does things like:
	//  - Compare url,name,address  of originator with same in certificate.
	//  - Checks revocation status.
	//  - Chekcs usage fields in certificate.
    doVerify(ssl, _authServerAddr);

    syslog(LOG_NOTICE, "SSL Connection auth-server opened.");

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

	// FIXME: What if messageSize > bufsize?
	// Contact the Auth server.
	handleMessage(ssl, proxyClientRequestBio, readBuf, readLen);

    syslog(LOG_NOTICE, "SSL Connection to auth-server closed.\n");

    SSL_free(ssl);
    ERR_remove_state(0);


    if(pid ==  0){ // The child terminates execution here.
		syslog(LOG_ERR, "Child is exiting.");
        exit(0);
    }
}

/* Reads a message from the proxy client over a BIO cannel  and returns the 
 * number of bytes read. Returns 0 if the call was not sucessuful or <0 if 
 * an error occurred.
 */
int  TlsSinkServer::readFromProxyClient(BIO *proxyClientRequestBio, 
						byte_ard *readBuf, int len)
{
	int err = BIO_read(proxyClientRequestBio, readBuf, len);

	if(err <= 0){
		syslog(LOG_ERR, "Read error: %d", err);
	}

	return err;
}

/* Writes a message to the proxy client over a BIO channel  and returns the 
 * number of bytes written or 0 if the call was not sucessuful. Returns <0 if
 * an error occurred.
 */
int TlsSinkServer::writeToProxyClient(BIO *proxyClientRequestBio, byte_ard *writeBuf,
									  int len)
{

	int err = BIO_write(proxyClientRequestBio, writeBuf, len);

	if(err <= 0){
		syslog(LOG_ERR, "Write error: %d", err);
	}

	return err;
}

/* Main server loop, just sits and waits for incoming messages, as soon as one
 * arrives a child process is forked an the loop returns to waiting for another
 * connection attempt to accept.
 */
void TlsSinkServer::serverMain(){
    BIO *authServerBio, *proxyClientAcceptBio, *proxyClientRequestBio;

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

	syslog(LOG_NOTICE, "Listening for Proxy Client requests on %s", 
				_serverListenPort);

	int err;
	while(true){

		syslog(LOG_NOTICE, "Waiting for new BIO connection.");

		// ... subsequent calls to BIO_do_accept cause the program to stop and
		// wait for an incoming connection from a client.
		if(BIO_do_accept(proxyClientAcceptBio) <= 0){
			log_err_exit("Error accepting proxy cilent connection");
		}

		syslog(LOG_NOTICE, "Accepted new BIO connection.");

		// Pop a BIO channel for an incoming connection off the accept BIO.
		proxyClientRequestBio = BIO_pop(proxyClientAcceptBio);

		// Fork a clild that uses our auth-server bio channel to get a 
		// tagged response from the auth-server.
		serverFork(proxyClientRequestBio, authServerBio);
		
		syslog(LOG_NOTICE, "-------------");

	}

    //SSL_CTX_free(ctx);
    //BIO_free(conn);
}

