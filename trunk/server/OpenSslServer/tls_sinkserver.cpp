/*
 * File name: tls_anon_server.c
 * Date:      2010-06-15 12:22
 * Author:    Kristján Rúnarsson
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
								TlsBaseServer(	CLIENT_MODE, serverAddr, 
												serverListenPort )
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
	
	//syslog(LOG_NOTICE, "%x", readBuf[0]);

	if(readBuf[0] == 0x10){
		handleIdResponse(ssl, proxyClientRequestBio, readBuf, readLen);
	}else if(readBuf[0] == 0x31){ 
		// Handshake message, regular rekey is ox30.
		handleRekey(ssl, proxyClientRequestBio, readBuf, readLen);
	}else if(readBuf[0] == 0x01){ 
		handleData(ssl, proxyClientRequestBio, readBuf, readLen);
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
	char szPid[20];
	sprintf(szPid,"%d%d-%d%d%d%d",
			readBuf[1],readBuf[2],readBuf[3],readBuf[4],readBuf[5],readBuf[6]);

	syslog(LOG_NOTICE,"Handling incoming idresponse message. PID: %s",szPid); 

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
	keyToSinkMsg.pID=(byte_ard*)malloc(ID_SIZE);
 
	unpack_keytosink((void*)keyToSinkBuf, &keyToSinkMsg);

	if (keyToSinkMsg.msgtype != 0x11) {
		log_err_exit("Authentication server didn't accept the ID/Cipher!");
	}

	syslog(LOG_NOTICE,"Authentication server accepted sensor with ID %s",szPid);

	// Done unpacking the keytosink message ------------------------------------

	byte_ard tmpID[10]; 
	memcpy(tmpID, keyToSinkMsg.pID, ID_SIZE);

	try {
		TsDbSinkSensorProfile tssp(keyToSinkMsg.key, tmpID, dbcd);

		tssp.persist();

	} catch(runtime_error rex) {
		log_err_exit(rex.what());
	}

	// Pack keytosense message -------------------------------------------------

	byte_ard keyToSenseBuf[KEYTOSENS_FULLSIZE];

	pack_keytosens(&keyToSinkMsg, keyToSenseBuf);

	syslog(LOG_NOTICE,"Dispatching session key packet to tsensor %s",szPid);

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

	char szPid[20];
	sprintf(szPid,"%d%d-%d%d%d%d",
			readBuf[1],readBuf[2],readBuf[3],readBuf[4],readBuf[5],readBuf[6]);

	syslog(LOG_NOTICE,"Rekey request received from device %s",szPid);

	try {
		TsDbSinkSensorProfile *tssp = new TsDbSinkSensorProfile(tmpID, dbcd);


		// Unpack rekey message -----------------------------------------------

		// Create the struct the recieve the packet to and malloc memory.
		struct message rekeymsg;
		rekeymsg.pID = (byte_ard*)malloc(ID_SIZE+1);  // Null term.
		rekeymsg.ciphertext = (byte_ard*)malloc(REKEY_CRYPTSIZE);

		byte_ard K_ST[KEY_BYTES];
		memcpy(K_ST,tssp->getKstSched(),KEY_BYTES);
		char szKeyStr[40];

		sprintf(szKeyStr,	"%.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x " 
							"%.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x",
							K_ST[0], K_ST[1], K_ST[2], K_ST[3], 
							K_ST[4], K_ST[5], K_ST[6], K_ST[7],
							K_ST[8], K_ST[9], K_ST[10], K_ST[11], 
							K_ST[12], K_ST[13], K_ST[14], K_ST[15] );

		syslog(LOG_NOTICE,"Session key is %s",szKeyStr);

		// Put the data in the struct
		unpack_rekey(readBuf, (const u_int32_ard*) (tssp->getKstSched()), 
						&rekeymsg);
		
		syslog(LOG_NOTICE, "nonce:  %x", rekeymsg.nonce);		
		// TODO: Make the nonce part of the device profile. 
		// Keep track to prevent replays and fiddling.
		
		char szCryptedPid[20];
		sprintf(szCryptedPid,"%d%d-%d%d%d%d",
				rekeymsg.pID[0],rekeymsg.pID[1],rekeymsg.pID[2],
				rekeymsg.pID[3],rekeymsg.pID[4],rekeymsg.pID[5]);
		
		syslog(LOG_NOTICE,"Crypted id is %s", szCryptedPid);
		// TODO: Make sure the plaintext PID and decrypted match.
		// This is the authenticating feature of the protocol.

		
		int validMac = verifyAesCMac((const u_int32_ard*)(tssp->getKstaSched()),
										rekeymsg.ciphertext,
										REKEY_CRYPTSIZE,
										rekeymsg.cmac);
		if(validMac == 0){
			log_err_exit("Mac of incoming rekey message did not match");
		}
		else {
			syslog(LOG_NOTICE,"MAC checked out ok");
		}
		
		// Done unpacking rekey message ---------------------------------------


		// Pack newkey --------------------------------------------------------

		// Get the key material for Kste, Kstea
		byte_ard R[BLOCK_BYTE_SIZE];
		// Get from the persistence object
		memcpy( R, tssp->getR(), KEY_BYTES );

		char szRandStr[50];
		sprintf(szRandStr,
				"%.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x "
				"%.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x",
				R[0], R[1], R[2], R[3],	R[4], R[5], R[6], R[7],
				R[8], R[9], R[10], R[11], R[12], R[13], R[14], R[15] );

		syslog(LOG_NOTICE,"Key material for %s: %s", szPid, szRandStr);
		
		// Populate the newkey struct
		message newkeymsg;
		newkeymsg.pID = rekeymsg.pID;
		newkeymsg.nonce = rekeymsg.nonce;
		memcpy(	newkeymsg.rand, R, KEY_BYTES );

		// Pack the newkey message
		byte_ard newkeybuf[NEWKEY_FULLSIZE]; 
		pack_newkey(	&newkeymsg, (const u_int32_ard*)tssp->getKstSched(),
						(const u_int32_ard*)tssp->getKstaSched(), newkeybuf );


		byte_ard M[16];
		memcpy(M,tssp->getKstaSched(),16);
		char szMacKeyStr[50];
		sprintf(szMacKeyStr,
				"%.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x "
				"%.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x",
				M[0], M[1], M[2], M[3],	M[4], M[5], M[6], M[7],
				M[8], M[9], M[10], M[11], M[12], M[13], M[14], M[15]);

		byte_ard MM[16];
		memcpy(MM,newkeymsg.cmac,16);
		char szMacStr[50];
		sprintf(szMacStr,
				"%.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x "
				"%.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x",
				MM[0], MM[1], MM[2], MM[3],	MM[4], MM[5], MM[6], MM[7],
				MM[8], MM[9], MM[10], MM[11], MM[12], MM[13], MM[14], MM[15]);

		syslog(LOG_NOTICE,"Using MAC key: %s",szMacKeyStr);
		syslog(LOG_NOTICE,"My MAC is: %s", szMacStr);


		// Done packing newkey ------------------------------------------------

		byte_ard Kste[16];
		memcpy(Kste,tssp->getKsteSched(),16);
		char szKsteStr[50];
		sprintf(szKsteStr,
				"%.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x "
				"%.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x",
				Kste[0], Kste[1], Kste[2], Kste[3],	
				Kste[4], Kste[5], Kste[6], Kste[7],
				Kste[8], Kste[9], Kste[10], Kste[11], 
				Kste[12], Kste[13], Kste[14], Kste[15]);
		syslog(LOG_NOTICE, "Kste: %s", szKsteStr);
 
		byte_ard Kstea[16];
		memcpy(Kstea,tssp->getKsteaSched(),16);
		char szKsteaStr[50];
		sprintf(szKsteaStr,
				"%.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x "
				"%.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x",
				Kstea[0], Kstea[1], Kstea[2], Kstea[3],	
				Kstea[4], Kstea[5], Kstea[6], Kstea[7],
				Kstea[8], Kstea[9], Kstea[10], Kstea[11], 
				Kstea[12], Kstea[13], Kstea[14], Kstea[15]);
		syslog(LOG_NOTICE, "Kstea: %s", szKsteaStr);
	
	    // Send newkey message to sensor.
       	// ----------------------------------
		writeToProxyClient(proxyClientRequestBio, newkeybuf, NEWKEY_FULLSIZE);

		// Close connection to proxy client.
		BIO_free(proxyClientRequestBio);
		ERR_remove_state(0);

		delete tssp;
		free (rekeymsg.pID);
		free (rekeymsg.ciphertext);

	} catch(runtime_error rex) {
		log_err_exit(rex.what());
	}
}

void TlsSinkServer::handleData(SSL *ssl, BIO* proxyClientRequestBio,
                                      byte_ard* readBuf, int readLen)
{
	syslog(LOG_NOTICE, "handleData()");

    // Crypto length is in the second byte
	int cryptoLen = (int)readBuf[1];
	syslog(LOG_NOTICE, "Encrypted buffer length is %d",cryptoLen);

	// The plaintext id is in the following 6 bytes
	byte_ard plainId[6];
	memcpy(plainId,readBuf+2,6); 
	// Output for debugging
	char szPlainId[10];
	sprintf(szPlainId, "%d%d-%d%d%d%d", 
			plainId[0], plainId[1], plainId[2], 
			plainId[3], plainId[4], plainId[5]);
	syslog(LOG_NOTICE,"Plaintext device id is %s", szPlainId);

	// Get the database profile based on the plaintext id
	TsDbSinkSensorProfile *tssp;
	try {
		tssp = new TsDbSinkSensorProfile(plainId, dbcd);

	} catch(runtime_error rex) {
		log_err_exit(rex.what());
	}

	// Unpack the sensor data using the given key
	struct data sensorData;
	unpack_data(readBuf, 
				(const u_int32_ard*) (tssp->getKsteSched()),
				&sensorData);

	// Validate the MAC
	int validMac = verifyAesCMac((const u_int32_ard*)(tssp->getKsteaSched()),
								 sensorData.ciphertext,
								 sensorData.cipher_len,
								 sensorData.cmac);
	if(validMac == 0){
		log_err_exit("Mac of incoming data message did not match");
	}
	else {
		syslog(LOG_NOTICE,"MAC checked out ok");
	}
		
	// Print the unpacked ID and some other stuff for debugging
	char szUnpackId[10];
	sprintf(szUnpackId, "%d%d-%d%d%d%d", 
			sensorData.id[0], sensorData.id[1], sensorData.id[2], 
			sensorData.id[3], sensorData.id[4], sensorData.id[5]);
	syslog(LOG_NOTICE, "Unpacked device id is %s", szUnpackId);
	syslog(LOG_NOTICE, "msg_type:     %x", sensorData.msgtype);
	syslog(LOG_NOTICE, "msg_time:     %ul", sensorData.msgtime);
	syslog(LOG_NOTICE, "data_len:     %x", sensorData.data_len);
	syslog(LOG_NOTICE, "cipher_len:   %x", sensorData.cipher_len);

	// Make sure the unpaced (decrypted!) message id is the
	// same as sent in plaintext
	if( strncmp((char *)plainId,(char *)sensorData.id,6)!=0 )
		log_err_exit("The plain and ciphered IDs did not match!");

	// TODO: Store and check the timestamp for a (weak) replay check.
	// This check will be weak since the client can reset the tsensor
	// time at will.

	// Write to file
	FILE *pFile;
	pFile = fopen("data.log","a");
	fprintf(pFile,"[%s,%d]:",szUnpackId,sensorData.msgtime);
	for (int i=0; i<sensorData.data_len; i++)
		fprintf(pFile,"%d;",sensorData.data[i]);
	fputc('\n',pFile);
	fclose(pFile);

	// Free all resources
	delete tssp;
	free(sensorData.ciphertext);
	free(sensorData.data);
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
	// TODO: Move proxyClientAcceptBio to class variable
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

