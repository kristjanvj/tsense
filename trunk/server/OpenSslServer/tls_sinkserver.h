/*
   File name: TlsSinkServer.h
   Date:      2010-06-21 11:28
   Author:    Kristján Rúnarsson
*/

#ifndef __TLSSERVER_H__
#define __TLSSERVER_H__

#include <stdexcept>
#include "protocol.h"
#include "tls_baseserver.h"
#include "ts_db_sinksensorprofile.h"
#include "tsense_keypair.h"
#include "aes_utils.h"

using namespace std;

class TlsSinkServer : public TlsBaseServer{
    private:
		const char *_authServerAddr, *_authServerPort;
		
		/*
		TSenseKeyPair *K_st;
		TSenseKeyPair *K_ste;

		byte_ard K_ST[BLOCK_BYTE_SIZE];
    	byte_ard *R;
    	byte_ard gammaKeySched[KEY_BYTES*11];
    	byte_ard K_STe[KEY_BYTES];
		*/

		dbConnectData dbcd;

        void serverFork(BIO *proxyClientReplyBio, BIO* authServerBio);

		void acceptProxyClientListenBio();

		int writeToAuth(SSL *ssl, byte_ard* writeBuf, int len);
		int readFromAuth(SSL *ssl, byte_ard* readBuf, int len);

		int readFromProxyClient(BIO *clientReplyBio, byte_ard *readBuf, 
								int len);
		int writeToProxyClient(BIO *clientReplyBio, byte_ard *writeBuf, 
								int len);
        int sendReceiveToAuth(SSL *ssl, byte_ard* readBuf, int readLen, 
								byte_ard* writeBuf);

		void handleIdResponse(SSL *ssl, BIO* proxyClientReqestBio,
								byte_ard* readBuf, int readLen);
		void initKeys(byte_ard *K_ST);

		void handleRekey(SSL *ssl, BIO* proxyClientRequestBio,
								byte_ard* readBuf, int readLen);

		int handleMessage(SSL *ssl, BIO* proxyClientRequestBio,
						  byte_ard *readBuf, int readLen);

    public:
        //TlsSinkServer(const char *hostName, const char *listenPort);
		TlsSinkServer(const char *authServerAddr, // Auths serv. IP/FQDN
					  const char *authServerPort, 
					  const char *serverAddr,	 // Own IP/FQDN
					  const char *serverListenPort);
        void serverMain();
};


#endif
