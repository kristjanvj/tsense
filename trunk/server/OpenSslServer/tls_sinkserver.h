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
#include "tsense_keypair.h"

using namespace std;

class TlsSinkServer : public TlsBaseServer{
    private:
		const char *_authServerAddr, *_authServerPort;
		
		TSenseKeyPair *K_st;

		byte_ard K_ST[BLOCK_BYTE_SIZE];

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

        void handleIdResponse(SSL *ssl, byte_ard* readBuf, int readLen);
		void handleIdResponse(SSL *ssl, BIO* proxyClientReqestBio,
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
