/*
   File name: TlsAuthServer.h
   Date:      2010-08-03 16:10
   Author:    Kristján Rúnarsson
*/

#ifndef __TLSAUTHSERVER_H__
#define __TLSAUTHSERVER_H__

#include "tls_baseserver.h"
#include "tsense_keypair.h"
#include "protocol.h"
#include <stdexcept>

using namespace std;

class TlsAuthServer : public TlsBaseServer{
	private:
		
		TSenseKeyPair *K_at;

		const char *_sinkServerAddr;
		void serverFork(void *arg, BIO* proxyClientRequestBio);

		void handleMessage(SSL *ssl);

		int writeToSink(SSL *ssl, byte_ard* writeBuf, int len);
		int readFromSink(SSL *ssl, byte_ard* readBuf, int len);

		void handleIdResponse(SSL *ssl, byte_ard *readBuf, int readLen);

    public:
		TlsAuthServer(	const char* sinkServerAddr, 
						const char *hostName, 
						const char *listenPort);
		~TlsAuthServer();
		void serverMain();
};

#endif
