/*
   File name: TlsAuthServer.h
   Date:      2010-08-03 16:10
   Author:    Kristján Rúnarsson
*/

#ifndef __TLSAUTHSERVER_H__
#define __TLSAUTHSERVER_H__

#include "tls_baseserver.h"
#include <stdexcept>

using namespace std;

class TlsAuthServer : public TlsBaseServer{
	private:
		const char *_sinkServerAddr;
		int doEcho(SSL *ssl);
		void serverFork(void *arg);

		int writeToSink(SSL *ssl, char* writeBuf, int len);
		int readFromSink(SSL *ssl, char* readBuf, int len);

    public:
		TlsAuthServer(const char* sinkServerAddr, const char *hostName, const char *listenPort);
		void serverMain();
};

#endif
