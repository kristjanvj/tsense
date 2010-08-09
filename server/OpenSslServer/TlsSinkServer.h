/*
   File name: TlsSinkServer.h
   Date:      2010-06-21 11:28
   Author:    Kristján Rúnarsson
*/

#ifndef __TLSSERVER_H__
#define __TLSSERVER_H__

#include "TlsBaseServer.h"
#include <stdexcept>

using namespace std;

class TlsSinkServer : public TlsBaseServer{
    private:
		const char *_authServerAddr, *_authServerPort;

        //int sendEcho(SSL *ssl);
        //void serverFork(void *arg);

        int sendEcho(SSL *ssl, char* readBuf, char* writeBuf);
        void serverFork(BIO *proxyClientReplyBio, void *arg, 
						char* readBuf, char* writeBuf);

		void acceptProxyClientListenBio();

		int writeToAuth(SSL *ssl, char* writeBuf, int len);
		int readFromAuth(SSL *ssl, char* readBuf, int len);

		int readFromProxyClient(BIO *clientReplyBio, char *readBuf);
		int writeToProxyClient(BIO *clientReplyBio, char *writeBuf);

    public:
        //TlsSinkServer(const char *hostName, const char *listenPort);
		TlsSinkServer(const char *authServerAddr, // Auths serv. IP/FQDN
					  const char *authServerPort, 
					  const char *serverAddr,	 // Own IP/FQDN
					  const char *serverListenPort);
        void serverMain();
};


#endif
