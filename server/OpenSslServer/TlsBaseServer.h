/*
   File name: TlsBaseServer.h
   Date:      2010-08-03 16:10
   Baseor:    Kristján Rúnarsson
*/

#ifndef __TLSBASESERVER_H__
#define __TLSBASESERVER_H__

#include <stdexcept>

#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define CADIR NULL
#define CAFILE "root.pem"

using namespace std;

#define CLIENT_MODE 0x1
#define SERVER_MODE 0x2

#define log_err_exit(msg) handleError(__FILE__, __LINE__, msg);

int verify_callback(int ok, X509_STORE_CTX *store);

class TlsBaseServer {
	protected:
		const char *_serverListenPort;
		const char *_serverAddr;
		SSL_CTX *ctx;

		void handleError(const char *file, int lineno, const char * msg);
		void initOpenSsl(void);
		void seedPrng(void);
		SSL_CTX *setupServerCtx(int mode);
		void doVerify(SSL *ssl, const char* peer);
		long postConnectionValidations(SSL *ssl, const char *peer);

    public:
		TlsBaseServer(const char *serverName, const char* listenPort);
		virtual void serverMain() = 0;

};

#endif
