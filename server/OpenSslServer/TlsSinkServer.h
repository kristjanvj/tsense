/*
   File name: TlsSinkServer.h
   Date:      2010-06-21 11:28
   Author:    Kristján Rúnarsson
*/

#ifndef __TLSSERVER_H__
#define __TLSSERVER_H__

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <iostream>
#include <sstream>
#include <string>

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#include <syslog.h>
#include <errno.h>
#include <gnutls/gnutls.h>
#include <string.h>

#include <openssl/ssl.h> /* Ubuntu/Debian: libssl-dev */
#include <openssl/err.h>


/* This is a sample TLS 1.0 echo server, for anonymous authentication only.
 */

using namespace std;

class TlsSinkServer {
    private:
		void handleError(const char* msg);
		void initOpenSSL();
		SSL_CTX* setupCtx();
		DH* setupDiffeHelleman();

		int _listenPort;

    public:
		TlsSinkServer(int listenPort);
		void serverMain();
};


#endif
