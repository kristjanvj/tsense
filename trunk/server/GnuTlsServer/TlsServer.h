/*
   File name: TlsServer.h
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

/* This is a sample TLS 1.0 echo server, for anonymous authentication only.
 */

#define MAX_BUF 1024
#define DH_BITS 1024

using namespace std;

class TlsServer {
    private:
        gnutls_anon_server_credentials_t anoncred;
        gnutls_session_t initTlsSession(void);

        gnutls_dh_params_t dh_params;
        int genDHParams(void);

        int _listenPort;

    public:
        TlsServer(int listenPort);
        void serverMain();
};


#endif
