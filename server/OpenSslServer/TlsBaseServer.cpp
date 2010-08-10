/*
 * File name: TlsBaseServer.cpp
 * Date:      2010-08-04 16:40
 * Author:    Kristján Rúnarsson
 */

#include <iostream>
#include <string>
#include <syslog.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "TlsBaseServer.h"

using namespace std;

int verify_callback(int ok, X509_STORE_CTX *store){

    syslog(LOG_NOTICE, "%s", "verify_callback");

    char data[256];

    // Print out some extended data in case of a certificate validation error.
    if(!ok){
        X509 *cert = X509_STORE_CTX_get_current_cert(store);
        int depth = X509_STORE_CTX_get_error_depth(store);
        int err = X509_STORE_CTX_get_error(store);

        syslog(LOG_NOTICE, "Error with certificate at depth: %d", depth);
        X509_NAME_oneline(X509_get_issuer_name(cert), data, 256);
        syslog(LOG_NOTICE, " issuer  = %s", data);
        X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
        syslog(LOG_NOTICE, " subject = %s", data);
        syslog(LOG_NOTICE, " err: %d:%s", err, 
						X509_verify_cert_error_string(err));
    }
}

TlsBaseServer::TlsBaseServer(const char *serverAddr, const char *serverListenPort) : 
										 	_serverAddr(serverAddr),
											_serverListenPort(serverListenPort){
	initOpenSsl();
	seedPrng();
}

void TlsBaseServer::doVerify(SSL *ssl){
    long err;
    if((err = postConnectionValidations(ssl, (char*)_serverAddr)) != X509_V_OK){
        syslog(LOG_NOTICE, "-Error: peer certificate: %s",
            X509_verify_cert_error_string(err));
        log_err_exit("Error checking SSL object after connection");
    }
}

void TlsBaseServer::handleError(const char *file, int lineno, const char * msg){
    syslog(LOG_ERR, "** %s:%i %s", file, lineno, msg);
	char buf [10000];
	ERR_error_string_n(ERR_peek_last_error(), buf, 10000);
	syslog(LOG_ERR,"%s",buf);
	exit(-1);
}

void TlsBaseServer::initOpenSsl(void) {
    if(!SSL_library_init()){
		syslog(LOG_NOTICE, "%s", "** OpenSSL initialization failed!");
		exit(-1);
	}
	SSL_load_error_strings();
}

void TlsBaseServer::seedPrng(void) {
  RAND_load_file("/dev/urandom", 1024);
}

long TlsBaseServer::postConnectionValidations(SSL *ssl, char *host) {
    X509        *cert;
    X509_NAME   *subject;
    char        data[256];
    int         extcount;
    int         ok = 0;

    syslog(LOG_NOTICE, "%s", "post_connection_check");

    if(!(cert = SSL_get_peer_certificate(ssl)) || !host){
        goto err_occured;
    }

    if((extcount = X509_get_ext_count(cert)) > 0) {

        int i;

        for(i = 0; i < extcount; i++){
            char    *extstr;

            /* typedef struct X509_extension_st {...} X509_EXTENSION;
             * typedef struct asn1_object_st {...} ASN1_OBJECT;
             */
            X509_EXTENSION *ext;

            ext = X509_get_ext(cert, i);
            extstr = (char*) OBJ_nid2sn(OBJ_obj2nid(X509_EXTENSION_get_object(ext)));

            if(!strcmp(extstr, "subjectAltName")){
                int j;
                const unsigned char *data;
                STACK_OF(CONF_VALUE) *val;
                CONF_VALUE *nval;
                X509V3_EXT_METHOD *meth; // struct v3_ext_method
                void *ext_str = NULL;

                if(!(meth = X509V3_EXT_get(ext))){
                    break;
                }

                data = ext->value->data;

#if (OPENSSL_VERSION_NUMBER > 0x00907000L) //----------------------------------
				if (meth->it) {
                  ext_str = ASN1_item_d2i(NULL, &data, ext->value->length,
                                          ASN1_ITEM_ptr(meth->it));
                } else {
                  ext_str = meth->d2i(NULL, &data, ext->value->length);
                }
#else //-----------------------------------------------------------------------
                ext_str = meth->d2i(NULL, &data, ext->value->length);
#endif //----------------------------------------------------------------------

                val = meth->i2v(meth, ext_str, NULL);

                for(j = 0; j < sk_CONF_VALUE_num(val); j++){
                    nval = sk_CONF_VALUE_value(val, j);

                    syslog(LOG_NOTICE, "value[%d] ----------------",j);
                    syslog(LOG_NOTICE, "Host      : %s", host);
                    syslog(LOG_NOTICE, "Conf Name : %s", nval->name);
                    syslog(LOG_NOTICE, "Conf Value: %s", nval->value);

                    if(!strcmp(nval->name, "DNS") && !strcmp(nval->value, host)){
                        ok = 1;
                        break;
                    }
                }
            }

            if(ok){
                break;
            }
        }
    }

    if(!ok && (subject = X509_get_subject_name(cert)) &&
       X509_NAME_get_text_by_NID(subject, NID_commonName, data, 256) > 0)
    {
        data[255] = 0;


        syslog(LOG_NOTICE, "Host      : %s", host);
        syslog(LOG_NOTICE, "Subj. Name: %s", data);

        if(strcasecmp(data, host) != 0){
            goto err_occured;
        }
    }
	X509_free(cert);
    return SSL_get_verify_result(ssl);


err_occured:
    if(cert){
        X509_free(cert);
    }

    return X509_V_ERR_APPLICATION_VERIFICATION;
}


SSL_CTX *TlsBaseServer::setupServerCtx(int mode){

    SSL_CTX *ctx;

	// Set verification filter callback function:
	//
	// Client mode:
	//      The SSL_VERIFY_PEER setting will cause the client to send it's 
	//      certificate. Failure on the part of the client to send it's certificate
	//      will not cause the handshake to be aborted unless the 
	//      SSL_VERIFY_FAIL_IF_NO_PEER_CERT flag is set. Failure to validate the 
	//      certificate will of course also cause the SSL handshake to terminate.
	//
	// Server mode:
	//      The SSL_VERIFY_PEER setting will cause the server to send a 
	//      certificate and depending on the server's setting may cause the SSL 
	//      handshake to fail if no client certificate is sent in reply by the 
	//		client. Failure to validate the certificate will of course also 
	//      cause the SSL handshake to terminate.
	if(mode == SERVER_MODE){
		ctx = SSL_CTX_new(TLSv1_server_method());
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
						   verify_callback);
	} else if (mode == CLIENT_MODE) {
		ctx=SSL_CTX_new(TLSv1_client_method());
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
	} else {
		log_err_exit("Unsupported mode.");
	}

	// Limit how far up the certificate chain do we go to look for a trusted
	// CA certificate. If we reach the end of the cain without finding
	// one or the chain is longer than 4 verification will fail.
	SSL_CTX_set_verify_depth(ctx,4);


    if(SSL_CTX_load_verify_locations(ctx, CAFILE, CADIR) !=1){
        log_err_exit("Error loading CA file and/or directory.");
    }

    if(SSL_CTX_set_default_verify_paths(ctx) != 1){
        log_err_exit("Errod loading default CA file and/or directory.");
    }

    if(SSL_CTX_use_certificate_chain_file(ctx, CERTFILE) != 1){
        log_err_exit("Error loading certificate from file.");
    }

    if(SSL_CTX_use_PrivateKey_file(ctx, CERTFILE, SSL_FILETYPE_PEM) != 1){
        log_err_exit("Error loading private key from file.");
    }

    return ctx;
}
