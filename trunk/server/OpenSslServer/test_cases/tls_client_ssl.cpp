/*
 * File name: client.c
 * Date:      2010-07-27 15:46
 * Author:    Kristján Rúnarsson
 */


#include "common.h"

#define CERTFILE "client.pem"
#define CADIR NULL
#define CAFILE "root.pem"

SSL_CTX *setup_client_ctx(void){
	SSL_CTX *ctx;

	ctx=SSL_CTX_new(TLSv1_client_method());

	if(SSL_CTX_load_verify_locations(ctx, CAFILE, CADIR) !=1){
		int_error("Error loading CA file and/or directory.");
	}

	if(SSL_CTX_set_default_verify_paths(ctx) != 1){
		int_error("Errod loading default CA file and/or directory.");
	}

	if(SSL_CTX_use_certificate_chain_file(ctx, CERTFILE) != 1){
		int_error("Error loading certificate from file.");
	}

	if(SSL_CTX_use_PrivateKey_file(ctx, CERTFILE, SSL_FILETYPE_PEM) != 1){
		int_error("Error loading private key from file.");
	}

	// Set verification filter callback function. The SSL_VERIFY_PEER 
	// setting will cause the server to send a certificate and depending
	// on the server's setting may cause the SSL handshake to fail if
	// no client certificate is sent in reply by the client. Failure
	// to validate the certificate will of course also cause the
	// SSL handshake to terminate.
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);

	// Limit how far up the certificate chain do we go to look for a trusted
	// CA certificate. If we reach the end of the cain without finding
	// one or the chain is longer than 4 verification will fail.
	SSL_CTX_set_verify_depth(ctx, 4);
	
	return ctx;
}

void do_verify(SSL *ssl){
	long err;
	if((err = post_connection_check(ssl, SERVER)) != X509_V_OK){
		fprintf(stderr, "-Error: peer certificate: %s\n", 
			X509_verify_cert_error_string(err));
		int_error("Error checking SSL object after connection");
	}
}


int do_client_loop(SSL *ssl){
	int err, nwritten;
	char buf[80];

	if(!fgets(buf, sizeof(buf), stdin)){
		return 0;
	}

	// Encrypts the plaintext buffer and dispatches it over it's
	// associate BIO channel. This will negotiate a TLS/SSL session
	// if it hasn't already been done explicitly by SSL_connect
	// or SSL_accept. If the peer requests a renegotiation it will
	// be performed transparently during the write operation.
	// For renegotiation to succeed, the ssl must have been
	// intitialized to client or server mode. 
	err = SSL_write(ssl, buf, strlen(buf));

	printf("errWrite = %d\n", err);

	char bufRead[80];

	printf("preRead\n");
	err = SSL_read(ssl, bufRead, 80);
	printf("errRead = %d\n", err);

	if(err <= 0){
		return 0;
	}

	bufRead[err] = 0x0;

	printf("read: %s\n", bufRead);

	return 1;
}

int main(int argc, char *argv[]){
    
	BIO *conn;		// Network I/O object.
	SSL *ssl;		// SSL encryption layer.
	SSL_CTX *ctx;	// Context for SSL object.

	init_OpenSSL();

	seed_prng();
	
	ctx = setup_client_ctx();

	// Sets up a BIO which is an I/O object that can handle network or 
	// file I/O. In this case the BIO abstracts a raw socket.
	//conn = BIO_new_connect(SERVER ":" PORT);
	conn = BIO_new_connect("sink.tsense.sudo.is:6002");

	if(!conn){
		int_error("Error createing connection BIO");
	}

	// Connect the BIO channel to a remote partner.
	if(BIO_do_connect(conn) <= 0){
		int_error("Error connecting to remote machine");
	}

	// The SSL object is created and the setting from the context are
	// copied into it. The ssl object is now in a generic state and can
	// perform either as a client or server in an SSL handshake.
	if(!(ssl = SSL_new(ctx))){
		int_error("Error creating an SSL context.");
	}

	// Set the bio that the SSL object is supposed to run on top of.
	// The ssl object will encrypt anyting passed to it and send it
	// over the BIO channel. You can also write directly to the
	// BIO channel if you so desire.
	SSL_set_bio(ssl,conn, conn);

	
	// This function call causes the SSL handshake to be initiated 
	// over the underlying BIO channel.
	if(SSL_connect(ssl) <= 0){
		int_error("Error connecting SSL object.");
	}

	fprintf(stderr, "SSL Connection opened\n");
	
	do_verify(ssl);

	if(do_client_loop(ssl)){
		// Gracefully terminates the SSL connection.
		SSL_shutdown(ssl);
	} else {
		// Resets the SSL object to allow a new connecton. Necessary
		// here to clear any session with errors from the session
		// cache.
		SSL_clear(ssl);
	}

	fprintf(stderr, "SSL connection closed\n");

	// Free all SSL object resources, this also fress the BIO object
	// so calling BIO_free() will result in a sefault.
	SSL_free(ssl);

	// Free the resources used by the SSL context.
	SSL_CTX_free(ctx);

    return 0;
}
