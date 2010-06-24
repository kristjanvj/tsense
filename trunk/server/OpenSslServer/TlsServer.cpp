/*
 * File name: tls_anon_server.c
 * Date:      2010-06-15 12:22
 * Author:    Kristján Rúnarsson
 */

/* This is a sample TLS 1.0 echo server, for anonymous authentication only.
 */

#include "TlsServer.h"


using namespace std;

TlsServer::TlsServer(int listenPort) : _listenPort(listenPort) {}

void TlsServer::handleError(const char* msg) {
    syslog(LOG_ERR, "%s", msg);
    exit(-1);
}

/* Register available algorithms and digests. Must be called before
 * any other action takes place. 
 */
void TlsServer::initOpenSSL() {
    if (!SSL_library_init())
        handleError("OpenSSL initialization failed");
    SSL_load_error_strings();
}


/* Set parameters for a Diffe-Hellman key exchange. A DH exchange allows two
 * unrelated entities to establish a shared secret key over an encrypted
 * connection. This can then be use for symmetric-key encryption.
 * 	
 *  - http://en.wikipedia.org/wiki/Diffie-Hellman_key_exchange
 *  - http://en.wikipedia.org/wiki/Symmetric_key
 */
DH* TlsServer::setupDiffeHelleman() {
    DH* dh = DH_new();
    if (!dh)
        handleError("DH_new failed");

    if (!DH_generate_parameters_ex(dh, 2, DH_GENERATOR_2, 0))
        handleError("DH_generate_parameters_ex failed");

    int codes = 0;
    if (!DH_check(dh, &codes))
        handleError("DH_check failed");

    if (!DH_generate_key(dh))
        handleError("DH_generate_key failed");

    return dh;
}

/* Sets up the SSL context structure for global default values and
 * certificate verification. Each application requires at lest one
 * context structure. The structure is used by the server to determine
 * default values for the connection.
 */
SSL_CTX* TlsServer::setupCtx() {
    SSL_CTX* ctx;

	/* Specify a connection that only understands the TLS V.1 protocol.
	 * A lot of the following code has variable, structures and calls 
	 * functions containing SSL which is confusing but this should
	 * create a pure TLS connection. SSL V.1,2 and 3 hello messages
	 * will not be understood.
	 */
    ctx = SSL_CTX_new(TLSv1_server_method());
    if (!ctx)
        handleError("SSL_CTX_new failed");

    DH* dh = setupDiffeHelleman();

	/* Sets up call back for Diff-Helleman key exchange.
	 */
    SSL_CTX_set_tmp_dh(ctx, dh);

    if (SSL_CTX_set_cipher_list(ctx, "ADH-AES256-SHA") != 1)
        handleError("Error setting cipher list (no valid ciphers)");

    return ctx;
}


void TlsServer::serverMain() {
    initOpenSSL();

    BIO *acc, *client;
    SSL* ssl;
    SSL_CTX* ctx;

    ctx = setupCtx();

    syslog(LOG_NOTICE, "%s", "Creating server socket ... ");

	stringstream port;
	port << _listenPort;
	/* Combines the BIO_new call and the BIO_set_accept_port() calls.
	 * The port is represented as a string of the form "host:port" 
	 * where host is the interface. Both host and port can be * which 
	 * means "select any interface/host".
	 *
	 * BIO = I/O abstraction that enable transparent handling of
	 *       encrypted/unencrypted connections and file I/O.
	 */
    acc = BIO_new_accept((char*)port.str().c_str());
    if (!acc)
        handleError("Error creating server socket");

    syslog(LOG_NOTICE, "%s", "Binding server socket ... ");
	/* The first time BIO_do_accept is called after BIO setup it attempts
	 * to create a socket and bind to it. On follwoing calls it will await
	 * an incoming connection or request a retry in non blocking mode.
	 */
    if (BIO_do_accept(acc) <= 0)
        handleError("Error binding server socket");

	//FIXME: Close this gracefully with a system signal.
    while (true) {
		syslog(LOG_NOTICE, "%s", "Accepting connections ...");

        if (BIO_do_accept(acc) <= 0)
            handleError("Error accepting connection");

		client = BIO_pop(acc);

		/* Create a new SSL context this context inherits it's settings
		 * from the master context created earlier.
		 */
        if (!(ssl = SSL_new(ctx)))
            handleError("Error creating SSL context");

		/* Connecti I/O abstraction object for TLS/SSL read/write ops.
		 */
        SSL_set_bio(ssl, client, client);

		/* Waits for a TLS/SSL handshake.*/
        if (SSL_accept(ssl) <= 0)

        handleError("Error accepting SSL connection");

		stringstream msg;
        msg << "SSL connection opened: " 
			<< SSL_get_cipher(ssl) << " " 
			<< SSL_get_cipher_version(ssl) << " (" 
			<< SSL_get_cipher_bits(ssl, 0) << " bits)\n";

		syslog(LOG_NOTICE, "%s", msg.str().c_str());

        char buff[256] = {0};

		/* Read what the client sent and echo it back with a slght modification.
		*/
        int r = SSL_read(ssl, buff, sizeof buff);
        if (r > 0) {
			msg.str("");
            msg << "Server received: <" << buff << ">\n";
			syslog(LOG_NOTICE, "%s", msg.str().c_str());
            char answer[256] = {0};
            r = sprintf(answer, "I (the server) received this: <%s>", buff);
            SSL_write(ssl, answer, r);
        }

		/* Gracefylly shuts down the SSL connection.
		*/
        SSL_shutdown(ssl);

		/* Decrements reference counters and frees up any resources.
		*/
        SSL_free(ssl);

        syslog(LOG_NOTICE, "%s", "SSL connection finished");
    }

	/* Free the SSL context and any resources before shutting down.
	 */
    SSL_CTX_free(ctx);
    BIO_free(acc);
    syslog(LOG_NOTICE, "%s", "Server closed\n");


}

/*
int main() {
	TlsServer FooBar(5556);
	FooBar.serverMain();
    return 0;
} // end main()
*/

