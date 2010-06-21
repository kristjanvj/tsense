/*
 * File name: tls_anon_server.c
 * Date:      2010-06-15 12:22
 * Author:    Kristján Rúnarsson
 */

/* This is a sample TLS 1.0 echo server, for anonymous authentication only.
 */

#include "TlsServer.h"

#define MAX_BUF 1024
#define DH_BITS 1024

using namespace std;

TlsServer::TlsServer(int listenPort) : _listenPort(listenPort) {}

gnutls_session_t TlsServer::initTlsSession(void) {

	gnutls_session_t session;

	gnutls_init (&session, GNUTLS_SERVER);

	gnutls_priority_set_direct (session, "NORMAL:+ANON-DH", NULL);

	gnutls_credentials_set (session, GNUTLS_CRD_ANON, anoncred);

	gnutls_dh_set_prime_bits (session, DH_BITS);

	return session;
}


/* Set parameters for a Diffe-Hellman key excnage. A DH exchange allows two
 * unrelated entities to establish a shared secret key over an encrypted
 * connection. This can then be use for symmetric-key encryption.
 * 	
 *  - http://en.wikipedia.org/wiki/Diffie-Hellman_key_exchange
 *  - http://en.wikipedia.org/wiki/Symmetric_key
 */
int TlsServer::genDHParams (void) {

	/* Generate Diffie-Hellman parameters - for use with DHE
	* kx algorithms. These should be discarded and regenerated
	* once a day, once a week or once a month. Depending on the
	* security requirements.  */
	gnutls_dh_params_init (&dh_params);
	gnutls_dh_params_generate2 (dh_params, DH_BITS);

	return 0;
}

void TlsServer::serverMain() {
	int err, listenSockDes, connSockDes, result, client_len;
	int optval = 1;
	char topbuf[512];
	char buffer[MAX_BUF + 1];
	struct sockaddr_in saServer, saClient;
	gnutls_session_t session;
	stringstream msg;

	/* this must be called once in the program */
	gnutls_global_init();

	gnutls_anon_allocate_server_credentials(&anoncred);

	// Diffe-Hellman parameter preperation.
	genDHParams();

	// Set up DH parameters for an anonymous server.
	gnutls_anon_set_server_dh_params(anoncred, dh_params);

	/* Socket operations */
	listenSockDes = socket(AF_INET, SOCK_STREAM, 0);

	if(err == -1){
		syslog(LOG_ERR, "Error creating listener socket.");
		exit(1);
	}

	// Server socket IP address setup.
	memset (&saServer, '\0', sizeof (saServer));
	saServer.sin_family = AF_INET;
	saServer.sin_addr.s_addr = INADDR_ANY;
	saServer.sin_port = htons (_listenPort);	/* Server Port number */

	/* Socket options:
	 *  - SOL_SOCKET: Sets socket option manipulation level.
	 *  - optval: Set 1 == SO_DEBUG?
	 */
	setsockopt(listenSockDes, SOL_SOCKET, SO_REUSEADDR, 
				(void *) &optval, sizeof (int));

	err = bind(listenSockDes, (sockaddr *) & saServer, sizeof (saServer));

	if(err == -1){
		syslog(LOG_ERR, "Error binding listener socket.");
		exit(1);
	}

	// Backlog == 1024 pending connections.
	err = listen(listenSockDes, 1024);
	if(err == -1){
		syslog(LOG_ERR, "Error setting up listening on socket.");
		exit(1);
	}

	msg << "Server ready. Listening to port '" <<  _listenPort << "'." << endl;
	syslog(LOG_NOTICE, msg.str().c_str());

	// Client socket IP address length.
	client_len = sizeof (saClient);

	while(true) {
		session = initTlsSession();

		/* Pop a request off the connection queue.*/
		connSockDes = accept(listenSockDes, (sockaddr*)&saClient, 
							 (socklen_t*)&client_len);

		msg.str("");
		msg << " - Connection from: " 
			<< inet_ntop (AF_INET, &saClient.sin_addr, topbuf, sizeof (topbuf))
			<< " on port: " << ntohs (saClient.sin_port) << endl;
		syslog(LOG_NOTICE, msg.str().c_str());

		// Sets first argument of transport function (PUSH/PULL).
		gnutls_transport_set_ptr(session, (gnutls_transport_ptr_t) connSockDes);

		// Returns GNUTLS_E_SUCCESS or else an error code.
		result = gnutls_handshake(session);

		if (result != GNUTLS_E_SUCCESS) {
			close(connSockDes);
			// Clears buffers associated with session.
			gnutls_deinit (session);

			msg.str("");
			msg << " *** Handshake failed " << gnutls_strerror (result) << endl << endl;
			syslog(LOG_NOTICE, msg.str().c_str());

			continue;
		}

		msg.str("");
		msg << " - Handshake was completed" << endl;
		syslog(LOG_NOTICE, msg.str().c_str());

		while(true) {
			memset(buffer, 0, MAX_BUF + 1);

			// Number of bytes recieved on sucess, 0 on EOF else negative error code.
			result = gnutls_record_recv(session, buffer, MAX_BUF);

			if (result == 0) {
				msg.str("");
				msg << " - Peer has closed the GNUTLS connection" << endl;
				syslog(LOG_NOTICE, msg.str().c_str());
				break;
			} else if (result < 0) {
				msg.str("");
				msg << " *** Received corrupted data(" << result 
					 << "). Closing the connection." << endl << endl;
				syslog(LOG_NOTICE, msg.str().c_str());
				break;
			} else if (result > 0) {
				// Dispatch reply to sender.
				msg.str("");
				msg << " - Dispatching reply to client." << endl;
				gnutls_record_send(session, buffer, strlen (buffer));
				syslog(LOG_NOTICE, msg.str().c_str());
			}
		}

		// Don't  wait for the peer to close the connection.
		gnutls_bye(session, GNUTLS_SHUT_WR);

		// Close client socket.
		close(connSockDes);

		// Clears buffers associated with session.
		gnutls_deinit(session);

	}
	close (listenSockDes);

	gnutls_anon_free_server_credentials (anoncred);

	gnutls_global_deinit ();
}

/*
int main() {
	TlsServer FooBar(5556);
	FooBar.serverMain();
    return 0;
} // end main()
*/
