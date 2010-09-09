/*
 * File name: TSenseAuthDaemon.cpp
 * Date:	  2006-08-08 16:05
 * Author:	Kristjan Runarsson
 */

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <getopt.h>

#include "BDaemon.h"
#include "tls_authserver.h"

#define PATHLEN 2048
#define ADDRLEN 2048
#define PORTLEN 6

using namespace std;

class TSenseAuthDaemon: public BDaemon{
	public:
		TSenseAuthDaemon(	const char *daemonName,
							const char* lockDir, 
							int daemonFlags,
                            const char* addr,       // My address
                            const char* port,       // My port
                            const char* sinkAddr);   // Peer (sink) addr.
	protected:
		void work();

	private:
		TlsAuthServer *tlsa;
};

TSenseAuthDaemon::TSenseAuthDaemon(const char *daemonName, 
						const char* lockDir, 
						int daemonFlags,
						const char* addr,       // My address
						const char* port,       // My port
						const char* sinkAddr)   // Peer (sink) addr.
				: BDaemon(daemonName, lockDir, daemonFlags)
{
	// The need for the sink server address may not be immediately apparent
	// but it is used during authentication of the sink server's x509 
	// certificate in the tls server component.
	// FIXME: To make allowance for multiple skinks the sink address register
	//        should be put in a database and this parameter shoudl be delted..
	tlsa = new TlsAuthServer(sinkAddr,		// Peer (sink) addr.
							 addr, port);	// Me.

	//tlsa = new TlsAuthServer("sink.tsense.sudo.is",				// Peer.,
	//						 "auth.tsense.sudo.is", "6001");	// Me.
} 

void TSenseAuthDaemon::work(){
	syslog(LOG_ERR, "%s", getWorkDir().c_str());
	tlsa->serverMain();
}

void usage(){
	fprintf(stderr, "SYNOPSIS\n");

	fprintf(stderr, "    tsauthd --workdir <Work dir> \n");
	fprintf(stderr, "            --lockdir <Lock file dir\n");
	fprintf(stderr, "            --addr    <Auth server addr>\n");
	fprintf(stderr, "            --port    <Auth server port>\n");
	fprintf(stderr, "            --siaddr  <Sink server address>\n");

	fprintf(stderr, "\n");

	fprintf(stderr, "DESCRIPTION\n");
	fprintf(stderr,
	"    A data sink that relays session key requests from a set of secure \n"
	"    tamper proof sensors to an authorization server. Once the session \n"
	"    key exchange complete the sink will recieve sensor data from each \n"
	"    sensor and store this in a database.\n");

	fprintf(stderr, "\n");

	fprintf(stderr, "OPTIONS\n");
	fprintf(stderr, "    --workdir Abs. path to working directory.\n");
	fprintf(stderr, "    --lockdir Abs. path to  lock file directory.\n");
	fprintf(stderr, "    --addr    Auth server FQDN or IP.\n");
	fprintf(stderr, "    --port    Auth server listening port.\n");
	fprintf(stderr, "    --siaddr  Sink server FQDN or IP.\n");
}


int main(int argc, char **argv)
{

	
	char lockDir[PATHLEN];
	char workDir[PATHLEN];

	static struct option long_options[] =
	{
		/* These options set a flag. */
		//{"verbose", no_argument,       &verbose_flag, 1},

		/* These options don't set a flag.
		  We distinguish them by their indices. */
		{"addr",  required_argument, 0, 'a'},
		{"port",  required_argument, 0, 'b'},
		{"siaddr",  required_argument, 0, 'c'},
		{"workdir",  required_argument, 0, 'e'},
		{"lockdir",  required_argument, 0, 'f'},
		{"help",     no_argument,       0, 'h'},
		{0, 0, 0, 0}
	};

	int option_index = 0;

	bool wDirPassed = false;


	bool isAddr, isPort, isSiAddr, isLockDir;
	isAddr = isPort = isSiAddr = isLockDir = false;


	char addr[ADDRLEN];
	char port[PORTLEN];
	char sinkAddr[ADDRLEN];

	if(argc < 0){
		cout << "options:" << endl;
	}

	int c;
    while ((c = getopt_long (argc, argv, "a:b:c:d:e:f:h",
                            long_options, &option_index)) != -1){

		switch (c) {
			case 'a':
				strncpy(addr, optarg, ADDRLEN);
				cout << "    addr=" << addr << endl;
				isAddr = true;
				break;

			case 'b':
				strncpy(port, optarg, PORTLEN);
				cout << "    port=" << port << endl;
				isPort = true;
				break;

			case 'c':
				strncpy(sinkAddr, optarg, ADDRLEN);
				cout << "    auaddr=" << sinkAddr << endl;
				isSiAddr = true;
				break;

			case 'e':
				strncpy(workDir, optarg, PATHLEN);
				cout << "    workDir=" << workDir << endl;
				wDirPassed = true;
				break;

			case 'f':
				strncpy(lockDir, optarg, PATHLEN);
				cout << "    lockDir=" << lockDir << endl;
				isLockDir = true;
				break;

			case 'h':
				usage();
				exit(0);

			case '?':
				usage();
				exit(0);
		}
	}

	if(!(isAddr && isPort && isSiAddr && isLockDir)){
		usage();
	}

	try{
		TSenseAuthDaemon authDaemon("tsenseauthd", 
			lockDir,
			//SINGLETON);
			SINGLETON|NO_DTTY,
			addr,
			port,
			sinkAddr);

		if(wDirPassed){
			cout << "wDirPassed" << endl;
			cout << "workDir=" << workDir << endl;
			authDaemon.setWorkDir(workDir);
		} else {
			cout << "else" << endl;
			char cwd[PATHLEN];
			getcwd(cwd, PATHLEN);
			authDaemon.setWorkDir(cwd);
		}

		cout << "Running auth daemon" << endl;
		authDaemon.run();
	}

	catch(DaemonException e){
		cout<<"exiting: "<<e.what()<<endl;
	}

	catch(runtime_error e){
		cout<<"exiting: "<<e.what()<<endl;
	}

	catch(...){
		unexpected();
	}

	return 0;
} // end main()
