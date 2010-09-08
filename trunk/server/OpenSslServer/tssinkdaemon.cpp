/*
 * File name: amsd.cpp
 * Date:	  2006-08-08 16:05
 * Author:	Kristjan Runarsson
 */

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <getopt.h>

#include "BDaemon.h"
#include "tls_sinkserver.h"

#define PATHLEN 2048
#define ADDRLEN 2048
#define PORTLEN 6

using namespace std;

class TSenseSinkDaemon: public BDaemon{
	public:
		TSenseSinkDaemon(	const char *daemonName, 
							const char* lockDir, 
							int daemonFlags,
							const char* addr,		// My address
							const char* port,		// My port
							const char* authAddr,	// Peer (auth) addr.
							const char* authPort);	// Peer (auth) port.

	protected:
		void work();

	private:
		TlsSinkServer *tlss;
};

TSenseSinkDaemon::TSenseSinkDaemon(const char *daemonName, 
								const char* lockDir, 
								int daemonFlags,
								const char* addr,		// My address
								const char* port,		// My port
								const char* authAddr,	// Peer (auth) addr.
								const char *authPort)	// Peer (auth) port.
					   
					: BDaemon(daemonName, lockDir, daemonFlags)
{

	

	tlss = new TlsSinkServer(authAddr, authPort, 	// Peer, auth.
							 addr, port);			// Me, sink.

	//tlss = new TlsSinkServer("auth.tsense.sudo.is", "6001", 	// Peer, auth.
	//						 "sink.tsense.sudo.is", "6002");	// Me, sink.
} 

void TSenseSinkDaemon::work(){
	tlss->serverMain();
}

void usage(){
    fprintf(stderr, "SYNOPSIS\n");

	fprintf(stderr, "    tssinkd --workdir <Work dir> \n");
    fprintf(stderr, "            --lockdir <Lock file dir\n");
    fprintf(stderr, "            --auaddr  <Auth server addr>\n");
    fprintf(stderr, "            --auport  <Auth server port>\n");
    fprintf(stderr, "            --addr    <Sink server address>\n");
    fprintf(stderr, "            --port    <Sink server port>\n");

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
    fprintf(stderr, "    --auaddr  Auth server FQDN or IP.\n");
    fprintf(stderr, "    --auport  Auth server listening port.\n");
    fprintf(stderr, "    --addr    Sink server FQDN or IP.\n");
    fprintf(stderr, "    --port    Sink server listening port.\n");
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
		{"auaddr",  required_argument, 0, 'c'},
		{"auport",  required_argument, 0, 'd'},
		{"workdir",  required_argument, 0, 'e'},
		{"lockdir",  required_argument, 0, 'f'},
		{"help",     no_argument,       0, 'h'},
		{0, 0, 0, 0}
	};

	int option_index = 0;

	bool wDirPassed = false;

	bool isAddr, isPort, isAuAddr, isAuPort, isLockDir;
	isAddr = isPort = isAuAddr = isAuPort = isLockDir = false;

	char addr[ADDRLEN];
	char port[PORTLEN];
	char authAddr[ADDRLEN];
	char authPort[PORTLEN];
	

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
				strncpy(authAddr, optarg, ADDRLEN);
				cout << "    auaddr=" << authAddr << endl;
				isAuAddr = true;
				break;

			case 'd':
				strncpy(authPort, optarg, PORTLEN);
				cout << "    auport=" << authPort << endl;
				isAuPort = true;
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

	if(!(isAddr && isPort && isAuAddr && isAuPort && isLockDir)){
		usage();
	}

	try{
		TSenseSinkDaemon sinkDaemon("tsensesinkd", 
			lockDir,
			//SINGLETON);
			SINGLETON|NO_DTTY,
			addr,
			port,
			authAddr,
			authPort);

		// The default working directory for BDaemon is /tmp, set it to
		// the location of the daemon or what ever is specified by option.

		if(wDirPassed){
			cout << "wDirPassed" << endl;
			cout << "workDir=" << workDir << endl;
			sinkDaemon.setWorkDir( workDir );
		} else {
			cout << "else" << endl;
			char cwd[PATHLEN];
			getcwd(cwd, PATHLEN);
			sinkDaemon.setWorkDir(cwd);
		}


		sinkDaemon.run();
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
