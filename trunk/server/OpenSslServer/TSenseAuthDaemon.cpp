/*
 * File name: TSenseAuthDaemon.cpp
 * Date:	  2006-08-08 16:05
 * Author:	Kristjan Runarsson
 */

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include "BDaemon.h"
#include "TlsAuthServer.h"

using namespace std;

class TSenseAuthDaemon: public BDaemon{
	public:
		TSenseAuthDaemon(const char *daemonName, const char* lockDir, int daemonFlags);
	protected:
		void work();

	private:
		TlsAuthServer *tlsa;
};

TSenseAuthDaemon::TSenseAuthDaemon(const char *daemonName, 
					   const char* lockDir, 
					   int daemonFlags) 
				: BDaemon(daemonName, lockDir, daemonFlags){

	tlsa = new TlsAuthServer("sink.tsense.sudo.is",				// Peer.,
							 "auth.tsense.sudo.is", "6001");	// Me.
} 

void TSenseAuthDaemon::work(){
	syslog(LOG_ERR, "%s", getWorkDir().c_str());
	tlsa->serverMain();
}

int main()
{
	try{
		TSenseAuthDaemon authDaemon("tsenseauthd", 
			"/home/kr/tsense/server/OpenSslServer/", SINGLETON);
		authDaemon.setWorkDir(
			"/home/kr/tsense/server/OpenSslServer");

		cout << "Running daemon" << endl;
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
