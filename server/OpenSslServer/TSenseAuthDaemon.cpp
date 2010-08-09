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
};

TSenseAuthDaemon::TSenseAuthDaemon(const char *daemonName, 
					   const char* lockDir, 
					   int daemonFlags) 
: BDaemon(daemonName, lockDir, daemonFlags){} 

void TSenseAuthDaemon::work(){
	TlsAuthServer tlsa("localhost", "6001");
	syslog(LOG_ERR, getWorkDir().c_str());
	tlsa.serverMain();
}

int main()
{

	try{
		//TSenseAuthDaemon authDaemon("tsensed", "/tmp/", SINGLETON);
		TSenseAuthDaemon authDaemon("tsenseauthd", "/tmp/", SINGLETON|NO_DTTY);
		authDaemon.setWorkDir(
			"/Users/kristjanr/Desktop/Arduino/tsense/server/OpenSslServer");

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
