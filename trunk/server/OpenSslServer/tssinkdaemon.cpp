/*
 * File name: amsd.cpp
 * Date:	  2006-08-08 16:05
 * Author:	Kristjan Runarsson
 */

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include "BDaemon.h"
#include "tls_sinkserver.h"

using namespace std;

class TSenseSinkDaemon: public BDaemon{
	public:
		TSenseSinkDaemon(const char *daemonName, const char* lockDir, int daemonFlags);
	protected:
		void work();

	private:
		TlsSinkServer *tlss;
};

TSenseSinkDaemon::TSenseSinkDaemon(const char *daemonName, 
					   const char* lockDir, 
					   int daemonFlags) 
: BDaemon(daemonName, lockDir, daemonFlags){
	tlss = new TlsSinkServer("auth.tsense.sudo.is", "6001", 	// Peer.
							 "sink.tsense.sudo.is", "6002");	// Me
} 

void TSenseSinkDaemon::work(){
	tlss->serverMain();
}

int main()
{
	try{
		TSenseSinkDaemon sinkDaemon("tsensesinkd", 
			"/home/kr/tsense/server/OpenSslServer/",
			SINGLETON);
			//SINGLETON|NO_DTTY);
		sinkDaemon.setWorkDir(
			"/home/kr/tsense/server/OpenSslServer");


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
