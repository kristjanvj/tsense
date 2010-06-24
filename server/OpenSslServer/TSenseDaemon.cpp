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
#include "TlsServer.h"

using namespace std;

class TSenseDaemon: public BDaemon{
	public:
		TSenseDaemon(const char *daemonName, const char* lockDir, int daemonFlags);
	protected:
		void work();
};

TSenseDaemon::TSenseDaemon(const char *daemonName, 
					   const char* lockDir, 
					   int daemonFlags) 
: BDaemon(daemonName, lockDir, daemonFlags){} 

void TSenseDaemon::work(){
	TlsServer tlss(5556);
	tlss.serverMain();
}

int main()
{

	try{
		//TSenseDaemon arDaemon("tsensed", "/tmp/", SINGLETON);
		TSenseDaemon arDaemon("tsensed", "/tmp/", SINGLETON|NO_DTTY);

		arDaemon.run();
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
