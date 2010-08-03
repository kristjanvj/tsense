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
#include "TlsSinkServer.h"

using namespace std;

class TSenseSinkDaemon: public BDaemon{
	public:
		TSenseSinkDaemon(const char *daemonName, const char* lockDir, int daemonFlags);
	protected:
		void work();
};

TSenseSinkDaemon::TSenseSinkDaemon(const char *daemonName, 
					   const char* lockDir, 
					   int daemonFlags) 
: BDaemon(daemonName, lockDir, daemonFlags){} 

void TSenseSinkDaemon::work(){
	TlsSinkServer tlss(5556);
	tlss.serverMain();
}

int main()
{

	try{
		//TSenseSinkDaemon arDaemon("tsensed", "/tmp/", SINGLETON);
		TSenseSinkDaemon arDaemon("tsensed", "/tmp/", SINGLETON|NO_DTTY);

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
