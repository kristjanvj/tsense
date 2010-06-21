/*
   File name: tdaemon.h
   Date:	  2006-08-08 14:29
   Author:	Kristjan Runarsson
*/

#include <iostream>
#include <fstream>
#include <string>
#include <stdexcept>
#include <sstream>

//Requisite C libraries. FIXME check, not all of them will really be needed.
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>

#ifndef __TDAEMON_H__
#define __TDAEMON_H__

// The Class initialization flag 0x10000 to 0x100008000.
#define MULTIPLE  0x0   // Allow multiple instances of daemon.
#define SINGLETON 0x100	// Singleton mode, creates lockfile.
						   

// Opt out flags for various daemoization tasks most daemons won't have any reason use them.
#define NO_SUMSK  0x1   // Do not set the umask.
#define NO_DTTY   0x2	// Disable detachment from TTY (i.e. fork() the daemon)
#define NO_ISLOG  0x4	// Disabe initializaton of syslog
#define NO_CROOT  0x8	// Do not change working directory.
#define NO_CFDSC  0x10	// Disable closing of file descriptors
#define NO_FTNULL 0x20	// Disable attachment of FDs 0,1,2 to /dev/null

#define LOCKMODE (S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)

using namespace std;
/**  \class BDaemon
 * \brief A daemon base class.
 *
 * This simple daemon base class provides all the basic tasks a daemon has to 
 * do peform. The intention is that this class be extended by the developer.
 */

//class BDaemonException: public Exception{
//}

class BDaemon{
public:
	/** Constructor.*/	
	BDaemon(const char *daemonName, const char* lockDir,  int daemonFlags);

	/** Destructor.*/
	~BDaemon();

	/** This Method is called from main. It calls Daemonize and Work(), thus
	 * starting the daemon.*/
	void  run();
	
	/** The working logic of the daemon should be implemented in this method.*/
	virtual void work();

	/** Checks the working directory using the getwd() function form the standard
	 * C-library rather than just retruning the value of '_daemonWorkDir'.*/
	void checkWorkDir(string& sWorkDir);
	
	//Accessors.
	/**Accessor.*/
	string getDaemonName();
	/**Accessor.*/
	int getDaemonPid();
	/**Accessor.*/
	string getLockFileName();
	/**Accessor.*/
	string getLockFilePath();
	/**Accessor.*/
	string getWorkDir();
	
private:

	/** The name of this daemon.*/
	string _daemonName;

	/** The daemon's working directory.*/
	string _daemonWorkDir;

	/** Initialization flags for the daemon defined in tdaemon.h.*/
	unsigned int _daemonFlags;
	
	/** The pid of the second child process (the actual daemon).*/
	int _daemonPid;

	/** Lockfile default location, hardwired to /var/run.*/
	string _lockFilePath;

	/** Path where the lock file will be created. */
	string _lockDir;

protected:

	/** Change the File Mode Mask (umask) to ensure ensure files created by 
	  * the daemon can be written and read properly.*/
	void setUmask();
	
	/** The standard daemonization method. Implement the daemonization logic
	 * using the utility functions provided by this class.*/
	virtual int daemonize(); 

	/** Become a session leader to lose any controlling terminal and ensure that
	 * future opens won't allocate controlling terminals.*/
	void detachTerminal();
	
	/** Change working directory to '/' to avoid blocking a umount.*/
	void changeWorkDir();
	
	/** Close all open file descripteors inherited form the parent.*/
	void fdClose();
	
	/** Attatch file descriptors 0, 1 and 2 to /dev/null to prevent unwanted 
	  * reads and writes to STDOUT/STDIN/STDERR.*/
	void fdToDevNull();

	/** Initialize the log facility.*/
	void initSyslog();

	/** Create lock file to ensure the daemon is a singleton.*/
	void lockDaemon();
	
	/** Obtain a write/read lock on a file dsecriptor.*/
	int lockFile(int lockFd);

	/** Does the lock file exist and is it locked. If it is locked print 
	 * message to console.*/
	void checkLocked();

}; // end class BDaemon

//Base exception class for BDaemon.
class DaemonException : public exception{
	public:
		explicit DaemonException(const string& what):
									   m_what(what){
		}

		virtual ~DaemonException() throw() {}

		virtual const char * what() const throw()
		{
			return m_what.c_str();
		}

	private:
		string m_what;
};

class ForkException : public DaemonException{
public:
	ForkException(const string& what) : DaemonException(what){}
	virtual ~ForkException() throw() {}
};

class SigHupException : public DaemonException{
public:
	SigHupException(const string& what) : DaemonException(what){}
	virtual ~SigHupException() throw() {}
};

class FdMaxException : public DaemonException{
public:
	FdMaxException(const string& what) : DaemonException(what){}
	virtual ~FdMaxException() throw() {}
};

#endif
