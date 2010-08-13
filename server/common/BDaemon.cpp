/*
 * File name: BDaemon.cpp
 * Date:	  2006-08-08 10:32
 * Author:	Kristjan Runarsson
 */

#include "BDaemon.h"
#include <stdexcept>
#include <signal.h>

using namespace std;

BDaemon::BDaemon(const char *dameonName, const char* lockDir, int daemonFlags):
				 _daemonName(dameonName),
				 _lockDir(lockDir),
				 _daemonFlags(daemonFlags),
				 _daemonPid(getpid()),
				 _daemonWorkDir("/tmp") {
	// Build the pat to the lock file.
	_lockFilePath  = lockDir + _daemonName + ".pid";
	

	// Check for terminating '/' character in lock file path.
	int slash = _lockDir.find_last_of("/");
	if(slash != _lockDir.size()-1){
		string msg = "The path to the lock directory must end with a '/'.";
		throw DaemonException(msg.c_str());
	}

}

BDaemon::~BDaemon(){}

void BDaemon::run(){

	checkLocked();
	daemonize();
	work();
}

void BDaemon::work(){ /*Abstract*/ }

int BDaemon::daemonize(){

	if(!(_daemonFlags & NO_SUMSK)){
		//syslog(LOG_NOTICE, "setUmask();");
		setUmask();
	}
	
	if(!(_daemonFlags & NO_DTTY)){
		//syslog(LOG_NOTICE, "detachTerminal();");
		detachTerminal();
	}
	
	if(!(_daemonFlags & NO_ISLOG)){
		// Make this call first because other methods in this class call syslog. 
		//syslog(LOG_NOTICE, "initSyslog()");
		initSyslog();
	}

	if(!(_daemonFlags & NO_CROOT)){
		//syslog(LOG_NOTICE, "changeWorkDir();");
		changeWorkDir();
	}
		
	if(!(_daemonFlags & NO_CFDSC)){
		//syslog(LOG_NOTICE, "fdClose();");
		fdClose();
	}
	
	if(!(_daemonFlags & NO_FTNULL)){
		//syslog(LOG_NOTICE, "fdToDevNull();");
		fdToDevNull();
	}

	if((_daemonFlags & SINGLETON)){
		//syslog(LOG_NOTICE,"singleton();");
		singleton();
	}
}

void BDaemon::setUmask(){
	umask(0);
}

void BDaemon::detachTerminal(){
	pid_t   pid;
	struct  sigaction sa;
	stringstream msg;

	// Become a session leader to lose the controlling terminal.
	if((pid=fork())<0){ //Fork a child process.
		syslog(LOG_ERR,"daemonName was unable to fork.");
		throw ForkException("A call to fork() failed.");
		exit(0);
	} else if(pid!=0){ // The parent exits here.
		exit(0);
	}

	msg << "Detatched terminal for '" << _daemonName
		 << "' with pid: " << _daemonPid << endl;

	syslog(LOG_NOTICE, "%s", msg.str().c_str());

	setsid(); // Create a new session.

	sa.sa_handler=SIG_IGN;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags=0;

	if(sigaction(SIGHUP, &sa, NULL)<0){
		throw SigHupException("I can't ignore SIGHUP.");
	}

	// Fork a second child to guarantee the daemon is not a session leader
	// which means that under System V it can't acquire a controlling terminal.
	if((pid=fork())<0){ //Fork a child process.
		throw ForkException("A call to fork() failed.");
	}else if(pid!=0){ // The parent exits here.
		exit(0);
	}

	_daemonPid=getpid();
	
}

void BDaemon::changeWorkDir(){
	chdir(_daemonWorkDir.c_str());
}

void BDaemon::fdClose(){
	int i;
	struct rlimit rl;

	// Get maximum number of file descriptors.
	if(getrlimit(RLIMIT_NOFILE, &rl)<0){
		throw FdMaxException("Unable to obtain maximum file limit.");
	}
	
	// Close all open file descriptors.
	if(rl.rlim_max==RLIM_INFINITY){
		rl.rlim_max=1024;
	}

	// Close the file descriptors.
	for(i=0; i<rl.rlim_max; i++){
		close(i);
	}
}

void BDaemon::fdToDevNull(){
	// Having closed all the filedescriptors open will return the lowest 
	// avalable one which is '0'.
	open("/dev/null", O_RDWR); 
	fcntl(0,F_DUPFD,1);  // Apparently dup & dup2 are redundant.
	fcntl(0,F_DUPFD,2);
}

void BDaemon::initSyslog(){
	// Strictly speaking this is optional since openlog gets called the first
	// time syslog is called. Calling it here is cleaner since it prefixes an
	// ident to the syslog messages.
	openlog(getDaemonName().c_str(),LOG_PID|LOG_CONS,LOG_DAEMON); 
}

void BDaemon::singleton(){
    int fd;
    struct flock fl;

	syslog(LOG_NOTICE, "%s", "singleton()");

	fd = open(_lockFilePath.c_str(), O_RDWR|O_CREAT, LOCKMODE);
    //fd = open(_lockFilePath.c_str(), O_RDWR|O_CREAT, 0644);

    if(fd == -1) {
        syslog(LOG_NOTICE, "failed to open %s", _lockFilePath.c_str());
        exit(1);
    }

    fl.l_type   = F_WRLCK;  /* F_RDLCK, F_WRLCK, F_UNLCK    */
    fl.l_whence = SEEK_SET; /* SEEK_SET, SEEK_CUR, SEEK_END */
    fl.l_start  = 0;        /* Offset from l_whence         */
    fl.l_len    = 0;        /* length, 0 = to EOF           */
    fl.l_pid    = getpid(); /* our PID                      */

    // Try to create a file lock, to test whether the lock file is 
    // already locked.
	checkLocked();

    // Write our own pid into the lockfile.
    ofstream fout(_lockFilePath.c_str());
    fout << getpid();
    fout << flush;
    fout.close();

    // The above seems to break the lock so we relock.
    if( fcntl(fd, F_SETLK, &fl) == -1) {    /* F_GETLK, F_SETLK, F_SETLKW */

        if( errno == EACCES || errno == EAGAIN) {
            syslog(LOG_NOTICE, "Failed to obtain file lock on lockfile. ");
            exit(1);
        }
    }
}

void  BDaemon::checkLocked(){
	struct flock lock;
	int lockFd;
	
	access(_lockFilePath.c_str(), F_OK);
	if(errno != ENOENT && _daemonFlags & SINGLETON){

		lockFd = open(_lockFilePath.c_str(), O_RDWR|O_CREAT, LOCKMODE);
		//lockFd = open(_lockFilePath.c_str(), O_RDWR|O_CREAT, 0644);

		lock.l_type = F_WRLCK;
		lock.l_start = 0;
		lock.l_whence = SEEK_SET;
		lock.l_len = 0;
		lock.l_pid = getpid();

		if(fcntl(lockFd, F_GETLK, &lock) < 0){
			syslog(LOG_ERR,"Got fcntl error.");
			exit(1);
		}

		if(lock.l_type != F_UNLCK){
			cerr << "An instance of '" << _daemonName  
				 << "' with pid: " << lock.l_pid 
				 <<"  is already running." << endl
				 <<"Lockfile: " << _lockFilePath << endl;

			string lockFilePid;
			ifstream inLockFile(_lockFilePath.c_str());
			inLockFile >> lockFilePid;
			inLockFile.close();

			syslog(LOG_ERR, 
				"An instance of '%s' with pid: %s is already running, Lockfile: %s",
				_daemonName.c_str(), lockFilePid.c_str(), _lockFilePath.c_str());

			close(lockFd);
			exit(1);
		}
	}
}

string BDaemon::getDaemonName(){
	return _daemonName;
}

int BDaemon::getDaemonPid(){
	return _daemonPid;
}

string BDaemon::getLockFilePath(){
	return _lockFilePath;
}

string BDaemon::getWorkDir(){
	return _daemonWorkDir;
}

void BDaemon::setWorkDir(string wdir){
	_daemonWorkDir = wdir;
}
