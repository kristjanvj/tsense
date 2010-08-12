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

	//checkLocked();
	daemonize();
	work();
}

void BDaemon::work(){ /*Abstract*/ }

int BDaemon::daemonize(){

	if(!(_daemonFlags & NO_SUMSK)){
		//syslog(LOG_NOTICE, "SetUmask();");
		setUmask();
	}
	
	if(!(_daemonFlags & NO_DTTY)){
		//syslog(LOG_NOTICE, "DetachTerminal();");
		detachTerminal();
	}
	
	if(!(_daemonFlags & NO_ISLOG)){
		// Make this call first because other methods in this class call syslog. 
		//syslog(LOG_NOTICE, "InitSyslog()");
		initSyslog();
	}

	if(!(_daemonFlags & NO_CROOT)){
		//syslog(LOG_NOTICE, "ChangeWorkDir();");
		changeWorkDir();
	}
		
	if(!(_daemonFlags & NO_CFDSC)){
		//syslog(LOG_NOTICE, "FdClose();");
		fdClose();
	}
	
	if(!(_daemonFlags & NO_FTNULL)){
		//syslog(LOG_NOTICE, "FdToDevNull();");
		fdToDevNull();
	}

	if((_daemonFlags & SINGLETON)){
		//syslog(LOG_NOTICE,"LockDaemon();");
		lockDaemon();
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
		//sleep(10); // DEBUG
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

/*
void BDaemon::lockDaemon(){
	int lockFd;
	char buf[16];

	lockFd = open(_lockFilePath.c_str(), O_RDWR|O_CREAT, LOCKMODE);

	if(lockFd < 0){
		syslog(LOG_ERR, "Unable to open the lockfile: %s", _lockFilePath.c_str());
		exit(1);
	}

	if(lockFile(lockFd) < 0) {
		if(errno == EACCES || errno == EAGAIN){
			close(lockFd);
			syslog(LOG_ERR, "Another instance of '%s' is already running, lockfile: %s",
				_daemonName.c_str(), _lockFilePath.c_str());
			exit(1);
		}
		syslog(LOG_ERR, "Unable to lock: %s", _lockFilePath.c_str());
		exit(1);
	}
	
	ftruncate(lockFd, 0);

	stringstream pid;
	pid << _daemonPid << endl;
	write(lockFd, pid.str().c_str(), strlen(pid.str().c_str())+1);
}
*/

void BDaemon::lockDaemon(){
	syslog(LOG_NOTICE, "%s", "lockDaemon(new)");

    int fd;
    struct flock fl;

    fd = open(_lockFilePath.c_str(), O_RDWR|O_CREAT, 0644);
    //fd = open(_lockFilePath.c_str(), O_RDWR);

    if(fd == -1) {
        syslog(LOG_NOTICE, "%s", "failed to open file");
		exit(1);
    }

    fl.l_type   = F_WRLCK;  /* F_RDLCK, F_WRLCK, F_UNLCK    */
    fl.l_whence = SEEK_SET; /* SEEK_SET, SEEK_CUR, SEEK_END */
    fl.l_start  = 0;        /* Offset from l_whence         */
    fl.l_len    = 0;        /* length, 0 = to EOF           */
    fl.l_pid    = getpid(); /* our PID                      */

    // Try to create a file lock, to test whether the lock file is 
	// already locked.
    if( fcntl(fd, F_SETLK, &fl) == -1) {    /* F_GETLK, F_SETLK, F_SETLKW */

		// We failed to create a file lock which means the file is indeed 
		// already locked.
        if( errno == EACCES || errno == EAGAIN) {

			string lockFilePid;
			ifstream inLockFile(_lockFilePath.c_str());
			inLockFile >> lockFilePid;

            syslog(LOG_NOTICE, "Lockfile already locked by %s", lockFilePid.c_str());
			exit(1);
        }
    }

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

/*
int BDaemon::lockFile(int lockFd){
	struct flock fl;

	fl.l_type = F_WRLCK;
	fl.l_start = 0;
	fl.l_whence = SEEK_SET;
	fl.l_len = 0;
	fl.l_pid = getpid();

	return fcntl(lockFd, F_SETLK, &fl);
}

void  BDaemon::checkLocked(){
	struct flock lock;
	int lockFd;
	
	access(_lockFilePath.c_str(), F_OK);
	if(errno != ENOENT && _daemonFlags & SINGLETON){

		lockFd = open(_lockFilePath.c_str(), O_RDWR|O_CREAT, LOCKMODE);

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
				 <<"  is already running, "
				 << "Lockfile: " << _lockFilePath << endl;
		}

		close(lockFd);
	}
}
*/

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
