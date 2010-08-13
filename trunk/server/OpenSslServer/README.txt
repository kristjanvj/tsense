Regarding the makefile:
-----------------------

make auth      - builds the TSense authentication daemon.
make sink      - Builds the TSense sink daemon.
make certs     - Builds the required certificates for the above. 
make genclean  - Deletes all cert files except: root.pem, client.pem and server.pem. 
make pemclean  - Deletes root.pem, client.pem and server.pem

To build the certificates:
--------------------------
First copy the *.cnf files from the 'certs' directory into the makefile 
directory. The certificates have to be built on a separte machine from the 
ones where the two severs are running. OpenSSL will throw an error if the 
root certificate  you are using with the auth or sink daemons was created on 
the same machine the daemon is running on. Other than building the certs on 
a separate machine from the two where you are running the servers it also 
seems to work to swap swap teh root certificates. In effect copy the root 
certificate created on the auth server to the sink server and vice versa.
