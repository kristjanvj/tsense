
CC = g++
CFLAGS = 
LFLAGS = -lssl -lcrypto
IFLAGS = -I/usr/include/ -I../common/ -I../../aes_crypt/lib/
RM = /bin/rm
CAT = /bin/cat
OPENSSL = /usr/bin/openssl

CRYPT_DIR=../../aes_crypt/lib/
PROT_DIR=../../aes_crypt/lib/
COMM_DIR=../common/


all_i32: servers_i32 certs
all_i64: servers_i64 certs

servers_i32: auth_i32 sink_i32
servers_i64: auth_i64 sink_i64

AUTHDNAME = tsauthd

AUTH_DD =	$(CC) -D_$(ARCH) $(IFLAGS) $(LFLAGS) tsauthdaemon.cpp \
			$(COMM_DIR)BDaemon.cpp \
			tls_baseserver.cpp tls_authserver.cpp tsense_keypair.cpp \
			$(CRYPT_DIR)protocol.cpp \
			$(CRYPT_DIR)aes_cmac.cpp \
			$(CRYPT_DIR)aes_crypt.cpp \
			-o $(AUTHDNAME)

AUTH_MSG = "Compiling auth server:\n-----------------------"

auth_i32: ARCH=INTEL_32
auth_i32:
	@echo $(AUTH_MSG)
	$(AUTH_DD)
	@echo

auth_i64: ARCH=INTEL_64
auth_i64:
	@echo $(AUTH_MSG)
	$(AUTH_DD)
	@echo


SINKDNAME = tssinkd

SINK_MSG = "Compiling sink server:\n-----------------------"

SINK_DD =	$(CC) -D_$(ARCH) $(IFLAGS) $(LFLAGS) tssinkdaemon.cpp \
			$(COMM_DIR)BDaemon.cpp \
			tls_baseserver.cpp tls_sinkserver.cpp tsense_keypair.cpp \
			$(CRYPT_DIR)protocol.cpp \
			$(CRYPT_DIR)aes_cmac.cpp \
			$(CRYPT_DIR)aes_crypt.cpp \
			-o $(SINKDNAME)

sink_i32: ARCH=INTEL_32
sink_i32:
	@echo $(SINK_MSG)
	$(SINK_DD)
	@echo

sink_i64: ARCH=INTEL_64
sink_i64:
	@echo $(SINK_MSG)
	$(SINK_DD)
	@echo

certs: root.pem serverCA.pem server.pem client.pem

root.pem:
	$(OPENSSL) req -newkey rsa:1024 -sha1 -keyout rootkey.pem -out rootreq.pem \
	-config root.cnf
	$(OPENSSL) x509 -req -in rootreq.pem -sha1 -extfile root.cnf -extensions \
	certificate_extensions -signkey rootkey.pem -out rootcert.pem
	$(CAT) rootcert.pem rootkey.pem > root.pem

serverCA.pem:
	$(OPENSSL) req -newkey rsa:1024 -sha1 -keyout serverCAkey.pem -out \
	serverCAreq.pem -config serverCA.cnf
	$(OPENSSL) x509 -req -in serverCAreq.pem -sha1 -extfile serverCA.cnf \
	-extensions certificate_extensions -CA root.pem -CAkey root.pem \
	-CAcreateserial -out serverCAcert.pem
	$(CAT) serverCAcert.pem serverCAkey.pem rootcert.pem > serverCA.pem

server.pem:
	$(OPENSSL) req -newkey rsa:1024 -sha1 -keyout serverkey.pem -out \
	serverreq.pem -config server.cnf -reqexts req_extensions
	$(OPENSSL) x509 -req -in serverreq.pem -sha1 -extfile server.cnf \
	-extensions certificate_extensions -CA serverCA.pem -CAkey \
	serverCA.pem -CAcreateserial -out servercert.pem
	$(CAT) servercert.pem serverkey.pem serverCAcert.pem rootcert.pem > server.pem

client.pem:
	$(OPENSSL) req -newkey rsa:1024 -sha1 -keyout clientkey.pem -out \
	clientreq.pem -config client.cnf -reqexts req_extensions
	$(OPENSSL) x509 -req -in clientreq.pem -sha1 -extfile client.cnf \
	-extensions certificate_extensions -CA root.pem -CAkey root.pem \
	-CAcreateserial -out clientcert.pem
	$(CAT) clientcert.pem clientkey.pem rootcert.pem > client.pem

certclean: genclean pemclean

genclean:
	$(RM) -f rootkey.pem rootreq.pem rootcert.pem root.srl
	$(RM) -f serverCAkey.pem serverCAreq.pem serverCAcert.pem serverCA.pem \
	serverCA.srl
	$(RM) -f serverkey.pem serverreq.pem servercert.pem
	$(RM) -f clientkey.pem clientreq.pem clientcert.pem

pemclean:
	$(RM) -f server.pem root.pem client.pem

clean:
	$(RM) -f $(AUTHDNAME) $(SINKDNAME)
