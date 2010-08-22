
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


all: servers certs

servers: auth sink

AUTHDNAME = tsauthd

MSG=" Please pass the ARCH variable to make like this:\n"\
	"     make <target> ARCH=INTEL_32|INTEL_64\n"\
	"DO NOT set the ARCH variable in the makefile it self.\n"\
	"Doing so can lead to hard-to-debug compiler errors."

ARCH=FOO

auth:
ifeq ($(ARCH),$(filter $(ARCH),INTEL_32 INTEL_64))
	@echo "Compiling  auth server:"
	@echo "-----------------------"
	$(CC) -D_$(ARCH) $(IFLAGS) $(LFLAGS) tsauthdaemon.cpp \
	$(COMM_DIR)BDaemon.cpp \
	tls_baseserver.cpp tls_authserver.cpp tsense_keypair.cpp \
	$(CRYPT_DIR)protocol.cpp \
	$(CRYPT_DIR)aes_cmac.cpp \
	$(CRYPT_DIR)aes_crypt.cpp \
	-o $(AUTHDNAME)
	@echo
else
	@echo
	@echo $(MSG)
	@echo
endif

SINKDNAME = tssinkd

sink:
ifeq ($(ARCH),$(filter $(ARCH),INTEL_32 INTEL_64))
	@echo "Compiling sink server:"
	@echo "-----------------------"

	$(CC) -D_$(ARCH) $(IFLAGS) $(LFLAGS) tssinkdaemon.cpp \
	$(COMM_DIR)BDaemon.cpp \
	tls_baseserver.cpp tls_sinkserver.cpp tsense_keypair.cpp \
	$(CRYPT_DIR)protocol.cpp \
	$(CRYPT_DIR)aes_cmac.cpp \
	$(CRYPT_DIR)aes_crypt.cpp \
	-o $(SINKDNAME)
	@echo
else
	@echo
	@echo $(MSG)
	@echo
endif

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
