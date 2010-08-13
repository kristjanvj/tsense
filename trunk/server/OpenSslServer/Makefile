
CC = g++
CFLAGS = 
LFLAGS = -lssl -lcrypto
IFLAGS = -I/usr/include/ -I../common/
RM = /bin/rm
CAT = /bin/cat
OPENSSL = /usr/bin/openssl

CERTS = root.pem serverCA.pem server.pem client.pem

all: $(CERTS) 

servers: auth sink

AUTHDNAME = tsauthd

auth:
	$(CC) $(IFLAGS) $(LFLAGS) tsauthdaemon.cpp ../common/BDaemon.cpp \
	tls_baseserver.cpp tls_authserver.cpp -o $(AUTHDNAME)

SINKDNAME = tssinkd

sink:
	$(CC) $(IFLAGS) $(LFLAGS) tssinkdaemon.cpp ../common/BDaemon.cpp \
	tls_baseserver.cpp tls_sinkserver.cpp -o $(SINKDNAME)

$(CERTS): $(CERTS:.pem=.cnf)
	echo "Creating root certificate:"
	echo "--------------------------"
	$(OPENSSL) req -newkey rsa:1024 -sha1 -keyout rootkey.pem -out rootreq.pem \
	-config root.cnf
	$(OPENSSL) x509 -req -in rootreq.pem -sha1 -extfile root.cnf -extensions \
	certificate_extensions -signkey rootkey.pem -out rootcert.pem
	$(CAT) rootcert.pem rootkey.pem > root.pem
	echo "Creating server CA:"
	echo "----------------------------"
	$(OPENSSL) req -newkey rsa:1024 -sha1 -keyout serverCAkey.pem -out \
	serverCAreq.pem -config serverCA.cnf
	$(OPENSSL) x509 -req -in serverCAreq.pem -sha1 -extfile serverCA.cnf \
	-extensions certificate_extensions -CA root.pem -CAkey root.pem \
	-CAcreateserial -out serverCAcert.pem
	$(CAT) serverCAcert.pem serverCAkey.pem rootcert.pem > serverCA.pem
	echo "Creating server certificate:"
	echo "----------------------------"
	$(OPENSSL) req -newkey rsa:1024 -sha1 -keyout serverkey.pem -out \
	serverreq.pem -config server.cnf -reqexts req_extensions
	$(OPENSSL) x509 -req -in serverreq.pem -sha1 -extfile server.cnf \
	-extensions certificate_extensions -CA serverCA.pem -CAkey \
	serverCA.pem -CAcreateserial -out servercert.pem
	$(CAT) servercert.pem serverkey.pem serverCAcert.pem rootcert.pem > server.pem
	echo "Creating client certificate:"
	echo "----------------------------"
	$(OPENSSL) req -newkey rsa:1024 -sha1 -keyout clientkey.pem -out \
	clientreq.pem -config client.cnf -reqexts req_extensions
	$(OPENSSL) x509 -req -in clientreq.pem -sha1 -extfile client.cnf \
	-extensions certificate_extensions -CA root.pem -CAkey root.pem \
	-CAcreateserial -out clientcert.pem
	$(CAT) clientcert.pem clientkey.pem rootcert.pem > client.pem

certclean:
	$(RM) -f rootkey.pem rootreq.pem rootcert.pem root.pem root.srl
	$(RM) -f serverCAkey.pem serverCAreq.pem serverCAcert.pem serverCA.pem \
	serverCA.srl
	$(RM) -f serverkey.pem serverreq.pem servercert.pem server.pem
	$(RM) -f clientkey.pem clientreq.pem clientcert.pem client.pem

clean:
	$(RM) -i $(AUTHDNAME) $(SINKDNAME)
