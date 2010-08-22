
CC = g++
CFLAGS = 
LFLAGS = -lssl -lcrypto

CRYPT_DIR=../../../aes_crypt/lib/
PROT_DIR=../../../aes_crypt/lib/
SERVER_DIR=../

IFLAGS = -I/usr/include/ -I$(CRYPT_DIR) -I$(PROT_DIR) -I$(SERVER_DIR)

RM = /bin/rm
CAT = /bin/cat
OPENSSL = /usr/bin/openssl

CLIBIO=clibio
CLISSL=clissl
CLIPROT=cliprot



all: $(CLIBIO) $(CLISSL) $(CLIPROT)

$(CLIBIO):
	@echo "Compiling BIO client:"
	@echo "---------------------"
	$(CC) $(LFLAGS) tls_client_bio.cpp common.c -o $(@) 
	@echo

$(CLISSL):
	@echo "Compiling BIO client:"
	@echo "---------------------"
	$(CC) $(LFLAGS) tls_client_ssl.cpp common.c -o $(@)
	@echo

ARCH=

CLIPROT_CC =	$(CC) -D_$(ARCH) $(LFLAGS) $(IFLAGS) \
				tls_client_prot.cpp \
				common.c \
				$(SERVER_DIR)tsense_keypair.cpp \
				$(PROT_DIR)protocol.cpp \
				$(CRYPT_DIR)aes_cmac.cpp \
				$(CRYPT_DIR)aes_crypt.cpp \
				-o $(CLIPROT)

MSG = "Compiling PROT client:\n----------------------"

cliprot_i32: ARCH=INTEL_32
cliprot_i32:
	@echo $(MSG)
	$(CLIPROT_CC)

cliprot_i64: ARCH=INTEL_64
cliprot_i64:
	@echo $(MSG)
	$(CLIPROT_CC)

clean:
	$(RM) -f $(CLIBIO) $(CLISSL) $(CLIPROT)
