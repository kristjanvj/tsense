
CC = g++
CFLAGS = 
LFLAGS = -lssl -lcrypto
IFLAGS = -I/usr/include/ -I../common/
RM = /bin/rm
CAT = /bin/cat
OPENSSL = /usr/bin/openssl

CRYPT_ROOT=../../../aes_crypt/lib/
PROT_ROOT=../../../aes_crypt/lib/

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

#filter 
$(CLIPROT):
ifeq ($(ARCH), $(or $(ARCH),INTEL32,INTEL64))
	@echo "Compiling PROT client:"
	@echo "----------------------"
	$(CC) -D_$(ARCH) $(LFLAGS) tls_client_prot.cpp common.c \
	$(PROT_ROOT)protocol.cpp \
	$(CRYPT_ROOT)aes_cmac.cpp \
	$(CRYPT_ROOT)aes_crypt.cpp \
	-o cliprot
	@echo
else
	@echo
	@echo 'Please either set the ARCH variable to INTEL32/INTEL64 in the'
	@echo 'make file orpass it to the makefile:'
	@echo '     make <target> [ARCH=INTEL32 | INTEL64]'
	@echo
endif

clean:
	$(RM) -f $(CLIBIO) $(CLISSL) $(CLIPROT)
