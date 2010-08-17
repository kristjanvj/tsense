
CC = g++
CFLAGS = 
LFLAGS = -lssl -lcrypto
IFLAGS = -I/usr/include/ -I../../../aes_crypt/lib/
RM = /bin/rm
CAT = /bin/cat
OPENSSL = /usr/bin/openssl

CRYPT_DIR=../../../aes_crypt/lib/
PROT_DIR=../../../aes_crypt/lib/

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

ARCH=FOO

MSG=" Please pass the ARCH variable to make like this:\n"\
    "     make <target> ARCH=INTEL_32|INTEL_64\n"\
	"DO NOT set the ARCH variable in the makefile it self.\n"\
	"Doing so can lead to hard-to-debug compiler errors."

$(CLIPROT):
ifeq ($(ARCH),$(filter $(ARCH),INTEL_32 INTEL_64))
	@echo "Compiling PROT client:"
	@echo "----------------------"
	$(CC) -D_$(ARCH) $(LFLAGS) $(IFLAGS) tls_client_prot.cpp common.c \
	$(PROT_DIR)protocol.cpp \
	$(CRYPT_DIR)aes_cmac.cpp \
	$(CRYPT_DIR)aes_crypt.cpp \
	-o cliprot
	@echo
else
	@echo
	@echo $(MSG)
	@echo
endif

clean:
	$(RM) -f $(CLIBIO) $(CLISSL) $(CLIPROT)
