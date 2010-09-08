
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
SENSORPROFILE=test_sensor_profile

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

IFLAGS += -I/usr/include/mysql/ 
LFLAGS += -lmysqlclient

SENSOR_PROFILE_CC =	$(CC) $(CFLAGS) -D_$(ARCH) $(IFLAGS) \
					$(LFLAGS) \
					$(CRYPT_DIR)aes_crypt.cpp \
					$(CRYPT_DIR)aes_cmac.cpp \
					$(CRYPT_DIR)aes_utils.cpp \
					$(CRYPT_DIR)aes_constants.cpp \
					$(SERVER_DIR)ts_db_basesensorprofile.cpp \
					$(SERVER_DIR)ts_db_sinksensorprofile2.cpp \
					$(SERVER_DIR)tsense_keypair.cpp \
					test_sensor_profile.cpp \
					-o $(SENSORPROFILE) \

MSG= "Compiling sensor profile test:\n------------------------------"

sp_test_i32: ARCH=INTEL_32
sp_test_i32:
	@echo $(MSG)
	$(SENSOR_PROFILE_CC)

sp_test_i64: ARCH=INTEL_64
sp_test_i64:
	@echo $(MSG)
	$(SENSOR_PROFILE_CC)

clean:
	$(RM) -f $(CLIBIO) $(CLISSL) $(CLIPROT) $(SENSORPROFILE)
