/*
   File name: tsense_db_sensor_profile.h
   Date:      2010-08-21 11:23
   Author:    Kristjan Runarsson
*/

#ifndef __TSENSE_DB_BASESENSOR_PROFILE_H__
#define __TSENSE_DB_BASESENSOR_PROFILE_H__

#include <iostream>
#include <stdexcept>

#include "aes_crypt.h"
#include "aes_cmac.h"

#include <mysql.h>

#include <string.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#define MSGLEN 1000
#define GET_MSG(msg) snprintf(msg, MSGLEN, "%s:%d - %s", \
        __FILE__, __LINE__, mysql_error(connection));

typedef struct db_conn_data {
	const char *hostName;
	const char *userName;
	const char *passWord;
	const char *dbName;
} dbConnectData;


using namespace std;

class TsDbSensorProfile {

protected:
	const char *_hostName;
	const char *_userName;
	const char *_passWord;
	const char *_dbName;

	byte_ard *devicePublicId;

	int base64Encode(unsigned char *input, int inlen, char* output);
	int base64Decode(char *input, int inlen, unsigned char *output);

public:
    TsDbSensorProfile(byte_ard * pID, dbConnectData dbcd);

	~TsDbSensorProfile();

	void deriveKeyScheds(byte_ard *key, byte_ard *constant, 
						 byte_ard *cryptoKeySched,
						 byte_ard *macKeySched);

	bool profileExists();

	virtual void retrieve() = 0;
	virtual void persist() = 0;
};



#endif

