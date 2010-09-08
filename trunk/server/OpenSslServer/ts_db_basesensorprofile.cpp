/*
	File name: tsense_db_sensor_profile.cpp
	Date:      2010-08-21 11:23
	Author:    Kristjan Runarsson
*/

#include "ts_db_basesensorprofile.h"

TsDbSensorProfile::TsDbSensorProfile(byte_ard * pID, dbConnectData dbcd)
{
	_hostName = dbcd.hostName;
	_userName = dbcd.userName;
	_passWord = dbcd.passWord;
	_dbName = dbcd.dbName;

	devicePublicId = pID;
}

TsDbSensorProfile::~TsDbSensorProfile() {
}

/* Given a byte_ard string of arbitrary length, create a base 64 representation
 * of that string. Note that the resulting base64 string stored in 'output'
 * must be one byte longer than the calculated length of the base64 encoded
 * string it contains since this function will null terminate the stirng.
 */
int TsDbSensorProfile::base64Encode(unsigned char *input, int inlen, 
										char* output) 
{
	BIO *bmem, *b64;
	BUF_MEM *bptr;

	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_new(BIO_f_base64());
	b64 = BIO_push(b64, bmem);
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	BIO_write(b64, input, inlen);
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);

	memcpy(output, bptr->data, bptr->length);
	output[bptr->length] = 0x0;

	BIO_free_all(b64);

	return strlen(output);;	
}

/* Given a base64 encoded string decode that string back to it's original
 * form and copy it into the 'output' parameter.
 */
int TsDbSensorProfile::base64Decode(char *input, int inlen, 
										unsigned char *output) 
{
	BIO *b64, *bmem, *foo;

	// Fills the first inlen bytes of output with 0x0. 
	memset(output, 0, inlen);

	bmem = BIO_new_mem_buf(input, inlen);
	b64 = BIO_new(BIO_f_base64());
	// creates a memory BIO using 'inlen' bytes of data at 'input'
	bmem = BIO_push(b64, bmem);
	BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);

	// attempts to read 'inlen' bytes from BIO 'bmem' and places the data 
	// in 'output' 
	int read = BIO_read(bmem, output, inlen);

	BIO_free_all(bmem);

	return read;
}


/* Given a single key:
 *  1) Expand the key schedule for that key.
 *  2) Derive a corresponding CMAC key using a constant.
 *  3) Expand the CMAC keyschedule.
 */
void TsDbSensorProfile::deriveKeyScheds(byte_ard *key, byte_ard *constant, 
									    byte_ard *cryptoKeySched,
									    byte_ard *macKeySched) {

	byte_ard cryptoKey[BLOCK_BYTE_SIZE];
	byte_ard macKey[BLOCK_BYTE_SIZE];

	memcpy(cryptoKey, (void*) key, BLOCK_BYTE_SIZE);

    // Expand crypto key schedule.
    KeyExpansion(key, cryptoKeySched);

    // Expand constant key schedule which we will need to generate the mac key.
    byte_ard constKeySched[BLOCK_BYTE_SIZE*11];
    KeyExpansion(constant, constKeySched);

    // Derive the mac key using AES cMAC. The constant is the key and the 
    // key is the message M that will be cMAC'ed.
    aesCMac((u_int32_ard*) constKeySched,
        cryptoKey,
        BLOCK_BYTE_SIZE,
        macKey);

    //Key schedule for the mac key
    KeyExpansion(macKey, macKeySched);
}

/* Take the class internal device public-id and check whether a corresponding
 * sensor profile exists in the server state table. If this process fails a
 * runtime error is trown.
 */
bool TsDbSensorProfile::profileExists() {

	MYSQL *connection, mysql;
	MYSQL_RES *result;
	MYSQL_ROW row;
	int query_state;

	mysql_init(&mysql);
    connection = mysql_real_connect(&mysql, _hostName, _userName,
                                    _passWord, _dbName, 0,0,0);

	char b64PID[12];
    int b64len = base64Encode(devicePublicId, 6, b64PID);

	const char *queryStr={"select count(*) from sink_state where pid = '%s'"};
	char query[1000];

	int qLen = sprintf(query, queryStr, b64PID);

	byte_ard ub64PID[KEY_BYTES*11];

	base64Decode(b64PID, strlen(b64PID), ub64PID);

	query_state = mysql_query(connection, query);
	if (query_state !=0) {
		char msg[MSGLEN];
		GET_MSG(msg);
		throw runtime_error(msg);
		return 1;
	}

	result = mysql_store_result(connection);

	row = mysql_fetch_row(result);


	if(atoi(row[0]) > 0) {
		return true;
	} else {
		return  false;
	}

    mysql_free_result(result);
    mysql_close(connection);
}

void TsDbSensorProfile::retrieve(){
}

void TsDbSensorProfile::persist() {
}
