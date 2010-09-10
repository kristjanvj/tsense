/*
 * File name: ts_db_sinksensorprofile.cpp
 * Date:      2010-08-29 10:48
 * Author:    
 */

#include <iostream>
#include <string>
#include <syslog.h>
#include "ts_db_sinksensorprofile.h"

using namespace std;

/* Create a sensor profile for device with a given public-id. The object is 
 * intiialized locally with a set of keys derived from K_ST. The content of the 
 * object, the device public-id and key schedules the objec contains,  must 
 * be persisted to the database by calling the persist() method.
 */

//byte_ard R[KEY_BYTES] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
//						  0x38, 0x39, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45 };

TsDbSinkSensorProfile::TsDbSinkSensorProfile(byte_ard * K_ST,  byte_ard * pID,
							dbConnectData dbcd) :
						TsDbSensorProfile(	pID, dbcd)
{
    generateKey(R);
	memcpy(Kst, K_ST, KEY_BYTES);
	generateKeyScheds();
}

/* Attempts to intialize it self from DB. If no profile corresponding to 
 * the given device pubic-id  exists in the database the key schedules
 * are set to 0x0.
 */
TsDbSinkSensorProfile::TsDbSinkSensorProfile(byte_ard * pID,
							dbConnectData dbcd) :
						TsDbSensorProfile(pID, dbcd)
{
	memset(Kst,0x0, KEY_BYTES);
	memset(R,0x0, KEY_BYTES);

	memset(Kst_Sched,0x0, KEY_BYTES*11);
	memset(Ksta_Sched,0x0, KEY_BYTES*11);
	memset(Kste_Sched,0x0, KEY_BYTES*11);
	memset(Kstea_Sched,0x0, KEY_BYTES*11);

	if(profileExists()){
		retrieve();
	}
}

/* Returns a pointer to the key schedule for K_st which is the 
 * session encyption key.
 */
byte_ard *TsDbSinkSensorProfile::getKstSched(){
	return Kst_Sched;
}

/* Returns a pointer to the key schedule for K_sta which is the 
 * session CMAC key that corresponds to K_st.
 */
byte_ard *TsDbSinkSensorProfile::getKstaSched(){
	return Ksta_Sched;
}

/* Returns a pointer to the key schedule for K_ste which is the 
 * session data transfer encyption key.
 */
byte_ard *TsDbSinkSensorProfile::getKsteSched(){
	return Kste_Sched;
}

/* Returns a pointer to the key schedule for K_st which is the 
 * session encyption key.
 */
byte_ard *TsDbSinkSensorProfile::getKsteaSched(){
	return Kstea_Sched;
}

byte_ard *TsDbSinkSensorProfile::getKst(){
	return Kst;
}

byte_ard *TsDbSinkSensorProfile::getR(){
	return R;
}

/* Generate the keys K_sta, K_ste and K_stea given K_st and store the key 
 * key schedules for these keys in the relavant class internal variables.
 */
void TsDbSinkSensorProfile::generateKeyScheds(){

	byte_ard gammaKeySched[KEY_BYTES*11];

	// Create a  K_ST object and use Beta to derive K_STa. Both
	// will then be stored in the key schedule list.
    deriveKeyScheds(Kst, cBeta, Kst_Sched, Ksta_Sched);


    KeyExpansion(cGamma, gammaKeySched);

	byte_ard K_STe[KEY_BYTES];
    // Derive K_STe using AES cMAC. The constant is the key and the 
    // R is the message M that will be cMAC'ed.
    aesCMac((u_int32_ard*) gammaKeySched,
        R,
        KEY_BYTES,
        K_STe);

    // Create a K_STe object wich derives K_STea using gamma. Both
	// will then be stored in the key schedule list..
    deriveKeyScheds(K_STe, cEpsilon, Kste_Sched, Kstea_Sched);
}

/* Retrieves the sensor profile corresponding to devicePublicId from the
 * database and stores the key schedules for K_st, K_sta, K_ste and K_stea 
 * in class internal variables. If this process fails a runtime error is 
 * thown.
 */
void TsDbSinkSensorProfile::retrieve(){

	MYSQL *connection, mysql;
    MYSQL_RES *result;
    MYSQL_ROW row;
    int query_state;

    mysql_init(&mysql);
    connection = mysql_real_connect(&mysql, _hostName, _userName,
                                    _passWord, _dbName, 0,0,0);

	const char *sQuery = {"select * from sink_state where pid = '%s'"};

	char b64PID[10];
	base64Encode(devicePublicId, 6, b64PID);

	char query[2000];
	int insertLen = snprintf(query, 2000, sQuery, b64PID);

	query_state = mysql_query(connection, query);

	if (query_state !=0) {
		char msg[MSGLEN];
		GET_MSG(msg);
		throw runtime_error(msg);
		return;
	}

	result = mysql_store_result(connection);

	row = mysql_fetch_row(result);

	//printf("%s\n", row[0]);
	//printf("%s\n", row[1]);
	//printf("%s\n", row[2]);

	base64Decode(row[0], strlen(row[0]), devicePublicId);

	base64Decode(row[1], strlen(row[1]), Kst);

	base64Decode(row[2], strlen(row[2]), R);

	printProfile();
	
	generateKeyScheds();

	mysql_free_result(result);
	mysql_close(connection);

}


/* Stores the key schedules for K_st, K_sta, K_ste and K_stea in the database.
 * The method uses the devicePublicId to look up the corresponding sensor
 * profile in the database. If a sensor profile already exists it is updated
 * otherwise one is added. All profiles and the devicePublicId is stored in
 * base64 encoded form. If this process fails a runtime error is thrown
 */
void TsDbSinkSensorProfile::persist(){

	MYSQL *connection, mysql;
	MYSQL_RES *result;
	MYSQL_ROW row;
	int query_state;

	mysql_init(&mysql);
	connection = mysql_real_connect(&mysql, _hostName, _userName,
					_passWord, _dbName, 0,0,0);

	char b64PID[10];
	base64Encode(devicePublicId, 6, b64PID);

	char b64Kst[KEY_BYTES*2];
	base64Encode(Kst, KEY_BYTES, b64Kst);

	char b64R[KEY_BYTES*2];
	base64Encode(R, KEY_BYTES, b64R);

	const char *insert = {"insert into sink_state (pid, KST, R)"
				" values ('%s', '%s', '%s')"};

	const char *update = {"update sink_state set "
				"KST='%s', R='%s' where pid='%s'"};
	char query[3000]; 

	if(profileExists()){
		syslog(LOG_NOTICE,"Updating profile for device %s", devicePublicId);
		int insertLen = snprintf(query,2000,update,b64Kst,b64R,b64PID);
	} else {
		syslog(LOG_NOTICE,"Inserting profile for device %s", devicePublicId);
		int insertLen = snprintf(query,2000,insert,b64PID,b64Kst,b64R);
	}

	query_state = mysql_query(connection, query);

	if (query_state != 0) {
		char msg[MSGLEN];
		GET_MSG(msg)
		throw runtime_error(msg);
		return;
	}

	mysql_close(connection);
}

void TsDbSinkSensorProfile::printProfile(){

	cout << "pid:" << endl;
	printByteArd(Kst_Sched, 6, 16);
	cout << endl;

	cout << "Kst:" << endl;
	printByteArd(Kst, KEY_BYTES, 16);
	cout << endl;

	cout << "R:" << endl;
	printByteArd(R, KEY_BYTES, 16);
	cout << endl;

	cout << "Kst_Sched:" << endl;
	printByteArd(Kst_Sched, KEY_BYTES*11, 16);
	cout << endl;

	cout << "Ksta_Sched:" << endl;
	printByteArd(Ksta_Sched, KEY_BYTES*11, 16);
	cout << endl;

	cout << "Kste_Sched:" << endl;
	printByteArd(Kste_Sched, KEY_BYTES*11, 16);
	cout << endl;

	cout << "Kstea_Sched:" << endl;
	printByteArd(Kstea_Sched, KEY_BYTES*11, 16);
	cout << endl;
}
