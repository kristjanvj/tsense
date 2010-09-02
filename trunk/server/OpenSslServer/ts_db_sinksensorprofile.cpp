/*
 * File name: ts_db_sinksensorprofile.cpp
 * Date:      2010-08-29 10:48
 * Author:    
 */

#include <iostream>
#include <string>
#include "ts_db_sinksensorprofile.h"

using namespace std;

/* Create a sensor profile for device with a given public-id. The object is 
 * intiialized locally with a set of keys derived from K_ST. The content of the 
 * object, the device public-id and key schedules the objec contains,  must 
 * be persisted to the database by calling the persist() method.
 */
TsDbSinkSensorProfile::TsDbSinkSensorProfile(byte_ard * K_ST,  byte_ard * pID,
							dbConnectData dbcd) :
						TsDbSensorProfile(	pID, dbcd)
{
	generateKeyScheds(K_ST);
}

/* Attempts to intialize it self from DB. If no profile corresponding to 
 * the given device pubic-id  exists in the database the key schedules
 * are set to 0x0.
 */
TsDbSinkSensorProfile::TsDbSinkSensorProfile(byte_ard * pID,
							dbConnectData dbcd) :
						TsDbSensorProfile(pID, dbcd)
{
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

/* Generate the keys K_sta, K_ste and K_stea given K_st and store the key 
 * key schedules for these keys in the relavant class internal variables.
 */
void TsDbSinkSensorProfile::generateKeyScheds(byte_ard *K_ST){

	byte_ard R[KEY_BYTES];

	byte_ard gammaKeySched[KEY_BYTES*11];

	// Create a  K_ST object and use Beta to derive K_STa. Both
	// will then be stored in the key schedule list.
    deriveKeyScheds(K_ST, cBeta, Kst_Sched, Ksta_Sched);

    generateKey(R);

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

	base64Decode(row[0], strlen(row[0]), devicePublicId);

	base64Decode(row[1], strlen(row[1]), Kst_Sched);

	base64Decode(row[2], strlen(row[2]), Ksta_Sched);

	base64Decode(row[3], strlen(row[3]), Kste_Sched);

	base64Decode(row[4], strlen(row[4]), Kstea_Sched);

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


	char b64Kst_Sched[KEY_BYTES*17];
	base64Encode(Kst_Sched, KEY_BYTES*11, b64Kst_Sched);


	char b64Ksta_Sched[KEY_BYTES*17];
	base64Encode(Ksta_Sched, KEY_BYTES*11, b64Ksta_Sched);


	char b64Kste_Sched[KEY_BYTES*17];
	base64Encode(Kste_Sched, KEY_BYTES*11, b64Kste_Sched);


	char b64Kstea_Sched[KEY_BYTES*17];
	base64Encode(Kstea_Sched, KEY_BYTES*11, b64Kstea_Sched);

	//cout << "persist()" << endl;
	//cout << "----------" << endl;
	//cout << "b64 PID:        " << endl << b64PID << endl << endl;
	//cout << "b64Kst_Sched:   " << endl << b64Kst_Sched << endl << endl;
	//cout << "b64Ksta_Sched:  " << endl << b64Ksta_Sched << endl << endl;
	//cout << "b64Kste_Sched:  " << endl << b64Kste_Sched << endl << endl;
	//cout << "b64Kstea_Sched: " << endl << b64Kstea_Sched << endl << endl;

	const char *insert = {"insert into sink_state (pid, KST, KSTa, KSTe, KSTea)"
						  " values ('%s', '%s', '%s', '%s', '%s')"};

	const char *update = {"update sink_state set "
						  "pid='%s', KST='%s', KSTa='%s', "
						  "KSTe='%s', KSTea='%s'"};
	char query[3000]; 

	const char *sQuery;

	if(profileExists()){
		sQuery = update;
	} else {
		sQuery = insert;
	}

	int insertLen = snprintf(query, 2000, sQuery, b64PID, b64Kst_Sched,
							b64Ksta_Sched, b64Kste_Sched, b64Kstea_Sched);

	query_state = mysql_query(connection, query);
	if (query_state != 0) {
		char msg[MSGLEN];
		GET_MSG(msg)
		throw runtime_error(msg);
		return;
	}

	mysql_free_result(result);
	mysql_close(connection);
}

void TsDbSinkSensorProfile::printProfile(){

	cout << "pid:" << endl;
	printByteArd(Kst_Sched, 6, 16);
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
