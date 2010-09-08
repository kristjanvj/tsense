/*
 * File name: test_sensor_profile.cpp
 * Date:      2010-08-28 17:52
 * Author:    
 */

#include <iostream>
#include <string>
#include "ts_db_basesensorprofile.h"
#include "ts_db_sinksensorprofile2.h"

#include <mysql.h>

#define ID_SIZE 6

MYSQL *connection, mysql;
MYSQL_RES *result;
MYSQL_ROW row;
int query_state;

using namespace std;

byte_ard KST[] = { 0x37, 0x13, 0x47, 0xb1, 0xb6, 0x05, 0xee, 0x01, 
				   0x33, 0x34, 0xfa, 0xa0, 0x70, 0x2d, 0x43, 0xa3 };

byte_ard Kst_SchedExpected[KEY_BYTES*11];
byte_ard Ksta_SchedExpected[KEY_BYTES*11];
byte_ard Kste_SchedExpected[KEY_BYTES*11];
byte_ard Kstea_SchedExpected[KEY_BYTES*11];

int main() {
	byte_ard pID[ID_SIZE+1] = {0x30, 0x30, 0x30, 0x30, 0x31, 0x31, 0x00};

	//--------------------------------------------------------------------------
	// TEST #1
	//--------------------------------------------------------------------------
	// Create an object that uses K_ST to generate all derived key schedules
	// locally. Then persist the key schedules and try to retrieve them again.
	dbConnectData dbcd;
	dbcd.hostName ="localhost";
	dbcd.userName = "tssink";
	dbcd.passWord = "pass";
	dbcd.dbName = "tsense";

	// Create a sink sensor profile that generates it's key sets locally.
	TsDbSinkSensorProfile *stdbsp = new TsDbSinkSensorProfile(KST, pID, dbcd);

	// Store the key schedules generated locally, they should match the
	// keys retrieved fromt he DB.
	memcpy(Kst_SchedExpected, stdbsp->getKstSched(), KEY_BYTES*11);
	memcpy(Ksta_SchedExpected, stdbsp->getKstaSched(), KEY_BYTES*11);
	memcpy(Kste_SchedExpected, stdbsp->getKsteSched(), KEY_BYTES*11);
	memcpy(Kstea_SchedExpected, stdbsp->getKsteaSched(), KEY_BYTES*11);

	cout << endl;
	cout << "Generated locally from Kst and R:" << endl;
	cout << endl;
	stdbsp->printProfile();

	// Store thhe key schedules in the database.
	stdbsp->persist();

	// Just to be sure overwrite the locally generated key schedules with zero.
	memset(stdbsp->getKstSched(), 0x0, KEY_BYTES*11);
	memset(stdbsp->getKstaSched(), 0x0, KEY_BYTES*11);
	memset(stdbsp->getKsteSched(), 0x0, KEY_BYTES*11);
	memset(stdbsp->getKsteaSched(), 0x0, KEY_BYTES*11);

	// Retrieve the key schedules from the database 
	stdbsp->retrieve();

	cout << endl;
	cout << "Generated from keys retrieved from DB:" << endl;
	cout << endl;
	stdbsp->printProfile();

	// If all base64 conversions were done correctly the key schedules
	// retrieved from the db and the ones mecpy'ed above should match.
	for(int i=0; i<KEY_BYTES*11; i++) {
		//rintf("Kst: %x, %x\n", Kst_SchedExpected[i], 
		//	stdbsp->getKstSched()[i]);
		
		if(Kst_SchedExpected[i] != stdbsp->getKstSched()[i]){
			cerr << "K_ST did not match." << endl;
			exit(1);
		}
	}

	for(int i=0; i<KEY_BYTES*11; i++) {
		//printf("Ksta: %x, %x\n", Ksta_SchedExpected[i], 
		//		stdbsp->getKstaSched()[i]);

		if(Ksta_SchedExpected[i] != stdbsp->getKstaSched()[i]){
			cerr << "K_STa did not match." << endl;
			exit(1);
		}

	}
	
	for(int i=0; i<KEY_BYTES*11; i++) {
		//printf("Kste: %x, %x\n", Kste_SchedExpected[i], 
		//		stdbsp->getKsteSched()[i]);

		if(Kste_SchedExpected[i] != stdbsp->getKsteSched()[i]){
			cerr << "K_STe did not match." << endl;
			exit(1);
		}

	}

	for(int i=0; i<KEY_BYTES*11; i++) {
		//printf("Kstea: %x, %x\n", Kstea_SchedExpected[i], 
		//		stdbsp->getKsteaSched()[i]);

		if(Kstea_SchedExpected[i] != stdbsp->getKsteaSched()[i]){
			cerr << "K_STea did not match." << endl;
			exit(1);
		}
	}

	cout << endl;
	cout << "All schedules retrieved were identical to those sent..." << endl;

	//--------------------------------------------------------------------------
	// TEST #2
	//--------------------------------------------------------------------------
	// Initialize an object without feeding it a K_ST and see if it
	// can sucessfully retrieve the key shcedules from the DB.
	TsDbSinkSensorProfile *stdbsp2 = new TsDbSinkSensorProfile(pID, dbcd);
	
	// If the object ws sucessfully initialized from DB the key schedules
	// the object now contains should match the ones generated locally at the
	// top of this function.
	for(int i=0; i<KEY_BYTES*11; i++) {
		//printf("Kst: %x, %x\n", Kst_SchedExpected[i], 
		//	stdbsp2->getKstSched()[i]);
		
		if(Kst_SchedExpected[i] != stdbsp2->getKstSched()[i]){
			cerr << "K_ST did not match." << endl;
			exit(1);
		}
	}

	for(int i=0; i<KEY_BYTES*11; i++) {
		//printf("Ksta: %x, %x\n", Ksta_SchedExpected[i], 
		//		stdbsp2->getKstaSched()[i]);

		if(Ksta_SchedExpected[i] != stdbsp2->getKstaSched()[i]){
			cerr << "K_STa did not match." << endl;
			exit(1);
		}

	}
	
	for(int i=0; i<KEY_BYTES*11; i++) {
		//printf("Kste: %x, %x\n", Kste_SchedExpected[i], 
		//		stdbsp2->getKsteSched()[i]);

		if(Kste_SchedExpected[i] != stdbsp2->getKsteSched()[i]){
			cerr << "K_STe did not match." << endl;
			exit(1);
		}

	}

	for(int i=0; i<KEY_BYTES*11; i++) {
		//printf("Kstea: %x, %x\n", Kstea_SchedExpected[i], 
		//		stdbsp2->getKsteaSched()[i]);

		if(Kstea_SchedExpected[i] != stdbsp2->getKsteaSched()[i]){
			cerr << "K_STea did not match." << endl;
			exit(1);
		}
	}

	cout << endl;
	cout << "Created solely based on keys retrieved from DB" << endl;
	cout << endl;
	stdbsp2->printProfile();

	cout << endl;
	cout << "All schedules retrieved from DB were matched those"  << 
			" generated locally..." << endl;


	//--------------------------------------------------------------------------
	// CLEANUP, Careful this empties the sink_state table
	//--------------------------------------------------------------------------
    mysql_init(&mysql);
    connection = mysql_real_connect(&mysql, "localhost", "tssink", "pass",
                                "tsense", 0,0,0);

    if (connection == NULL) {
        cout << mysql_error(&mysql) << endl;
        return 1;
    }

	    query_state = mysql_query(connection, "delete from sink_state");
    if (query_state !=0) {
        cout << mysql_error(connection) << endl;
        return 1;
    }

    mysql_free_result(result);
    mysql_close(connection);


	//--------------------------------------------------------------------------
	// TEST #3
	//--------------------------------------------------------------------------
	// Create an object with a device ID that does not exist in the DB should
	// yeil key schedules initialized to zero.
	byte_ard pID2[ID_SIZE+1] = {0x31, 0x31, 0x31, 0x31, 0x32, 0x32, 0x00};

	TsDbSinkSensorProfile *stdbsp3 = new TsDbSinkSensorProfile(pID, dbcd);

	for(int i=0; i<KEY_BYTES*11; i++) {
		
		if(0x0 != stdbsp3->getKstSched()[i]){
			cerr << "K_ST was not zero." << endl;
			exit(1);
		}
		
		if(0x0 != stdbsp3->getKstaSched()[i]){
			cerr << "K_STa was not zero." << endl;
			exit(1);
		}
		
		if(0x0 != stdbsp3->getKsteSched()[i]){
			cerr << "K_STe was not zero." << endl;
			exit(1);
		}
		
		if(0x0 != stdbsp3->getKsteaSched()[i]){
			cerr << "K_STea was not zero." << endl;
			exit(1);
		}
	}

	cout << endl;
	cout << "Created with no entry in DB for this PID." << endl;
	cout << "Keys, schedules and pid should be all zero."<<endl;
	cout << endl;
	stdbsp3->printProfile();

	cout << "All schedules were set to 0x0..." << endl;

	

} // end main()
