/*
   File name: ts_db_sinksensorprofile.h
   Date:      2010-08-29 10:48
   Author:    
*/

#ifndef __TS_DB_SINKSENSORPROFILE_H__
#define __TS_DB_SINKSENSORPROFILE_H__

#include "ts_db_basesensorprofile.h"
#include "aes_crypt.h"
#include "aes_utils.h"
#include "aes_constants.h"

#include <stdlib.h>

class TsDbSinkSensorProfile : public TsDbSensorProfile {

protected:
	byte_ard Kst_Sched[KEY_BYTES*11];
	byte_ard Ksta_Sched[KEY_BYTES*11];
	byte_ard Kste_Sched[KEY_BYTES*11];
	byte_ard Kstea_Sched[KEY_BYTES*11];

public:
	TsDbSinkSensorProfile(byte_ard *K_ST, byte_ard *pID, dbConnectData dbcd);
	TsDbSinkSensorProfile(byte_ard *pID, dbConnectData dbcd);

	byte_ard *getKstSched();
	byte_ard *getKstaSched();
	byte_ard *getKsteSched();
	byte_ard *getKsteaSched();

	void generateKeyScheds(byte_ard *K_ST);

	void retrieve();
	void persist();

	void testEncoding();

	void printProfile();
};

#endif
