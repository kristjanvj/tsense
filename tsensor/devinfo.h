
#ifndef __ard_dev_info_H__
#define __ard_dev_info_H__

//
// TODO: REMOVE THIS FILE -- INTEGRATE WITH protocol.h
//


// TODO: A chunk of this should be part of the protocol pack/unpack and so forth.
#define ID_BIT_SIZE    48
#define TIME_BIT_SIZE  32
#define LEN_BIT_SIZE    8
#define SINT_BIT_SIZE   8 
#define ICNT_BIT_SIZE   4
#define ITYPE_BIT_SIZE  4
#define ABITL_BIT_SIZE  4
#define VAL_BIT_SIZE    8

#define ABITL 8


#define INTERFACE_COUNT 2   // The number of sampled interfaces
#define INTERFACE1 0
#define INTERFACE2 1
#define INTERFACE1_NAME "TEMPERATURE"
#define INTERFACE2_NAME "LUMINOSITY"
#define INTERFACE1_TYPE 0x01
#define INTERFACE2_TYPE 0x0A

// Consider Using the PROGMEM modifier to load settings into the flash memory.
// See: http://www.arduino.cc/en/Reference/PROGMEM
// Algernatively, use the EEPROM. See http://www.arduino.cc/en/Reference/EEPROM

/*
char manName[] = {"TSG"};
char modelName[] = {"ALPHA"};
char serialNo[] = {"0000001"};
char manDate[] = {"aug 6, 2010"};

byte_ard devId[6] = {0x00,0x01,0x00,0x00,0x00,0x0F};
byte_ard masterKey[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};

byte_ard interface_types[INTERFACE_COUNT] = {INTERFACE1_TYPE,INTERFACE2_TYPE};
char* interface_names[INTERFACE_COUNT] = {INTERFACE1_NAME,INTERFACE2_NAME};
*/

#endif /* __ard_dev_info_H__ */
