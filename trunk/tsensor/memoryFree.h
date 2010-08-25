
/**
 *   memoryFree.h
 *
 *   Report available memory on the Arduino.
 *   Copied from http://www.arduino.cc/playground/Code/AvailableMemory
 */

#ifndef	MEMORY_FREE_H
#define MEMORY_FREE_H

#ifdef __cplusplus
extern "C" {
#endif

int freeMemory();

#ifdef  __cplusplus
}
#endif

#endif