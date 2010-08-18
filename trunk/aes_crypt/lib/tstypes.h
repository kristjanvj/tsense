
/**
 *
 *  Kristjan Valur Jonsson
 *  Benedikt Kristinsson
 *
 *  Platform dependent typedefs for the AES code. Moved out of aes_crypt.h
 *  by kvj aug 17,2010.
 * 
 *  This file is part of the Trusted Sensors Research Project (TSense).
 *
 *  TSense is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  TSense is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with the TSense code.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef __TSTYPES_H
#define __TSTYPES_H

#if !(defined(_INTEL_32) || defined(_INTEL_64))
// Defines for the arduino platform
  #define _ARDUINO_DUEMILANOVE         
#endif

// typedef's depending on platform
#ifdef _ARDUINO_DUEMILANOVE
typedef unsigned char       byte_ard;
typedef int                 int16_ard;
typedef unsigned int        u_int16_ard;
typedef long                int32_ard;
typedef unsigned long       u_int32_ard;
typedef float               float32_ard;
#endif
#ifdef  _INTEL_32
typedef unsigned char       byte_ard;
typedef short               int16_ard;
typedef unsigned short      u_int16_ard;
typedef int                 int32_ard;
typedef unsigned int        u_int32_ard;
typedef long long           int64_ard;
typedef unsigned long long  u_int64_ard;
typedef float               float32_ard;
#endif
#ifdef  _INTEL_64
typedef unsigned char       byte_ard;
typedef short               int16_ard;
typedef unsigned short      u_int16_ard;
typedef int                 int32_ard;
typedef unsigned int        u_int32_ard;
typedef long                int64_ard;
typedef unsigned long       u_int64_ard;
typedef float               float32_ard;
#endif

#define KEY_BYTES 16

#endif /* __TSTYPES_H */
