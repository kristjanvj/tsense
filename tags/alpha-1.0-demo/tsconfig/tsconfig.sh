#!/bin/sh

#
# Makefile to compile and upload a program to Arduino Duemilanove with ATmega328 
#
# TSense project. Flasher for tsensor device EEPROM.
#
# Kristjan V. Jonsson
# 2010
#

echo "Preparing tsensor device"

#
# Generate the necessary temporary directories
#
mkdir tmp

#
# Run the python utility to generate cpp source file. tspcgen (tsensor program code generator) generates
# a C program for the Arduino which will initialize the device EEPROM on initialization.
#
python tspcgen.py -o tmp/tsexec.cpp -i [1,$1] -m ["TSG","ALPHA"]

#
# Now, compile the source file for the Arduino and do all the necessary woodoo.
# This stuff was stolen off the shift-verify output of tsburner.pde. Can perhaps be cut down.
#
avr-gcc -c -g -Os -w -ffunction-sections -fdata-sections -mmcu=atmega328p -DF_CPU=16000000L -DARDUINO=18 -I/usr/share/arduino/hardware/arduino/cores/arduino /usr/share/arduino/hardware/arduino/cores/arduino/WInterrupts.c -o tmp/WInterrupts.c.o 
avr-gcc -c -g -Os -w -ffunction-sections -fdata-sections -mmcu=atmega328p -DF_CPU=16000000L -DARDUINO=18 -I/usr/share/arduino/hardware/arduino/cores/arduino /usr/share/arduino/hardware/arduino/cores/arduino/wiring.c -o tmp/wiring.c.o 
avr-gcc -c -g -Os -w -ffunction-sections -fdata-sections -mmcu=atmega328p -DF_CPU=16000000L -DARDUINO=18 -I/usr/share/arduino/hardware/arduino/cores/arduino /usr/share/arduino/hardware/arduino/cores/arduino/wiring_pulse.c -o tmp/wiring_pulse.c.o 
avr-gcc -c -g -Os -w -ffunction-sections -fdata-sections -mmcu=atmega328p -DF_CPU=16000000L -DARDUINO=18 -I/usr/share/arduino/hardware/arduino/cores/arduino /usr/share/arduino/hardware/arduino/cores/arduino/pins_arduino.c -o tmp/pins_arduino.c.o 
avr-gcc -c -g -Os -w -ffunction-sections -fdata-sections -mmcu=atmega328p -DF_CPU=16000000L -DARDUINO=18 -I/usr/share/arduino/hardware/arduino/cores/arduino /usr/share/arduino/hardware/arduino/cores/arduino/wiring_analog.c -o tmp/wiring_analog.c.o 
avr-gcc -c -g -Os -w -ffunction-sections -fdata-sections -mmcu=atmega328p -DF_CPU=16000000L -DARDUINO=18 -I/usr/share/arduino/hardware/arduino/cores/arduino /usr/share/arduino/hardware/arduino/cores/arduino/wiring_digital.c -o tmp/wiring_digital.c.o 
avr-gcc -c -g -Os -w -ffunction-sections -fdata-sections -mmcu=atmega328p -DF_CPU=16000000L -DARDUINO=18 -I/usr/share/arduino/hardware/arduino/cores/arduino /usr/share/arduino/hardware/arduino/cores/arduino/wiring_shift.c -o tmp/wiring_shift.c.o 
avr-g++ -c -g -Os -w -fno-exceptions -ffunction-sections -fdata-sections -mmcu=atmega328p -DF_CPU=16000000L -DARDUINO=18 -I/usr/share/arduino/hardware/arduino/cores/arduino /usr/share/arduino/hardware/arduino/cores/arduino/Print.cpp -o tmp/Print.cpp.o 
avr-g++ -c -g -Os -w -fno-exceptions -ffunction-sections -fdata-sections -mmcu=atmega328p -DF_CPU=16000000L -DARDUINO=18 -I/usr/share/arduino/hardware/arduino/cores/arduino /usr/share/arduino/hardware/arduino/cores/arduino/main.cpp -o tmp/main.cpp.o 
avr-g++ -c -g -Os -w -fno-exceptions -ffunction-sections -fdata-sections -mmcu=atmega328p -DF_CPU=16000000L -DARDUINO=18 -I/usr/share/arduino/hardware/arduino/cores/arduino /usr/share/arduino/hardware/arduino/cores/arduino/WMath.cpp -o tmp/WMath.cpp.o 
avr-g++ -c -g -Os -w -fno-exceptions -ffunction-sections -fdata-sections -mmcu=atmega328p -DF_CPU=16000000L -DARDUINO=18 -I/usr/share/arduino/hardware/arduino/cores/arduino /usr/share/arduino/hardware/arduino/cores/arduino/HardwareSerial.cpp -o tmp/HardwareSerial.cpp.o 
avr-g++ -c -g -Os -w -fno-exceptions -ffunction-sections -fdata-sections -mmcu=atmega328p -DF_CPU=16000000L -DARDUINO=18 -I/usr/share/arduino/hardware/arduino/cores/arduino /usr/share/arduino/hardware/arduino/cores/arduino/Tone.cpp -o tmp/Tone.cpp.o 
avr-ar rcs  tmp/core.a  tmp/WInterrupts.c.o 
avr-ar rcs  tmp/core.a  tmp/wiring.c.o 
avr-ar rcs  tmp/core.a  tmp/wiring_pulse.c.o 
avr-ar rcs  tmp/core.a  tmp/pins_arduino.c.o 
avr-ar rcs  tmp/core.a  tmp/wiring_analog.c.o 
avr-ar rcs  tmp/core.a  tmp/wiring_digital.c.o 
avr-ar rcs  tmp/core.a  tmp/wiring_shift.c.o 
avr-ar rcs  tmp/core.a  tmp/Print.cpp.o 
avr-ar rcs  tmp/core.a  tmp/main.cpp.o 
avr-ar rcs  tmp/core.a  tmp/WMath.cpp.o 
avr-ar rcs  tmp/core.a  tmp/HardwareSerial.cpp.o 
avr-ar rcs  tmp/core.a  tmp/Tone.cpp.o 
avr-g++ -c -g -Os -w -fno-exceptions -ffunction-sections -fdata-sections -mmcu=atmega328p -DF_CPU=16000000L -DARDUINO=18 -I/usr/share/arduino/hardware/arduino/cores/arduino -I/usr/share/arduino/libraries/EEPROM -I/usr/share/arduino/libraries/EEPROM/utility /usr/share/arduino/libraries/EEPROM/EEPROM.cpp -o tmp/EEPROM.cpp.o 

#
# Here we finally begin to compile the temporary cpp file
#
avr-g++ -c -g -Os -w -fno-exceptions -ffunction-sections -fdata-sections -mmcu=atmega328p -DF_CPU=16000000L -DARDUINO=18 -I/usr/share/arduino/hardware/arduino/cores/arduino -I/usr/share/arduino/libraries/EEPROM  tmp/tsexec.cpp -o tmp/tsexec.cpp.o 
avr-gcc -Os -Wl,--gc-sections -mmcu=atmega328p -o  tmp/tsexec.cpp.elf  tmp/EEPROM.cpp.o  tmp/tsexec.cpp.o  tmp/core.a -L tmp -lm 
avr-objcopy -O ihex -j .eeprom --set-section-flags=.eeprom=alloc,load --no-change-warnings --change-section-lma .eeprom=0  tmp/tsexec.cpp.elf  tmp/tsexec.cpp.eep 
avr-objcopy -O ihex -R .eeprom  tmp/tsexec.cpp.elf  tmp/tsexec.cpp.hex 

#
# Use avrdude to flash to the chip
#
avrdude -v -v -v -v -patmega328p -carduino -P/dev/ttyUSB0 -b57600 -D -Uflash:w:tmp/tsexec.cpp.hex:i

#
# Remove the temporary directory
#
rm -rf tmp


