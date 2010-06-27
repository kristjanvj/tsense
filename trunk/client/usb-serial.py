# encoding: utf-8

import serial

ser = serial.Serial('/dev/ttyUSB0', 9600, timeout=1) # If we need more platforms → os.name

# My Arduino code is set up so it writes the boards ID after 10 seconds
board_id = ser.readline()[:-1]
print board_id

# Send 'C' (for challenge) to signal the board for challenge
print 'Signalling challenge'
ser.write('C')
print ser.readline()[:-1]
