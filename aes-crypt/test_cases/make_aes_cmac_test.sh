#!/bin/sh

# File name: make_cmac_test.sh
# Date:      2010-07-12 13:26
# Author:    Kristj�n R�narsson

g++ -Wall -D_INTEL_64 aes_cmac_test.cpp ../arduino_aes/aes_cmac.cpp ../arduino_aes/aes_crypt.cpp -I ../arduino_aes/ -O2 -o aes_cmac_test

