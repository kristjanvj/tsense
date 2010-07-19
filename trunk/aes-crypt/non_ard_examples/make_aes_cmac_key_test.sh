#!/bin/sh

# File name: make_cmac_test.sh
# Date:      2010-07-12 13:26
# Author:    Kristján Rúnarsson

g++ -Wall -D_INTEL_64 aes_cmac_key_test.cpp ../arduino_aes/aes_crypt.cpp -I ../arduino_aes/ -O2 -o aes_cmac_key_test


