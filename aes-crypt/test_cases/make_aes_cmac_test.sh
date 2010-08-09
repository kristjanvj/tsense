#!/bin/sh
g++ -Wall -D_INTEL_32 aes_cmac_test.cpp ../lib/aes_cmac.cpp ../lib/aes_crypt.cpp -I ../lib/ -O2 -o aes_cmac_test


