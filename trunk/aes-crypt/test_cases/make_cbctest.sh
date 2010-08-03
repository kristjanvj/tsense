g++ -Wall -D_INTEL_32 cbc_test.cpp ../arduino_aes/aes_crypt.cpp -I ../arduino_aes/ -O2 -o cbctest
#g++ -Wall -D_INTEL_64 aes_linked.cc ../arduino_aes/aes_crypt.cpp -I ../arduino_aes/ -O2 -o aes_linked
