

g++ -Wall -D_INTEL_32 cbc_test.cpp ../lib/aes_crypt.cpp -I ../lib/ -O2 -o cbc_test
g++ -Wall -D_INTEL_32 cbc_rnd_test.cpp ../lib/aes_crypt.cpp -I ../lib/ -O2 -o cbc_rnd_test
