g++ -Wall -D_INTEL_32 protocol_tests.cpp ../lib/aes_crypt.cpp ../lib/protocol.cpp ../lib/aes_cmac.cpp -I ../lib/ -O2 -o ptests
