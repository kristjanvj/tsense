g++ -Wall -D_INTEL_32 block_e.cpp ../arduino_aes/aes_crypt.cpp -I ../arduino_aes/ -O2 -o block_e
g++ -Wall -D_INTEL_32 block_d.cpp ../arduino_aes/aes_crypt.cpp -I ../arduino_aes/ -O2 -o block_d
#g++ -Wall -D_INTEL_64 aes_linked.cc ../arduino_aes/aes_crypt.cpp -I ../arduino_aes/ -O2 -o aes_linked
