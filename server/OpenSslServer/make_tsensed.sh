#!/bin/sh

# File name: make_anon.sh
# Date:      2010-06-19 10:26
# Author:    Kristján Rúnarsson

g++ -I/usr/include/ -I../common/  -lssl -lcrypto -L/usr/lib/ TSenseDaemon.cpp ../common/BDaemon.cpp TlsServer.cpp -o tsensed
#g++ -I/usr/include/ -lssl -lcrypto -L/usr/lib/ TlsServer.cpp -o tsensed
