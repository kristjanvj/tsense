#!/bin/sh

# File name: make_anon.sh
# Date:      2010-06-19 10:26
# Author:    Kristján Rúnarsson

g++ -I/usr/include/ -I../common/  -lssl -lcrypto -L/usr/lib/ TSenseSinkDaemon.cpp ../common/BDaemon.cpp TlsBaseServer.cpp TlsSinkServer.cpp -o tssinkd
