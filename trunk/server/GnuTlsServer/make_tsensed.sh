#!/bin/sh

# File name: make_anon.sh
# Date:      2010-06-19 10:26
# Author:    Kristj�n R�narsson

g++ -I/usr/local/include/ -I../common -lgnutls -L/usr/local/lib/ TSenseDaemon.cpp ../common/BDaemon.cpp TlsServer.cpp -o tsensed
