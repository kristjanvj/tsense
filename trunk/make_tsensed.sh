#!/bin/sh

# File name: make_anon.sh
# Date:      2010-06-19 10:26
# Author:    Kristj�n R�narsson

g++ -I/usr/local/include/ -lgnutls -L/usr/local/lib/ TSenseDaemon.cpp BDaemon.cpp TlsServer.cpp -o tsensed
