#!/bin/sh

# File name: make_anon.sh
# Date:      2010-06-19 10:26
# Author:    Kristj�n R�narsson

g++ -I/usr/include/ -I../common/  -lssl -lcrypto -L/usr/lib/ TSenseAuthDaemon.cpp ../common/BDaemon.cpp TlsBaseServer.cpp TlsAuthServer.cpp -o tsauthd
