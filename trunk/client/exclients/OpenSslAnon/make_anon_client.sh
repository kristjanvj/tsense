#!/bin/sh

# File name: make_anon.sh
# Date:      2010-06-19 10:26
# Author:    Kristj�n R�narsson

g++ -lcrypto -lssl ossl_anon_client.c -o ossl_anon_client
