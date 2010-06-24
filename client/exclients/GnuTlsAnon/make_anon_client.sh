#!/bin/sh

# File name: make_anon.sh
# Date:      2010-06-19 10:26
# Author:    Kristján Rúnarsson

g++ -I/usr/local/include/ -lgnutls -L/usr/local/lib/ tls_anon_client.c tcp.c -o tls_anon_client
