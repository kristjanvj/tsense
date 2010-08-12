#!/bin/sh

# File name: strippassfrompem.sh
# Date:      2010-08-12 14:35
# Author:    

openssl rsa -in server.pem -out server_nopass.pem
openssl x509 -in server.pem >> server_nopass.pem

openssl rsa -in client.pem -out client_nopass.pem
openssl x509 -in client.pem >> client_nopass.pem

openssl rsa -in client.pem -out client_nopass.pem
openssl x509 -in client.pem >> client_nopass.pem


