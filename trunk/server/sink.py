#!/usr/bin/python
# coding: utf-8

# Benedikt Kristinsson
# An example implementation of a very basic sink made in Python using SSL.

import ssl
from socket import socket, AF_INET, SOCK_STREAM
from pprint import pformat

sock = socket(AF_INET, SOCK_STREAM)

ssl_sock = ssl.wrap_socket(sock,
                           certfile = 'dummy.pem',
                           ca_certs = 'dummy.pem',
                           cert_reqs=ssl.CERT_REQUIRED)

ssl_sock.connect(('localhost', 4848))

print repr(ssl_sock.getpeername())
print ssl_sock.cipher()
print pformat(ssl_sock.getpeercert())

ssl_sock.write('Hello\n')
ssl_sock.write('World.')

ssl_sock.close()
