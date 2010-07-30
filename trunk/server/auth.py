#!/bin/bin/python
# coding: utf-8

# Benedikt Kristinsson, 2010
# Simple AUTH server for the TSesne project that
# communicates with a Sink server over a SSL tunnel.

import ssl
from socket import socket

def waitformsg(stream):
    data = stream.read(1024)
    while data:
        if not data:
            break
        else:
            yield data
            data = stream.read(1024)

    

bindsocket = socket()
bindsocket.bind(('localhost', 4848))
bindsocket.listen(5) # Backlog, max number of queued connections. 

while True:
    print 'Waiting for connection'
    listening_socket, fromaddr = bindsocket.accept()  # returns pair
    stream = ssl.wrap_socket(listening_socket,
                             server_side = True,
                             certfile = 'dummy.pem',
                             ssl_version= ssl.PROTOCOL_SSLv23)

    for msg in waitformsg(stream):
        print 'I recived this:', repr(msg)
