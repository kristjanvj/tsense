# encoding: utf-8
# License: GPLv3
# Author: Benedikt Kristinsson
# Tsense research project

from OpenSSL import SSL
import socket, sys, random, os, serial

def init_OpenSSL():
    # What is going on here?
    pass

def setup_ctx():
    # Initialize context
    print 'Initializing context..',
    ctx = SSL.Context(SSL.TLSv1_METHOD)
    ctx.set_cipher_list('ADH-AES256-SHA')
    print '\bdone.'
    return ctx

def setup_serial():
    # If we want to waste enery on making the client run on windows
    # we can use os.name to check for the platform
    ser = serial.Serial('/dev/ttyUSB0', 9600)
    return ser

if __name__ == '__main__':
    # Port and host information
    port = 5556
    host = 'localhost'
    # Buffer size
    buff_size = 1024

    ctx = setup_ctx()

    print 'Creating connection...',
    try:
        ssl_conn = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        ssl_conn.connect((host, port))
    except socket.error, e:
        print 'failed. \n\tError: %s' % e
        sys.exit(1)
    else:
        print '\bdone.'

    # Write a random number to the server and read the answer
    random.seed(os.urandom(2))
    send_data = random.randint(0, 1024)
    print 'Data to server: %i' % send_data

    try:
        ssl_conn.send(str(send_data))
        recv_data = ssl_conn.recv(buff_size)
    except SSL.Error, e:    # returns a tuple, see pyOpenSSL documentation
        print e 
    else:
        print 'Recieved this data from server: \' %s\'' % recv_data

    # Talk to the board
    board = setup_serial();
    # My Arduino is set up to send the ID after 10 seconds...
    print 'Waiting for board ID...',
    board_id = board.readline()[3:-1]
    print '\b [%s]' % board_id

    print 'Signalling challenge to board...',
    board.write('C')
    print '\bdone.\nBoard response: %s' % board.readline()[:-1]

    ssl_conn.shutdown()
    ssl_conn.close()
