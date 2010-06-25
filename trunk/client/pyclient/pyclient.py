# encoding: utf-8
# License: GPLv3
# Author: Benedikt Kristinsson
# Tsense research project

from OpenSSL import SSL
import socket, sys, random, os

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
        print 'Recieved this data from server: %s' % recv_data

    # Close the socket
    sock.shutdown()
    sock.close()
