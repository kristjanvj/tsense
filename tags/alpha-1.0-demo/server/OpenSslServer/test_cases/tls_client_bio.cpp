/*
 * File name: TlsClientBIO.c
 * Date:      2010-08-14 10:53
 * Author:    Kristján Rúnarsson
 */

#include "common.h"

void do_client_loop(BIO *conn){
    int err, nwritten;
    char buf[80];
    char inBuf[80];

    /*
    for(;;){
        if(!fgets(buf, sizeof(buf), stdin)){
            break;
        }

        for(nwritten = 0; nwritten < sizeof(buf); nwritten+=err){
            err = BIO_write(conn, buf + nwritten, strlen(buf) - nwritten);
            if(err <= 0){
                return;
            }
        }
    }
    */

    fgets(buf, sizeof(buf), stdin);

    printf("gets: %s", buf);

    err = BIO_write(conn, buf, strlen(buf));

    printf("Done writing\n");

    err = BIO_read(conn, inBuf, sizeof(inBuf));

    inBuf[err] = 0x0;
    printf("Done reading: %s", inBuf);
}

int main(int argc, char *argv[]){

    BIO *conn;

    init_OpenSSL();
	
	conn = BIO_new_connect("sink.tsense.sudo.is:6002");

    if(!conn){
        int_error("Error createing connection BIO");
    }

    if(BIO_do_connect(conn) <= 0){
        int_error("Error connecting to remote machine");
    }

    fprintf(stderr, "Connection opened\n");
    do_client_loop(conn);
    fprintf(stderr, "Connection closed\n");

    BIO_free(conn);

    return 0;
}

