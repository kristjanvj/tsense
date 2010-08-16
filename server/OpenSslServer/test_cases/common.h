/*
   File name: common.h
   Date:      2010-07-27 15:32
   Author:    Kristján Rúnarsson

   Shamelessly ripped from here:
   http://www.opensslbook.com/code.html
*/

#ifndef __COMMON_H__
#define __COMMON_H__

#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "../../../aes_crypt/lib/protocol.h"

#include <pthread.h>

#define THREAD_CC 
#define THREAD_TYPE pthread_t
#define THREAD_CREATE(tid, entry, arg) pthread_create(&(tid), NULL, (entry), (arg))

#define PORT "6001"
#define SERVER "localhost"
#define CLIENT "localhost"

#define int_error(msg) handle_error(__FILE__, __LINE__, msg);
void handle_error(const char* file, int lineno, const char* msg);

void init_OpenSSL(void);

void seed_prng(void);

int verify_callback(int ok, X509_STORE_CTX *store);

long post_connection_check(SSL *ssl, char *host);

#define MUTEX_TYPE pthread_mutex_t
#define MUTEX_SETUP(x) pthread_mutex_init(&(x), NULL)
#define MUTEX_CLEANUP(x) pthread_mutex_destroy(&(x))
#define MUTEX_LOCK(x) pthread_mutex_lock(&(x))
#define MUTEX_UNLOCK(x) pthread_mutex_unlock(&(x))
#define THREAD_ID pthread_self( )

/* This array will store all of the mutexes available to OpenSSL. */
static MUTEX_TYPE *mutex_buf = NULL ;


static void locking_function(int mode, int n, const char * file, int line);

static unsigned long id_function(void);

int THREAD_setup(void);

int THREAD_cleanup(void);

#endif
