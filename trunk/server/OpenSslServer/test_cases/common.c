/*
 * File name: common.c
 * Date:      2010-07-27 15:40
 * Author:    Kristján Rúnarsson
 */


#include "common.h"

void handle_error(const char *file, int lineno, const char * msg){
	fprintf(stderr, "** %s:%i %s\n", file, lineno, msg);
	ERR_print_errors_fp(stderr);
	exit(-1);
}

void init_OpenSSL(void) {
	if(!THREAD_setup() || !SSL_library_init()){
		fprintf(stderr, "** OpenSSL initialization failed!\n");
		exit(-1);
	}
	SSL_load_error_strings();
}

void seed_prng(void)
{
  RAND_load_file("/dev/urandom", 1024);
}

// Callback function that allows you to intercept the X509 certificate 
// verification results.
int verify_callback(int ok, X509_STORE_CTX *store){

	printf("verify_callback\n");

	char data[256];
	
	// Print out some extended data in case of a certificate validation error.
	if(!ok){
		X509 *cert = X509_STORE_CTX_get_current_cert(store);
		int depth = X509_STORE_CTX_get_error_depth(store);
		int err = X509_STORE_CTX_get_error(store);

		fprintf(stderr, "Error with certificate at depth: %d\n", depth);
		X509_NAME_oneline(X509_get_issuer_name(cert), data, 256);
		fprintf(stderr, " issuer  = %s\n", data);
		X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
		fprintf(stderr, " subject = %s\n", data);
		fprintf(stderr, " err: %d:%s\n", err, X509_verify_cert_error_string(err));
	}
}

long post_connection_check(SSL *ssl, char *host) {
	X509		*cert;
	X509_NAME	*subject;
	char		data[256];
	int			extcount;
	int			ok = 0;

	printf("post_connection_check\n");

	if(!(cert = SSL_get_peer_certificate(ssl)) || !host){
		goto err_occured;
	}

	if((extcount = X509_get_ext_count(cert)) > 0) {

		int i;

		for(i = 0; i < extcount; i++){
			char	*extstr;

			/* typedef struct X509_extension_st {...} X509_EXTENSION;
			 * typedef struct asn1_object_st {...} ASN1_OBJECT;
			 */
			X509_EXTENSION *ext;

			ext = X509_get_ext(cert, i);
			extstr = (char*) OBJ_nid2sn(OBJ_obj2nid(X509_EXTENSION_get_object(ext)));

			if(!strcmp(extstr, "subjectAltName")){
				int j;
				const unsigned char *data;
				STACK_OF(CONF_VALUE) *val;
				CONF_VALUE *nval;
				X509V3_EXT_METHOD *meth; // struct v3_ext_method
				void *ext_str = NULL;

				if(!(meth = X509V3_EXT_get(ext))){
					break;
				}

				data = ext->value->data;

#if (OPENSSL_VERSION_NUMBER > 0x00907000L) //----------------------------------
                if (meth->it) {
                  ext_str = ASN1_item_d2i(NULL, &data, ext->value->length,
                                          ASN1_ITEM_ptr(meth->it));
                } else {
                  ext_str = meth->d2i(NULL, &data, ext->value->length);
				}
#else //-----------------------------------------------------------------------
                ext_str = meth->d2i(NULL, &data, ext->value->length);
#endif //----------------------------------------------------------------------

				val = meth->i2v(meth, ext_str, NULL);

				for(j = 0; j < sk_CONF_VALUE_num(val); j++){
					nval = sk_CONF_VALUE_value(val, j);
					
					printf("value[%d] ----------------\n",j);
					printf("Host      : %s\n", host);
					printf("Conf Name : %s\n", nval->name);
					printf("Conf Value: %s\n", nval->value);

					if(!strcmp(nval->name, "DNS") && !strcmp(nval->value, host)){
						ok = 1;
						break;
					}
				}
			}

			if(ok){
				break;
			}
		}
	}
	
	if(!ok && (subject = X509_get_subject_name(cert)) &&
	   X509_NAME_get_text_by_NID(subject, NID_commonName, data, 256) > 0)
	{
		data[255] = 0;


		printf("Host      : %s\n", host);
		printf("Subj. Name: %s\n", data);

		if(strcasecmp(data, host) != 0){
			goto err_occured;
		}
	}

	X509_free(cert);
	return SSL_get_verify_result(ssl);


err_occured:
	if(cert){
		X509_free(cert);
	}

	return X509_V_ERR_APPLICATION_VERIFICATION;
}

static void locking_function(int mode, int n, const char * file, int line) {
    if (mode & CRYPTO_LOCK){
        MUTEX_LOCK(mutex_buf[n]);
    }else{
        MUTEX_UNLOCK(mutex_buf[n]);
    }
}

static unsigned long id_function(void) {
  return ((unsigned long)THREAD_ID);
}


int THREAD_setup(void) {
	int i;
	mutex_buf = (MUTEX_TYPE *) malloc(CRYPTO_num_locks( ) * sizeof(MUTEX_TYPE));

	if(!mutex_buf){
		return 0;
	}

	for (i = 0; i < CRYPTO_num_locks( ); i++){
		MUTEX_SETUP(mutex_buf[i]);
	}

	CRYPTO_set_id_callback(id_function);
	CRYPTO_set_locking_callback(locking_function);

	return 1;
}

int THREAD_cleanup(void) {
	int i;
	if(!mutex_buf){
		return 0;
	}

	CRYPTO_set_id_callback(NULL);
	CRYPTO_set_locking_callback(NULL);
	for (i = 0; i < CRYPTO_num_locks( ); i++){
		MUTEX_CLEANUP(mutex_buf[i]);
	}

	free(mutex_buf);
	mutex_buf = NULL;

	return 1;
}
