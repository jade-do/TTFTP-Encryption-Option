/*
** name: ttftp-crypto.c
**
** author: bjr
** created: 8 apr 2019
** last modified:
**         0 apr 2019
**
*/

#include<string.h>
#include<stdlib.h>
#include<stdio.h>
#include<assert.h>
#include<arpa/inet.h>
#include<openssl/md5.h>

#include "ttftp-enc.h"


void print_hex( char * b, int n ) {
	int i ;
	for (i=0;i<n;i++) printf("%02hhx", b[i]) ;
}

Node * new_node( char * user, char * pass, Node * next ) {
	Node * n = (Node *) malloc(sizeof(Node)) ;
	n->user = strdup(user) ;
	n->pass = strdup(pass) ;
	n->next = next ;
	return n ;
}

void print_nodes( Node * n ) {
	int i ;
	while (n) {
		printf("(%s,%s)->", n->user, n->pass ) ;
		n = n->next ;
	}
	printf("NULL") ;
}

Node * find_node( Node * root, char * user ) {
	// find user
	while ( root ) {
		if ( !strcmp(root->user,user) ) return root ;
		root = root->next ;
	}
	return NULL ;
}

#define SEP ": \n\t"

Node * parse_pwfile( char * filename ) {
	Node * n = NULL ;
	FILE * f ; 
	char s[1024] ;
	char * u ;
	char * p ;

	if (! (f = fopen(filename, "r" )) ) {
		return NULL ;
	}

	while ( fgets( s, sizeof(s), f) ) {
		if (s[0]=='#') continue ;
	
		u = strtok(s,SEP) ;
		if ( !u ) continue ;
		p = strtok(NULL,SEP) ;
		if ( !p ) continue ;
		if (g_verbose) {
			printf("%s:%d: adding (|%s|,|%s|) to linked list\n",__FILE__, __LINE__, u,p) ;
		}
		n = new_node( u, p, n ) ;
	}

	fclose(f) ; 
	return n ; 
}


/*       crypto 
*/

char next_random() {
	static FILE * fr = NULL ;
	static int r = 0 ;
	if ( g_debug & DEBUGFLAG_NORANDOM  ) {
		return ++r ;
	}

	if ( ! fr ) {
		if ( g_verbose )  printf("%s:%d: opening dev-urandom\n", __FILE__, __LINE__ ) ;
		fr = fopen("/dev/urandom","r") ;
	}
	return getc(fr) ;
}

void padding( char * b, int len ) {

	// given a 512 byte block pointed to by b, with the first len byte
	// of data, pad out the remaining bytes accordingly.
	// the buffer b is modified
	// that is, 0x80 is put at location len, and 0x00 put in all bytes following

	assert( len<TFTP_DATALEN && len>=0 ) ;

	// write your code
        b[len] = 0x80;

        for(int i = (len + 1); i < TFTP_DATALEN; i ++){
                b[i] = 0x00;
	}
	return ;
}

int unpadding( char * b ) {

	// given a 512 byte buffer pointed to by b, which is padded, 
	// return the number of data bytes in buffer b,
	// that is, the number of bytes before the first 0x80
	// the buffer b is not modified 
	int i = 0;
	
	while(i < TFTP_DATALEN){
		if ((*(b+i)) == (char) 0x80){
			break;
		} else{
			i++;
		}
	}
	return i ;
}

void passwd_md5(char * pwd, char * md5pwd ) {
	// given the password, and a 16 byte buffer pointed to by
	// md5pwd, calculate the MD5 on pwd and place the result in 
	// md5pwd

	// this is done for you, as an example of how to call MD5

	MD5( (unsigned char *) pwd, strlen(pwd), md5pwd) ;

	IF_VERBOSE {
		int i; 
		printf("passwd_md5: pwd=|%s|, md5=|", pwd ) ;
		for (i=0; i< MD5_DIGEST_LENGTH; i++ )  {
			printf("%02hhx", md5pwd[i]) ;
			if ( (i%4)==3 ) printf(" ") ;
		}
		printf("|\n") ;
	}

	return ;
}

void HE (char * key, char * data, char * R_i){
	
	char * concat;
	int len;

	len = 32;
        concat = malloc(len);
        memcpy(concat, data, 16);
        memcpy(concat+16,key, 16);
	
	MD5((unsigned char *) concat, len, R_i);

	free(concat);

	return ;
}

void HD (char * key, char * data, char * D_i){
        char * concat;
        int len;

        len = 32;
        concat = malloc(len);
        memcpy(concat, key, 16);
        memcpy(concat+16, data, 16);

        MD5((unsigned char *) concat, len, D_i);

        free(concat);

        return ;
}

void HF (char * key, char * data, char * MAC){
	
	char * key_comp = malloc(16); // bit wise complement of the key

	for(int i = 0; i < 16; i++){
		*(key_comp + i) = ~(*(key +i)); 
	}

	HD(key_comp, data, MAC);

	return;
}

void encrypt_block( char * buf, char * key, char * ofb_prev ) {

	// given a 512 byte buffer pointed to by buf, a key, and the previous
	// 16 byte OFB value, encrypt the buffer and update ofb_prev.
	// the buffer is updated by the encrypted bytes
	// ofb_prev is updated so that repeated calls chain properly.
	// the first call to encrypt_block has authenticator as the contents
	// of ofb_prev
	int numbytes = 16;
	char * concat;
	char * R_i = malloc(16); // ofb_curr
	char * B_i = malloc(16); // 16 byte data subblock
	char * C_i = malloc(16); // encrypted 16 byte data subblock
        
 	bzero(R_i, 16);
	bzero(B_i, 16);
	bzero(C_i, 16);

	for (int i = 0; i < 32; i++){
		HE(key, ofb_prev, R_i);
		
		memcpy(B_i, buf+(16*i), 16);
		
		for (int j = 0; j < 16; j++){
			*(C_i + j) = *(R_i + j) ^ *(B_i + j);
		}
		
		memcpy(buf+(16*i), C_i, 16);
		bzero(ofb_prev, 16);
		memcpy(ofb_prev, R_i, 16);
		bzero(R_i, 16);
	}
	free(R_i);
	free(B_i);
	free(C_i);
	return ;
}

void cbc_hash( char * hash, char * enc_buf, char * key ) {

	// given a 16 byte partially finished hash, a 512 byte buffer,
	// and the key, update hash to incorporate the buffer into the
	// hash. buf is unchanged.
	
	char * D_i_prev = malloc(16);
	char * D_i = malloc(16); // the hash
	char * C_i = malloc(16); // encrypted data sent to cl or received from server
	char * XOR_i = malloc(16); 

	bzero(D_i_prev, 16);
	bzero(D_i, 16);
	bzero(C_i, 16);

	for(int i = 0; i < 32; i++){
		
		memcpy(C_i, enc_buf+(16*i), 16);

		for (int j = 0; j < 16; j++) {
			*(XOR_i + j) = *(C_i + j) ^ *(D_i_prev + j);
		}

		HD(key, XOR_i, D_i);

		bzero(D_i_prev, 16);
		memcpy(D_i_prev, D_i, 16);
		bzero(C_i, 16);

		if(i < 31){
			bzero(D_i, 16);
		}
	}

	memcpy(hash, D_i, 16);

	return ;
}

void cbc_hash_finalize ( char * hash, char * key ) {

	// finalize the 16 byte hash (do the special last hash on it)
	char * MAC = malloc(16);

	bzero(MAC, 16);

	HF(key, hash, MAC);
	memcpy(hash, MAC, 16);
	free(MAC);
	return ;
}

// this is an example of how to encrypt
// probably not exactly the useful function
void special_encrypt( char * buf, char * secret, int secret_len, char * ra, int ra_len ) {
	char * md ;
	int i ;
	char * tb = (char *) malloc( secret_len+ra_len) ;
	memcpy(tb, secret, secret_len) ;
	memcpy(tb+secret_len, ra, ra_len ) ;
	md = (char *) MD5((unsigned char *) tb, secret_len+ra_len, NULL ) ;
	free(tb) ;
	for (i=0;i<AUTHEN_LEN;i++) {
		buf[i] ^= md[i] ;
	}
	return ;
}
