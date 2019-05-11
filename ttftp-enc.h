/*
** name: ttftp-enc.h
**
** author: bjr
** created: 31 jan 2015 by bjr
** last modified:
**		9 april 2019 for csc424-192 -bjr 
**
*/

#define MAXMSGLEN 2048
#define MAXFILENAMELEN 256

#define TFTP_RRQ 1
#define TFTP_WRQ 2
#define TFTP_DATA 3
#define TFTP_ACK 4
#define TFTP_ERR 5

#define TFTP_ERR_UNKN 0
#define TFTP_ERR_FNF 1
#define TFTP_ERR_ILLG 4
#define TFTP_ERR_USR 7

#define OCTET_STRING "octet"
#define OFBCBC_STRING "ofbcbc"
#define TFTP_DATALEN 512

#define ACK_TIMEOUT 10 
#define ACK_RETRY 3

#define MODE_OCTET 2
#define MODE_OFBCBC 3

#define VAR_SIZE 0 

#define DEBUGFLAG_NOCRYPTO  01
#define DEBUGFLAG_NORANDOM  02
#define AUTHEN_LEN 16

#define IF_VERBOSE if (g_verbose) 

extern int g_verbose ;
extern int g_debug ;

struct Params {
	char * hostname ;
	int port ;
	char * filename ;
	char * upass ;
	char * uname ;
	char * pwfile ;
	int no_randomness ;
	int no_loop ;
	int use_encryption ;
	int is_server ;
	/* add more parameters here, if needed */
} ;

typedef struct Node {
	char * user ;
	char * pass ;
	struct Node * next ;
} Node ;

struct TftpReq {
	char opcode[2] ;
	char filename_and_mode[VAR_SIZE] ;
} ;

struct TftpData {
	char opcode[2] ;
	char block_num[2] ;
	char data[VAR_SIZE] ; /* zero to 512 bytes */
} ;

struct TftpAck {
	char opcode[2] ;
	char block_num[2] ;
} ;

struct TftpError {
	char opcode[2] ;
	char error_code[2] ;
	char error_msg[VAR_SIZE] ;
} ;

// forward definitions for ttftp_crypto

Node * find_node( Node * root, char * user ) ;
Node * parse_pwfile( char * filename ) ;
void print_nodes( Node * n ) ;
void print_hex( char * b, int n ) ;

// crypto functions
char next_random(void) ;
void padding( char * b, int len ) ;
int unpadding( char * b ) ;
void encrypt_block( char * buf, char * key, char * ofb_prev ) ;
void passwd_md5(char * pwd, char * md5pwd ) ;
void cbc_hash( char * hash, char * buf, char * key ) ;
void cbc_hash_finalize( char * hash, char * key ) ;

// forward definitions 
int  ttftp_client( struct Params * params ) ;
int  ttftp_server( struct Params * params ) ;
int  get_opcode(char * buf) ;
int  get_block_number(char * buf) ;
