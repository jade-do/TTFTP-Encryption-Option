/*
** name: ttftp-enc.c
**
** author: bjr
** created: 31 jan 2015 by bjr
** last modified:
**		14 feb 2016, for 162 semester of csc424 -bjr 
**      09 apr 2019, for 192 semester of csc424 -bjr
**
*/

#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<string.h>
#include<fcntl.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<netdb.h>
#include<assert.h>
#include<unistd.h>
#include<openssl/md5.h>

#include "ttftp-enc.h"

#define USAGE_MESSAGE "usage:\tttftp-enc [-vLR] [-s passwordfile] port\n\tttftp-enc [-vR]  [-u username -s password]  -h host -f filename port"

int g_verbose = 0 ;
int g_debug = 0 ;

int main(int argc, char * argv[]) {
	int ch ;
	struct Params params ;
	memset((void *)&params,0,sizeof(struct Params) ) ;

	// check whether we can use short as the data type for 2 byte int's
	assert(sizeof(short)==2) ;

	while ((ch = getopt(argc, argv, "vLRf:h:s:u:")) != -1) {
		switch(ch) {
		case 'v':
			g_verbose ++ ;
			break ;
		case 'h':
			params.hostname = strdup(optarg) ;
			break ;
		case 'f':
			params.filename = strdup(optarg) ;
			break ;
		case 'L':
			params.no_loop = 1;
			break ;
		case 's':
			params.pwfile = strdup(optarg) ;
			params.upass = params.pwfile ;
			break ;
		case 'u':
			params.uname = strdup(optarg) ;
			break ;
		case 'R':
			params.no_randomness = 1 ;
			g_debug |= DEBUGFLAG_NORANDOM ;
			break ;
		case '?':
		default:
			printf("%s\n",USAGE_MESSAGE) ;
			return 0 ;
		}
	}
	argc -= optind;
	argv += optind;
		if ( argc!= 1 ) {
		fprintf(stderr,"%s\n",USAGE_MESSAGE) ;
		exit(0) ;
	}

	params.port = atoi(*argv) ;
	assert(params.port) ;

	// sanity check inputs
	if ( !params.hostname && !params.filename ) {
		// server
		params.is_server = 1 ;
		if (params.uname) {
			fprintf(stderr,"error -u option not used for server.\n") ;
			fprintf(stderr,"%s\n",USAGE_MESSAGE) ;
			exit(0) ;
		}
		if (params.pwfile) params.use_encryption = 1 ;
	}
	else  {
		// client
		if ( !params.hostname || !params.filename ) {
			fprintf(stderr,"both hostname and filename are needed\n") ;
			fprintf(stderr,"%s\n",USAGE_MESSAGE) ;
			exit(0) ;    
		}
		if (params.uname && params.upass ) params.use_encryption = 1 ;
		else if ( params.uname || params.upass ) {
				fprintf(stderr,"both username and password are needed\n") ;
				fprintf(stderr,"%s\n",USAGE_MESSAGE) ;
				exit(0) ;    
		}
	}

	if (!params.is_server ) return ttftp_client( &params ) ;
	else return ttftp_server( &params ) ;

	IF_VERBOSE printf("goodbye\n") ; 
	return 0 ;
}

