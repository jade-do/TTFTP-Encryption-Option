/*
** name: ttftp-client.c (encryption option)
**
** author: bjr
** created: 31 jan 2015 by bjr
** last modified:
**		8 apr 2019
**
**
*/

#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<string.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<netdb.h>
#include<assert.h>
#include<unistd.h>
#include<openssl/md5.h>

#include "ttftp-enc.h"


int  ttftp_client( struct Params * params ) {
	int encryp_accepted = 0;
	struct TftpReq * req;
	struct TftpData * data_prev;
	struct TftpData * data_curr;
	struct TftpAck * ack;
	struct TftpError * error;
	short opcode;
	short block;
	int numbytes;
	char auth[AUTHEN_LEN];
	int pos;
	int unpad;
	int first;

	/* struct sockaddr_in my_addr; */
	struct sockaddr_in their_addr;
	struct hostent *he ;
        int sockfd, i ;
	int bytes_sent;
	char buf[MAXMSGLEN];
        unsigned int addr_len;

	char authenticator[AUTHEN_LEN] ;
	char md5pwd[AUTHEN_LEN] ;
	char cbc[AUTHEN_LEN] ;
	char D_n[16];
	char MAC[16];
	int is_MAC = 0;
	int more_blocks ;

	IF_VERBOSE printf("line %d(%s): client loop entered\n", __LINE__,  __FILE__ ) ;

	// create RRQ
	if ((params->uname == NULL) && (params->upass == NULL)) {
		numbytes = 2 + strlen(params->filename) + 1 + strlen(OCTET_STRING) + 1;
	} else {
		FILE * fp;
		fp = fopen("/dev/urandom", "r");
		fread(&auth, sizeof(char), AUTHEN_LEN, fp);
		fclose(fp);
		numbytes = 2 + strlen(params->filename) + 1 + strlen(OFBCBC_STRING) + 1 + strlen(params->uname) + 1 + AUTHEN_LEN;
	}

	req = malloc(numbytes);
	opcode = htons(TFTP_RRQ);

	memcpy(&(req->opcode), &opcode, sizeof(short));
	memcpy(&(req->filename_and_mode), params->filename, strlen(params->filename)+1);
	pos = strlen(params->filename)+1;

	if((params->uname == NULL) && (params->upass == NULL)){
		memcpy(&(req->filename_and_mode[pos]), OCTET_STRING, strlen(OCTET_STRING)+1);
	} else {
                memcpy(&(req->filename_and_mode[pos]), OFBCBC_STRING, strlen(OFBCBC_STRING)+1);
		pos += strlen(OFBCBC_STRING)+1;
		memcpy(&(req->filename_and_mode[pos]), params->uname, strlen(params->uname)+1);
		pos += strlen(params->uname)+1;
		memcpy(&(req->filename_and_mode[pos]), &auth, AUTHEN_LEN);		
		passwd_md5(params->upass, md5pwd);
	}

        // create a socket to send
        if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1 ) {
                perror("socket") ;
                exit(1) ;
        }

        // get hostname
        if ((he=gethostbyname(params->hostname))==NULL) {
                perror("gethostbyname") ;
                exit(1) ;
        }
        //create address block
        their_addr.sin_family = AF_INET ;
        their_addr.sin_port = htons((short)params->port) ;
        their_addr.sin_addr = *((struct in_addr *)he->h_addr) ;
        memset(&(their_addr.sin_zero), '\0', 8 ) ;

        // send RadiusPacket
        if ((bytes_sent=sendto(sockfd, req, numbytes, 0,
                        (struct sockaddr *)&their_addr, sizeof(struct sockaddr)) ) == -1 ) {
                perror("sendto") ;
                exit(1) ;
        }
	more_blocks = 1 ; /* value expected */
	        

	while ( more_blocks ) {

		// get DAT
            	addr_len = sizeof(struct sockaddr);
            	if((numbytes = recvfrom(sockfd, buf, MAXMSGLEN-1, 0, (struct sockaddr *)&their_addr, &addr_len)) == -1) {
                	perror("recvfrom");
                	exit(1);
            	}
		opcode = htons(*((short *)buf));

		if (opcode == TFTP_DATA) {
                	
			data_curr = (struct TftpData *)buf;
			if((params->uname != NULL) && (params->upass != NULL)) {

				if (more_blocks != 1) {
						
					cbc_hash(D_n, data_prev->data, md5pwd);
					encrypt_block(data_prev->data, md5pwd, auth);

					if (numbytes < (TFTP_DATALEN+4)){
						// current block is MAC
						unpad = unpadding(data_prev->data);
						is_MAC = 1;
					} else {
						// current block is padded data block
						unpad = numbytes - 4;
					}
                       		
				
					for(int i = 0; i < unpad; i++) {
                               			putchar(data_prev->data[i]);
                        		}

					if(is_MAC){
				        	cbc_hash_finalize(D_n, md5pwd);
                                        	memcpy(MAC, D_n, 16);
					}
				
					free(data_prev);
				}
			} else {
				for(int i = 0; i < numbytes -4; i++) {
                                	putchar(data_curr->data[i]);
                        	}
			}
            	} else if(opcode == TFTP_ERR) {
                	error = (struct TftpError *)buf;
                	puts(error->error_msg);
			exit(1);
            	} else {
                    puts("unknown opcode. ending file transfer");
                    break;                
            	}

		// send ACK
	        opcode = htons(TFTP_ACK);
        	block = htons((short) more_blocks);
        	ack = malloc(4);

        	memcpy(&(ack->opcode), &opcode, sizeof(short));
        	memcpy(&(ack->block_num), &block, sizeof(short));

        	if ((bytes_sent=sendto(sockfd, ack, 4, 0,(struct sockaddr *)&their_addr, sizeof(struct sockaddr)) ) == -1 ) {
            		perror("sendto") ;
            		exit(1) ;
        	}

        	free(ack);
		
		if(numbytes < (TFTP_DATALEN + 4)){
			more_blocks = 0 ;
		} else {
			if((params->uname != NULL) && (params->upass != NULL)) {
				data_prev = malloc(TFTP_DATALEN + 4);
				memcpy(data_prev, data_curr, TFTP_DATALEN+4);
				//bzero(data_curr, TFTP_DATALEN+4);
			}
			more_blocks++;
		}
	}

        /* if MAC validates */
	if ((params->uname != NULL) && (params->upass != NULL)) {
        	if(memcmp(MAC, data_curr->data, 16) == 0){
                	memset(data_prev,'\0', (TFTP_DATALEN +4));
                	memset(data_curr, '\0', (TFTP_DATALEN + 4));

                	return 0;
        	} else {
                	memset(data_prev,'\0', (TFTP_DATALEN +4));
                	memset(data_curr, '\0', (TFTP_DATALEN + 4));
                	return -1;
        	}
	} else {
		return 0;
	}
}
