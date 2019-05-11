/*
** name: ttftp-server.c (encryption option)
**
** author: bjr
** created: 14 feb 2016 by bjr
** last modified:
**		10 april 2019
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

struct TftpError * create_error(short err_code, char * err_msg, int sockfd, struct sockaddr_in their_addr) {

	struct TftpError * error;
	short opcode = htons(TFTP_ERR);
	short code = htons(err_code);
	int the_numbytes;
	int bytes_sent;

	the_numbytes = 2 + 2 + strlen(err_msg);

	error = malloc(the_numbytes);
	memcpy(&(error->opcode), &opcode, sizeof(short));
	memcpy(&(error->error_code), &code, sizeof(short));
	memcpy(&(error->error_msg), err_msg, strlen(err_msg));

	if ((bytes_sent=sendto(sockfd, error, the_numbytes, 0, (struct sockaddr *)&their_addr, sizeof(struct sockaddr)) ) == -1 ) {
                perror("sendto") ;
                exit(1) ;
        }

	free(error);
}

int  ttftp_server( struct Params * params ) {

	struct TftpReq * req;
	struct TftpAck * ack;
	struct TftpError * error;

	int sockfd_l;
	int sockfd_s ;
	struct sockaddr_in my_addr;
	struct sockaddr_in their_addr;
	int block_count ;
	
	Node * ll_users ;
	Node * user;
	int pos;
	FILE * fp;

	char buf[MAXMSGLEN];
	int addr_len;
	int numbytes, bytes_sent, bytes_recv;
	int tid_c;

	char * md5pwd;
	char authen[16];
	char MAC[16];
	char D_n[16];
	int req_encryption = 0;

	IF_VERBOSE printf("ttfpt_server: server loop entered\n") ;

	if (params->use_encryption) {
		ll_users = parse_pwfile(params->pwfile) ;
		if ( !ll_users ) {
			printf("error: password file |%s|\n", params->pwfile ) ;
			return 0 ; 
		}
		IF_VERBOSE {
			printf("%s:%d: user list: ", __FILE__, __LINE__ ) ;
			print_nodes(ll_users) ; 
			printf("\n") ;
		}
	}

	// create the listener socket
        if ((sockfd_l = socket(AF_INET, SOCK_DGRAM, 0)) == -1 ) {
                perror("socket") ;
                exit(1) ;
        }

        my_addr.sin_family = AF_INET ;
        my_addr.sin_port = htons((short)params->port) ;
        my_addr.sin_addr.s_addr = INADDR_ANY ;
        memset(&(my_addr.sin_zero),'\0',8) ;

        if (bind(sockfd_l, (struct sockaddr *)&my_addr,
                sizeof(struct sockaddr)) == -1 ) {
                perror("bind") ;
                exit(1) ;
        }

	IF_VERBOSE printf("line %d: listening on port %d\n",__LINE__,params->port) ;


	do {

		// get the RREQ packet
                addr_len = sizeof(struct sockaddr) ;
                if ((numbytes=recvfrom(sockfd_l, buf, MAXMSGLEN-1, 0,
                                (struct sockaddr *)&their_addr, &addr_len)) == -1 ) {
                        perror("recvfrom") ;
                        exit(1) ;
                }

		buf[numbytes] = '\0';
	
		req = (struct TftpReq *)buf;
	        tid_c = ntohs(their_addr.sin_port);

		if(memcmp(&(req->filename_and_mode[strlen(req->filename_and_mode)+1]), OFBCBC_STRING, strlen(OFBCBC_STRING)) == 0) {
			// username look up and password comparison here
			req_encryption = 1;
			pos = strlen(req->filename_and_mode) + 1 + strlen(OFBCBC_STRING) + 1;
			user = find_node(ll_users, &(req->filename_and_mode[pos]));
			md5pwd = malloc(16);
			passwd_md5(user->pass, md5pwd);
			memcpy(authen, &(req->filename_and_mode[numbytes-16 - 2]), AUTHEN_LEN);
		} else if((memcmp(&(req->filename_and_mode[strlen(req->filename_and_mode)+1]), OCTET_STRING, strlen(OCTET_STRING)))!= 0){
			// error packet raised 
		}		
		
		// opens file
		fp = fopen(req->filename_and_mode, "r");
	
		// if you want to handle multiple transfers, the easiest way is to
		// for a child for each request
		if ( !fork() ) {
			int more_blocks;
        		struct TftpData * data;
        		int bytes_read;
			short data_opcode;
			short block;
			int wait_MAC = 1;

			// child process, to handle a single transfer
			// open a session socket, for just this transfer

                        if ((sockfd_s = socket(AF_INET, SOCK_DGRAM, 0)) == -1 ) {
                                perror("socket") ;
                                exit(1) ;
                        }

			data_opcode = htons(TFTP_DATA);
			more_blocks = 1;
			while (more_blocks) {
				if(wait_MAC) {
					data = malloc(TFTP_DATALEN+4);
					block = htons(more_blocks);
					memcpy(&(data->opcode), &data_opcode, sizeof(short));
            				memcpy(&(data->block_num), &block, sizeof(short));
					bytes_read = fread(data->data, sizeof(char), TFTP_DATALEN, fp);

					if(params->use_encryption && req_encryption){					
                                        	if(bytes_read < TFTP_DATALEN) {
                                                	padding(data->data, bytes_read);
                                        	}
						bytes_read = TFTP_DATALEN;					
						encrypt_block(data->data, md5pwd, authen);
						cbc_hash(D_n, data->data, md5pwd);		
					}
				                                // send a DAT packet
                                	if ((bytes_sent=sendto(sockfd_s, data, 4 + bytes_read, 0,(struct sockaddr *)&their_addr, sizeof(struct sockaddr)) ) == -1 ) {
                                        	perror("sendto") ;
                                        	exit(1) ;
                                	}

				} else {
                        		// sending the 16 byte MAC
                        		data = malloc(16 + 4);
                        		memcpy(&(data->opcode), &data_opcode, sizeof(short));
                        		memcpy(&(data->block_num), &block, sizeof(short));
					cbc_hash_finalize(D_n, md5pwd);
					memcpy(MAC, D_n, 16);
					memcpy(&(data->data), MAC, 16);

                        		if ((bytes_sent=sendto(sockfd_s, data, 4 + 16, 0,(struct sockaddr *)&their_addr, sizeof(struct sockaddr)) ) == -1 ) {
                                		perror("sendto") ;
                                		exit(1) ;
                        		}
				 }
    
				// wait for an ACK packet
            			if ((numbytes=recvfrom(sockfd_s, buf, MAXMSGLEN-1, 0, (struct sockaddr *)&their_addr, &addr_len)) == -1 ) {
                			perror("recvfrom") ;
                			exit(1) ;
           			 }  

           			ack = (struct TftpAck *)buf;

            			if(tid_c != ntohs(their_addr.sin_port)){
            				// TO DO: Construct Error Packet
					create_error(5, "Unknown transfer ID", sockfd_s, their_addr);
				}      

            			if(TFTP_ACK != ntohs(*((short *)ack->opcode))){
                			// TO DO: Construct Error Packet
					create_error(4, "Not An ACK Packet", sockfd_s, their_addr);
					break;
            			}

           			if(more_blocks != ntohs(*(short *)ack->block_num)){
                			// TO DO: Construct Error Packet
					create_error(1, "Non-matching BlockNum", sockfd_s, their_addr);
					break;
            			}
				
				free(data);

				// for encryption option
				if(wait_MAC == 0){
					more_blocks = 0;
				} else {
					more_blocks++;
				}

				// for non encryption option
				if(feof(fp) && (!(params->use_encryption) || !(req_encryption))){
					more_blocks = 0;
				} else if (feof(fp)){
					wait_MAC = 0;
				}
				
			}

			return 0 ;
			assert(0==1) ; // never gets here

		} // end of fork
		fclose(fp);
	} while (!params->no_loop) ;

	return 0 ;
}

