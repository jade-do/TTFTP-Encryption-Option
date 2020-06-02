# TTFTP Project — Encryption Option
by: burt rosenberg
at: university of miami

The original best-effort, packetized data delivery
Adding Encryption to the Truly Trivial File Transfer

Building on the Truly Trivial File Transfer Project, a reduced functionality of the RFC 1350 TFTP protocol, we add a complete communication security solution protecting the confidentiality, integrity and authenticity of the channel. We use key hash functions based on MD5 in OFB mode encryption, with a CBC MAC based on the Encrypt-then-MAC method. In addition, we use a standard padding. We also provide a protocol extension, slightly in the spirit of RFC 1782, that negotiates the use of encryption and provides the required parameters (i.e. username and authenticator).

## Specific Objectives
The project is an exercise in all issues in data encryption including,

block encryption using OFB mode,
keyed hash functions as encryption primitives,
initial vectors to insure semantic security,
MAC'ing for integrity, and CBC MACs,
message padding techniques,
key management.

## Man Page


### NAME
    ttftp-enc
    
### SYNOPSIS
    ttftp-enc [-vR -p PORT] [-s passwordfile] (-l | -L)
    ttftp-enc [-vR -p PORT] [-u username -s password] host filename
    
    
### DESCRIPTION
    Implements a client and a server for the tftp protocol. If called without -h and -f
    options, the programs implements the ttftp server listening on port_port_. 
    If called with both -h and -f options, the program implements the ttftp client, 
    requesting to read file _filename_ from host _host_ connecting on port _port_.

    If client has both the -u and -s options, ofbcbc mode is requested. The transfer
    is encrypted. Is the server has the -s option, ofbcbc mode is enabled, else the
    server rejects a client's request for an encrypted transfer. Requests for 
    non-encrypted transfer are accepted by the server whether or not ofbcbd mode
    is enabled.

    The client writes the received bytes to standard out.

    The tftp protocol is modified to support encryption by declaring the mode to be
    "ofbcbc" in the read request packet, and extending the read request packet format
    to send the username and a 16 byte authenticator nonce. Otherwise the transfer type is
    octet.

    It is an error to request encryption if the server has not be started with a 
    passwordfile; or if the username is not found in the passwordfile. Note that 
    octet mode continues to be supported.
    
### OPTIONS
    client and server options:
      -R no randomness.
      -v verbose. Multiple increase verbosity
      -p port 
      -h help
  
    server options:
      -L do not loop - service one read request then exit.
      -l loop
      -s filename containing username, password pairs (when enabled for ofbcbc mode).
    
    client options: 
      -f File to read.
      -h as client: hostname of server.
      -s password (ofbcbc mode only)
      -u username (ofbcbc mode only)

### ERRORS
    The client program exists with status -1 if the ofbcbc transfer results in a
    incorrect MAC, otherwise the exit status is 0.
    
    Errors that result due to incorrect or inconsistent command line arguments
    SHOULD be supported, including the sending of protocol compliant TFTP error
    packets.

### NOTES
    Implement only read requests, and mode octet or ofbcbc.

    The maximum filename length is 256 characters, and cannot contain a pathname.

    The -R option suppresses randomness. The client authenticator is fixed
    as 0x01, 0x02, ..., 0x10.

### BUGS
    In accordance with RFC 1782, the maximum size of a request packet should be 512
    bytes, in which case, the filename length restriction can be removed, as redundant.
    In contrast to RFC 1782, the options are not all strings, and are not a knowledged
    by an OACK packet.
    
    Along with ttftp, the command line sucks. -p should be non-default port, -k the key,
    and filename and host arguements, not options.

### HISTORY
    First introduced in Fall 2003 as MyTftp. Made Truly Trivial in Spring 2015.
    Encryption option introduced in Spring 2015. OFB/CBC with keyed MD5 with 
    user passwords introduced Spring of 2019.

### LAST UPDATED 
    April 10, 2019

## RREQ packet for ofbcbc mode

To announce a request for encrypted file transfer the client sense a RREQ packet with mode "ofbcb" and two additional fields. The username is a sequence of alphanumeric characters and authenticator (auth) is a 16 byte sequence nonce.

Mode = "octet"

     2 bytes      chars   1 byte   chars  1 byte
    +--------+------------+-----+--------+-----+
    | Opcode |  Filename  |  0  |  Mode  |  0  |
    +--------+------------+-----+--------+-----+

Mode = "ofbcbc"

     2 bytes     chars    1 byte   chars  1 byte   string   1 byte   16 bytes
    +--------+------------+-----+--------+-----+------------+-----+-----------+
    | Opcode |  Filename  |  0  |  Mode  |  0  |  username  |  0  |   auth    |
    +--------+------------+-----+--------+-----+------------+-----+-----------+

## Data blocks and padding for ofbcbc

When in ofbcbc mode, the file length is padded to a multiple of 512 bytes, and and sent as 512 byte blocks as in the original protocol. If the file length is already a multiple of 512 bytes, an additional 512 bytes is added. The final block is a 16 byte block containing the MAC. Signaling the last data block by a block of less than 512 bytes is maintained by the protocol extension.

The padding of the final datablock follows ISO/IEC 7816-4. The first padding byte is 0x80 and all following padding bytes are 0x00.

### DATA BLOCKS

  [1,Data(512 bytes)] [2,Data(512 bytes)] ... [n,Data/Padding(512 bytes)] [n+1,MAC(16 bytes)]


### PADDING

  One padding byte:      byte_0   .........   byte_509 byte_510 0x80

  Two padding bytes:     byte_0   ....   byte_508 byte_509 0x80 0x00
    
  Three padding byte:    byte_0 ... byte_507 byte_508 0x80 0x00 0x00
    
  512 bytes of padding:  0x80 0x00   ..............   0x00 0x00 0x00
The data bytes of the file are collected into 128 bit subblocks, and padded to the next even multiple of 512 bytes. The encryption uses the IV, the port numbers for the session, block numbers, and sub-block identifiers, to derive a 128 bit pseudorandom block which is exclusive or'ed with the data sub-block. To decode, this block is recalculated by the data receiver and is exclusive or'ed again to retrieve the plaintext. The calculation for the counter mode AES is:
Encryption and MAC

Three keyed hash functions are defined, HE(key,data), HD(key,data), and HF(key,data), by appending or prepending the key (a shared secret) to the data (a 16 byte buffer), in the case of HF then bitwise complementing the key, and hashing to result by MD5.

HE is used for encryption to create sequence of 16 byte pseudorandom blocks that are exclusive orded with the data blocks.

The MAC is encrypt-then-MAC style, where the sequence of blocks after encryption are used in a CBC construction using HD in all but the last hash, where HF is used.

### Keyed Hash functions

   HE(key,data) = MD5( data || key )  
   HD(key,data) = MD5(  key || data )  
   HF(key,data) = MD5( ~key || data )  
   
   where ~key is the bit-wise complement of key, and || is concatenation

### Encryption and Decryption

   R_i = HE(secret, R_{i-1})   
   C_i = R_i (+) B_i  (server computation)    
   B_i = R_i (+) C_i  (client computation)   
   
   where
   
      secret is the MD5 of the user's password,
      R_0 is the 16 byte authenticator from RREQ, 
      B_i is a 16 byte data subblock i, for i = 1, 2, ... n,
      and C_i is the encrypted 16 byte data subblock i, sent to client.

### MAC calculation

   D_i = HD(secret,C_i (+) D_{i-1})  
   MAC = HF(secret, D_n)  
   
   where
   
      secret is the MD5 of the user's password,
      D_0 is 16 bytes of all zeros
      n is the number of data subblocks (not including the MAC)
      i = 1, 2, ..., n
      MAC is sent to the client as the last data block.
      
There are 32 16-byte subblocks to the TFTP protocol's 512 byte blocks.
The padding scheme rounds up the message length to a 512 byte multiple.
      
## Key management

The shared secret, called the password, is a printable character string. The client receives the password as a command line option. The server extracts the username from the RREQ and retrieves the password for the file named as a command line option.

This password is MD5 hashed before use in the cryptographic functions, as shown in the above calculations.

## Error messages

Errors possible through command line options and arguments *should* be handled. For instance the server should return an error packet for file not found and when encryption is requested but not enabled. Errors arising from protocol violations *may* be handled. For instance, an authentication field of length other than 16 bytes.

The list of errors recommended are,

 Error
 Code     Message              Meaning
-----+----------------------+--------------------------------------------------------
   1   file not found          requested file to read is not available
   4   mode not supported      request other than a read
                               mode is other than octet or ofbcbc
                               ofbcbc is requested but not enabled on the server
                               RREQ is otherwise malformed
   7   user not found          password for an ofbcbc is unknown to the server
## Implementation Notes

Here are a few thoughts on how to go about implementing this project. One skill in writing software is how to arrange your work in small steps. What to work on and when, to build the project up gradually, testing all the time, refining the vision for the software as you become familiar with the details.

You begin with a merge of project 3 and project 4; mostly project 3 with a few cut and pastes from project 4, concerning the cryptography. You must have project 3 working very well before moving on the the encryption option. Review the problems you might have had in project 3, as discovered by the project 3 Makefile-test, understand, and correct. You code should pass all project 3 tests.

Begin by handling the new RREQ format. Get the username lookup working, and check that the authenticator is generated, transmitted, and stored properly. See if the client and server can agree on whether or not the encryption option will be employed.

The next step is the padding. Let the data be in the clear (do not worry about encryption in this step) and teach your code how to pad the data. Send a fixed 16 byte last packet, a place-holder for the MAC. Never mind it is phony. At this point you are exploring how to do padding, getting it right, and the program flow that knows when to send the 16 byte final packet.

Then do the unpadding on the client. Things get a bit tricky here, as you cannot know if a data block is padded or not just by looking at it. A block might end with what looks like a padding sequence, but not be a padded block. Data can mimic the padding sequence! What determines whether or not a block is padded is that the padded block comes right before the 16 byte final packet.

After long last, at this point, you are back to where you started from. You can now pass all tests from project 3, except the data goes through a padding and unpadding, and a final 16 byte phony MAC that does nothing but go for a ride and get discarded. But now that that's done, it's ready for crypto.

At this point, retest the non-encryption option, that it still works, and that the encryption option is invoked in correct circumstances.

Now implement encryption. Implement encryption and watch the gibberish fly. Then implement decryption and watch the gibberish become plaintext again. You will now be able to again pass all tests from project 3. As the final step, implement the MAC.

## Protocol Trace

This is the transfer of a zero-byte file. The 512 block 1 is a block entirely of padding. Block 2 is the 16 byte MAC. The -R option is used to get a repeatable trace.

This all is tricky. Alert me of your output does not match, and you think it is correct.

SCREEN 1 (this will not match much, the verbose output is your own choice)

ubuntu@ip-172-30-1-171:~/myrepo.svn/burt/proj5$ make run-server
killall ttftp-enc
ttftp-enc: no process found
Makefile:47: recipe for target 'run-server' failed
make: [run-server] Error 1 (ignored)
touch running-server
./ttftp-enc -vRL -s mypasswords.txt 33031
Line 201: server loop entered
ttftp-crypto.c:87: adding (|pikachu|,|pa22Word0|) to linked list
ttftp-crypto.c:87: adding (|superman|,|Kryptonite7|) to linked list
ttftp-crypto.c:87: adding (|wonderwoman|,|Themyscira|) to linked list
ttftp-server.c:211: user list: (wonderwoman,Themyscira)->(superman,Kryptonite7)->(pikachu,pa22Word0)->NULL
Line 217: listening on port 33031
goodbye // this is the parent process exiting
check_transfer_mode: mode: |ofbcbc|
strdup_username: username |pikachu|
memdup_authenticator: filename |0bytes.bin|
ttftp-crypto.c:131: pwd=pa22Word0, md5=409932ab 1df27813 669ff207 cdf5ec47 
line 273: encrypting user |pikachu| password |pa22Word0| authenticator |0102030405060708090a0b0c0d0e0f10|
line 294(ttftp-server.c): received RRQ for file 0bytes.bin, host 127.0.0.1 at port 44019
padding: len 0
sending 512 data bytes as block 1 (is_encrypting 1) to host 127.0.0.1 at port 44019. retries 1
received opcode 4 for block 1 from host 127.0.0.1 at port 44019
sending 16 data bytes as block 2 (is_encrypting 1) to host 127.0.0.1 at port 44019. retries 1
received opcode 4 for block 2 from host 127.0.0.1 at port 44019



SCREEN 2

ubuntu@ip-172-30-1-171:~/myrepo.svn/burt/proj5$ make run-client
./ttftp-enc -R -h localhost -f 0bytes.bin -u pikachu -s pa22Word0 33031 > test.out
ubuntu@ip-172-30-1-171:~/myrepo.svn/burt/proj5$ ls -l test.out
-rw-rw-r-- 1 ubuntu ubuntu 0 Apr 11 00:12 test.out
ubuntu@ip-172-30-1-171:~/myrepo.svn/burt/proj5$ 



SCREEN 3

ubuntu@ip-172-30-1-171:~/myrepo.svn/burt/proj5$ make tcpdump  
sudo tcpdump -i lo -lX port 33031 or portrange 10000-65535  
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode  
listening on lo, link-type EN10MB (Ethernet), capture size 262144 bytes  
    
00:12:39.370039 IP localhost.42322 > localhost.33031: UDP, length 44  
	0x0000:  4500 0048 6235 4000 4011 da6d 7f00 0001  E..Hb5@.@..m....  
	0x0010:  7f00 0001 a552 8107 0034 fe47 0001 3062  .....R...4.G..0b  
	0x0020:  7974 6573 2e62 696e 006f 6662 6362 6300  ytes.bin.ofbcbc.  
	0x0030:  7069 6b61 6368 7500 0102 0304 0506 0708  pikachu.........  
	0x0040:  090a 0b0c 0d0e 0f10                      ........  
00:12:39.371627 IP localhost.56884 > localhost.42322: UDP, length 516  
	0x0000:  4500 0220 6236 4000 4011 d894 7f00 0001  E...b6@.@.......  
	0x0010:  7f00 0001 de34 a552 020c 0020 0003 0001  .....4.R........  
	0x0020:  1db9 aacc 6c20 84af 89ca 1947 e2f9 1794  ....l......G....  
	0x0030:  6c0f d669 ccc9 5005 15fc abe9 fc56 6768  l..i..P......Vgh  
	0x0040:  2cb1 c216 b226 8431 0c32 41ed fd64 f80b  ,....&.1.2A..d..  
	0x0050:  d68c fcf4 cac5 5ed3 e659 eb2d ac8d b3e9  ......^..Y.-....  
	0x0060:  9c59 15c2 8254 4378 b818 444f 5faf 40c0  .Y...TCx..DO_.@.  
	0x0070:  45c0 efcc eae9 ee3f c396 59f8 a858 2957  E......?..Y..X)W  
	0x0080:  94b3 abf9 fd4a 6391 2273 f45c 2b94 af7e  .....Jc."s.\+..~  
	0x0090:  4d76 c728 2b7b 027b 7ff2 afd1 ad77 4d55  Mv.(+{.{.....wMU  
	0x00a0:  c310 f9e6 85cc dd4f 0860 1be5 a4a1 897c  .......O.`.....|  
	0x00b0:  ed67 43b0 57dc ec76 ba00 603b 78ee c545  .gC.W..v..`;x..E  
	0x00c0:  a8ea cf4a d7f9 9616 22d8 9639 51b7 4f11  ...J...."..9Q.O.  
	0x00d0:  644e 8f35 ae0c 0b18 99c0 d3c5 9575 3e89  dN.5.........u>.  
	0x00e0:  aba1 388a 09cb e3c0 c50f bdf1 f6da 6e6b  ..8...........nk  
	0x00f0:  e788 2e09 db4f 3163 a5db 3437 1231 4ba7  .....O1c..47.1K.  
	0x0100:  5fec ea42 2f1b 1095 8181 f7fc 252b 0bf7  _..B/.......%+..  
	0x0110:  1e11 a626 69b9 3dcb 9a44 5d3b ee7b f222  ...&i.=..D];.{."  
	0x0120:  93ec 4687 43e9 13f0 d4e1 8d8f 48a9 cc2e  ..F.C.......H...  
	0x0130:  ba6d b1a8 ea13 62a2 8b59 0fe8 bda8 a36d  .m....b..Y.....m  
	0x0140:  c363 c1ba f289 009f b11a 1b13 278c 0082  .c..........'...  
	0x0150:  c539 bcc9 192f c726 be7c a270 14b2 ef82  .9.../.&.|.p....  
	0x0160:  5b7b fcdf f537 290d 1e61 4b8f 130e edfe  [{...7)..aK.....  
	0x0170:  0910 b2e3 883f 82db f48e e4db 907e 1740  .....?.......~.@
	0x0180:  7e9a f056 cbde 8ed1 6a69 c388 4f18 7453  ~..V....ji..O.tS
	0x0190:  5d2c 2311 2fc5 d694 7ce5 f756 fca3 7436  ],#./...|..V..t6
	0x01a0:  9884 92f0 15ef 0595 da69 1488 6595 e3ae  .........i..e...
	0x01b0:  56cf 188f 57c8 e767 a863 e321 dab7 b77c  V...W..g.c.!...|
	0x01c0:  cbde d47c 1708 f8f6 e7eb 10fe 7a7b b7e8  ...|........z{..
	0x01d0:  19b5 f507 898f c472 120f 5333 49fb 2392  .......r..S3I.#.
	0x01e0:  0738 2a9d fee4 abc6 1fde 57ed ebfc f8ee  .8*.......W.....
	0x01f0:  2b63 01be 1734 b5f0 9de9 2f5f db63 1b0e  +c...4..../_.c..
	0x0200:  821d 13c9 cae6 d090 3c7a 9da2 cd92 078d  ........<z......
	0x0210:  691e 111c fabf 9c58 d254 f074 c113 c952  i......X.T.t...R
00:12:39.372341 IP localhost.42322 > localhost.56884: UDP, length 4
	0x0000:  4500 0020 6237 4000 4011 da93 7f00 0001  E...b7@.@.......
	0x0010:  7f00 0001 a552 de34 000c fe1f 0004 0001  .....R.4........
00:12:39.372522 IP localhost.56884 > localhost.42322: UDP, length 20
	0x0000:  4500 0030 6238 4000 4011 da82 7f00 0001  E..0b8@.@.......
	0x0010:  7f00 0001 de34 a552 001c fe2f 0003 0002  .....4.R.../....
	0x0020:  9396 9e03 c823 420b 0274 9d2f ef70 c1e3  .....#B..t./.p..
00:12:39.372598 IP localhost.42322 > localhost.56884: UDP, length 4
	0x0000:  4500 0020 6239 4000 4011 da91 7f00 0001  E...b9@.@.......
	0x0010:  7f00 0001 a552 de34 000c fe1f 0004 0002  .....R.4........


  
