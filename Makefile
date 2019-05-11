#
# Name: bjr
# Date: 14 feb 2016
# 
# last update:
#		9 april 2019
# 

COPTS= 
#COPTS= -Wall

# adjust these macro values accordingly.
# you may have to adjust PORT= to claim an available port

PORT= 33031

FILE_S = file-on-server.txt
FILE_C = file-on-client.txt
SERVER_HOST = localhost
PWFILE = mypasswords.txt

# various test files
FILE = poem.txt
#FILE = 545bytes.bin
#FILE = 0bytes.bin
#FILE = 512byteszero.bin

USER = pikachu
PASS = pa22Word0

all:
	make ttftp-enc

build:
	make ttftp-enc

ttftp-crypto.o: ttftp-crypto.c ttftp-enc.h
	cc ${COPTS} -c -o $@ $<

ttftp-server.o: ttftp-server.c ttftp-enc.h
	cc ${COPTS} -c -o $@ $<

ttftp-client.o: ttftp-client.c ttftp-enc.h
	cc ${COPTS} -c -o $@ $<

# note the order for the link. the crypto library goes last
ttftp-enc: ttftp-enc.c ttftp-server.o ttftp-client.o ttftp-crypto.o ttftp-enc.h
	cc ${COPTS} -o $@ $< ttftp-client.o ttftp-server.o ttftp-crypto.o -lcrypto

run-server: ttftp-enc
	-killall ttftp-enc
	touch running-server
	./ttftp-enc -vRL -s ${PWFILE} ${PORT}

run-server-plain: ttftp-enc
	-killall ttftp-enc
	touch running-server
	./ttftp-enc -vL ${PORT}
	
run-client: ttftp-enc
	./ttftp-enc -R -h ${SERVER_HOST} -f ${FILE} -u ${USER} -s ${PASS} ${PORT} > test.out

run-client-nouser: ttftp-enc
	./ttftp-enc -R -h ${SERVER_HOST} -f ${FILE} -u nosuchuser -s ${PASS} ${PORT} > test.out

run-client-nofile: ttftp-enc
	./ttftp-enc -R -h ${SERVER_HOST} -f nosuchfile -u ${USER} -s ${PASS} ${PORT} > test.out

test-x: ttftp-enc
	@echo "check the server is running"
	rm running-server
	echo `date` >> ${FILE_S}
	./ttftp -h ${SERVER_HOST} -f ${FILE_S} ${PORT} > ${FILE_C}
	diff ${FILE_S} ${FILE_C}
	@echo "check that the server has exited"
	ps aux | grep ttftp-enc

quick-test:
	@echo "better to run each of these separate, in a separate window"
	@echo "while running make tcpdump in a third window"
	@echo "but this is simple and might work as a quick check"
	make run-server
	make text-x

tcpdump:
	sudo tcpdump -i lo -lX port ${PORT} or portrange 10000-65535

# this is used to install the open ssl libraries; only needed once after an install
# use this if for instance, cc cannot find openssl/md5.h 
install-openssl:
	sudo apt-get install libssl-dev

clean:
	-rm ttftp-enc ttftp-crypto.o ttftp-server.o ttftp-client.o 
	-rm ${FILE_S} ${FILE_C} running-server test.out

submit:
	@echo svn add your work
	svn commit -m "submitted for grading"


