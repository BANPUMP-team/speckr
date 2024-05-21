all : encrypt.o speckr.o trivialexample encrypt
encrypt.o : encrypt.c speckr.h
	cc -c encrypt.c
speckr.o : speckr.c speckr.h
	cc -c speckr.c
encrypt : encrypt.c
	cc -Wall -o encrypt encrypt.c speckr.o -largon2
trivialexample : trivialexample.c
	cc -Wall -o trivialexample trivialexample.c speckr.o -largon2
clean :
	rm -rf encrypt trivialexample encrypt.o speckr.o 
