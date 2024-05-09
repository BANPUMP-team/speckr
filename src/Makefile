all : encrypt.o speckr.o encrypt
encrypt.o : encrypt.c speckr.h
	cc -c encrypt.c
speckr.o : speckr.c speckr.h
	cc -c speckr.c
encrypt : encrypt.c
	cc -Wall -o encrypt encrypt.c speckr.o -largon2
clean :
	rm -rf encrypt encrypt.o speckr.o 
