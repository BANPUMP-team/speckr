/*      (C) 2024 Alin-Adrian Anton <alin.anton@cs.upt.ro>, Petra Csereoka <petra.csereoka@cs.upt.ro>
 * 
 *      This program is free software: you can redistribute it and/or modify it under the terms of the 
 *      GNU General Public License as published by the Free Software Foundation,
 *      either version 3 of the License, or (at your option) any later version.
 *
 *      This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
 *      without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *      See the GNU General Public License for more details.
 *      You should have received a copy of the GNU General Public License along with this program. 
 *      If not, see <https://www.gnu.org/licenses/>. 
*/  

// Example of how to use

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>

#include "speckr.h"

#define MAXPWDLEN 32

int main(int argc, char *argv[]) {
    struct termios original,noecho;
    struct stat statbuf;
    speckr_ctx CTX, CTXcopy;
    uint32_t pt[2], ct[2];
    char passwd[MAXPWDLEN];
    size_t pwdlen;
    off_t fsize;
    FILE *fp;
    int ret;

    if (argc < 2) {
	fprintf(stderr, "Usage: %s filename\n", argv[0]);
	return 0;
    }

    if (stat(argv[1], &statbuf) == -1) {
	    perror("stat()");
	    return 1;
    }

    fsize = statbuf.st_size;

    tcgetattr(STDIN_FILENO,&original);
    noecho = original;
    noecho.c_lflag = noecho.c_lflag ^ ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &noecho);
    printf("Password: ");
    fgets(passwd, MAXPWDLEN, stdin);
    fprintf(stdout, "\n");
    pwdlen = strlen(passwd);
    passwd[pwdlen-1] = '\0';
    tcsetattr(STDIN_FILENO, TCSANOW, &original);
    
    speckr_init(&CTX, passwd);
    speckr_ctx_dup(&CTXcopy, &CTX);

    fp = fopen(argv[1], "r+");
    if (fp == NULL) {
	perror("fopen()");
	return 2;
    }

    clock_t t0 = clock();

    ret=8;
    while(ret==8) {
       if ((ret=fread(pt, 1, 8, fp))==0) { // read 64 bits
	    if (ferror(fp)) {
	            perror("fread()");
        	    exit(EXIT_FAILURE);
	    }
        }

       SpeckREncrypt(pt, ct, &CTX);

       fseek(fp, 0-ret, SEEK_CUR);

       if (fwrite(ct, 8, 1, fp)!=1) { // write 64 bits
            perror("fwrite()");
            exit(EXIT_FAILURE);
        }

    }

    fclose(fp);
    if (truncate(argv[1], fsize) == -1) {
	perror("truncate()");
	exit(EXIT_FAILURE);
    }

    clock_t t1 = clock();    

    printf("Done (%Lf)\n", (long double)(t1 - t0));

  
    return 0;
}

