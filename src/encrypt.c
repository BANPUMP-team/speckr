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
#include <ctype.h>

#include "speckr.h"

#define MAXPWDLEN 32

/*
 * cracklib is better for measuring weak passwords
 */

int isStrongPassword(const char *password) {
    int length = strlen(password);

    // Criteria for a strong password
    int hasUpper = 0;
    int hasLower = 0;
    int hasDigit = 0;
    int hasSpecial = 0;

    // Check each character of the password
    for (int i = 0; i < length; i++) {
        if (isupper(password[i])) {
            hasUpper = 1;
        } else if (islower(password[i])) {
            hasLower = 1;
        } else if (isdigit(password[i])) {
            hasDigit = 1;
        } else if (ispunct(password[i])) {
            hasSpecial = 1;
        }
    }

    // Password is strong if all criteria are met
    return length >= 10 && hasUpper && hasLower && hasDigit && hasSpecial;
}


int main(int argc, char *argv[]) {
    struct termios original,noecho;
    struct stat statbuf;
    speckr_ctx CTX;
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

    /* get original filesize */

    fsize = statbuf.st_size;

    /* read password without printing echo bytes on screen */

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

    if (!isStrongPassword(passwd)) {
	fprintf(stderr, "Weak password.\n Use uppercase, lowercase, digits and special chars -- at least 10 bytes long.\n");
	return (10);
    }	    

    /*
     * use argon2 to derive sboxes and initial internal states based on the given password
     * this stuff is stored in the speckr context "CTX" object including the expanded key
     */

    speckr_init(&CTX, passwd);
//    speckr_ctx_dup(&CTXcopy, &CTX); // not needed just an example

    
    /*
     *  open file for reading and writing 
     */

    fp = fopen(argv[1], "rb+");
    if (fp == NULL) {
	perror("fopen()");
	return 2;
    }

    clock_t t0 = clock();

    /*
     * read 64 bits, encrypt/decrypt, overwrite 64 bits
     */

    ret=8;
    while(ret==8) {
       if ((ret=fread(pt, 1, 8, fp))==0) { // read 64 bits
	    if (ferror(fp)) {
	            perror("fread()");
        	    exit(EXIT_FAILURE);
	    }
        }

       SpeckREncrypt(pt, ct, &CTX);

       fseek(fp, 0-ret, SEEK_CUR); /* prepare to overwrite plaintext 64 bits with ciphertext */

       if (fwrite(ct, 8, 1, fp)!=1) { /* overwrite 64 bits of ciphertext */
            perror("fwrite()");
            exit(EXIT_FAILURE);
        }

    }

    fclose(fp);

    /*
     * if we read less than 8 bytes because filesize is not a multiple of 64 bits
     * we need to truncate to original filesize since surplus encrypted bits are
     * not from the original plaintext but dummy bytes
     */

    if (truncate(argv[1], fsize) == -1) {
	perror("truncate()");
	exit(EXIT_FAILURE);
    }

    /*
     * some clock dummy measurement to get an idea
     */

    clock_t t1 = clock();    

    printf("Done (%Lf)\n", (long double)(t1 - t0));

    return 0;
}

