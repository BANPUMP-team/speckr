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

// Trivial example of how to use

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

int main(void) {
    struct termios original,noecho; /* this is for reading password with no echo on screen */
    speckr_ctx CTX;
    uint32_t pt[2], ct[2]; /* plaintext is 64 bits, ciphertext is 64 bits, key will be derived from passwd: 96 bits */
    char passwd[MAXPWDLEN];
    size_t pwdlen;

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

    /*
     * use argon2 to derive sboxes and initial internal states based on the given password
     * this stuff is stored in the speckr context "CTX" object including the expanded key
     */

    speckr_init(&CTX, passwd);
    
    pt[0] = 1234; pt[1] = 5678;
    ct[0] = 0; ct[1] = 0;

    /* first call encrypts pt into ct using the key from CTX */

    SpeckREncrypt(pt, ct, &CTX);

    printf("After encryption: ct[0] = %u ct[1] = %u\n", ct[0], ct[1]);

    /*
     * IMPORTANT for decryption the internal states except sboxes and key need to be reset
     * so use speckr_reset_ctr to restart everything and decrypt with the same password
     * or feel free to make a copy of the original CTX or initialize another CTX with the same password
     */

    speckr_reset_ctr(&CTX);

    /* second call decrypts ct into pt using the key from CTX */
  
    pt[0] = 0; pt[1] = 0;

    SpeckREncrypt(ct, pt, &CTX);

    printf("After decryption: pt[0] = %u pt[1] = %u\n", pt[0], pt[1]);
    
    return 0;
}

