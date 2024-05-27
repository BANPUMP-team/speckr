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

// Textline encryption example

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
#define MAXLINESIZE 8192 // jumbo frames multiple of 8 bytes


// Helper function to extract a specific byte from a multi-byte value
// regardless of system's endianness (assuming big-endian processing)
uint8_t get_byte(uint32_t value, size_t index) {
  return (value >> (8 * (3 - index))) & 0xFF;
}


// Function to convert a string to blocks
void string_to_blocks(const char *input, size_t input_len, uint32_t *blocks,
                      size_t *num_blocks) {
  size_t i, j;
  size_t num_full_blocks = input_len / 4;
  size_t remaining_bytes = input_len % 4;

  *num_blocks = num_full_blocks + (remaining_bytes > 0 ? 1 : 0);

  for (i = 0; i < num_full_blocks; i++) {
    blocks[i] = 0;
    for (j = 0; j < 4; j++) {
      blocks[i] = (blocks[i] << 8) | (uint8_t)input[i * 4 + j];
    }
  }

  if (remaining_bytes > 0) {
    blocks[*num_blocks - 1] = 0;
    for (j = 0; j < remaining_bytes; j++) {
      blocks[*num_blocks - 1] = (blocks[*num_blocks - 1] << 8) |
                                (uint8_t)input[num_full_blocks * 4 + j];
    }
  }
}

// Function to convert blocks back to string with big-endian processing
void blocks_to_string(const uint32_t *blocks, size_t num_blocks, char *output,
                      size_t *output_len) {
  size_t i, j;
  size_t output_index = 0;
  size_t remaining_bytes = num_blocks * 4;

  *output_len = remaining_bytes;
  output[*output_len] = '\0';  // Null terminate the output string

  for (i = 0; i < num_blocks; i++) {
    for (j = 0; j < 4 && output_index < *output_len; j++) {
      uint8_t byte = get_byte(blocks[i], j);
      if (byte) {
        output[output_index++] = byte;
      }
    }
  }
}


int main(int argc, char *argv[]) {
    struct termios original,noecho; /* this is for reading password with no echo on screen */
    speckr_ctx CTX;
    uint32_t pt[2], ct[2]; /* plaintext is 64 bits, ciphertext is 64 bits, key will be derived from passwd: 96 bits */
    char passwd[MAXPWDLEN];
    size_t pwdlen, input_len=0, num_blocks;
    char msg[MAXLINESIZE];
    uint32_t ct_blocks[MAXLINESIZE*2/8], pt_blocks[MAXLINESIZE*2/8]; // multiple of 8
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
    
    printf("Enter message to be encrypted (textline):\n");
    fgets(msg, MAXLINESIZE, stdin);
    input_len = strlen(msg);

    string_to_blocks(msg, input_len, pt_blocks, &num_blocks);

    printf("Number of blocks is %zu\n", num_blocks);

    // Print unencrypted blocks
    printf("Unencrypted Blocks:\n");
    for (size_t i = 0; i < num_blocks; i++) {
        printf("%08x ", pt_blocks[i]);
    }
    printf("\n");

    /* first call encrypts pt into ct using the key from CTX */

    // Encrypt each block
    for (size_t i = 0; i < num_blocks; i += 2) {
    	pt[0] = pt_blocks[i];
    	pt[1] = pt_blocks[i+1];   
        SpeckREncrypt(pt, ct, &CTX);
	ct_blocks[i] = ct[0];
	ct_blocks[i+1] = ct[1];
    }

   // Print blocks
    printf("Encrypted Blocks:\n");
    for (size_t i = 0; i < num_blocks; i++) {
        printf("%08x ", ct_blocks[i]);
    }
    printf("\n");

    speckr_reset_ctr(&CTX);

    // second call decrypts ct into pt using the key from CTX 
  

      // Decrypt each block
    for (size_t i = 0; i < num_blocks; i += 2) {
    	ct[0] = ct_blocks[i];
    	ct[1] = ct_blocks[i+1];    
        SpeckREncrypt(ct, pt, &CTX);
	pt_blocks[i] = pt[0];
	pt_blocks[i+1] = pt[1];

    }

    // Print encrypted blocks
    printf("Decrypted Blocks:\n");
    for (size_t i = 0; i < num_blocks; i++) {
        printf("%08x ", pt_blocks[i]);
    }
    printf("\n");
    
    msg[0] = 0;
    // Convert decrypted blocks back to string
    blocks_to_string(pt_blocks, num_blocks, msg, &input_len);
    printf("Decrypted and reconstructed string: %s\n", msg);
    
    return 0;
}


