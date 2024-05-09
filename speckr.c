/*
 *      Speck-R implementation based on https://link.springer.com/article/10.1007/s11042-020-09625-8
 *      adjusted with RC4D_KSA from https://link.springer.com/chapter/10.1007/978-3-030-64758-2_2
 *
 *      Uses functions and macros from the NSA implementation guide.
 *
 *      (C) 2024 Alin-Adrian Anton <alin.anton@cs.upt.ro>, Petra Csereoka <petra.csereoka@cs.upt.ro>
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

#include <argon2.h> /* libargon2 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "speckr.h"

//#include "blake3.h" for hashing the file or payload

#define ARGON_HASHLEN 32
#define ARGON_SALTLEN 16

/* 
 * RC4D_KSA is from https://link.springer.com/chapter/10.1007/978-3-030-64758-2_2
 */
void RC4D_KSA(uint8_t k[], uint8_t L, uint8_t *S) {
    int i,j=0;
    uint8_t aux;

    for (i=0; i<256; i++) S[i] = i;

    j = 0;
    for (i=0; i<256; i++) {
        j = (j + S[(i + k[i % L]) % 256] + k[i % L]) % 256;
	    aux=S[i]; S[i]=S[j]; S[j]=aux;
    }
}

void SpeckRKeySchedule(uint32_t K[],uint32_t rk[]) // SPECK reference implementation
{
    uint32_t i,C=K[2],B=K[1],A=K[0];
  
    for(i=0;i<26;){
        rk[i]=A; ER32(B,A,i++);
        rk[i]=A; ER32(C,A,i++);
    }
}

void copy_bytes_to_uint32(const uint8_t *source, uint32_t *destination, size_t elements) {
    typedef union {
        uint32_t value;
	uint8_t parts[4];
    } CopyUnion;
	
    for (size_t i = 0; i < elements; ++i) {
        CopyUnion u;

	for (int j = 0; j < 4; ++j) {
	    u.parts[j] = source[i * 4 + j]; // Copy 4 bytes at a time
	}

	destination[i] = u.value;
    }
}

void split_uint64_to_uint32(uint64_t input, uint32_t *low, uint32_t *high) {
    *low = (uint32_t)(input & 0xFFFFFFFF);
    *high = (uint32_t)(input >> 32);
}


void speckr_init(speckr_ctx *CTX, const char *password) {
    int i;
    uint8_t *pwd = (uint8_t *)password;
    uint32_t pwdlen;
    uint32_t derived_key[3];
    uint8_t hash[ARGON_HASHLEN];
    uint8_t salt[ARGON_SALTLEN];
    uint8_t K[12]; 

    CTX->NL = 0; 
    CTX->NR = 0; 
    CTX->it1 = 0; 
    CTX->it2 = 0; 
    CTX->loop = 0; 

    memset(salt, 0x00, ARGON_SALTLEN);
    pwdlen = strlen((char *)pwd); 

    CTX->t_cost = 20;           // 2-pass computation
    CTX->m_cost = (1<<16);      // 64 mebibytes memory usage
    CTX->parallelism = 1;       // number of threads and lanes
			   
    argon2i_hash_raw(CTX->t_cost, CTX->m_cost, CTX->parallelism, pwd, pwdlen, salt, ARGON_SALTLEN, hash, ARGON_HASHLEN);
    copy_bytes_to_uint32(hash, derived_key, 3); // 3 * 32 = 96 bits

    SpeckRKeySchedule(derived_key, CTX->derived_key_r);

    for (i=0;i<12;i++) K[i]=hash[i+12];
    RC4D_KSA(K, 12, CTX->Sbox1);

    argon2i_hash_raw(CTX->t_cost, CTX->m_cost, CTX->parallelism, hash, ARGON_HASHLEN, salt, ARGON_SALTLEN, hash, ARGON_HASHLEN);

    for (i=0;i<12;i++) K[i]=hash[i+12];
    RC4D_KSA(K, 12, CTX->Sbox2);

    argon2i_hash_raw(CTX->t_cost, CTX->m_cost, CTX->parallelism, hash, ARGON_HASHLEN, salt, ARGON_SALTLEN, hash, ARGON_HASHLEN);

    for (i=0;i<12;i++) K[i]=hash[i+12];
    RC4D_KSA(K, 12, CTX->Sbox3);
}

/* copy CTX2 into CTX1 */
void speckr_ctx_dup(speckr_ctx *CTX1, speckr_ctx *CTX2) {
    int i;

    CTX1->NL = CTX2->NL; 
    CTX1->NR = CTX2->NR; 
    CTX1->it1 = CTX2->it1; 
    CTX1->it2 = CTX2->it2; 
    CTX1->loop = CTX2->loop;
    CTX1->t_cost = CTX2->t_cost;      // 2-pass computation
    CTX1->m_cost = CTX2->m_cost;      // 64 mebibytes memory usage
    CTX1->parallelism = CTX2->parallelism; // number of threads and lanes
    for (i=0;i<256;i++) CTX1->Sbox1[i] = CTX2->Sbox1[i];
    for (i=0;i<256;i++) CTX1->Sbox2[i] = CTX2->Sbox2[i];
    for (i=0;i<256;i++) CTX1->Sbox3[i] = CTX2->Sbox3[i];
    for (i=0;i<26;i++) CTX1->derived_key_r[i] = CTX2->derived_key_r[i];
}

void speckr_reset_ctr(speckr_ctx *CTX) {
    CTX->NL = 0; 
    CTX->NR = 0; 
    CTX->it1 = 0; 
    CTX->it2 = 0; 
    CTX->loop = 0; 
}

void SpeckREncrypt(const uint32_t Pt[], uint32_t *Ct, speckr_ctx *CTX) { 
    uint32_t i, aux;
    uint32_t x, y;
    uint32_t wbuf[2];

    x = CTX->NL; 
    y = CTX->NR;
    wbuf[1] = x; 
    wbuf[0] = y;

    Ct[0] = (wbuf[0] << 24) | (wbuf[0] >> 24) | ((wbuf[0] << 8) & 0xFF0000) | ((wbuf[0] >> 8) & 0xFF00); // y
    Ct[1] = (wbuf[1] << 24) | (wbuf[1] >> 24) | ((wbuf[1] << 8) & 0xFF0000) | ((wbuf[1] >> 8) & 0xFF00); // x
    
    for(i = 0; i < SPECKR_ROUNDS; i++) {
        ER32(Ct[1], Ct[0], CTX->derived_key_r[i + CTX->loop]);
    } // end of rounds loop

    x = Ct[1]; 
    y = Ct[0];
    
    /* 
     * without the following swap, in the case of out-of-sequence packets (ie. on-the-fly UDP decryption) 
     * set SPECKR_ROUNDS to 26 and rehash the password after 4 Gb and set CTX->NR counter to packet_no x slice_size + 8 x offset
     */
    aux = x; 
    x = y; 
    y = aux;

    CTX->NR++; 

    y = CTX->Sbox1[y >> 24 & 0xFF] << 24 | CTX->Sbox1[y >> 16 & 0xFF] << 16 | CTX->Sbox1[y >> 8 & 0xFF] << 8 | CTX->Sbox1[y & 0xFF];
    Ct[0] ^= y ^ Pt[0];

    x = CTX->Sbox1[x >> 24 & 0xFF] << 24 | CTX->Sbox1[x >> 16 & 0xFF] << 16 | CTX->Sbox1[x >> 8 & 0xFF] << 8 | CTX->Sbox1[x & 0xFF];
    Ct[1] ^= x ^ Pt[1];

    // Update Sbox substitution operation follows
    CTX->it1++; 
    CTX->it2++;
    if (CTX->it1 == 2000) {
        for (i = 0; i < 256; i++) 
            CTX->Sbox1[i] = CTX->Sbox2[CTX->Sbox1[i]];
        CTX->it1 = 0;
        if (CTX->it2 == 2000 * 2000) {
            for (i = 0; i < 256; i++) 
                CTX->Sbox2[i] = CTX->Sbox3[CTX->Sbox2[i]];
            CTX->it2 = 0;
        }
    }

    CTX->loop = (CTX->loop + SPECKR_ROUNDS) % (25 - SPECKR_ROUNDS);
}

/*
 *  This function is for encrypting out of order packets like UDP 
 *
 *  packet_no, packet_size and offset are provided by the caller and offset is incremented 8 bytes at a time (blocksize is 64 bits)
 */

void SpeckREncrypt_packet(const uint32_t Pt[], uint32_t *Ct, speckr_ctx *CTX, off_t packet_no, size_t packet_size, off_t offset) { 
    uint32_t i;
    uint32_t x, y;
    uint32_t wbuf[2];
    uint64_t datasize;


    datasize = packet_no * packet_size + 8 * offset; // 64 bits at a time
    split_uint64_to_uint32(datasize, &CTX->NR, &CTX->NL);

    x = CTX->NL; 
    y = CTX->NR;
    wbuf[1] = x; 
    wbuf[0] = y;

    Ct[0] = (wbuf[0] << 24) | (wbuf[0] >> 24) | ((wbuf[0] << 8) & 0xFF0000) | ((wbuf[0] >> 8) & 0xFF00); // y
    Ct[1] = (wbuf[1] << 24) | (wbuf[1] >> 24) | ((wbuf[1] << 8) & 0xFF0000) | ((wbuf[1] >> 8) & 0xFF00); // x
    
    for(i = 0; i < 26; i++) {
        ER32(Ct[1], Ct[0], CTX->derived_key_r[i]);
    } // end of rounds loop

    x = Ct[1]; 
    y = Ct[0];
    
    y = CTX->Sbox1[y >> 24 & 0xFF] << 24 | CTX->Sbox1[y >> 16 & 0xFF] << 16 | CTX->Sbox1[y >> 8 & 0xFF] << 8 | CTX->Sbox1[y & 0xFF];
    Ct[0] ^= y ^ Pt[0];

    x = CTX->Sbox1[x >> 24 & 0xFF] << 24 | CTX->Sbox1[x >> 16 & 0xFF] << 16 | CTX->Sbox1[x >> 8 & 0xFF] << 8 | CTX->Sbox1[x & 0xFF];
    Ct[1] ^= x ^ Pt[1];

    // Update Sbox substitution operation follows
    CTX->it1++; 
    CTX->it2++;
    if (CTX->it1 == 2000) {
        for (i = 0; i < 256; i++) 
            CTX->Sbox1[i] = CTX->Sbox2[CTX->Sbox1[i]];
        CTX->it1 = 0;
        if (CTX->it2 == 2000 * 2000) {
            for (i = 0; i < 256; i++) 
                CTX->Sbox2[i] = CTX->Sbox3[CTX->Sbox2[i]];
            CTX->it2 = 0;
        }
    }

    /* 
     * without the following swap, in the case of out-of-sequence packets (ie. on-the-fly UDP decryption) 
     * set SPECKR_ROUNDS to 26 and rehash the password after 4 Gb and set CTX->NR counter to packet_no x slice_size + 8 x offset
     */
}

