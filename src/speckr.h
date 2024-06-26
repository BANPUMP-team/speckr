#define SPECKR_ROUNDS 7 

/*
 * SpeckR context
 */
typedef struct {
	uint32_t it1, it2;
	uint32_t NL, NR;
	uint8_t Sbox1[256], Sbox2[256], Sbox3[256];
	uint8_t loop;
	uint32_t derived_key_r[26];
	uint32_t t_cost;      // 2-pass computation
	uint32_t m_cost;      // 64 mebibytes memory usage
	uint32_t parallelism; // number of threads and lanes
} speckr_ctx;

/*
 * SPECK reference implementation macro
 */
#define ROTL32(x,r) (((x)<<(r)) | (x>>(32-(r)))) 
#define ROTR32(x,r) (((x)>>(r)) | ((x)<<(32-(r)))) 

#define ER32(x,y,k) (x=ROTR32(x,8), x+=y, x^=k, y=ROTL32(y,3), y^=x) 
#define DR32(x,y,k) (y^=x, y=ROTR32(y,3), x^=k, x-=y, x=ROTL32(x,8)) 

void SpeckRKeySchedule(uint32_t K[],uint32_t rk[]);
void SpeckREncrypt(const uint32_t Pt[], uint32_t *Ct, speckr_ctx *CTX);

/*
 *  The _async() function is for encrypting out of order packets like UDP 
 *  We recommend fixed size for the packet_size to avoid repeating the counter
 *
 *  For now the *easy* way is to _reset_ctr() when new packet arrives in order
 *  to reset internal it1 and it2 Sbox counters. Counter mode counter is going
 *  to be overwritten by the provided parameters:
 *
 *  packet_no, packet_size and offset are provided by the caller and offset
 *  is incremented 8 bytes at a time (blocksize is 64 bits)
 *
 */
void SpeckREncrypt_async(const uint32_t Pt[], uint32_t *Ct, speckr_ctx *CTX, 
		uint64_t packet_no, uint64_t packet_size, uint64_t offset);

void speckr_init(speckr_ctx *CTX, const char *password);
/* copy CTX2 into CTX1 */
void speckr_ctx_dup(speckr_ctx *CTX1, speckr_ctx *CTX2);
void speckr_reset_ctr(speckr_ctx *CTX);

