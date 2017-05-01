#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <SDL.h>
#include <string.h>
#include <openssl/md5.h>

// ADD CITATION PLEASE!!!! CARTOONIFY AND PASSWORD CRACKER AND THIS RANDOM
// ASS https://github.com/majidgolshadi/Compute-MD5-with-CPU-and-GPU-CUDA/blob/master/md5.h

#define THREADS_PER_BLOCK 72
#define LENGTH 8
#define NUM_CHAR 36

typedef unsigned int GPU_MD5_u32plus;
 
typedef struct {
	GPU_MD5_u32plus lo, hi;
	GPU_MD5_u32plus a, b, c, d;
	unsigned char buffer[64];
	GPU_MD5_u32plus block[16];
} GPU_MD5_CTX;
 
//extern void MD5_Init(MD5_CTX *ctx);
//extern void MD5_Update(MD5_CTX *ctx, const void *data, unsigned long size);
//extern void MD5_Final(unsigned char *result, MD5_CTX *ctx);
/*
 * The basic MD5 functions.
 *
 * F and G are optimized compared to their RFC 1321 definitions for
 * architectures that lack an AND-NOT instruction, just like in Colin Plumb's
 * implementation.
 */
#define F(x, y, z)			((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z)			((y) ^ ((z) & ((x) ^ (y))))
#define H(x, y, z)			(((x) ^ (y)) ^ (z))
#define H2(x, y, z)			((x) ^ ((y) ^ (z)))
#define I(x, y, z)			((y) ^ ((x) | ~(z)))
 
/*
 * The MD5 transformation for all four rounds.
 */
#define STEP(f, a, b, c, d, x, t, s) \
	(a) += f((b), (c), (d)) + (x) + (t); \
	(a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s)))); \
	(a) += (b);
 
/*
 * SET reads 4 input bytes in little-endian byte order and stores them in a
 * properly aligned word in host byte order.
 *
 * The check for little-endian architectures that tolerate unaligned memory
 * accesses is just an optimization.  Nothing will break if it fails to detect
 * a suitable architecture.
 *
 * Unfortunately, this optimization may be a C strict aliasing rules violation
 * if the caller's data buffer has effective type that cannot be aliased by
 * MD5_u32plus.  In practice, this problem may occur if these MD5 routines are
 * inlined into a calling function, or with future and dangerously advanced
 * link-time optimizations.  For the time being, keeping these MD5 routines in
 * their own translation unit avoids the problem.
 */
#if defined(__i386__) || defined(__x86_64__) || defined(__vax__)
#define SET(n) \
	(*(GPU_MD5_u32plus *)&ptr[(n) * 4])
#define GET(n) \
	SET(n)
#else
#define SET(n) \
	(ctx->block[(n)] = \
	(GPU_MD5_u32plus)ptr[(n) * 4] | \
	((GPU_MD5_u32plus)ptr[(n) * 4 + 1] << 8) | \
	((GPU_MD5_u32plus)ptr[(n) * 4 + 2] << 16) | \
	((GPU_MD5_u32plus)ptr[(n) * 4 + 3] << 24))
#define GET(n) \
	(ctx->block[(n)])
#endif
 
/*
 * This processes one or more 64-byte data blocks, but does NOT update the bit
 * counters.  There are no alignment requirements.
 */


__device__ static const void *body(GPU_MD5_CTX *ctx, const void *data, unsigned long size)
{
	const unsigned char *ptr;
	GPU_MD5_u32plus a, b, c, d;
	GPU_MD5_u32plus saved_a, saved_b, saved_c, saved_d;
 
	ptr = (const unsigned char *)data;
 
	a = ctx->a;
	b = ctx->b;
	c = ctx->c;
	d = ctx->d;
 
	do {
		saved_a = a;
		saved_b = b;
		saved_c = c;
		saved_d = d;
 
/* Round 1 */
		STEP(F, a, b, c, d, SET(0), 0xd76aa478, 7)
		STEP(F, d, a, b, c, SET(1), 0xe8c7b756, 12)
		STEP(F, c, d, a, b, SET(2), 0x242070db, 17)
		STEP(F, b, c, d, a, SET(3), 0xc1bdceee, 22)
		STEP(F, a, b, c, d, SET(4), 0xf57c0faf, 7)
		STEP(F, d, a, b, c, SET(5), 0x4787c62a, 12)
		STEP(F, c, d, a, b, SET(6), 0xa8304613, 17)
		STEP(F, b, c, d, a, SET(7), 0xfd469501, 22)
		STEP(F, a, b, c, d, SET(8), 0x698098d8, 7)
		STEP(F, d, a, b, c, SET(9), 0x8b44f7af, 12)
		STEP(F, c, d, a, b, SET(10), 0xffff5bb1, 17)
		STEP(F, b, c, d, a, SET(11), 0x895cd7be, 22)
		STEP(F, a, b, c, d, SET(12), 0x6b901122, 7)
		STEP(F, d, a, b, c, SET(13), 0xfd987193, 12)
		STEP(F, c, d, a, b, SET(14), 0xa679438e, 17)
		STEP(F, b, c, d, a, SET(15), 0x49b40821, 22)
 
/* Round 2 */
		STEP(G, a, b, c, d, GET(1), 0xf61e2562, 5)
		STEP(G, d, a, b, c, GET(6), 0xc040b340, 9)
		STEP(G, c, d, a, b, GET(11), 0x265e5a51, 14)
		STEP(G, b, c, d, a, GET(0), 0xe9b6c7aa, 20)
		STEP(G, a, b, c, d, GET(5), 0xd62f105d, 5)
		STEP(G, d, a, b, c, GET(10), 0x02441453, 9)
		STEP(G, c, d, a, b, GET(15), 0xd8a1e681, 14)
		STEP(G, b, c, d, a, GET(4), 0xe7d3fbc8, 20)
		STEP(G, a, b, c, d, GET(9), 0x21e1cde6, 5)
		STEP(G, d, a, b, c, GET(14), 0xc33707d6, 9)
		STEP(G, c, d, a, b, GET(3), 0xf4d50d87, 14)
		STEP(G, b, c, d, a, GET(8), 0x455a14ed, 20)
		STEP(G, a, b, c, d, GET(13), 0xa9e3e905, 5)
		STEP(G, d, a, b, c, GET(2), 0xfcefa3f8, 9)
		STEP(G, c, d, a, b, GET(7), 0x676f02d9, 14)
		STEP(G, b, c, d, a, GET(12), 0x8d2a4c8a, 20)
 
/* Round 3 */
		STEP(H, a, b, c, d, GET(5), 0xfffa3942, 4)
		STEP(H2, d, a, b, c, GET(8), 0x8771f681, 11)
		STEP(H, c, d, a, b, GET(11), 0x6d9d6122, 16)
		STEP(H2, b, c, d, a, GET(14), 0xfde5380c, 23)
		STEP(H, a, b, c, d, GET(1), 0xa4beea44, 4)
		STEP(H2, d, a, b, c, GET(4), 0x4bdecfa9, 11)
		STEP(H, c, d, a, b, GET(7), 0xf6bb4b60, 16)
		STEP(H2, b, c, d, a, GET(10), 0xbebfbc70, 23)
		STEP(H, a, b, c, d, GET(13), 0x289b7ec6, 4)
		STEP(H2, d, a, b, c, GET(0), 0xeaa127fa, 11)
		STEP(H, c, d, a, b, GET(3), 0xd4ef3085, 16)
		STEP(H2, b, c, d, a, GET(6), 0x04881d05, 23)
		STEP(H, a, b, c, d, GET(9), 0xd9d4d039, 4)
		STEP(H2, d, a, b, c, GET(12), 0xe6db99e5, 11)
		STEP(H, c, d, a, b, GET(15), 0x1fa27cf8, 16)
		STEP(H2, b, c, d, a, GET(2), 0xc4ac5665, 23)
 
/* Round 4 */
		STEP(I, a, b, c, d, GET(0), 0xf4292244, 6)
		STEP(I, d, a, b, c, GET(7), 0x432aff97, 10)
		STEP(I, c, d, a, b, GET(14), 0xab9423a7, 15)
		STEP(I, b, c, d, a, GET(5), 0xfc93a039, 21)
		STEP(I, a, b, c, d, GET(12), 0x655b59c3, 6)
		STEP(I, d, a, b, c, GET(3), 0x8f0ccc92, 10)
		STEP(I, c, d, a, b, GET(10), 0xffeff47d, 15)
		STEP(I, b, c, d, a, GET(1), 0x85845dd1, 21)
		STEP(I, a, b, c, d, GET(8), 0x6fa87e4f, 6)
		STEP(I, d, a, b, c, GET(15), 0xfe2ce6e0, 10)
		STEP(I, c, d, a, b, GET(6), 0xa3014314, 15)
		STEP(I, b, c, d, a, GET(13), 0x4e0811a1, 21)
		STEP(I, a, b, c, d, GET(4), 0xf7537e82, 6)
		STEP(I, d, a, b, c, GET(11), 0xbd3af235, 10)
		STEP(I, c, d, a, b, GET(2), 0x2ad7d2bb, 15)
		STEP(I, b, c, d, a, GET(9), 0xeb86d391, 21)
 
		a += saved_a;
		b += saved_b;
		c += saved_c;
		d += saved_d;
 
		ptr += 64;
	} while (size -= 64);
 
	ctx->a = a;
	ctx->b = b;
	ctx->c = c;
	ctx->d = d;
 
	return ptr;
}
 
__device__ void GPU_MD5_Init(GPU_MD5_CTX *ctx)
{
	ctx->a = 0x67452301;
	ctx->b = 0xefcdab89;
	ctx->c = 0x98badcfe;
	ctx->d = 0x10325476;
 
	ctx->lo = 0;
	ctx->hi = 0;
}
 
__device__ void GPU_MD5_Update(GPU_MD5_CTX *ctx, const void *data, unsigned long size)
{
        GPU_MD5_u32plus saved_lo;
	unsigned long used, available;
 
	saved_lo = ctx->lo;
	if ((ctx->lo = (saved_lo + size) & 0x1fffffff) < saved_lo)
		ctx->hi++;
	ctx->hi += size >> 29;
 
	used = saved_lo & 0x3f;
 
	if (used) {
		available = 64 - used;
 
		if (size < available) {
			memcpy(&ctx->buffer[used], data, size);
			return;
		}
 
		memcpy(&ctx->buffer[used], data, available);
		data = (const unsigned char *)data + available;
		size -= available;
		body(ctx, ctx->buffer, 64);
	}
 
	if (size >= 64) {
		data = body(ctx, data, size & ~(unsigned long)0x3f);
		size &= 0x3f;
	}
 
	memcpy(ctx->buffer, data, size);
}
 
#define OUT(dst, src) \
	(dst)[0] = (unsigned char)(src); \
	(dst)[1] = (unsigned char)((src) >> 8); \
	(dst)[2] = (unsigned char)((src) >> 16); \
	(dst)[3] = (unsigned char)((src) >> 24);
 
__device__ void GPU_MD5_Final(unsigned char *result, GPU_MD5_CTX *ctx)
{
	unsigned long used, available;
 
	used = ctx->lo & 0x3f;
 
	ctx->buffer[used++] = 0x80;
 
	available = 64 - used;
 
	if (available < 8) {
		memset(&ctx->buffer[used], 0, available);
		body(ctx, ctx->buffer, 64);
		used = 0;
		available = 64;
	}
 
	memset(&ctx->buffer[used], 0, available - 8);
 
	ctx->lo <<= 3;
	OUT(&ctx->buffer[56], ctx->lo)
	OUT(&ctx->buffer[60], ctx->hi)
 
	body(ctx, ctx->buffer, 64);
 
	OUT(&result[0], ctx->a)
	OUT(&result[4], ctx->b)
	OUT(&result[8], ctx->c)
	OUT(&result[12], ctx->d)
 
	memset(ctx, 0, sizeof(*ctx));
}


 

__global__ void kernal(char* password, uint8_t* hash) {

  char passwordone[9] = "password";
  
  //Initialize the MD5 context
  GPU_MD5_CTX context;
  GPU_MD5_Init(&context);

  //add our data to MD5
  GPU_MD5_Update(&context, passwordone, LENGTH);

  //Finish
  uint8_t output[MD5_DIGEST_LENGTH];
  GPU_MD5_Final(output, &context);

  for(size_t i=0; i<MD5_DIGEST_LENGTH; i++) {
    printf("%x", output[i]);
  }
  printf("\n");
}

int main() {
  char password[9] = "password";
  uint8_t testHash[MD5_DIGEST_LENGTH];
  MD5((unsigned char*) password, LENGTH, testHash);
  //printf("CPU calc: %u\n", testHash);

  for(size_t i=0; i<MD5_DIGEST_LENGTH; i++) {
    printf("%hhx", testHash[i]);
  }
  printf("\n");
  
  uint8_t* gpu_hash;
  if(cudaMalloc(&gpu_hash, sizeof(uint8_t) * MD5_DIGEST_LENGTH) != cudaSuccess) {
    fprintf(stderr, "Failed to allocate memory for gpu hash\n");
    exit(2);
  }

  char* gpu_password;
  if(cudaMalloc(&gpu_password, sizeof(char)* LENGTH+1) != cudaSuccess) {
    fprintf(stderr, "Failed to allocate memory for password\n");
    exit(2);
  }
  
  if(cudaMemcpy(gpu_password, password, sizeof(char) * LENGTH+1,  cudaMemcpyHostToDevice) != cudaSuccess) {
  fprintf(stderr, "Failed to copy password to the GPU\n");
  }

  
  kernal<<<1,1>>>(gpu_password, gpu_hash);

  if(cudaDeviceSynchronize() != cudaSuccess){
      fprintf(stderr, "the error came from inside the kernel...comes back\n");
      fprintf(stderr, "%s\n", cudaGetErrorString(cudaPeekAtLastError()));
      }
}
