#include <stdio.h>
#include <stdbool.h>
#include <openssl/md5.h>

#define THREADS_PER_BLOCK 64
#define LENGTH 8
#define NUM_CHAR 36

__device__ void md5-calc(char* passGuess, char* guessHash) {
  
}

__global__ void singleCheck(unint8_t* endGoal, bool* checker) {
  char password[LENGTH];
  password[0] = ThreadIdx.x % NUM_CHAR;
  password[1] BlockIdx.x*2 + (ThreadIdx.x / NUM_CHAR)
  password[2] = (BlockIdx.x / 18) % NUM_CHAR;
  password[3] = (BlockIdx.x / 648) % NUM_CHAR;
  password[4] = (BlockIdx.x / 23328) % NUM_CHAR;
  password[5] = (BlockIdx.x / 839808) % NUM_CHAR;
  password[6] = (BlockIdx.x / 30233088) % NUM_CHAR;
  password[7] = BlockIdx.x / 108839168;
  
  uint8_t ciphertext[MD5_DIGEST_LENGTH+1];
  MD5((unsigned char*) password, LENGTH, ciphertext);
  if (!(*checker) && memcmp(ciphertext, endGoal, MD5_DIGEST_LENGTH) == 0) {
  checker = true;
  }
}

int main() {
  kernel<<<1,1>>>();
  cudaDeviceSynchronize();
  return 0;
}
