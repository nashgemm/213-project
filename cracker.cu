#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <SDL.h>
#include <openssl/md5.h>

#define THREADS_PER_BLOCK 72
#define LENGTH 8
#define NUM_CHAR 36
/*
__device__ void md5Calc(char* password, uint8_t* md5Password) {
  MD5((unsigned char*) password, LENGTH, md5Password);
}
*/

__global__ void singleCheck(uint8_t* testHash, bool* checker) {
  printf("In the kernal!\n");
  char password[LENGTH+1];
  password[0] = threadIdx.x % NUM_CHAR;
  password[1] = blockIdx.x*2 + (threadIdx.x / NUM_CHAR);
  password[2] = (blockIdx.x / 18) % NUM_CHAR;
  password[3] = (blockIdx.x / 648) % NUM_CHAR;
  password[4] = (blockIdx.x / 23328) % NUM_CHAR;
  password[5] = (blockIdx.x / 839808) % NUM_CHAR;
  password[6] = (blockIdx.x / 30233088) % NUM_CHAR;
  password[7] = blockIdx.x / 108839168;
  password[8] = '\0';
  if (password[6] == 'r') {
  printf("%s\n", password);
  }
  /*
  uint8_t md5Password[MD5_DIGEST_LENGTH+1];
  md5Calc(password, md5Password);
  if (!(*checker) && memcmp(md5Password, testHash, MD5_DIGEST_LENGTH) == 0) {
     *checker = true;
  }*/
}

int main() {
  char testPassword[LENGTH];
  uint8_t testHash[MD5_DIGEST_LENGTH+1];
  bool* checker = (bool*)malloc(sizeof(bool));;
  *checker = false;

  uint8_t* gpu_testHash;
  bool* gpu_checker;

  if(cudaMalloc(&gpu_testHash, sizeof(uint8_t)* MD5_DIGEST_LENGTH+1) != cudaSuccess) {
    fprintf(stderr, "Failed to allocate memory for testHash\n");
    exit(2);
  }

  if(cudaMalloc(&gpu_checker, sizeof(bool)) != cudaSuccess) {
    fprintf(stderr, "Failed to allocate memory for checker\n");
    exit(2);
  }

  if(cudaMemcpy(gpu_testHash, testHash, sizeof(uint8_t) * MD5_DIGEST_LENGTH+1,  cudaMemcpyHostToDevice) != cudaSuccess) {
  fprintf(stderr, "Failed to copy testHash to the GPU\n");
  }

  if(cudaMemcpy(gpu_checker, checker, sizeof(bool),  cudaMemcpyHostToDevice) != cudaSuccess) {
  fprintf(stderr, "Failed to copy checker to the GPU\n");
  }
  
  printf("Enter in your test password: ");
  scanf("%s", testPassword);
  //MD5((unsigned char*) testPassword, LENGTH, testHash);
  
  //maybe make sure that's the number of blocks we want?
  size_t NUM_BLOCKS = pow(NUM_CHAR, LENGTH)/THREADS_PER_BLOCK;
  singleCheck<<<NUM_BLOCKS,NUM_CHAR*2>>>(gpu_testHash, gpu_checker);
  cudaDeviceSynchronize();
  if (*gpu_checker) {
    printf("found the password\n");
  }
  return 0;
}
