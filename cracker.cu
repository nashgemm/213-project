#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <SDL.h>
#include <string.h>
#include <openssl/md5.h>
#include <sys/time.h>
#include <time.h>

/*
 * 213 Project: Password Cracking on the GPU
 * Team Members: Ajuna Kyaruzi, Gemma Nash and Kathryn Yetter
 *
 * Citation:
 * We got the GPU MD5 code from: 
 http://openwall.info/wiki/people/solar/software/public-domain-source-code/md5
 * We looked over the code from the Password Cracker labs. 
 * Our previous partners were Mattori, Clara and Adam
 * Charlie, Medha and Maddy were great helps in debugging our program
 */ 

#define THREADS_PER_BLOCK 72
#define LENGTH 8
#define NUM_CHAR 36

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
#define STEP(f, a, b, c, d, x, t, s)                            \
  (a) += f((b), (c), (d)) + (x) + (t);                          \
  (a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s))));    \
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
#define SET(n)                                  \
  (*(GPU_MD5_u32plus *)&ptr[(n) * 4])
#define GET(n)                                  \
  SET(n)
#else
#define SET(n)                                  \
  (ctx->block[(n)] =                            \
   (GPU_MD5_u32plus)ptr[(n) * 4] |              \
   ((GPU_MD5_u32plus)ptr[(n) * 4 + 1] << 8) |   \
   ((GPU_MD5_u32plus)ptr[(n) * 4 + 2] << 16) |  \
   ((GPU_MD5_u32plus)ptr[(n) * 4 + 3] << 24))
#define GET(n)                                  \
  (ctx->block[(n)])
#endif

#define OUT(dst, src)                           \
  (dst)[0] = (unsigned char)(src);              \
  (dst)[1] = (unsigned char)((src) >> 8);       \
  (dst)[2] = (unsigned char)((src) >> 16);      \
  (dst)[3] = (unsigned char)((src) >> 24);

typedef unsigned int GPU_MD5_u32plus;
 
typedef struct {
  GPU_MD5_u32plus lo, hi;
  GPU_MD5_u32plus a, b, c, d;
  unsigned char buffer[64];
  GPU_MD5_u32plus block[16];
} GPU_MD5_CTX;
 
typedef struct string {
  char pwd[LENGTH+1];
} string_t;


typedef struct password_entry {
  char pwd[LENGTH+1];
  uint8_t password_md5[MD5_DIGEST_LENGTH];
} password_entry_t;

typedef struct dictionary_entry {
  char word[LENGTH+1];
  int length;
  struct dictionary_entry * next;
} dictionary_entry_t;

/**
 * Get the time in milliseconds since UNIX epoch
 * Taken from Charlie's util.c in the worm lab
 */
size_t time_ms();

/**
 * Read a file of username and MD5 passwords. 
 * Return a linked list of entries.
 */
password_entry* read_password_file(const char* filename, int *size);

/**
 * Read a file of english words in the dictionary.
 * Return a linked list of words sorted by length
 */
dictionary_entry * parse_dictionary (const char* filename, int * eight, int * seven, int * six);

/**
 * Matches a given passwordHash against an item from a passwordEntry array.
 * Changes checker if a match was found
 */
__global__ void popularPasswords(uint8_t* passwordHash, password_entry * passwordEntries, bool* checker);

/** 
 * Given a dictionary word of less than 8 characters, add numbers to the end
 * And test against the given password hash
 * Changes checker if a match was found
 */
__global__ void shorterPasswords(uint8_t* passwordHash, string* entries, int numDigits, int endNumber, bool * checker);

/**
 * Makes an eight character alphanumeric password and tests it against a given passwordHash
 * Changes checker if the passwords match
 */
__global__ void bruteForce(uint8_t* passwordHash, bool* checker, int offset);


int main() {
  char password[LENGTH+1];
  uint8_t passwordHash[MD5_DIGEST_LENGTH+1];
  bool* checker = (bool*)malloc(sizeof(bool));
  *checker = false;
  int size = 0; 

  char* password_filename = "./popular-passwords.txt";
  char* dictionary_filename = "./dictionary.txt";

  printf("Enter in your test password: ");
  scanf("%s", &password);
  size_t start_time = time_ms();
  MD5((unsigned char*) password, LENGTH, passwordHash);
 
  password_entry* passwordEntries = read_password_file(password_filename, &size);

  uint8_t* gpu_passwordHash;
  bool* gpu_checker;
  password_entry* gpu_passwordEntries;

  if(cudaMalloc(&gpu_passwordEntries, (sizeof(password_entry) * size)) != cudaSuccess) {
    fprintf(stderr, "Failed to allocate memory for passwordEntries\n");
    exit(2);
  }

  if(cudaMemcpy(gpu_passwordEntries, passwordEntries, sizeof(password_entry) * size,  cudaMemcpyHostToDevice) != cudaSuccess) {
    fprintf(stderr, "Failed to copy passwordEntries to the GPU\n");
  }

  if(cudaMalloc(&gpu_passwordHash, (sizeof(uint8_t)* MD5_DIGEST_LENGTH) +1) != cudaSuccess) {
    fprintf(stderr, "Failed to allocate memory for passwordHash\n");
    exit(2);
  }
    
  if(cudaMemcpy(gpu_passwordHash, passwordHash, (sizeof(uint8_t) * MD5_DIGEST_LENGTH) + 1,  cudaMemcpyHostToDevice) != cudaSuccess) {
    fprintf(stderr, "Failed to copy passwordHash to the GPU\n");
  }
  
  if(cudaMalloc(&gpu_checker, sizeof(bool)) != cudaSuccess) {
    fprintf(stderr, "Failed to allocate memory for checker\n");
    exit(2);
  }
  
  if(cudaMemcpy(gpu_checker, checker, sizeof(bool),  cudaMemcpyHostToDevice) != cudaSuccess) {
    fprintf(stderr, "Failed to copy checker to the GPU\n");
  }
 
  int num_blocks = (round((float) (size / THREADS_PER_BLOCK))) + 1;
  popularPasswords<<<num_blocks, THREADS_PER_BLOCK>>>(gpu_passwordHash, gpu_passwordEntries, gpu_checker);

  if(cudaDeviceSynchronize() != cudaSuccess){
    fprintf(stderr, "The error came from the call to popular passwords using popular passwords file \n");
  }

  if(cudaMemcpy(checker, gpu_checker, sizeof(bool),  cudaMemcpyDeviceToHost) != cudaSuccess) {
    fprintf(stderr, "Failed to copy checker from the first approach using popular passwords \n");
  }
  
  if (*checker == true) {
    size_t end_time = time_ms();
    size_t total_time_secs = (end_time - start_time)/1000;
    size_t total_time_milli = (end_time - start_time) % 1000;
    printf("It took %u seconds and %u milliseconds to find your password.\n", total_time_secs, total_time_milli);
  } else {
    
    int six_size = 0;
    int seven_size = 0;
    int eight_size = 0;

    dictionary_entry * dictionaryEntries = parse_dictionary(dictionary_filename, &eight_size, &seven_size, &six_size);

    string words_len_six[six_size];
    string words_len_seven[seven_size];
    password_entry* words_len_eight = (password_entry*) malloc(sizeof(password_entry) * eight_size);

    int sixCount = 0;
    int sevenCount = 0;
    int eightCount = 0;

    dictionary_entry* cur = dictionaryEntries;
    while(cur != NULL){
      int len = cur->length;
      switch(len){
      case 6:
        strcpy(words_len_six[sixCount++].pwd, cur->word);
        break;

      case 7:
        strcpy(words_len_seven[sevenCount++].pwd, cur->word);
        break;

      case 8:
        strcpy(words_len_eight[eightCount].pwd, cur->word);
        MD5((unsigned char*) cur->word, LENGTH,  words_len_eight[eightCount++].password_md5);
        break;
      }
      cur = cur->next;
    }

    password_entry* gpu_len_eight;

    if(cudaMalloc(&gpu_len_eight, sizeof(password_entry) * eight_size) != cudaSuccess) {
      fprintf(stderr, "Failed to allocate memory for gpu_len_8\n");
      exit(2);
    } 

    if(cudaMemcpy(gpu_len_eight, words_len_eight, sizeof(password_entry) * eight_size,  cudaMemcpyHostToDevice) != cudaSuccess) {
      fprintf(stderr, "Failed to copy words of length eight to the GPU\n");
    }
 
    num_blocks = (round((float) (eight_size / THREADS_PER_BLOCK))) + 1;
    popularPasswords<<<num_blocks,THREADS_PER_BLOCK>>>(gpu_passwordHash, gpu_len_eight, gpu_checker);

    if(cudaDeviceSynchronize() != cudaSuccess){
      fprintf(stderr, "The error came from the call to popular passwords based off of dictionary words of length 8 \n");
    }
    
    if(cudaMemcpy(checker, gpu_checker, sizeof(bool),  cudaMemcpyDeviceToHost) != cudaSuccess) {
      fprintf(stderr, "Failed to copy checker from the popular passwords call from dictionary length 8 \n");
    }

    cudaFree(gpu_len_eight);
    
    if (*checker == true) {
      size_t end_time = time_ms();
      size_t total_time_secs = (end_time - start_time)/1000;
      size_t total_time_milli = (end_time - start_time) % 1000;
      printf("It took %u seconds and %u milliseconds to find your password.\n", total_time_secs, total_time_milli);
    } else { //try adding numbers to words of length 7

      string* gpu_len_seven;
      if(cudaMalloc(&gpu_len_seven, sizeof(string) * seven_size) != cudaSuccess) {
        fprintf(stderr, "Failed to allocate memory for gpu_len_7\n");
        exit(2);
      }

      if(cudaMemcpy(gpu_len_seven, words_len_seven, sizeof(string) * seven_size,  cudaMemcpyHostToDevice) != cudaSuccess) {
        fprintf(stderr, "Failed to copy words of length seven to the GPU\n");
      }
    
      shorterPasswords<<<seven_size, 10>>>(gpu_passwordHash, gpu_len_seven, 1, 10, gpu_checker);

      
      if(cudaDeviceSynchronize() != cudaSuccess){
        fprintf(stderr, " \n");
      }
    
      if(cudaMemcpy(checker, gpu_checker, sizeof(bool),  cudaMemcpyDeviceToHost) != cudaSuccess) {
        fprintf(stderr, "Failed to copy checker from the GPU round 2\n");
      }

      cudaFree(gpu_len_seven);
      if (*checker == true) {
        size_t end_time = time_ms();
        size_t total_time_secs = (end_time - start_time)/1000;
        size_t total_time_milli = (end_time - start_time) % 1000;
        printf("It took %u seconds and %u milliseconds to find your password.\n", total_time_secs, total_time_milli);
      } else { //try adding numbers to words of length 6

        string* gpu_len_six;
        if(cudaMalloc(&gpu_len_six, sizeof(string) * six_size) != cudaSuccess) {
          fprintf(stderr, "Failed to allocate memory for gpu_len_6\n");
          exit(2);
        }
   
        if(cudaMemcpy(gpu_len_six, words_len_six, sizeof(string) * six_size,  cudaMemcpyHostToDevice) != cudaSuccess) {
          fprintf(stderr, "Failed to copy words of length six to the GPU\n");
        }
        
        shorterPasswords<<<six_size, 100>>>(gpu_passwordHash, gpu_len_six, 2, 100, gpu_checker);

        
        if(cudaDeviceSynchronize() != cudaSuccess){
          fprintf(stderr, "the error came from the second call to popular_passwords \n");
        }
    
        if(cudaMemcpy(checker, gpu_checker, sizeof(bool),  cudaMemcpyDeviceToHost) != cudaSuccess) {
          fprintf(stderr, "Failed to copy checker from the GPU round 2\n");
        }

        cudaFree(gpu_len_six);
        if (*checker == true) {
          size_t end_time = time_ms();
          size_t total_time_secs = (end_time - start_time)/1000;
          size_t total_time_milli = (end_time - start_time) % 1000;
          printf("It took %u seconds and %u milliseconds to find your password.\n", total_time_secs, total_time_milli);
        }  else {
      
          int i = 0;
          for(; i < 783641; i++) {
            bruteForce<<<50000,THREADS_PER_BLOCK>>>(gpu_passwordHash, gpu_checker, i*50000);
            if(cudaMemcpy(checker, gpu_checker, sizeof(bool),  cudaMemcpyDeviceToHost) != cudaSuccess) {
              fprintf(stderr, "Failed to copy checker from the GPU round 3\n");
            }
            if (*checker) {
              break;
            }
            if(cudaDeviceSynchronize() != cudaSuccess){
              fprintf(stderr, "the error came from inside the kernel...comes back\n");
              fprintf(stderr, "%s\n", cudaGetErrorString(cudaPeekAtLastError()));
            }
          }
          if (!(*checker)) {
            bruteForce<<<32048, THREADS_PER_BLOCK>>>(gpu_passwordHash, gpu_checker, i*50000);
          }
  
          if(cudaDeviceSynchronize() != cudaSuccess){
            fprintf(stderr, "the error came from inside the kernel...comes back\n");
          }
  
          if(cudaMemcpy(checker, gpu_checker, sizeof(bool),  cudaMemcpyDeviceToHost) != cudaSuccess) {
            fprintf(stderr, "Failed to copy checker from the GPU round 4\n");
          }
  
          if (*checker == true) {
            size_t end_time = time_ms();
            size_t total_time_secs = (end_time - start_time)/1000;
            size_t total_time_milli = (end_time - start_time) % 1000;
            printf("It took %u seconds and %u milliseconds to find your password.\n", total_time_secs, total_time_milli);

            FILE* password_file = fopen(password_filename, "a");
            if (password_file == NULL) {
              perror("opening password file");
              exit(2);
            }
            fprintf(password_file, "%s\n", password);
            fclose(password_file);
            
            FILE* password_file_size = fopen(password_filename, "r+");
            if (password_file_size == NULL) {
              perror("opening password file");
              exit(2);
            }
            fprintf(password_file_size, "%d\n", size+1);
            fclose(password_file_size);
          }
        }
      }
    }
  }

  free(checker);
  cudaFree(gpu_passwordEntries);
  cudaFree(gpu_checker);
  cudaFree(gpu_passwordHash);

  return 0;
}

// Citation: Got this code from Charlie for measuring computation time
size_t time_ms() {
  struct timeval tv;
  if(gettimeofday(&tv, NULL) == -1) {
    perror("gettimeofday");
    exit(2);
  }
  
  // Convert timeval values to milliseconds
  return tv.tv_sec*1000 + tv.tv_usec/1000;
}

dictionary_entry * parse_dictionary (const char* filename, int * eight, int * seven, int * six) {
  // Open the dictionary file
  FILE* dictionary_file = fopen(filename, "r");
  if (dictionary_file == NULL) {
    perror("opening dictionary file");
    exit(2);
  }

  int eight_size = 0;
  int seven_size = 0;
  int six_size = 0;
  
  dictionary_entry* dictionary = NULL;
  
  // Read until we hit the end of the file
  while (!feof(dictionary_file)) {

    char word[LENGTH*2];
    // Try to read. The space in the format string is required to eat the newline
    if(fscanf(dictionary_file, " %s ", word) != 1) {
      fprintf(stderr, "Error reading password file: malformed line\n");
      exit(2);
    }

    int len = strlen(word);
    word[len] = '\0';
    
    switch (len) {
    case 8:
      eight_size++;
      break;

    case 7:
      seven_size++;
      break;

    case 6:
      six_size++;
      break;
    }


    if (len < 9 && len > 5) {
      // Make space to hold the popular password unhashed
      dictionary_entry* entry = (dictionary_entry*) malloc(sizeof(dictionary_entry));

      // Copy the word to entry but make it lowercase
      for (int i = 0; word[i]; i++) {
        entry->word[i] = tolower(word[i]);
      }
      
      entry->length = len;
      
      // Add the new node to the front of the list
      entry->next = dictionary;
      dictionary = entry;
    }
  }

  *eight = eight_size;
  *seven = seven_size;
  *six = six_size;
  return dictionary;
}

// Citation: This code is based off of Mattori and Ajuna's Password Cracker code
password_entry* read_password_file(const char* filename, int *size) {
  // Open the password file
  FILE* password_file = fopen(filename, "r");
  if (password_file == NULL) {
    perror("opening password file");
    exit(2);
  }

  char length[LENGTH];
  // Get the first line containing the number of passwords
  if(fscanf(password_file, " %s ", length) != 1) {
    fprintf(stderr, "Error reading password file: malformed line\n");
    exit(2);
  }

  *size = atoi(length);

  password_entry* passwords = (password_entry*) malloc(sizeof(password_entry) * *size);
  int i = -1;

  // Read until we hit the end of the file
  while (!feof(password_file) && i < *size) {
    i++;
  
    // Make space to hold the popular password unhashed
    char * passwd = (char *) malloc(sizeof(char) * 9);
    uint8_t * md5_string = (uint8_t *) malloc(sizeof(uint8_t) * MD5_DIGEST_LENGTH * 2 + 1);
    
    // Try to read. The space in the format string is required to eat the newline
    if(fscanf(password_file, " %s ", passwd) != 1) {
      fprintf(stderr, "Error reading password file: malformed line\n");
      exit(2);
    }
   
    // Convert the passwd to a MD5 and store it
    MD5((unsigned char*) passwd, LENGTH,  md5_string);
    
    // Add the new node to the front of the list
    strcpy(passwords[i].pwd, passwd);
    memcpy(passwords[i].password_md5, md5_string, MD5_DIGEST_LENGTH);
  }

  return passwords;
}

__device__ static const void *body(GPU_MD5_CTX *ctx, const void *data, unsigned long size) {
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
 
__device__ void GPU_MD5_Init(GPU_MD5_CTX *ctx) {
  ctx->a = 0x67452301;
  ctx->b = 0xefcdab89;
  ctx->c = 0x98badcfe;
  ctx->d = 0x10325476;
 
  ctx->lo = 0;
  ctx->hi = 0;
}
 
__device__ void GPU_MD5_Update(GPU_MD5_CTX *ctx, const void *data, unsigned long size) {
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
 
__device__ void GPU_MD5_Final(unsigned char *result, GPU_MD5_CTX *ctx) {
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

__device__ char computeChar(int i) {
  i = i % NUM_CHAR;
  if (i < 26) {
    return (char) i + 97;
  } else {
    return (char) i + 22;
  }
}

__global__ void bruteForce(uint8_t* passwordHash, bool* checker, int offset) {
  int new_block_id = blockIdx.x + offset;
  
  char password[LENGTH+1];
 
  // Calculates the characters of the password to be generated. `pow` function was not
  // available 
  password[7] = computeChar(threadIdx.x);
  password[6] = computeChar(new_block_id*2 + (threadIdx.x / NUM_CHAR));
  password[5] = computeChar(new_block_id / 18);
  password[4] = computeChar(new_block_id / 648);
  password[3] = computeChar(new_block_id / 23328);
  password[2] = computeChar(new_block_id / 839808);
  password[1] = computeChar(new_block_id / 30233088);
  password[0] = computeChar(new_block_id / 1088391168);
  password[8] = '\0';

  //Initialize the MD5 context
  GPU_MD5_CTX context;
  GPU_MD5_Init(&context);

  //add our data to MD5
  GPU_MD5_Update(&context, password, LENGTH);

  //Finish calculating the MD5
  uint8_t output[MD5_DIGEST_LENGTH];
  GPU_MD5_Final(output, &context);

  int match = 0;
  
  for(size_t i=0; i < MD5_DIGEST_LENGTH; i++) {
    if (output[i] == passwordHash[i]) {
      match++;
    }
  }

  if (match == MD5_DIGEST_LENGTH) {
    *checker = true;
    printf("Password has been found on the GPU by bruteForce. It is %s \n", password);
  }
}

__global__ void popularPasswords(uint8_t* passwordHash, password_entry* passwordEntries, bool* checker) {

  int index = (blockIdx.x * THREADS_PER_BLOCK) + threadIdx.x;
  uint8_t* passwordEntry = passwordEntries[index].password_md5;
   
  int match = 0;
  
  for(size_t i=0; i < MD5_DIGEST_LENGTH; i++) {
    if (passwordHash[i] == passwordEntry[i]) {
      match++;
    }
  }

  if (match == MD5_DIGEST_LENGTH) {
    *checker = true;
    printf("Password has been found on the GPU by popularPasswords. It is %s \n", passwordEntries[index].pwd);
  }
}


__global__ void shorterPasswords(uint8_t* passwordHash, string * entries, int numDigits, int endNumber, bool * checker) {
  char * word = entries[blockIdx.x].pwd;
  int addOnInteger = (int) threadIdx.x;
  char cur[LENGTH+1];
  int i = 0;
  for (; i < LENGTH - numDigits; i++) {
    cur[i] = word[i];
  }
  if (numDigits < 4) {
    cur[LENGTH-1] = (char) (addOnInteger % 10) + 48;
  }
  if (numDigits > 1) {
    cur[LENGTH - 2] = (char) ((addOnInteger / 10) % 10) + 48;
    if (numDigits > 2) {
      cur[LENGTH - 3] = (char) ((addOnInteger / 100) % 10) + 48;
      if (numDigits > 3) {
        cur[LENGTH - 4] = (char) ((addOnInteger / 1000) % 10) + 48;
      }
    }
  }
  //Initialize the MD5 context
  GPU_MD5_CTX context;
  GPU_MD5_Init(&context);

  //add our data to MD5
  GPU_MD5_Update(&context, cur, LENGTH);

  //Finish computing MD5
  uint8_t md5_hash[MD5_DIGEST_LENGTH];
  GPU_MD5_Final(md5_hash, &context);
     
  int match = 0;
  
  for(size_t i=0; i < MD5_DIGEST_LENGTH; i++) {
    if (md5_hash[i] == passwordHash[i]) {
      match++;
    }
  }

  if (match == MD5_DIGEST_LENGTH) {
    *checker = true;
    printf("Password has been found on the GPU by adding numbers to the end of a dictionary word. It is %s \n", cur);
  }
}
