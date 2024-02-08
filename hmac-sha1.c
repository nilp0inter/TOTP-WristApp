#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#define MAX_MSG_LEN 32 // Maximum message length as a constant
#define BLOCK_SIZE 64 // Block size for SHA-1
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

uint32_t a, b, c, d, e, f, k, temp;
uint32_t w[16];
int i;
uint64_t bitsLen;
size_t paddedLen;
uint8_t buffer[BLOCK_SIZE + MAX_MSG_LEN]; // Allocate buffer for the largest possible scenario

void print_digest(uint32_t *digest) {
    for (i = 0; i < 5; i++) {
        printf("%08x", digest[i]);
    }
    printf("\n");
}

void process_block(uint32_t *h, const uint8_t *chunk) {
    // Initialize w[16] from the chunk
    for (i = 0; i < 16; i++) {
        w[i] = (uint32_t)chunk[i*4] << 24 | (uint32_t)chunk[i*4+1] << 16 |
               (uint32_t)chunk[i*4+2] << 8 | (uint32_t)chunk[i*4+3];
    }

    a = h[0];
    b = h[1];
    c = h[2];
    d = h[3];
    e = h[4];

    // Main loop
    for (i = 0; i < 80; i++) {
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }

        if (i >= 16) {
            w[i%16] = LEFTROTATE(w[(i+13)%16] ^ w[(i+8)%16] ^ w[(i+2)%16] ^ w[i%16], 1);
        }

        temp = LEFTROTATE(a, 5) + f + e + k + w[i%16];
        e = d;
        d = c;
        c = LEFTROTATE(b, 30);
        b = a;
        a = temp;
    }

    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
}

void sha1_hash(const char *input, size_t inputLen, uint32_t *h) {
    bitsLen = inputLen * 8; // Length in bits
    paddedLen = ((inputLen + 8 + 63) / 64) * 64; // Calculate new length with padding
    uint8_t *paddedInput = calloc(paddedLen, sizeof(uint8_t)); // Allocate memory for padded input

    h[0] = 0x67452301;
    h[1] = 0xEFCDAB89;
    h[2] = 0x98BADCFE;
    h[3] = 0x10325476;
    h[4] = 0xC3D2E1F0;

    // Copy input into padded input and append the 0x80 padding byte
    memcpy(paddedInput, input, inputLen);
    paddedInput[inputLen] = 0x80;

    // Append the length in bits at the end of the last block
    for (i = 0; i < 8; i++) {
        paddedInput[paddedLen - 8 + i] = (uint8_t)(bitsLen >> (8 * (7 - i)));
    }

    // Process each block
    for (size_t j = 0; j < paddedLen; j += 64) {
        process_block(h, paddedInput + j);
    }

    free(paddedInput); // Free the allocated memory
}

void hmac_sha1(const uint8_t *key, size_t key_len, const char *msg, size_t msg_len, uint32_t *h) {
    uint32_t temp_key[5]; // Temporary storage if key needs to be hashed
    size_t i;

    // If key is longer than BLOCK_SIZE, hash it
    if (key_len > BLOCK_SIZE) {
        sha1_hash((const char *)key, key_len, temp_key);
        key = (uint8_t *)temp_key;
        key_len = 20; // Length of SHA-1 hash output
    }

    // Initialize buffer with k_ipad XOR operation
    for (i = 0; i < key_len; i++) {
        buffer[i] = key[i] ^ 0x36;
    }
    for (; i < BLOCK_SIZE; i++) {
        buffer[i] = 0x36;
    }

    // Append message to the buffer
    memcpy(buffer + BLOCK_SIZE, msg, msg_len);

    // Compute inner hash
    sha1_hash((const char *)buffer, BLOCK_SIZE + msg_len, h);

    // Re-initialize buffer with k_opad XOR operation
    for (i = 0; i < key_len; i++) {
        buffer[i] = key[i] ^ 0x5C;
    }
    for (; i < BLOCK_SIZE; i++) {
        buffer[i] = 0x5C;
    }

    // Append inner hash result to buffer
    for (i = 0; i < 5; i++) {
        buffer[BLOCK_SIZE + i * 4] = (uint8_t)(h[i] >> 24);
        buffer[BLOCK_SIZE + i * 4 + 1] = (uint8_t)(h[i] >> 16);
        buffer[BLOCK_SIZE + i * 4 + 2] = (uint8_t)(h[i] >> 8);
        buffer[BLOCK_SIZE + i * 4 + 3] = (uint8_t)(h[i]);
    }

    // Compute outer hash
    sha1_hash((const char *)buffer, BLOCK_SIZE + 20, h);
}


/*
   >>> import hashlib, hmac
   >>> hmac.new(b"your secret key", b"123456", hashlib.sha1).hexdigest()
  'f1514f0827d8365cb8929b36468dbdb16e86dced'
*/
int main() {
    const uint8_t key[] = "your secret key";
    const char *message = "123456";
    uint32_t digest[5]; // To store the HMAC result

    hmac_sha1(key, sizeof(key) - 1, message, strlen(message), digest);
    print_digest(digest);

    return 0;
}
