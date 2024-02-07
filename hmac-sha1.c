#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

void print_digest(uint32_t *digest) {
    for (int i = 0; i < 5; i++) {
        printf("%08x", digest[i]);
    }
    printf("\n");
}

void process_block(uint32_t *h, const uint8_t *chunk) {
    uint32_t a, b, c, d, e, f, k, temp;
    uint32_t w[16];

    // Initialize w[16] from the chunk
    for (int i = 0; i < 16; i++) {
        w[i] = (uint32_t)chunk[i*4] << 24 | (uint32_t)chunk[i*4+1] << 16 |
               (uint32_t)chunk[i*4+2] << 8 | (uint32_t)chunk[i*4+3];
    }

    a = h[0];
    b = h[1];
    c = h[2];
    d = h[3];
    e = h[4];

    // Main loop
    for (int i = 0; i < 80; i++) {
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
    /* size_t inputLen = strlen(input); */
    uint64_t bitsLen = inputLen * 8; // Length in bits
    size_t paddedLen = ((inputLen + 8 + 63) / 64) * 64; // Calculate new length with padding
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
    for (int i = 0; i < 8; i++) {
        paddedInput[paddedLen - 8 + i] = (uint8_t)(bitsLen >> (8 * (7 - i)));
    }

    // Process each block
    for (size_t i = 0; i < paddedLen; i += 64) {
        process_block(h, paddedInput + i);
    }

    free(paddedInput); // Free the allocated memory
}

#define BLOCK_SIZE 64 // Block size for SHA-1

void hmac_sha1(const uint8_t *key, size_t key_len, const char *msg, size_t msg_len, uint32_t *h) {
    uint8_t k_ipad[BLOCK_SIZE + 1] = {0};
    uint8_t k_opad[BLOCK_SIZE + 1] = {0};
    uint32_t temp_key[5]; // SHA-1 outputs a 20-byte hash
    size_t i;

    // If key is longer than BLOCK_SIZE, hash it
    if (key_len > BLOCK_SIZE) {
        sha1_hash((const char *)key, key_len, temp_key);
        key = (uint8_t *) temp_key;
        key_len = 20;
    }

    // Prepare the inner and outer padded keys
    for (i = 0; i < key_len; i++) {
        k_ipad[i] = key[i] ^ 0x36;
        k_opad[i] = key[i] ^ 0x5C;
    }
    for (i = key_len; i < BLOCK_SIZE; i++) {
        k_ipad[i] = 0x36;
        k_opad[i] = 0x5C;
    }

    // Perform inner SHA-1
    uint8_t inner_padding[BLOCK_SIZE + msg_len];
    memcpy(inner_padding, k_ipad, BLOCK_SIZE);
    memcpy(inner_padding + BLOCK_SIZE, msg, msg_len);
    sha1_hash((const char *)inner_padding, BLOCK_SIZE + msg_len, h);

    // Prepare the outer padding input
    uint8_t outer_padding[BLOCK_SIZE + 20]; // 20 bytes for the SHA-1 hash
    memcpy(outer_padding, k_opad, BLOCK_SIZE);

    // Convert hash output to bytes
    for (i = 0; i < 5; i++) {
        outer_padding[BLOCK_SIZE + i * 4] = (uint8_t)(h[i] >> 24);
        outer_padding[BLOCK_SIZE + i * 4 + 1] = (uint8_t)(h[i] >> 16);
        outer_padding[BLOCK_SIZE + i * 4 + 2] = (uint8_t)(h[i] >> 8);
        outer_padding[BLOCK_SIZE + i * 4 + 3] = (uint8_t)(h[i]);
    }

    // Perform outer SHA-1
    sha1_hash((const char *)outer_padding, BLOCK_SIZE + 20, h);
}

/*
   >>> import hashlib, hmac
   >>> hmac.new(b"your secret key", b"The quick brown fox jumps over the lazy dog", hashlib.sha1).hexdigest()
  'bddfca7fd0c91bbd60496da3af21ab6bbc2a6f11'
*/
int main() {
    const uint8_t key[] = "your secret key";
    const char *message = "The quick brown fox jumps over the lazy dog";
    uint32_t digest[5]; // To store the HMAC result

    hmac_sha1(key, sizeof(key) - 1, message, strlen(message), digest);
    print_digest(digest);

    return 0;
}
