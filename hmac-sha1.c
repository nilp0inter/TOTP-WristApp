#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>

#define MAX_MSG_LEN 64 // Maximum message length as a constant
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

void hmac_sha1(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint32_t *h) {
    uint32_t temp_key[5]; // Temporary storage if key needs to be hashed
    size_t i;

    // NOTE: This step will be performed by the preprocessor, so this code
    // can be ignored.
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


uint32_t dynamic_truncation(uint32_t digest[5]) {
    // Convert digest to a byte pointer to access individual bytes
    uint8_t* p = (uint8_t*)digest;

    // Determine the offset. Use the last byte & 0x0F to get the offset value
    uint8_t offset = p[19] & 0x0F; // Last byte of the HMAC-SHA1 result

    // Build the truncatedHash from the bytes, ensuring big-endian order
    uint32_t truncatedHash = ((uint32_t)p[offset] & 0x7F) << 24 |
                             (uint32_t)p[offset + 1] << 16 |
                             (uint32_t)p[offset + 2] << 8 |
                             (uint32_t)p[offset + 3];

    return truncatedHash;
}

// Function to fill the time_step array from the current Unix timestamp
// Ensures the array is fully initialized to avoid issues with uninitialized memory
void get_current_time_step(uint8_t time_step[8]) {
    memset(time_step, 0, 8); // Zero out the array to ensure clean state

    uint64_t current_time = (uint64_t)time(NULL); // Get current Unix timestamp
    uint64_t timestep_value = current_time / 30; // Divide by the TOTP time step (e.g., 30 seconds)

    // Convert to big-endian format and ensure complete initialization
    for (int i = 7; i >= 0; i--) {
        time_step[i] = (uint8_t)(timestep_value & 0xFF);
        timestep_value >>= 8;
    }
}

// Assuming digest is a uint8_t array with 20 bytes for SHA1 hash
uint32_t extract_totp(const uint8_t* digest, int digits) {
    // Offset is the low 4 bits of the last byte of the digest
    int offset = digest[19] & 0xF;
    
    // Extract the dynamic binary code
    uint32_t code = ((digest[offset] & 0x7F) << 24)
                  | ((digest[offset + 1] & 0xFF) << 16)
                  | ((digest[offset + 2] & 0xFF) << 8)
                  | (digest[offset + 3] & 0xFF);
    
    // Apply modulo operation with 10^digits
    uint32_t totp = code % (uint32_t)pow(10, digits);
    
    return totp;
}

// To deal with the endianness, we need to convert the uint32_t array to a uint8_t array
// NOTE: The device is already big-endian, so this step won't be necessary
void uint32_to_uint8(const uint32_t* input, uint8_t* output, size_t length) {
    for (size_t i = 0; i < length; i++) {
        uint32_t value = input[i];
        output[i * 4 + 0] = (value >> 24) & 0xFF;
        output[i * 4 + 1] = (value >> 16) & 0xFF;
        output[i * 4 + 2] = (value >> 8) & 0xFF;
        output[i * 4 + 3] = value & 0xFF;
    }
}


int main() {
    const uint8_t key[] = "12345678901234567890"; // Mock secret key
    /* //       59     |  1970-01-01  | 0000000000000001 | 94287082 |  SHA1  | */
    /* uint8_t time_step[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }; */

    uint8_t time_step[8];
    get_current_time_step(time_step); // Get current time_step properly initialized


    uint32_t digest[5]; // To store the HMAC result
    hmac_sha1(key, sizeof(key) - 1, time_step, sizeof(time_step), digest); // Calculate HMAC-SHA1
                                                                           //
    print_digest(digest); // Output the HMAC-SHA1 result

    uint8_t byteDigest[20];
    uint32_to_uint8(digest, byteDigest, 5);

    int digits = 8; // TOTP digits
    uint32_t totp = extract_totp(byteDigest, digits);
    
    printf("TOTP: %0*u\n", digits, totp);
    
    return 0;
}
