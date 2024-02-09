#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <assert.h>

#define MAX_MSG_LEN 64 // Maximum message length as a constant
#define BLOCK_SIZE 64 // Block size for SHA-1
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))
#define PADDED_LEN 128 // Hardcoded padded length

uint32_t a, b, c, d, e, f, k, temp;
uint32_t w[16];
size_t j;
int i;
uint64_t bitsLen;
size_t paddedLen;
uint8_t buffer[BLOCK_SIZE + MAX_MSG_LEN]; // Allocate buffer for the largest possible scenario
uint8_t paddedInput[PADDED_LEN]; // Allocate buffer for the largest possible scenario

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

    h[0] = 0x67452301;
    h[1] = 0xEFCDAB89;
    h[2] = 0x98BADCFE;
    h[3] = 0x10325476;
    h[4] = 0xC3D2E1F0;

    // Initialize the buffer to 0
    memset(paddedInput, 0, PADDED_LEN);

    // Copy input into padded input and append the 0x80 padding byte
    memcpy(paddedInput, input, inputLen);
    paddedInput[inputLen] = 0x80;

    // Append the length in bits at the end of the last block
    for (i = 0; i < 8; i++) {
        paddedInput[PADDED_LEN - 8 + i] = (uint8_t)(bitsLen >> (8 * (7 - i)));
    }

    // Process each block
    for (j = 0; j < PADDED_LEN; j += 64) {
        process_block(h, paddedInput + j);
    }

}


void hmac_sha1(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint32_t *h) {
    uint32_t temp_key[5]; // Temporary storage if key needs to be hashed
    size_t i;

    // NOTE: This step will be performed by the preprocessor, so this if
    // statement can be ignored.
    //
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

void get_current_time_step(uint8_t time_step[8]) {
    memset(time_step, 0, 8); // Zero out the array to ensure clean state

    uint64_t current_time = (uint64_t)time(NULL); // Get current Unix timestamp
    uint64_t timestep_value = current_time / 30; // Divide by the TOTP time step (e.g., 30 seconds)

    // Convert to big-endian format and ensure complete initialization
    for (int i = 7; i >= 0; i--) {
        time_step[i] = (uint8_t)timestep_value;
        timestep_value >>= 8;
    }
}

void get_time_step(uint8_t time_step[8], uint64_t timestep) {
    memset(time_step, 0, 8); // Zero out the array to ensure clean state

    for (int i = 7; i >= 0; i--) {
        time_step[i] = (uint8_t)timestep;
        timestep >>= 8;
    }
    printf("Time step: %02x%02x%02x%02x%02x%02x%02x%02x\n", time_step[0], time_step[1], time_step[2], time_step[3], time_step[4], time_step[5], time_step[6], time_step[7]);
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

// Function to test a single TOTP case
void test_totp(const uint8_t* key, size_t key_len, const uint8_t* time_step, uint32_t expected, int digits) {
    uint32_t digest[5]; // To store the HMAC result
    uint8_t byteDigest[20];
    
    hmac_sha1(key, key_len, time_step, 8, digest); // Calculate HMAC-SHA1
    uint32_to_uint8(digest, byteDigest, 5); // Convert digest to bytes
    uint32_t totp = extract_totp(byteDigest, digits); // Extract TOTP
    
    printf("TOTP: %0*u (Expected: %0*u)\n", digits, totp, digits, expected);
    assert(totp == expected); // Verify TOTP
}

  /* |      59     |  1970-01-01  | 0000000000000001 | 94287082 |  SHA1  | */
  /* |  1111111109 |  2005-03-18  | 00000000023523EC | 07081804 |  SHA1  | */
  /* |  1111111111 |  2005-03-18  | 00000000023523ED | 14050471 |  SHA1  | */
  /* |  1234567890 |  2009-02-13  | 000000000273EF07 | 89005924 |  SHA1  | */
  /* |  2000000000 |  2033-05-18  | 0000000003F940AA | 69279037 |  SHA1  | */
  /* | 20000000000 |  2603-10-11  | 0000000027BC86AA | 65353130 |  SHA1  | */

int main() {
    const int digits = 8; // TOTP digits
    const uint8_t key[] = "12345678901234567890"; // Mock secret key
    uint8_t time_step[8]; // To store the time step

    get_time_step(time_step, 59 / 30); // Get the time step for the first test case
    test_totp(key, sizeof(key) - 1, time_step, 94287082, digits);

    get_time_step(time_step, 1111111109 / 30); // Get the time step for the second test case
    test_totp(key, sizeof(key) - 1, time_step, 7081804, digits);

    get_time_step(time_step, 1111111111 / 30); // Get the time step for the third test case
    test_totp(key, sizeof(key) - 1, time_step, 14050471, digits);

    get_time_step(time_step, 1234567890 / 30); // Get the time step for the fourth test case
    test_totp(key, sizeof(key) - 1, time_step, 89005924, digits);

    get_time_step(time_step, 2000000000 / 30); // Get the time step for the fifth test case
    test_totp(key, sizeof(key) - 1, time_step, 69279037, digits);

    get_time_step(time_step, 20000000000 / 30); // Get the time step for the sixth test case
    test_totp(key, sizeof(key) - 1, time_step, 65353130, digits);
    
    return 0;
}
