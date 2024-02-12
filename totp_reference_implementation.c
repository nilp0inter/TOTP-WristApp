#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>


#define MAX_MSG_LEN 64 // Maximum message length as a constant
#define BLOCK_SIZE 64 // Block size for SHA-1
#define PADDED_LEN 128 // Hardcoded padded length

// Define the left rotate operation
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

uint32_t a, b, c, d, e, f, k, temp, w_temp;  // Store the temporary variables
uint32_t h[5];  // Store the hash result

uint8_t j;
int32_t i;  // XXX: Why this needs to be signed?

uint8_t buffer[BLOCK_SIZE + MAX_MSG_LEN]; // Shared buffer for HMAC-SHA1 and SHA-1
uint8_t offset; // Offset for dynamic truncation and totp extraction
uint32_t code;  // Final TOTP code

inline uint32_t address_w(uint8_t j, uint8_t i) {
    return (uint32_t)buffer[j + i*4] << 24 | (uint32_t)buffer[j + i*4+1] << 16 |
           (uint32_t)buffer[j + i*4+2] << 8 | (uint32_t)buffer[j + i*4+3];
}

void sha1_hash(size_t inputLen) {
    h[0] = 0x67452301;
    h[1] = 0xEFCDAB89;
    h[2] = 0x98BADCFE;
    h[3] = 0x10325476;
    h[4] = 0xC3D2E1F0;

    // Append 0x80 to the end of the message
    buffer[inputLen] = 0x80;

    // Append the length in bits at the end of the last block
    for (i = 0; i < 8; i++) {
        buffer[PADDED_LEN - 8 + i] = (uint8_t)((inputLen * 8) >> (8 * (7 - i)));
    }

    // Process each block
    for (j = 0; j < PADDED_LEN; j += 64) {
        a = h[0];
        b = h[1];
        c = h[2];
        d = h[3];
        e = h[4];

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
                w_temp = LEFTROTATE(address_w(j, (i+13)%16) ^ address_w(j, (i+8)%16) ^ address_w(j, (i+2)%16) ^ address_w(j, i%16), 1);
                buffer[j + (i%16)*4] = (uint8_t)(w_temp >> 24);
                buffer[j + (i%16)*4+1] = (uint8_t)(w_temp >> 16);
                buffer[j + (i%16)*4+2] = (uint8_t)(w_temp >> 8);
                buffer[j + (i%16)*4+3] = (uint8_t)(w_temp);
            } else {
                w_temp = address_w(j, i%16);
            }

            temp = LEFTROTATE(a, 5) + f + e + k + w_temp;
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
}


void hmac_sha1(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len) {
    // Initialize the buffer to 0
    for (i = 0; i < PADDED_LEN; i++) {
        buffer[i] = 0;
    }

    // Initialize buffer with k_ipad XOR operation
    for (i = 0; i < key_len; i++) {
        buffer[i] = key[i] ^ 0x36;
    }
    for (; i < BLOCK_SIZE; i++) {
        buffer[i] = 0x36;
    }

    // Append message to the buffer
    for (i = 0; i < msg_len; i++) {
        buffer[BLOCK_SIZE + i] = msg[i];
    }

    // Compute inner hash
    sha1_hash(BLOCK_SIZE + msg_len);

    // Re-initialize buffer to 0
    for (i = 0; i < PADDED_LEN; i++) {
        buffer[i] = 0;
    }
    
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
    sha1_hash(BLOCK_SIZE + 20);
}


uint32_t dynamic_truncation() {
    // Convert digest to a byte pointer to access individual bytes
    uint8_t* p = (uint8_t*)h;

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
    for (i = 7; i >= 0; i--) {
        time_step[i] = 0;
    }

    uint64_t current_time = (uint64_t)time(NULL); // Get current Unix timestamp
    uint64_t timestep_value = current_time / 30; // Divide by the TOTP time step (e.g., 30 seconds)

    // Convert to big-endian format and ensure complete initialization
    for (i = 7; i >= 0; i--) {
        time_step[i] = (uint8_t)timestep_value;
        timestep_value >>= 8;
    }
}


void get_time_step(uint8_t time_step[8], uint64_t timestep) {
    for (i = 7; i >= 0; i--) {
        time_step[i] = 0;
    }

    for (i = 7; i >= 0; i--) {
        time_step[i] = (uint8_t)timestep;
        timestep >>= 8;
    }
    // DEBUG
    /* printf("Time step: %02X%02X%02X%02X%02X%02X%02X%02X\n", time_step[0], time_step[1], time_step[2], time_step[3], time_step[4], time_step[5], time_step[6], time_step[7]); */
}


uint32_t extract_totp(const uint8_t* digest, int digits) {
    // Offset is the low 4 bits of the last byte of the digest
    offset = digest[19] & 0x0F;

    // Extract the dynamic binary code
    code = ((digest[offset] & 0x7F) << 24)
           | ((digest[offset + 1] & 0xFF) << 16)
           | ((digest[offset + 2] & 0xFF) << 8)
           | (digest[offset + 3] & 0xFF);

    // Emulate 10^digits using repeated addition (k is the divisor)
    k = 1;
    for (i = 0; i < digits; i++) {
        temp = 0;
        for (j = 0; j < 10; j++) {
            temp += k;
        }
        k = temp;
    }

    // Apply modulo operation using repeated subtraction
    while (code >= k) {
        code -= k;
    }

    return code;
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
    uint8_t byteDigest[20];
    
    hmac_sha1(key, key_len, time_step, 8); // Calculate HMAC-SHA1
    uint32_to_uint8(h, byteDigest, 5); // Convert digest to bytes
    uint32_t totp = extract_totp(byteDigest, digits); // Extract TOTP
    
    printf("TOTP: %0*u (Expected: %0*u) ->", digits, totp, digits, expected);

    if (totp != expected) {
        printf(" \033[0;31mFAILED\033[0m\n");
    } else {
        printf(" \033[0;32mPASSED\033[0m\n");
    }
}


void print_digest(uint32_t *digest) {
    for (i = 0; i < 5; i++) {
        printf("%08x", digest[i]);
    }
    printf("\n");
}


// Test vectors from RFC 6238
//  |      59     |  1970-01-01  | 0000000000000001 | 94287082 |  SHA1  |
//  |  1111111109 |  2005-03-18  | 00000000023523EC | 07081804 |  SHA1  |
//  |  1111111111 |  2005-03-18  | 00000000023523ED | 14050471 |  SHA1  |
//  |  1234567890 |  2009-02-13  | 000000000273EF07 | 89005924 |  SHA1  |
//  |  2000000000 |  2033-05-18  | 0000000003F940AA | 69279037 |  SHA1  |
//  | 20000000000 |  2603-10-11  | 0000000027BC86AA | 65353130 |  SHA1  |
int main() {
    const int digits = 8; // TOTP digits
    const uint8_t key[] = "12345678901234567890"; // Mock secret key
    uint8_t time_step[8]; // To store the time step

    get_time_step(time_step, 59 / 30); // Get the time step for the first test case
    test_totp(key, sizeof(key) - 1, time_step, 94287082, digits);
    print_digest(h);

    get_time_step(time_step, 1111111109 / 30); // Get the time step for the second test case
    test_totp(key, sizeof(key) - 1, time_step, 7081804, digits);
    print_digest(h);

    get_time_step(time_step, 1111111111 / 30); // Get the time step for the third test case
    test_totp(key, sizeof(key) - 1, time_step, 14050471, digits);
    print_digest(h);

    get_time_step(time_step, 1234567890 / 30); // Get the time step for the fourth test case
    test_totp(key, sizeof(key) - 1, time_step, 89005924, digits);
    print_digest(h);

    get_time_step(time_step, 2000000000 / 30); // Get the time step for the fifth test case
    test_totp(key, sizeof(key) - 1, time_step, 69279037, digits);
    print_digest(h);

    get_time_step(time_step, 20000000000 / 30); // Get the time step for the sixth test case
    test_totp(key, sizeof(key) - 1, time_step, 65353130, digits);
    print_digest(h);

    get_current_time_step(time_step); // Get the current time step
    hmac_sha1(key, sizeof(key) - 1, time_step, 8); // Calculate HMAC-SHA1
    uint32_to_uint8(h, buffer, 5); // Convert digest to bytes
    code = extract_totp(buffer, digits); // Extract TOTP
    printf("\nCurrent TOTP: %0*u\n\n", digits, code);

    printf("You can check the current TOTP code at https://totp.danhersam.com/\n");
    printf("Secret key: GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n");
    printf("Number of digits: %d\n", digits);
    
    return 0;
}
