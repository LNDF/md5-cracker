#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

#define MAX_SIZE 512

unsigned char get_digit(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return 0xff;
}

int hex_to_bin(const char* in, unsigned char* out) {
    size_t len = strlen(in);
    if (len % 2 != 0) {
        return 1;
    }
    const char* end = in + len;
    const char* p = in;
    unsigned char* q = out;
    for (; p < end; p += 2, ++q) {
        unsigned char hi = get_digit(*p);
        unsigned char lo = get_digit(*(p + 1));
        if (hi == 0xff || lo == 0xff) {
            return 1;
        }
        *q = (hi << 4) | lo;
    }
    return 0;
}

int md5(const unsigned char* data, size_t size, unsigned char* hash) {
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        return 1;
    }
    const EVP_MD* md = EVP_md5();
    if (md == NULL) {
        EVP_MD_CTX_free(mdctx);
        return 1;
    }
    if (EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        return 1;
    }
    if (EVP_DigestUpdate(mdctx, data, size) != 1) {
        EVP_MD_CTX_free(mdctx);
        return 1;
    }
    if (EVP_DigestFinal_ex(mdctx, hash, NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        return 1;
    }
    EVP_MD_CTX_free(mdctx);
    return 0;
}

int run(char* testbuf, unsigned char* hash) {
    int testbuf_size = 0;
    while (1) {
        for (int i = 0; i < MAX_SIZE; ++i) {
            testbuf[i] = testbuf[i] == 0 ? 0x20 : testbuf[i] + 1;
            if (testbuf[i] < 0x7f) {
                testbuf_size = testbuf_size > i ? testbuf_size : i + 1;
                goto test;
            }
            testbuf[i] -= 0x5f; // 0x7f - 0x20
        }
        return 1;
test:
        unsigned char testhash[16];
        if (md5(testbuf, testbuf_size, testhash)) {
            return 2;
        }
        if (memcmp(testhash, hash, 16) == 0) {
            return 0;
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <hash>\n", argv[0]);
        return 1;
    }
    if (strlen(argv[1]) != 32) {
        printf("Invalid hash length\n");
        return 1;
    }
    unsigned char hash[16];
    if (hex_to_bin(argv[1], hash)) {
        printf("Invalid hash\n");
        return 1;
    }
    char testbuf[MAX_SIZE];
    memset(testbuf, 0x0, MAX_SIZE);
    int result = run(testbuf, hash);
    if (result == 0) {
        printf("Found: %s\n", testbuf);
    } else if (result == 1) {
        printf("Error: exceeded maximum size\n");
    } else if (result == 2) {
        printf("Error: MD5 failed\n");
    }
    return result;
}