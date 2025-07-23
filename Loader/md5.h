#pragma once
#include <iostream>
#include <string>
#include <cstring>
#include <sstream>
#include <iomanip>

#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

#define FF(a, b, c, d, x, s, ac) { \
    (a) += F ((b), (c), (d)) + (x) + (unsigned int)(ac); \
    (a) = ROTATE_LEFT ((a), (s)); \
    (a) += (b); \
}
#define GG(a, b, c, d, x, s, ac) { \
    (a) += G ((b), (c), (d)) + (x) + (unsigned int)(ac); \
    (a) = ROTATE_LEFT ((a), (s)); \
    (a) += (b); \
}
#define HH(a, b, c, d, x, s, ac) { \
    (a) += H ((b), (c), (d)) + (x) + (unsigned int)(ac); \
    (a) = ROTATE_LEFT ((a), (s)); \
    (a) += (b); \
}
#define II(a, b, c, d, x, s, ac) { \
    (a) += I ((b), (c), (d)) + (x) + (unsigned int)(ac); \
    (a) = ROTATE_LEFT ((a), (s)); \
    (a) += (b); \
}

class MD5 {
public:
    MD5();
    auto calculate(const std::string& input) -> std::string;

private:
    unsigned int state[4];    
    unsigned int count[2];    
    unsigned char buffer[64]; 
    unsigned char digest[16]; 
    bool finalized;           

    auto init() -> void;
    auto update(const unsigned char* input, size_t length) -> void;
    auto finalize() -> void;
    auto transform(const unsigned char block[64]) -> void;
    auto encode(unsigned char* output, const unsigned int* input, size_t len) -> void;
    auto decode(unsigned int* output, const unsigned char* input, size_t len) -> void;
};