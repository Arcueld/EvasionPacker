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
    std::string calculate(const std::string& input);

private:
    unsigned int state[4];    // 状态(ABCD)
    unsigned int count[2];    // 位数计数器
    unsigned char buffer[64]; // 输入缓冲区
    unsigned char digest[16]; // 消息摘要
    bool finalized;           // 是否已完成计算

    void init();
    void update(const unsigned char* input, size_t length);
    void finalize();
    void transform(const unsigned char block[64]);
    void encode(unsigned char* output, const unsigned int* input, size_t len);
    void decode(unsigned int* output, const unsigned char* input, size_t len);
};