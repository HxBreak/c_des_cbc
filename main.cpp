#include <iostream>
#include <sstream>
#include <cstring>
#include "stdio.h"
#include "des.h"

size_t pkcs5padding_encode(unsigned char *src, size_t len){
    size_t paddNum = 8 - len % 8;
    auto new_data = new char[len + paddNum];
    memset(new_data, 0, len + paddNum);
    memcpy(new_data, src, len);
    for (int i = 0; i < paddNum; ++i) {
        new_data[len + i] = paddNum;
    }
    return paddNum + len;
}

int main() {
    std::cout << "Hello, World!" << std::endl;
    mbedtls_des3_context context, deContext;

    mbedtls_des3_init(&context);
    mbedtls_des3_init(&deContext);
    unsigned char key[] = "iyyxscjinatcomxpenngo?#@";
    unsigned char iv[] = "67985432";
    unsigned char iv2[] = "67985432";
    mbedtls_des3_set3key_enc(&context, key);
    mbedtls_des3_set3key_dec(&deContext, key);
//    int mbedtls_des3_crypt_cbc( mbedtls_des3_context *ctx,
//                                int mode,
//                                size_t length,
//                                unsigned char iv[8],
//                                const unsigned char *input,
//                                unsigned char *output );
    unsigned char * buf = (unsigned char *)(new char[1024]);
    char * data = (char *) ("123");
    size_t len = strlen(data);
    size_t paddNum = 8 - len % 8;
    auto new_data = new char[len + paddNum];
    memset(new_data, 0, len + paddNum);
    memcpy(new_data, data, len);
    for (int i = 0; i < paddNum; ++i) {
        new_data[len + i] = paddNum ;
    }
    unsigned char ch[8] = {0};
    mbedtls_des3_crypt_cbc(&context, MBEDTLS_DES_ENCRYPT, paddNum + len, iv, (unsigned char *)new_data, buf);
    mbedtls_des3_crypt_cbc(&deContext, MBEDTLS_DES_DECRYPT, 8, iv2, (unsigned char *)buf, ch);
    mbedtls_des3_free(&deContext);
    mbedtls_des3_free(&context);
    delete [] new_data;
    std::stringstream stream;
    for (int i = 0; i < 8; ++i) {
//        std::cout << std::oct << (int)buf[i] << " " ;
        printf("%d ", (signed char)buf[i]);
//        printf("%d ", c);
    }
    for (int i = 0; i < 8; ++i) {
        std::cout << std::oct << ch[i] << " " ;
    }
    return 0;
}