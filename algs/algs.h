#ifndef ALGS_H
#define ALGS_H

#include "../filecrypt.h"

#define ALGORITHM_XOR   0
#define ALGORITHM_AES   1

#define ALGORITHM_MAX   16
#define ALGORITHM_DEFAULT   ALGORITHM_XOR

#define HASH_SHA1       0
#define HASH_SHA224     1
#define HASH_SHA256     2
#define HASH_SHA384     3
#define HASH_SHA512     4

#define HASH256_SIZE    32
#define AES_BLOCK_SIZE  16

#define DEFAULT_IV      "0123456789012345"

void init_algs();
crypt_operations *get_crypt_ops(int algs);
int algs_valid(file_crypt_info *crypt_info);
void init_algs_info(file_crypt_info *crypt_info);
char *get_algorithm_name(int algorithm_id);
int is_right_password(const char *user_password, uint8_t *password_hash);
int get_password_hash(const char *user_password, uint8_t *password_hash);

int get_hash(int type, uint8_t *message, uint64_t length, uint8_t *out);
int aes_encrypt_common(uint8_t *input, uint64_t length, const unsigned char *password,
        const unsigned char *iv, uint8_t *out, uint64_t *out_length);
int aes_decrypt_common(uint8_t *input, uint64_t length, const unsigned char *password,
        const unsigned char *iv, uint8_t *out, uint64_t *out_length);

extern crypt_operations xor_crypt_operations;
extern crypt_operations aes_crypt_operations;

#endif // ALGS_H