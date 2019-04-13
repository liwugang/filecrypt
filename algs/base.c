#include "algs.h"

#include <openssl/evp.h>

int get_hash(int type, uint8_t *message, uint64_t length, uint8_t *out) {
    int result = FALSE;
    EVP_MD_CTX *ctx;
    if ((ctx = EVP_MD_CTX_create()) == NULL) {
        printf("error occur in: %s-%s:%d\n", __FILE__, __func__, __LINE__);
        return FALSE;
    }
    const EVP_MD *hash_type = NULL;
    switch (type) {
    case HASH_SHA1:
        hash_type = EVP_sha1();
        break;
    case HASH_SHA224:
        hash_type = EVP_sha224();
        break;
    case HASH_SHA256:
        hash_type = EVP_sha256();
        break;
    case HASH_SHA384:
        hash_type = EVP_sha384();
        break;
    case HASH_SHA512:
        hash_type = EVP_sha512();
        break;
    default:
        printf("error occur in: %s-%s:%d\n", __FILE__, __func__, __LINE__);
        goto CLEANUP;
    }
    if (1 != EVP_DigestInit_ex(ctx, hash_type, NULL)) {
        printf("error occur in: %s-%s:%d\n", __FILE__, __func__, __LINE__);
        goto CLEANUP;
    }
    if (1 != EVP_DigestUpdate(ctx, message, length)) {
        printf("error occur in: %s-%s:%d\n", __FILE__, __func__, __LINE__);
        goto CLEANUP;
    }
    if (1 != EVP_DigestFinal_ex(ctx, out, NULL)) {
        printf("error occur in: %s-%s:%d\n", __FILE__, __func__, __LINE__);
        goto CLEANUP;
    }
    result = TRUE;

CLEANUP:
    EVP_MD_CTX_destroy(ctx);
    return result;
}

int aes_encrypt_common(uint8_t *input, uint64_t length, const unsigned char *password,
        const unsigned char *iv, uint8_t *out, uint64_t *out_length) {
    int result = FALSE;
    EVP_CIPHER_CTX *ctx;
    uint64_t offset = 0;
    int have_done = 0;
    int value = 0;
    int input_length = 0;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        printf("error occur in: %s-%s:%d\n", __FILE__, __func__, __LINE__);
        return FALSE;
    }
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, password, iv)) {
        printf("error occur in: %s-%s:%d\n", __FILE__, __func__, __LINE__);
        goto CLEANUP;
    }

    while (length) {
        if (length > INT32_MAX) {
            input_length = INT32_MAX;
        } else {
            input_length = length;
        }
        if (1 != EVP_EncryptUpdate(ctx, out + have_done, &value, input + offset, input_length)) {
            printf("error occur in: %s-%s:%d\n", __FILE__, __func__, __LINE__);
            goto CLEANUP;
        }
        length -= input_length;
        offset += input_length;
        have_done += value;
    }
    if (1 != EVP_EncryptFinal_ex(ctx, out + have_done, &value)) {
        printf("error occur in: %s-%s:%d\n", __FILE__, __func__, __LINE__);
        goto CLEANUP;
    }
    have_done += value;
    *out_length = have_done;

    result = TRUE;

CLEANUP:
    EVP_CIPHER_CTX_free(ctx);
    return result;
}

int aes_decrypt_common(uint8_t *input, uint64_t length, const unsigned char *password,
        const unsigned char *iv, uint8_t *out, uint64_t *out_length) {
    int result = FALSE;
    EVP_CIPHER_CTX *ctx;
    uint64_t offset = 0;
    int have_done = 0;
    int value = 0;
    int input_length = 0;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        printf("error occur in: %s-%s:%d\n", __FILE__, __func__, __LINE__);
        return FALSE;
    }
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, password, iv)) {
        printf("error occur in: %s-%s:%d\n", __FILE__, __func__, __LINE__);
        goto CLEANUP;
    }

    while (length) {
        if (length > INT32_MAX) {
            input_length = INT32_MAX;
        } else {
            input_length = length;
        }
        if (1 != EVP_DecryptUpdate(ctx, out + have_done, &value, input + offset, input_length)) {
            printf("error occur in: %s-%s:%d\n", __FILE__, __func__, __LINE__);
            goto CLEANUP;
        }
        length -= input_length;
        offset += input_length;
        have_done += value;
    }
    if (1 != EVP_DecryptFinal_ex(ctx, out + have_done, &value)) {
        printf("error occur in: %s-%s:%d\n", __FILE__, __func__, __LINE__);
        // ERR_print_errors_fp(stdout); // print the error infomation from from openssl
        goto CLEANUP;
    }
    have_done += value;
    *out_length = have_done;
    result = TRUE;

CLEANUP:
    EVP_CIPHER_CTX_free(ctx);
    return result;
}