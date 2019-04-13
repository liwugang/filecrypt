#include "algs.h"

uint64_t aes_get_crypt_file_length(file_crypt_info *crypt_info) {
    // come from http://www.obviex.com/articles/CiphertextSize.pdf
    return crypt_info->file_length + AES_BLOCK_SIZE - crypt_info->file_length % AES_BLOCK_SIZE;
}

int aes_is_right_password(file_crypt_info *crypt_info, const char *user_password) {
    if (crypt_info->key_length != HASH256_SIZE) {
        return FALSE;
    }
    return is_right_password(user_password, crypt_info->key);
}

int aes_encrypt(file_crypt_info *crypt_info, const char *user_password,
                     void *input_data, void *output_data) {
    uint64_t have_encrypted = 0;
    if (!aes_encrypt_common(input_data, crypt_info->file_length, user_password, DEFAULT_IV,
                    output_data, &have_encrypted)) {
        return FALSE;
    }
    if (have_encrypted != crypt_info->crypt_file_length - crypt_info->crypt_file_offset) {
        return FALSE;
    }
    get_password_hash(user_password, crypt_info->key);
    crypt_info->key_length = HASH256_SIZE;
    return TRUE;
}

int aes_decrypt(file_crypt_info *crypt_info, const char *user_password,
                     void *input_data, void *output_data) {
    uint64_t have_decrypted = 0;
    if (!aes_decrypt_common(input_data, crypt_info->crypt_file_length - crypt_info->crypt_file_offset,
            user_password, DEFAULT_IV, output_data, &have_decrypted)) {
        return FALSE;
    }
    if (have_decrypted != crypt_info->file_length) {
        return FALSE;
    }
    return TRUE;
}

crypt_operations aes_crypt_operations = {
    .get_crypt_file_length = aes_get_crypt_file_length,
    .is_right_password = aes_is_right_password,
    .encrypt = aes_encrypt,
    .decrypt = aes_decrypt,
};