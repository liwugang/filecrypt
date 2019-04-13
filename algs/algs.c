#include "algs.h"

struct crypt_operations *algs_array[ALGORITHM_MAX];

void init_algs() {
    algs_array[ALGORITHM_XOR] = &xor_crypt_operations;
    algs_array[ALGORITHM_AES] = &aes_crypt_operations;
}

char *get_algorithm_name(int algorithm_id) {
    switch (algorithm_id) {
    case ALGORITHM_XOR:
        return "xor";
    case ALGORITHM_AES:
        return "aes";
    default:
        return "unkown";
    }
}

crypt_operations *get_crypt_ops(int algs) {
    if (algs >= 0 && algs < ALGORITHM_MAX && algs_array[algs] != NULL) {
        return algs_array[algs];
    } else {
        return NULL;
    }
}

int algs_valid(file_crypt_info *crypt_info) {
    crypt_operations *ops = get_crypt_ops(crypt_info->crypt_algorithm);
    if (ops) {
        if (ops->get_crypt_file_length(crypt_info) + crypt_info->crypt_file_offset == \
                crypt_info->crypt_file_length) {
            return TRUE;
        }
    }
    return FALSE;
}

void init_algs_info(file_crypt_info *crypt_info) {
    crypt_operations *ops = get_crypt_ops(crypt_info->crypt_algorithm);
    if (!ops) {
        return;
    }
    crypt_info->crypt_file_offset = sizeof(file_crypt_info) + crypt_info->file_name_length;
    crypt_info->crypt_file_length = ops->get_crypt_file_length(crypt_info)
            + crypt_info->crypt_file_offset;
}

int is_right_password(const char *user_password, uint8_t *password_hash) {
    int result = FALSE;
    uint8_t calculate_hash[HASH256_SIZE];
    uint8_t *buffer = NULL;

    buffer = (uint8_t *) malloc(strlen(user_password) + 1 + 8);
    *(uint32_t *)buffer = FIRST_MAGIC;
    *(uint32_t *)(buffer + 4) = SECOND_MAGIC;
    strcpy(buffer + 8, user_password);
    result = get_hash(HASH_SHA256, buffer, strlen(user_password) + 8, (uint8_t *)&calculate_hash);
#ifdef DEBUG
    int i;
    printf("calculate: ");
    for (i = 0; i < 32; i++) {
        printf("%x%x", (calculate_hash[i] >> 4) & 0xF, calculate_hash[i] & 0xF);
    }
    printf("  saved:");
    for (i = 0; i < 32; i++) {
        printf("%x%x", (password_hash[i] >> 4) & 0xF, password_hash[i] & 0xF);
    }
    printf("\n");
#endif
    if (result == TRUE && !memcmp(calculate_hash, password_hash, HASH256_SIZE)) {
        result = TRUE;
    } else {
        result = FALSE;
    }
    free(buffer);
    return result;
}

int get_password_hash(const char *user_password, uint8_t *password_hash) {
    int result = FALSE;
    uint8_t *buffer = NULL;

    buffer = (uint8_t *) malloc(strlen(user_password) + 1 + 8);
    *(uint32_t *)buffer = FIRST_MAGIC;
    *(uint32_t *)(buffer + 4) = SECOND_MAGIC;
    strcpy(buffer + 8, user_password);
    result = get_hash(HASH_SHA256, buffer, strlen(user_password) + 8, password_hash);
#ifdef DEBUG
    int i;
    printf("password hash:");
    for (i = 0; i < 32; i++) {
        printf("%x%x", (password_hash[i] >> 4) & 0xF, password_hash[i] & 0xF);
    }
    printf("\n");
#endif
    free(buffer);
    return result;
}