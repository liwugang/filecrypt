#include "algs.h"


struct crypt_operations *algs_array[ALGORITHM_MAX];

void init_algs() {
    algs_array[ALGORITHM_XOR] = &xor_crypt_operations;
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
    crypt_info->crypt_file_length = ops->get_crypt_file_length(crypt_info) + crypt_info->crypt_file_offset;
}