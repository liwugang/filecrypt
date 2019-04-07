#ifndef ALGS_H
#define ALGS_H

#include "../filecrypt.h"

#define ALGORITHM_XOR   0
#define ALGORITHM_DES   1 // TODO

#define ALGORITHM_MAX   16

void init_algs();
crypt_operations *get_crypt_ops(int algs);
int algs_valid(file_crypt_info *crypt_info);
void init_algs_info(file_crypt_info *crypt_info);

extern crypt_operations xor_crypt_operations;

#endif // ALGS_H