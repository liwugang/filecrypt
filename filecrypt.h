#ifndef FILE_CRYPT
#define FILE_CRYPT

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <fcntl.h>
#include <fts.h>
#include <libgen.h>
#include <getopt.h>
#include <time.h>

#include <errno.h>

#define FIRST_MAGIC  0x454C4946 // 'FILE'
#define SECOND_MAGIC 0x50595243 // 'CRYP'

#define TRUE    1
#define FALSE   0

#define VERSION_ENCRYPT_FILENAME       1
#define VERSION_CURRENT                1

typedef struct file_crypt_info {
    uint32_t magic[2];
    uint64_t file_name_length;
    uint64_t file_length;
    uint64_t crypt_file_length;
    uint64_t crypt_file_offset;
    uint64_t crypt_algorithm;
    uint64_t key_length;
    uint8_t key[256];
} file_crypt_info;

typedef struct crypt_operations {
    uint64_t (*get_crypt_file_length) (file_crypt_info *crypt_info);
    int (*is_right_password) (file_crypt_info *crypt_info, const char *user_password);
    int (*encrypt) (file_crypt_info *crypt_info, const char *user_password, void *input_data, void *output_data);
    int (*decrypt) (file_crypt_info *crypt_info, const char *user_password, void *input_data, void *output_data);
} crypt_operations;

#include "algs/algs.h"

#endif // FILE_CRYPT