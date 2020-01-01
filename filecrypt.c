#include "filecrypt.h"

static int crypt_info_valid(file_crypt_info *crypt_info) {
    uint64_t crypt_file_length;
    if (crypt_info->magic[0] != FIRST_MAGIC || crypt_info->magic[1] != SECOND_MAGIC) {
        return FALSE;
    }
    return algs_valid(crypt_info);
}

void init_crypt_info(file_crypt_info *crypt_info) {
    memset(crypt_info, 0, sizeof(*crypt_info));
    crypt_info->magic[0] = FIRST_MAGIC;
    crypt_info->magic[1] = SECOND_MAGIC;
}

char *get_crypt_file_name(const char *file_name) {
    char *crypt_file_name = NULL;
    struct timespec tp;
    if (clock_gettime(CLOCK_REALTIME, &tp) != -1) {
        char buffer[128];
        sprintf(buffer, "%lld%lld", tp.tv_sec, tp.tv_nsec);
        crypt_file_name = malloc(strlen(buffer) + 1);
        strcpy(crypt_file_name, buffer);
    } else {
        crypt_file_name = (char *) malloc(strlen(file_name) + strlen("_encrypted") + 1);
        strcpy(crypt_file_name, file_name);
        strcat(crypt_file_name, "_encrypted");
    }
    return crypt_file_name;
}

void usage(const char *exec_name) {
    printf("%s: A simple encrypt/decrypt file tool\n\n", exec_name);
    printf("usage: %s [-e|-d] [-r] [-p password] [-a algorithm] [-h] [-t num_threads] [-D] path\n", exec_name);

    printf("  -e        encrypt the files in the path\n");
    printf("  -d        decrypt the files in the path\n");
    printf("  -r        recursive the path\n");
    printf("  -p        password to encrypt or decrypt\n");
    printf("  -a        select algorithm to encrypt and decrypt the files which encrypted by it\n");
    printf("            supported algorithms: [xor, aes], xor is default\n");
    printf("  -t        thread num to work, range: [1 - %d], default: 1\n", get_nprocs_conf());
    printf("  -D        open debug mode\n");
    printf("  -h        show this usage\n");
}

int crypt_file(const char *file_name, int encrypt, int decrypt, const char *password, int algorithm_id) {
    int fd = -1, wfd = -1;
    int encrypted = FALSE;
    int delete_origin = FALSE;
    int delete_new = FALSE;
    uint64_t file_length;
    uint64_t dest_file_length;
    uint64_t need_space_size;
    crypt_operations *ops;

    struct stat st;
    file_crypt_info crypt_info;

    char *dest_file_name = NULL;

    void *source_addr = MAP_FAILED;
    void *dest_addr = MAP_FAILED;

    char *dup_path = strdup(file_name);
    chdir(dirname(dup_path));
    free(dup_path);

    fd = open(file_name, O_RDONLY);
    if (fd < 0) {
        printf("open file error %s - %s!\n", file_name, strerror(errno));
        return -1;
    }
    fstat(fd, &st);
    file_length = st.st_size;

    if (file_length > sizeof(crypt_info)) {
        if (read(fd, &crypt_info, sizeof(crypt_info)) != sizeof(crypt_info)) {
            goto CLEANUP;
        }
        if (crypt_info_valid(&crypt_info)) {
            dest_file_name = (char *) malloc(crypt_info.file_name_length);
            dest_file_length = crypt_info.file_length;
            need_space_size = dest_file_length + AES_BLOCK_SIZE; // need more space. If filesize > AES_MAX_SIZE
            read(fd, dest_file_name, crypt_info.file_name_length);
            // TODO: should check the file length equal to crypt_info.crypt_file_length
            encrypted = TRUE;
        }
    }
    if (!encrypted) {
        init_crypt_info(&crypt_info);
        crypt_info.file_length = file_length;
        crypt_info.file_name_length = strlen(file_name) + 1;
        crypt_info.crypt_algorithm = algorithm_id == ALGORITHM_MAX ? ALGORITHM_DEFAULT : algorithm_id;
        init_algs_info(&crypt_info);
        dest_file_name = get_crypt_file_name(file_name);
        dest_file_length = crypt_info.crypt_file_length;
        need_space_size = dest_file_length;
    }
    if (crypt_info.crypt_algorithm != algorithm_id && algorithm_id != ALGORITHM_MAX) {
        encrypt = decrypt = FALSE;
    }
    if (encrypt) {
        if (encrypted) {
            printf("%-30shave encrypted     %s\n", file_name, get_algorithm_name(crypt_info.crypt_algorithm));
            goto CLEANUP;
        }
    } else if (decrypt) {
        if (!encrypted) {
            printf("%-30shave not encrypted\n", file_name);
            goto CLEANUP;
        }
    } else {
        if (encrypted) {
            printf("%-30shave encrypted     %s     %s\n", file_name,
                    get_algorithm_name(crypt_info.crypt_algorithm), dest_file_name);
        } else {
            printf("%-30shave not encrypted\n", file_name);
        }
        goto CLEANUP;
    }

    ops = get_crypt_ops(crypt_info.crypt_algorithm);
    if (!ops) {
        printf("the algorithm: %d is not supported!\n", crypt_info.crypt_algorithm);
        goto CLEANUP;
    }
    if (!strlen(password)) {
        printf("%-30sthe password must be at least one!\n", file_name);
        goto CLEANUP;
    }
    source_addr = mmap(NULL, file_length, PROT_READ, MAP_PRIVATE, fd, 0);
    if (source_addr == MAP_FAILED) {
        printf("%-30ssource addr error: %d!\n", file_name, errno);
        goto CLEANUP;
    }

    wfd = open(dest_file_name, O_RDWR | O_CREAT, st.st_mode | 0x1FF);
    ftruncate(wfd, need_space_size);
    dest_addr = mmap(NULL, need_space_size, PROT_READ | PROT_WRITE, MAP_SHARED, wfd, 0);
    if (dest_addr == MAP_FAILED) {
        printf("%-30sdest source error: %d\n", file_name, errno);
        goto CLEANUP_SOURCE;
    }

    if (encrypt) {
        if (ops->encrypt(&crypt_info, password, source_addr, dest_addr + crypt_info.crypt_file_offset)) {
            memcpy(dest_addr, &crypt_info, sizeof(crypt_info));
            memcpy(dest_addr + sizeof(crypt_info), file_name, strlen(file_name) + 1);
            printf("%-30sencrypt done!\n", file_name);
            delete_origin = TRUE;
        } else {
            printf("%-30sencrypt failed!\n", file_name);
            delete_new = TRUE;
        }
    } else {
        if (!ops->is_right_password(&crypt_info, password)) {
            printf("%-30sthe password is not right!\n", file_name);
            delete_new = TRUE;
        } else {
            if (ops->decrypt(&crypt_info, password, source_addr + crypt_info.crypt_file_offset, dest_addr)) {
                printf("%-30sdecrypt done!\n", file_name);
                delete_origin = TRUE;
            } else {
                printf("%-30sdecrypt failed!\n", file_name);
                delete_new = TRUE;
            }
        }
    }
    munmap(dest_addr, need_space_size);
    if (need_space_size != dest_file_length) {
        ftruncate(wfd, dest_file_length);
    }

CLEANUP_SOURCE:
    munmap(source_addr, file_length);

CLEANUP:
    if (fd != -1) close(fd);
    if (wfd != -1) close(wfd);
    if (delete_origin) unlink(file_name);
    if (delete_new) unlink(dest_file_name);
    free(dest_file_name);
    return TRUE;
}

void walk_paths(char *path, int encrypt, int decrypt, int recursive, const char *password, int algorithm_id) {
    FTS *fts;
    FTSENT *ftsent;

    char *real_path = realpath(path, NULL);
    char *paths[2] = {real_path, NULL};
    if (!real_path) {
        printf("path is not exits!\n");
        return;
    }
    fts = fts_open(paths, 0, NULL);
    if (!fts) {
        printf("open fts error!\n");
        return;
    }
    while ((ftsent = fts_read(fts)) != NULL) {
        switch (ftsent->fts_info) {
        case FTS_D:
            if (!recursive && strcmp(ftsent->fts_path, real_path)) {
                fts_set(fts, ftsent, FTS_SKIP);
            }
            break;
        case FTS_F:
            // crypt_file(ftsent->fts_name, encrypt, decrypt, password, algorithm_id);
            doing_work(ftsent->fts_path, ftsent->fts_statp->st_size);
            // ftsent->fts_name);
            break;
        default:
            break;
        }
    }
    free(real_path);
    fts_close(fts);
}

int main(int argc, char **argv) {
    int ch;
    int algorithm_id = ALGORITHM_MAX;
    int list = FALSE;
    int encrypt = FALSE;
    int decrypt = FALSE;
    int recursive = FALSE;
    const char *password = NULL;
    const char *path = NULL;
    int password_space_size = 0;
    char *new_password = NULL;
    int thread_num = 1; // default use the main thread
    int debug_mode = FALSE;

    struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
		{"encrypt", no_argument, NULL, 'e'},
		{"decrypt", no_argument, NULL, 'd'},
		{"recursive", no_argument, NULL, 'r'},
		{"password", required_argument, NULL, 'p'},
        {"algroithm", required_argument, NULL, 'a'},
        {"thread", required_argument, NULL, 't'},
        {"debug", no_argument, NULL, 'D'},
		{NULL, 0, NULL, 0}
    };

    while ((ch = getopt_long(argc, argv, "hedrp:a:t:D", long_options, NULL)) != -1) {
        switch (ch) {
        case 'h':
            usage(argv[0]);
            exit(-1);
        case 'e':
            encrypt = TRUE;
            break;
        case 'd':
            decrypt = TRUE;
            break;
        case 'r':
            recursive = TRUE;
            break;
        case 'p':
            password = optarg;
            break;
        case 'a':
            if (!strcmp(optarg, "xor")) {
                algorithm_id = ALGORITHM_XOR;
            } else if (!strcmp(optarg, "aes")) {
                algorithm_id = ALGORITHM_AES;
            } else {
                printf("have not support this algorithm: %s\n", optarg);
                exit(-1);
            }
            break;
        case 't':
            thread_num = atoi(optarg);
            break;
        case 'D':
            debug_mode = TRUE;
            break;
        default:
            usage(argv[0]);
            exit(-1);
        }
    }

    if (encrypt && decrypt) {
        printf("encrypt and decrypt only one!\n");
        exit(-1);
    }

    if ((encrypt || decrypt) && !password) {
        printf("need password!\n");
        exit(-1);
    }
    if (thread_num < 1 || thread_num > get_nprocs_conf()) {
        printf("thread nums is not valid! must be in range [1, %d]\n", get_nprocs_conf());
        exit(-1);
    }

    if (optind == argc) {
        usage(argv[0]);
        exit(-1);
    }

    init_algs();

    if (password) {
        password_space_size = ((strlen(password) + (AES_BLOCK_SIZE - 1)) / AES_BLOCK_SIZE + 1)
                * AES_BLOCK_SIZE;
        new_password = calloc(password_space_size, 1);
        strcpy(new_password, password);
    }

    thread_manager_init(encrypt, decrypt, new_password, algorithm_id, thread_num, debug_mode);
    for (; optind < argc; optind++) {
        walk_paths(argv[optind], encrypt, decrypt, recursive, new_password, algorithm_id);
    }
    wait_threads_exit();
    free(new_password);
    return 0;
}