#include <pthread.h>

#include "filecrypt.h"

int global_encrypt = FALSE;
int global_decrypt = FALSE;
const char *global_password = NULL;
int global_algorithm_id = -1;
int global_debug_mode = FALSE;

int only_main = TRUE; // just the main thread, no need to create another threads
int can_exit = FALSE;

int thread_num = 0;
pthread_t *thread_ids = NULL;

typedef struct node {
    char *file_name;
    time_t enter_time;
    struct node *next;
} node;

node **heads = NULL, **tails = NULL;
pthread_spinlock_t *node_locks = NULL;

int current = 0;
uint64_t *total_file_size = NULL;

void begin_crypt(const char *file_name, time_t enter_time, int thread_id) {
    printf("thread: %2d waited %5ds\t%s\n", thread_id, time(NULL) - enter_time, file_name);
}

void end_crypt(const char *file_name, time_t begin_time, int thread_id) {
    printf("thread: %2d crypt %5ds\t%s\n", thread_id, time(NULL) - begin_time, file_name);
}

node *get_work(int index) {
    node *p = NULL;
    pthread_spin_lock(&node_locks[index]);
    if (heads[index]) {
        p = heads[index];
        if (heads[index] == tails[index]) {
            heads[index] = tails[index] = NULL;
        } else {
            heads[index] = heads[index]->next;
        }
    }
    pthread_spin_unlock(&node_locks[index]);
    return p;
}

int select_min() {
    uint64_t min = total_file_size[current];
    int min_index = current;
    int i, j;
    for (i = (current + 1) % thread_num, j = 0; j < thread_num - 1; j++, i = (i + 1) % thread_num) {
        if (total_file_size[i] < min) {
            min = total_file_size[i];
            min_index = i;
        }
    }
    current = min_index;
    return min_index;
}

void put_work(char *file_name, uint64_t file_size) {
    int index = select_min();
    total_file_size[index] += file_size;
    node *new_node = (node *)malloc(sizeof(node));
    new_node->file_name = strdup(file_name);
    new_node->next = NULL;
    if (global_debug_mode) {
        printf("put %s-0x%lx to %d\n", file_name, file_size, index);
        new_node->enter_time = time(NULL);
    }
    pthread_spin_lock(&node_locks[index]);
    if (tails[index] == NULL) {
        heads[index] = tails[index] = new_node;
    } else {
        tails[index]->next = new_node;
        tails[index] = new_node;
    }
    pthread_spin_unlock(&node_locks[index]);
}

void doing_work(char *file_name, uint64_t file_size) {
    if (only_main) {
        time_t current_time = time(NULL);
        crypt_file(file_name, global_encrypt, global_decrypt, global_password, global_algorithm_id);
        if (global_debug_mode) {
            end_crypt(file_name, current_time, 0);
        }
    } else {
        put_work(file_name, file_size);
    }
}

void *thread_function(void *argument) {
    int index = (int)argument;
    if (global_debug_mode) {
        printf("create thread: %d\n", index);
    }
    sleep(1);
    char *file_name = NULL;
    node *p = NULL;
    while ((p = get_work(index)) != NULL || !can_exit) {
        if (p) {
            time_t current_time = time(NULL);
            if (global_debug_mode) {
                begin_crypt(p->file_name, p->enter_time, index);
            }
            crypt_file(p->file_name, global_encrypt, global_decrypt, global_password, global_algorithm_id);
            if (global_debug_mode) {
                end_crypt(p->file_name, current_time, index);
            }
            free(p->file_name);
            free(p);
        }
    }
    if (global_debug_mode) {
        printf("thread: %2d exit\n", index);
    }
}

void thread_manager_init(int encrypt, int decrypt, const char *password, int algorithm_id,
                         int num, int debug_mode) {
    global_encrypt = encrypt;
    global_decrypt = decrypt;
    global_password = password;
    global_algorithm_id = algorithm_id;
    global_debug_mode = debug_mode;
    if (global_encrypt || global_decrypt) {
        int i;
        thread_num = num;
        only_main = thread_num == 1;
        if (!only_main) {
            thread_ids = (pthread_t *) calloc(sizeof(pthread_t), thread_num);
            heads = (node **) calloc(sizeof(node *), thread_num);
            tails = (node **) calloc(sizeof(node *), thread_num);
            node_locks = (pthread_spinlock_t *) calloc(sizeof(pthread_spinlock_t), thread_num);
            total_file_size = (uint64_t *) calloc(sizeof(uint64_t), thread_num);
            for (i = 0; i < thread_num; i++) {
                pthread_create(&thread_ids[i], NULL, thread_function, (void *)i);
                pthread_spin_init(&node_locks[i], PTHREAD_PROCESS_PRIVATE);
            }
        }
    }
    if (global_debug_mode) {
        printf("only main: %d, thread num: %d\n", only_main, thread_num);
    }
}

void wait_threads_exit() {
    if (only_main) {
        return;
    }
    can_exit = TRUE;
    for (int i = 0; i < thread_num; i++) {
        pthread_join(thread_ids[i], NULL);
    }
}