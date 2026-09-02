#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <endian.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include <openssl/sha.h>

#include "btc_miner.h"


// global variables ////////////////////////////////////////////////////////////
volatile uint64_t nonce_cnt = 0;
volatile uint64_t tot_nonce_cnt = 0;
volatile uint32_t job_id = 0;
volatile uint32_t winning_nonce = 0;
volatile int block_found = 0;
volatile int should_stop = 0;
int nprocs = 0;
int edge_fd = -1;

block128_t master_template = {};
hash_t master_midstate = {};
hash_t global_target = {};
hash_t found_block_hash = {};

pthread_mutex_t job_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t job_cond = PTHREAD_COND_INITIALIZER;

// thread pool /////////////////////////////////////////////////////////////////

typedef struct {
    int thread_id;
} worker_cfg_t;

void *
miner_worker(void *arg)
{
    pthread_setname_np(pthread_self(), "worker");
    worker_cfg_t *cfg = arg;

    cuda_init();

    uint32_t job_id_local = 0;
    chunk2_t chunk2;

    uint32_t loop_cnt = 0;
    int threads_per_block = 768;
    int sm_count = 48;
    int blocks_per_sm = 4096;
    // uint32_t total_blocks = 48 * 88000; // full for one
    cuda_get_tuned(&threads_per_block, &sm_count);
    uint64_t gpu_range = (uint64_t)threads_per_block * sm_count * blocks_per_sm;
    int mul = (uint64_t)NONCE_MAX / gpu_range;
    uint32_t last_range = NONCE_MAX - gpu_range * mul;
    uint32_t last_bpsm = last_range / (threads_per_block * sm_count) + 1;

    while (1) {
        pthread_mutex_lock(&job_mutex);
        while (!should_stop && (nonce_cnt >= NONCE_MAX || block_found) && (job_id_local == job_id)) {
            if (nonce_cnt >= NONCE_MAX)
                eventfd_write(edge_fd, 1);
            pthread_cond_wait(&job_cond, &job_mutex);
        }

        if (unlikely(should_stop)) {
            pthread_mutex_unlock(&job_mutex);
            break;
        }

        if (unlikely(job_id_local != job_id)) {
            job_id_local = job_id;
#if CUDASHA256_NOSWAP
            chunk_swap32((void *)&chunk2, (void *)&master_template.chunks.c2, 16);
#else
            memcpy(&chunk2, &master_template.chunks.c2, sizeof(chunk2));
#endif
        }
        pthread_mutex_unlock(&job_mutex);

        uint64_t start = __sync_fetch_and_add(&nonce_cnt, gpu_range);
        uint32_t bpsm = blocks_per_sm;

        if ((start + gpu_range) > NONCE_MAX) {
            __sync_add_and_fetch(&tot_nonce_cnt, last_range);
            bpsm = last_bpsm;
        }
        else
            __sync_add_and_fetch(&tot_nonce_cnt, gpu_range);

        uint32_t h_block_found = 0;
        uint32_t h_winning_nonce = 0;
        hash_t h_found_hash = {0};

        cuda_sha256d_btc(
                master_midstate.u32,
                (void *)&chunk2,
                global_target.u32,
                start,
                // threads_per_block,
                // total_blocks,
                bpsm,
                loop_cnt++ & 1,
                &h_winning_nonce,
                &h_block_found,
                h_found_hash.u32
        );

        if (unlikely(h_block_found) && __sync_bool_compare_and_swap(&block_found, 0, 1)) {
            winning_nonce = h_winning_nonce;
            memcpy(found_block_hash.u8, h_found_hash.u8, 32);

            printf("<%08x> ", winning_nonce);
            hash_dump(found_block_hash.u32);

            eventfd_write(edge_fd, 1);
        }
    }
    cuda_free();
    pthread_exit(0);
}

////////////////////////////////////////////////////////////////////////////////

int
main()
{

#ifdef CUDASHA256_TEST
    if (cuda_sha256_test())
        return 1;
    // return 0;
#endif

    // blocking SIGPIPE
    sigset_t signal_set;
    sigemptyset(&signal_set);
    sigaddset(&signal_set, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &signal_set, NULL);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }
    struct sockaddr_un addr = {
            .sun_family = AF_UNIX,
            .sun_path = SOCKET_NAME,
    };
    printf("Connect to controller... ");
    fflush(stdout);
    while (connect(fd, &addr, offsetof(struct sockaddr_un, sun_path) + sizeof(SOCKET_NAME) - 1) < 0) {
        if (errno == ECONNREFUSED || errno == ENOENT) {
            sleep(1);
            continue;
        }
        perror("connect");
        return 1;
    }
    printf("Done!\n");

    if ((edge_fd = eventfd(0, EFD_NONBLOCK)) < 0) {
        perror("eventfd");
        return 1;
    }
    int timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (timer_fd < 0) {
        perror("timer_fd");
        return 1;
    }
    struct itimerspec tspec = {
            .it_interval = { .tv_sec = 60, },
            .it_value = { .tv_sec = 60, },
    };
    if (timerfd_settime(timer_fd, 0, &tspec, 0) < 0) {
        perror("timer_settime");
        return 1;
    }

    struct pollfd fds[] = {
            [FD_CTRL] = { .fd = fd, .events = POLLIN, },
            [FD_WORKER] = { .fd = edge_fd, .events = POLLIN, },
            [FD_TIMER] = { .fd = timer_fd, .events = POLLIN, },
    };

    // nprocs = get_nprocs();
    nprocs = 1;
    pthread_t threads[nprocs];
    worker_cfg_t cfgs[nprocs];
    for (int i = 0; i < nprocs; ++i) {
        cfgs[i].thread_id = i;
        pthread_create(&threads[i], 0, miner_worker, &cfgs[i]);
    }

    uint64_t last_nonce = 0;
    master_template = (block128_t) {
        .full = {
                .ver = 3,
                .prev_hash = {},
                .merkle_root = {},
                .time = 0,
                .bits = 0,
                .nonce = 0,
                .end = 0x80,
                .pad = {},
                .len_be = htobe64(BLOCK_SZ * 8),
        },
    };

    while (!should_stop) {
        int rdy = poll(fds, sizeof(fds) / sizeof(*fds), -1);
        if (rdy == -1) {
            if (errno == EINTR)
                continue;
            perror("poll");
            break;
        }
        if (!rdy)
            continue;

        pthread_mutex_lock(&job_mutex);

        if (fds[FD_CTRL].revents & POLLIN) {
            int32_t cmd;
            ssize_t sz = recv(fd, &cmd, sizeof(cmd), MSG_WAITALL);

            if (sz <= 0 || cmd == CMD_STOP) {
                printf("STOP!%s%s\n", (sz>0)? "": " [Error] ", (sz>0)? "": strerror(errno));
                should_stop = 1;
                pthread_cond_broadcast(&job_cond);
                pthread_mutex_unlock(&job_mutex);
                break;
            }
            if (cmd == CMD_NEW_JOB) {
                recv(fd, master_template.u8, sizeof(block_t), MSG_WAITALL);
                SHA256_CTX ctx;
                SHA256_Init(&ctx);
                SHA256_Transform(&ctx, (void *)&master_template);
                memcpy(master_midstate.u32, ctx.h, sizeof(master_midstate));
                hash_target_create(master_template.full.bits, global_target.u32);
                // printf("target:    ");
                // hash_dump(global_target.u32);
                ++job_id;
                nonce_cnt = 0;
                block_found = 0;
                pthread_cond_broadcast(&job_cond);
                printf("new job\n");
                for (int i = 0; i < 80; ++i)
                    printf("%02x", master_template.u8[i]);
                putchar('\n');
            }
        }

        if (fds[FD_WORKER].revents & POLLIN) {
            eventfd_read(edge_fd, &(eventfd_t){0});
            if (block_found) {
                uint32_t cmd = CMD_FOUND;
                send(fd, &cmd, sizeof(uint32_t), 0);
                send(fd, (void *)&winning_nonce, sizeof(winning_nonce), 0);
                send(fd, &master_template.full.time, sizeof(master_template.full.time), 0);
                // send(fd, found_block_hash.u8, 32, 0);
                // block_found = 0;
                __sync_lock_release(&block_found);
                cmd = CMD_REQUEST;
                send(fd, &cmd, sizeof(uint32_t), 0);
                fsync(fd);
                printf("reported & requested\n");
            }
            else {
                // all nonces have been used up
                if (unlikely(nonce_cnt >= NONCE_MAX)) {
                    uint32_t t = time(0);
                    if (t != master_template.full.time) {
                        master_template.full.time = t;
                        ++job_id;
                        nonce_cnt = 0;
                        // block_found = 0;
                        __sync_lock_release(&block_found);
                        pthread_cond_broadcast(&job_cond);
                        // printf("new time\n");
                    } else {
                        uint32_t cmd = CMD_REQUEST;
                        send(fd, &cmd, sizeof(uint32_t), 0);
                        fsync(fd);
                        printf("requested\n");
                    }
                }
            }
        }

        if (fds[FD_TIMER].revents & POLLIN) {
            read(timer_fd, &(uint64_t){0}, sizeof(uint64_t));

            uint64_t cur_nonce = tot_nonce_cnt;
            uint64_t diff = cur_nonce - last_nonce;
            last_nonce = cur_nonce;
            printf(" -> %6.2f MH/s\n", (double)diff / 60000000.0);
            fflush(stdout);
        }

        pthread_mutex_unlock(&job_mutex);
    }

    for (int i = 0; i < nprocs; ++i)
        pthread_join(threads[i], 0);

    return 0;
}
