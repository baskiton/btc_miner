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
#include <sys/sysinfo.h>
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
volatile int idle_workers = 0;
int nprocs = 0;
int edge_fd = -1;

block128_t master_template = {};
hash_t master_midstate = {};
hash_t global_target = {};
hash_t found_block_hash = {};

pthread_mutex_t job_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t job_cond = PTHREAD_COND_INITIALIZER;

////////////////////////////////////////////////////////////////////////////////

static int inline
hash_check(const uint32_t h[8], const uint32_t t[8])
{
    for (int i = 8; i--;) {
        if (likely(h[i] > t[i]))
            return 0;
        if (unlikely(h[i] < t[i]))
            return 1;
    }
    return 1;
}

// thread pool /////////////////////////////////////////////////////////////////

#define WORKER_RANGE_SZ (1ULL << 20)

typedef struct {
    int thread_id;
} worker_cfg_t;

void *
miner_worker(void *arg)
{
    worker_cfg_t *cfg = arg;

    uint32_t job_id_local = 0;
    chunk2_t chunk2;

    struct {
        SHA256_CTX r1_base_ctx,
                r2_base_ctx;
        union {
            SHA256_CTX r1_work_ctx;
            round2_block_t r2;
        };
        SHA256_CTX r2_work_ctx;
    } ctx = {};

    SHA256_Init(&ctx.r2_base_ctx);

    while (1) {
        pthread_mutex_lock(&job_mutex);
        while (!should_stop && (nonce_cnt >= NONCE_MAX || block_found) && (job_id_local == job_id)) {
            if (nonce_cnt >= NONCE_MAX && __sync_add_and_fetch(&idle_workers, 1) >= nprocs)
                eventfd_write(edge_fd, 1);
            pthread_cond_wait(&job_cond, &job_mutex);
        }

        if (unlikely(should_stop)) {
            pthread_mutex_unlock(&job_mutex);
            break;
        }

        if (unlikely(job_id_local != job_id)) {
            job_id_local = job_id;
            memcpy(&chunk2, &master_template.chunks.c2, sizeof(chunk2));
            memcpy(ctx.r1_base_ctx.h, master_midstate.u8, sizeof(master_midstate));
            // printf("[%i] new job %i\n", cfg->thread_id, job_id_local);
        }
        pthread_mutex_unlock(&job_mutex);

        uint64_t start = __sync_fetch_and_add(&nonce_cnt, WORKER_RANGE_SZ);
        __sync_add_and_fetch(&tot_nonce_cnt, WORKER_RANGE_SZ);
        if (unlikely(start > NONCE_MAX))
            continue;
        uint64_t end = start + WORKER_RANGE_SZ;
        if (unlikely(end > NONCE_MAX))
            end = NONCE_MAX;

        for (uint64_t nonce = start; nonce < end; ++nonce) {
            if (unlikely(!(nonce & ((1 << 13) - 1)) && (job_id_local != job_id || block_found || should_stop)))
                break;
            chunk2.nonce = nonce;

            memcpy(&ctx.r1_work_ctx, &ctx.r1_base_ctx, sizeof(SHA256_CTX));
            memcpy(&ctx.r2_work_ctx, &ctx.r2_base_ctx, sizeof(SHA256_CTX));
            SHA256_Transform(&ctx.r1_work_ctx, (void *)&chunk2);
            hash_swap(ctx.r1_work_ctx.h);
            ctx.r2.end = 0x80;
            ctx.r2.len_be = htobe64(sizeof(hash_t) * 8);
            SHA256_Transform(&ctx.r2_work_ctx, (void *)&ctx.r2);
            hash_swap(ctx.r2_work_ctx.h);

            if (unlikely(hash_check(ctx.r2_work_ctx.h, global_target.u32))) {
                if (__sync_bool_compare_and_swap(&block_found, 0, 1)) {
                    winning_nonce = nonce;
                    memcpy(found_block_hash.u8, ctx.r2_work_ctx.h, sizeof(found_block_hash));

                    printf("<%08x> ", winning_nonce);
                    hash_dump(ctx.r2_work_ctx.h);

                    eventfd_write(edge_fd, 1);
                    pthread_mutex_lock(&job_mutex);
                    pthread_cond_broadcast(&job_cond);
                    pthread_mutex_unlock(&job_mutex);
                }
                break;
            }
        }
    }
    pthread_exit(0);
}

////////////////////////////////////////////////////////////////////////////////

int
main()
{
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

    nprocs = get_nprocs();
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
                idle_workers = 0;
                ++job_id;
                nonce_cnt = 0;
                block_found = 0;
                pthread_cond_broadcast(&job_cond);
                printf("new job\n");
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
                fsync(fd);
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
                        idle_workers = 0;
                        ++job_id;
                        nonce_cnt = 0;
                        block_found = 0;
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
