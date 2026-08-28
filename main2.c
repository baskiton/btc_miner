#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/timerfd.h>
#include <sys/un.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include <openssl/sha.h>


#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define SHA256_CHUNK_SZ 64
#define NONCE_MAX (1ULL << 32)

#define FD_CTRL 0
#define FD_WORKER 1
#define FD_TIMER 2

typedef uint64_t uint256_t[4];

typedef union {
    uint32_t u32[SHA256_DIGEST_LENGTH / sizeof(uint32_t)];
    uint8_t u8[SHA256_DIGEST_LENGTH];
} hash_t;

typedef struct {
    uint32_t ver;
    hash_t prev_hash;
    hash_t merkle_root;
    uint32_t time;
    uint32_t bits;
    uint32_t nonce;
} block_t;
#define BLOCK_SZ sizeof(block_t)    // 80

typedef struct {
    uint32_t ver;
    hash_t prev_hash;
    union {
        uint8_t merkle_head_u8[28];
        uint32_t merkle_tail_u8[7];
    };
} chunk1_t;

typedef struct {
    union {
        uint8_t merkle_tail_u8[4];
        uint32_t merkle_tail_u32;
    };
    uint32_t time;
    uint32_t bits;
    uint32_t nonce;

    uint8_t end;
    uint8_t pad[64 - 16 - 9];
    uint64_t len_be;
} chunk2_t;

typedef struct {
    uint32_t ver;
    hash_t prev_hash;
    hash_t merkle_root;
    uint32_t time;
    uint32_t bits;
    uint32_t nonce;

    uint8_t end;
    uint8_t pad[128 - BLOCK_SZ - 9];
    uint64_t len_be;
} cunk_full_t;

typedef union {
    cunk_full_t full;
    struct {
        chunk1_t c1;
        chunk2_t c2;
    } chunks;
    uint8_t raw_u8[128];
    uint64_t raw_u64[16];
} block128_t;

typedef struct {
    hash_t hash;
    uint8_t end;
    uint8_t pad[64 - sizeof(hash_t) - 9];
    uint64_t len_be;
} round2_block_t;

// commands ////////////////////////////////////////////////////////////////////

#define SOCKET_NAME "\0/tmp/btc_like"

#define CMD_IN_NEW_JOB 1
#define CMD_IN_STOP (-1)

#define CMD_OUT_FOUND 100
#define CMD_OUT_REQUEST 101

////////////////////////////////////////////////////////////////////////////////

// global variables ////////////////////////////////////////////////////////////
volatile uint64_t nonce_cnt = 0;
volatile uint32_t job_id = 0;
volatile uint32_t winning_nonce = 0;
volatile int block_found = 0;
volatile int should_stop = 0;
volatile int idle_workers = 0;
int nprocs = 0;
int edge_fd = -1;

block128_t master_template;
hash_t master_midstate = {};
hash_t global_target = {};
hash_t found_block_hash = {};

pthread_mutex_t job_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t job_cond = PTHREAD_COND_INITIALIZER;

////////////////////////////////////////////////////////////////////////////////

static void
hash_reverse(uint32_t t[8])
{
    for (int i = 0; i < 4; ++i) {
        uint32_t x = t[i];
        t[i] = t[7 - i];
        t[7 - i] = x;
    }
}

static inline void
hash_swap(uint32_t *h)
{
    h[0] = __builtin_bswap32(h[0]);     // only for le-arch
    h[1] = __builtin_bswap32(h[1]);     // only for le-arch
    h[2] = __builtin_bswap32(h[2]);     // only for le-arch
    h[3] = __builtin_bswap32(h[3]);     // only for le-arch
    h[4] = __builtin_bswap32(h[4]);     // only for le-arch
    h[5] = __builtin_bswap32(h[5]);     // only for le-arch
    h[6] = __builtin_bswap32(h[6]);     // only for le-arch
    h[7] = __builtin_bswap32(h[7]);     // only for le-arch
}

static void
hash_target_create(uint32_t bits, uint32_t target[8])
{
    memset(target, 0, SHA256_DIGEST_LENGTH);
    uint32_t e = bits >> 24;
    uint32_t c = bits & 0xffffff;
    if (e < 3)
        return;
    uint32_t shift = (e - 3) << 3;      // * 8
    uint32_t a_idx = (shift >> 5);  // shift / 32
    uint32_t a_sh = shift & 31;         // shift % 32
    if (a_idx < 8) {
        target[a_idx] = c << a_sh;
        if (a_idx < 7 && (a_sh > 8)) {
            a_sh = 32 - a_sh;
            target[a_idx + 1] = c >> a_sh;
        }
    }
}

static int inline
hash_check(const uint32_t h[8], const uint32_t t[8])
{
    for (int i = 8; i-- > 0; ) {
        if (likely(__builtin_bswap32(h[i]) > t[i]))
            return 0;
        if (unlikely(__builtin_bswap32(h[i]) < t[i]))
            return 1;
    }
    return 1;
}

static void
hash_dump(const uint32_t t[8])
{
    // for (int i = 0; i < 8; ++i)
    for (int i = 8; i--;)
        printf("%08x ", t[i]);
    putchar('\n');
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
        while (!should_stop && (nonce_cnt >= NONCE_MAX || block_found) && (job_id_local == job_id))
            pthread_cond_wait(&job_cond, &job_mutex);

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
        if (unlikely(start > NONCE_MAX)) {
            if (__sync_add_and_fetch(&idle_workers, 1) >= nprocs)
                eventfd_write(edge_fd, 1);
            continue;
        }
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

            if (unlikely(hash_check(ctx.r2_work_ctx.h, global_target.u32))) {
                if (__sync_bool_compare_and_swap(&block_found, 0, 1)) {
                    winning_nonce = nonce;
                    memcpy(found_block_hash.u8, ctx.r2_work_ctx.h, sizeof(found_block_hash));

                    printf("<%08x> ", winning_nonce);
                    // hash_dump(work_ctx[1].h);
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

void
hex_to_bytes(const char *hex_str, unsigned char *byte_array)
{
    size_t len = strlen(hex_str);
    for (size_t i = 0; i < len; i += 2)
        sscanf(hex_str + i, "%2hhx", &byte_array[i / 2]);
}

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
            .it_interval = { .tv_sec = 1, },
            .it_value = { .tv_sec = 1, },
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

            if (sz <= 0 || cmd == CMD_IN_STOP) {
                printf("STOP!%s%s\n", (sz>0)? "": " [Error] ", (sz>0)? "": strerror(errno));
                should_stop = 1;
                pthread_cond_broadcast(&job_cond);
                pthread_mutex_unlock(&job_mutex);
                break;
            }
            if (cmd == CMD_IN_NEW_JOB) {
                recv(fd, master_template.raw_u8, sizeof(block_t), MSG_WAITALL);
                SHA256_CTX ctx;
                SHA256_Init(&ctx);
                SHA256_Transform(&ctx, (void *)&master_template);
                memcpy(master_midstate.u32, ctx.h, sizeof(master_midstate));
                hash_target_create(master_template.full.bits, global_target.u32);
                idle_workers = 0;
                ++job_id;
                nonce_cnt = 0;
                block_found = 0;
                last_nonce = 0;
                pthread_cond_broadcast(&job_cond);
                printf("new job\n");
            }
        }

        if (fds[FD_WORKER].revents & POLLIN) {
            eventfd_read(edge_fd, &(eventfd_t){0});
            if (block_found) {
                uint32_t cmd = CMD_OUT_FOUND;
                send(fd, &cmd, sizeof(uint32_t), 0);
                send(fd, (void *)&winning_nonce, sizeof(winning_nonce), 0);
                hash_reverse(found_block_hash.u32);
                send(fd, found_block_hash.u8, 32, 0);
                fsync(fd);
                block_found = 0;
                printf("reported\n");
            }
            else {
                // all nonces have been used up
                // if (unlikely(nonce_cnt >= NONCE_MAX))
                uint32_t t = time(0);
                if (t != master_template.full.time) {
                    master_template.full.time = t;
                    idle_workers = 0;
                    ++job_id;
                    nonce_cnt = 0;
                    block_found = 0;
                    last_nonce = 0;
                    pthread_cond_broadcast(&job_cond);
                }
                else {
                    uint32_t cmd = CMD_OUT_REQUEST;
                    send(fd, &cmd, sizeof(uint32_t), 0);
                    fsync(fd);
                    printf("requested\n");
                }
            }
        }

        if (fds[FD_TIMER].revents & POLLIN) {
            read(timer_fd, &(uint64_t){0}, sizeof(uint64_t));

            uint64_t cur_nonce = nonce_cnt;
            if (cur_nonce > NONCE_MAX)
                cur_nonce = NONCE_MAX;
            uint64_t diff = cur_nonce - last_nonce;
            last_nonce = cur_nonce;
            double mhashes = (double)diff / 1000000.0;
            double progress = ((double)cur_nonce / (double )NONCE_MAX) * 100.0;
            if (cur_nonce < NONCE_MAX && !block_found) {
                printf(" -> %6.2f MH/s | %5.1f%%\n", mhashes, progress);
                fflush(stdout);
            }
        }

        pthread_mutex_unlock(&job_mutex);
    }

    for (int i = 0; i < nprocs; ++i)
        pthread_join(threads[i], 0);

    return 0;
}
