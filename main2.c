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
#include <sys/un.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include <openssl/sha.h>


#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

//#define BITS 0x17023cc1
//#define BITS 0x1e00ffff
#define BITS 0x1d00ffff
//#define BITS 0x1d123456

typedef uint64_t uint256_t[4];

typedef union {
    uint256_t u256;
    uint64_t u64[4];
    uint32_t u32[8];
    uint8_t u8[32];
} hash_t;

typedef struct {
    hash_t prev_hash;
    uint32_t ver;
    uint32_t bits;
    uint32_t time;
    uint32_t nonce;
} block_t;
#define BLOCK_INIT { .prev_hash={}, .ver=1, .bits=BITS, .time=(uint32_t)time(0), .nonce=0, }

#define BLOCK_SZ sizeof(block_t)    // 48

typedef struct {
    block_t block_h;
    uint8_t end;
    uint8_t pad[64 - BLOCK_SZ - 9];
    uint64_t len_be;
} block64_t;
#define BLOCK64_INIT { .block_h=BLOCK_INIT, .end=0x80, .len_be=htobe64(BLOCK_SZ * 8), }

typedef struct {
    hash_t hash;
    uint8_t end;
    uint8_t pad[64 - sizeof(hash_t) - 9];
    uint64_t len_be;
} round2_block_t;

// global variables ////////////////////////////////////////////////////////////
volatile uint64_t nonce_cnt = 0;
volatile uint32_t job_id = 0;
volatile uint32_t winning_nonce = 0;
volatile int block_found = 0;
volatile int should_stop = 0;

block64_t master_block;
hash_t global_target;
hash_t found_block_hash;

pthread_mutex_t job_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t job_cond = PTHREAD_COND_INITIALIZER;

volatile sig_atomic_t got_sigusr1 = 0;
volatile sig_atomic_t got_sigstop = 0;

////////////////////////////////////////////////////////////////////////////////

static void
create_target(uint32_t bits, uint32_t target[8])
{
    memset(target, 0, 32);
    uint32_t e = bits >> 24;
    uint32_t c = bits & 0xffffff;
    uint32_t shift = (e - 3) << 3;      // * 8
    uint32_t a_idx = 7 - (shift >> 5);  // shift / 32
    uint32_t a_sh = shift & 31;         // shift % 32
    target[a_idx] = c << a_sh;
//    printf("a_idx=%u a_sh=%u\n", a_idx, a_sh);
    if (a_idx && (a_sh > 8)) {
        a_sh = 32 - a_sh;
        target[a_idx-1] = c >> a_sh;
    }
//    uint32_t mask = !!a_idx;
    target[a_idx - !!a_idx] |= ((c >> 1) >> (31 - a_sh)) * !!a_idx;
}

static int inline
check_target(const uint32_t a[8], const uint32_t target[8])
{
    for (int i = 0; i < 8; i++) {
        if (likely(a[i] > target[i]))
            return 0;
        if (unlikely(a[i] < target[i]))
            return 1;
    }
    return 1;
}

static void
dump_target(const uint32_t t[8])
{
    for (int i = 0; i < 8; ++i)
        printf("%08x", t[i]);
    putchar('\n');
}


// thread pool /////////////////////////////////////////////////////////////////
#define CHUNK_SIZE (1ULL << 20)

typedef struct {
    int thread_id;
} worker_cfg_t;

#define b_nonce b.block_h.nonce

void *
miner_worker(void *arg)
{
    worker_cfg_t *cfg = arg;

    uint32_t job_id_local = 0;
    block64_t b;
    round2_block_t r2 = {
            .hash = {},
            .end = 0x80,
            .pad = {},
            .len_be = htobe64(sizeof(hash_t) * 8),  // 256
    };

    // uint32_t *nonce_ptr = &b.block_h.nonce;

    SHA256_CTX r0_ctx, r1_ctx, r2_ctx;
    SHA256_Init(&r0_ctx);

    while (1) {
        pthread_mutex_lock(&job_mutex);
        while (!should_stop && (nonce_cnt >= (1ULL << 32) || block_found) && (job_id_local == job_id))
            pthread_cond_wait(&job_cond, &job_mutex);

        if (unlikely(should_stop)) {
            pthread_mutex_unlock(&job_mutex);
            break;
        }

        if (unlikely(job_id_local != job_id)) {
            job_id_local = job_id;
            memcpy(&b, &master_block, sizeof(master_block));
            printf("[%i] new job %i\n", cfg->thread_id, job_id_local);
        }
        pthread_mutex_unlock(&job_mutex);

        uint64_t start = __sync_fetch_and_add(&nonce_cnt, CHUNK_SIZE);
        if (unlikely(start > (1ULL << 32)))
            continue;
        uint64_t end = start + CHUNK_SIZE;
        if (unlikely(end > (1ULL << 32)))
            end = 1ULL << 32;

        for (uint64_t nonce = start; nonce < end; ++nonce) {
            if (unlikely(!(nonce & ((1 << 13) - 1)) && (job_id_local != job_id || block_found || should_stop)))
                break;
            b_nonce = nonce;
            memcpy(&r1_ctx, &r0_ctx, sizeof(r0_ctx));
            memcpy(&r2_ctx, &r0_ctx, sizeof(r0_ctx));
            SHA256_Transform(&r1_ctx, (void *)&b);

            memcpy(r2.hash.u32, r1_ctx.h, sizeof(hash_t));
            SHA256_Transform(&r2_ctx, (void *) &r2);

            if (unlikely(check_target(r2_ctx.h, global_target.u32))) {
                if (__sync_bool_compare_and_swap(&block_found, 0, 1)) {
                    winning_nonce = nonce;
                    memcpy(found_block_hash.u8, r2_ctx.h, sizeof(found_block_hash));

                    printf("%08x ", winning_nonce);
                    dump_target(r2_ctx.h);

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

// #undef b_nonce

////////////////////////////////////////////////////////////////////////////////

void
signal_handler(int sig)
{
    switch (sig) {
    case SIGUSR1:
    case SIGUSR2:
        got_sigusr1 = 1;
        break;

    case SIGHUP:
    case SIGINT:
    case SIGABRT:
    case SIGTERM:
        got_sigstop = 1;
        break;

    default:
        break;
    }
}

int
main()
{
    sigset_t signal_set;
    sigemptyset(&signal_set);
    sigaddset(&signal_set, SIGHUP);
    sigaddset(&signal_set, SIGINT);
    sigaddset(&signal_set, SIGABRT);
    sigaddset(&signal_set, SIGTERM);
    sigaddset(&signal_set, SIGUSR1);
    sigaddset(&signal_set, SIGUSR2);
    pthread_sigmask(SIG_BLOCK, &signal_set, NULL);

    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);

    create_target(BITS, global_target.u32);

    int nprocs = get_nprocs();
    pthread_t threads[nprocs];
    worker_cfg_t cfgs[nprocs];
    for (int i = 0; i < nprocs; ++i) {
        cfgs[i].thread_id = i;
        pthread_create(&threads[i], 0, miner_worker, &cfgs[i]);
    }

    master_block = (block64_t)BLOCK64_INIT;

    uint64_t last_nonce = 0;
    struct timespec timeout;

    while (!should_stop) {
        pthread_mutex_lock(&job_mutex);

        if (job_id && block_found)
            memcpy(master_block.block_h.prev_hash.u8, found_block_hash.u8, sizeof(found_block_hash));
        else if (got_sigusr1) {
            FILE *f = fopen("/dev/urandom", "rb");
            if (f) {
                fread(master_block.block_h.prev_hash.u64, 8, 4, f);
                fclose(f);
                int sh = 0;
                uint32_t v;
                for (int i = 0; i < 8; ++i) {
                    if (global_target.u32[i]) {
                        v = global_target.u32[i];
                        while (v) {
                            v >>= 1;
                            ++sh;
                        }
                        v = (v << (sh+1)) - 1;
                        master_block.block_h.prev_hash.u32[i] &= v;
                        break;
                    }
                    else
                        master_block.block_h.prev_hash.u32[i] = 0;
                }
            }
            printf("<outer>  ");
            dump_target(master_block.block_h.prev_hash.u32);
            got_sigusr1 = 0;
        }

        ++job_id;
        nonce_cnt = 0;
        block_found = 0;
        last_nonce = 0;
        // memset(found_block_hash.u8, 0, sizeof(found_block_hash));

        master_block.block_h.time = time(0);

        pthread_cond_broadcast(&job_cond);
        pthread_sigmask(SIG_UNBLOCK, &signal_set, NULL);

        while (!block_found && nonce_cnt < (1ULL << 32) && !got_sigstop && !got_sigusr1) {
            clock_gettime(CLOCK_MONOTONIC, &timeout);
            timeout.tv_sec += 1;

            pthread_cond_clockwait(&job_cond, &job_mutex, CLOCK_MONOTONIC, &timeout);

            uint64_t cur_nonce = nonce_cnt;
            if (cur_nonce > (1ULL << 32))
                cur_nonce = 1ULL << 32;
            uint64_t diff = cur_nonce - last_nonce;
            last_nonce = cur_nonce;
            double mhashes = (double)diff / 1000000.0;
            double progress = ((double)cur_nonce / (double )(1ULL << 32)) * 100.0;
            if (cur_nonce < (1ULL << 32) && !block_found && !got_sigstop && !got_sigusr1) {
                printf(" -> %6.2f MH/s | %5.1f%%\n", mhashes, progress);
                fflush(stdout);
            }
        }
        pthread_sigmask(SIG_BLOCK, &signal_set, NULL);

        if (got_sigstop) {
            printf("STOP!\n");
            should_stop = 1;
            pthread_cond_broadcast(&job_cond);
        }
        else if (nonce_cnt >= (1ULL << 32) && !block_found) {
            printf("next round\n\n");
        }
        pthread_mutex_unlock(&job_mutex);
    }

    for (int i = 0; i < nprocs; ++i)
        pthread_join(threads[i], 0);

    return 0;
}
