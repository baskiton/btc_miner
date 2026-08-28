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


#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

//#define BITS 0x17023cc1
//#define BITS 0x1e00ffff
#define BITS 0x1d00ffff
//#define BITS 0x1d123456

#define SHA256_CHUNK_SZ 64
#define NONCE_MAX (1ULL << 32)

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

// global variables ////////////////////////////////////////////////////////////
volatile uint64_t nonce_cnt = 0;
volatile uint32_t job_id = 0;
volatile uint32_t winning_nonce = 0;
volatile int block_found = 0;
volatile int should_stop = 0;

block128_t master_template;
hash_t master_midstate = {};
hash_t global_target = {};
hash_t found_block_hash = {};
hash_t master_prev_hash = {};

pthread_mutex_t job_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t job_cond = PTHREAD_COND_INITIALIZER;

volatile sig_atomic_t got_sigusr1 = 0;
volatile sig_atomic_t got_sigstop = 0;

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
    // for (int i = 0; i < 8; ++i)
    //     h[i] = __builtin_bswap32(h[i]);     // only for le-arch

    // for (uint32_t *i = h + 7; i >= h; --i)
    //     *i = __builtin_bswap32(*i);

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
    // round2_block_t r2 = {
    //         .hash = {},
    //         .end = 0x80,
    //         .pad = {},
    //         .len_be = htobe64(sizeof(hash_t) * 8),  // 256
    // };

    // SHA256_CTX
    //     r1_base_ctx,
    //     r2_base_ctx,
    //     r1_work_ctx,
    //     r2_work_ctx;

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
            printf("[%i] new job %i\n", cfg->thread_id, job_id_local);
        }
        pthread_mutex_unlock(&job_mutex);

        uint64_t start = __sync_fetch_and_add(&nonce_cnt, WORKER_RANGE_SZ);
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
            // memcpy(r2.hash.u32, r1_work_ctx.h, sizeof(hash_t));
            SHA256_Transform(&ctx.r2_work_ctx, (void *)&ctx.r2);

            // if (unlikely(nonce == 0x49fd5c48)) {
            //     printf("time=%i\n"
            //            "bits=0x%08x\n"
            //            "nonc=0x%08x\n",
            //            (chunk2.time), (chunk2.bits), (chunk2.nonce));
            //     hash_dump(ctx.r2_work_ctx.h);
            // }

            if (unlikely(hash_check(ctx.r2_work_ctx.h, global_target.u32))) {
                if (__sync_bool_compare_and_swap(&block_found, 0, 1)) {
                    winning_nonce = nonce;
                    memcpy(found_block_hash.u8, ctx.r2_work_ctx.h, sizeof(found_block_hash));

                    printf("%08x ", winning_nonce);
                    // hash_dump(work_ctx[1].h);
                    hash_dump(ctx.r2_work_ctx.h);

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

    int nprocs = get_nprocs();
    pthread_t threads[nprocs];
    worker_cfg_t cfgs[nprocs];
    for (int i = 0; i < nprocs; ++i) {
        cfgs[i].thread_id = i;
        pthread_create(&threads[i], 0, miner_worker, &cfgs[i]);
    }

    master_template = (block128_t) {
        .full = {
                .ver = 3,
                .prev_hash = master_prev_hash,
                .merkle_root = {},
                .time = 0,
                .bits = BITS,
                .nonce = 0,
                .end = 0x80,
                .pad = {},
                .len_be = htobe64(BLOCK_SZ * 8),
        },
    };
    const char bh[] = "00401423bd5920eacafda4307b31b2607bc74b2ea506cffa4609020000000000000000007bf602eedbb613e09577c5725515e3a4d74d3fef7600730547ab3e6519a7d40d7d39906ac13c0217485cfd49";
    hex_to_bytes(bh, master_template.raw_u8);

    hash_target_create(master_template.full.bits, global_target.u32);
    hash_dump(global_target.u32);

    printf("vers=0x%08x\n"
           "time=%i\n"
           "bits=0x%08x\n"
           "nonc=0x%08x\n",
           (master_template.full.ver), (master_template.full.time), (master_template.full.bits), (master_template.full.nonce));
    fputs("prev=", stdout);
    hash_dump(master_template.full.prev_hash.u32);
    fputs("merk=", stdout);
    hash_dump(master_template.full.merkle_root.u32);
    putchar('\n');
    memcpy(master_prev_hash.u32, master_template.full.prev_hash.u32, 32);

    uint64_t last_nonce;
    struct timespec timeout;

    while (!should_stop) {
        pthread_mutex_lock(&job_mutex);

        if (job_id && block_found)
            for (int i = 0; i < 8; ++i)
                master_prev_hash.u32[i] = __builtin_bswap32(found_block_hash.u32[i]);
            // memcpy(master_prev_hash.u8, found_block_hash.u8, sizeof(found_block_hash));
        else if (got_sigusr1)
            got_sigusr1 = 0;

        ++job_id;
        nonce_cnt = 0;
        block_found = 0;
        last_nonce = 0;
        // memset(found_block_hash.u8, 0, sizeof(found_block_hash));

        uint32_t cur_time = time(0);
        master_template.full.prev_hash = master_prev_hash;
        // master_template.full.time = cur_time;
        // master_template.full.bits = BITS;
        // master_template.full.nonce = 0;
        fputs("prev=", stdout);
        hash_dump(master_template.full.prev_hash.u32);

        SHA256_CTX ctx;
        SHA256_Init(&ctx);
        SHA256_Transform(&ctx, (void *)&master_template);
        memcpy(master_midstate.u32, ctx.h, sizeof(master_midstate));

        pthread_cond_broadcast(&job_cond);
        pthread_sigmask(SIG_UNBLOCK, &signal_set, NULL);

        while (!block_found && nonce_cnt < NONCE_MAX && !got_sigstop && !got_sigusr1) {
            clock_gettime(CLOCK_MONOTONIC, &timeout);
            timeout.tv_sec += 1;

            pthread_cond_clockwait(&job_cond, &job_mutex, CLOCK_MONOTONIC, &timeout);

            uint64_t cur_nonce = nonce_cnt;
            if (cur_nonce > NONCE_MAX)
                cur_nonce = NONCE_MAX;
            uint64_t diff = cur_nonce - last_nonce;
            last_nonce = cur_nonce;
            double mhashes = (double)diff / 1000000.0;
            double progress = ((double)cur_nonce / (double )NONCE_MAX) * 100.0;
            if (cur_nonce < NONCE_MAX && !block_found && !got_sigstop && !got_sigusr1) {
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
        else if (nonce_cnt >= NONCE_MAX && !block_found) {
            printf("next round\n\n");
        }
        pthread_mutex_unlock(&job_mutex);
    }

    for (int i = 0; i < nprocs; ++i)
        pthread_join(threads[i], 0);

    return 0;
}
