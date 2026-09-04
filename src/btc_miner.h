#ifndef BTCMINER_BTC_MINER_H
#define BTCMINER_BTC_MINER_H

#include <stdint.h>
#include <stdio.h>

#include <openssl/sha.h>


#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define SHA256_CHUNK_SZ 64
#define NONCE_MAX (1ULL << 32)

#define FD_CTRL 0
#define FD_WORKER 1
#define FD_TIMER 2

// commands ////////////////////////////////////////////////////////////////////

#define SOCKET_NAME "\0/tmp/btcminer"

#define CMD_NEW_JOB 1
#define CMD_STOP (-1)

#define CMD_FOUND 100
#define CMD_REQUEST 101

////////////////////////////////////////////////////////////////////////////////

typedef union {
    uint32_t u32[32 / sizeof(uint32_t)];
    uint8_t u8[32];
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
    uint8_t u8[128];
    uint32_t u32[32];
    uint64_t u64[16];
} block128_t;

typedef struct {
    hash_t hash;
    uint8_t end;
    uint8_t pad[64 - sizeof(hash_t) - 9];
    uint64_t len_be;
} round2_block_t;

static void
chunk_swap32(uint32_t *d, uint32_t *s, int n)
{
    for (int i = n; i--;)
        d[i] = __builtin_bswap32(s[i]);
}

static void
hash_reverse(uint32_t t[8])
{
    for (int i = 0; i < 4; ++i) {
        uint32_t x = t[i];
        t[i] = t[7 - i];
        t[7 - i] = x;
    }
}

static void
hash_dump(const uint32_t h[8])
{
    // for (int i = 0; i < 8; ++i)
    for (int i = 8; i--;)
        printf("%08x ", h[i]);
    putchar('\n');
    fflush(stdout);
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
    uint32_t shift = (e - 3) << 3;  // * 8
    uint32_t a_idx = (shift >> 5);  // shift / 32
    uint32_t a_sh = shift & 31;     // shift % 32
    if (a_idx < 8) {
        target[a_idx] = c << a_sh;
        if (a_idx < 7 && (a_sh > 8)) {
            a_sh = 32 - a_sh;
            target[a_idx + 1] = c >> a_sh;
        }
    }
    // target[a_idx] = c << a_sh;
    // target[a_idx - !!a_idx] |= ((c >> 1) >> (31 - a_sh)) * !!a_idx;
}

#ifdef CUDASHA256_TEST
int cuda_sha256_test();
#endif

extern void cuda_init();
extern void cuda_free();
extern void cuda_sha256(const uint32_t data[16], uint32_t hash[8]);
extern void cuda_sha256d(const uint32_t data[16], uint32_t hash[8]);
extern void cuda_sha256d_cont(const uint32_t state[8], const uint32_t data[16], uint32_t hash[8]);
extern void cuda_sha256d_btc(
        const uint32_t state[8],
        const uint32_t data[16],
        const uint32_t target[8],
        uint64_t start_nonce,
        // uint32_t threads_per_block,
        // uint32_t total_blocks,
        uint32_t blocks_per_sm,
        uint32_t buf_idx,
        uint32_t *job_upd,
        uint32_t *winning_nonce,
        uint32_t *block_found,
        uint32_t hash[8]);
extern void cuda_get_tuned(int *h_threads_per_block, int *h_sm_count);

#endif //BTCMINER_BTC_MINER_H
