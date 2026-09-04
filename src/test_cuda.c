#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <endian.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <openssl/sha.h>

#include "btc_miner.h"


#ifdef CUDASHA256_TEST

static int
test_sha256(uint8_t data[64], uint32_t ref_hash[8])
{
    printf("test SHA256\n");
    printf("REF:  ");
    hash_dump(ref_hash);

    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Transform(&ctx, data);
    printf("oSSL: ");
    hash_dump(ctx.h);

    uint32_t result[8];
    cuda_sha256((uint32_t *)data, result);
    printf("CUDA: ");
    hash_dump(result);

    int ret = !(memcmp(ref_hash, ctx.h, 32) || memcmp(ref_hash, result, 32));
    printf("%s\n\n", ret? "SUCCESS": "FAILED");
    return !ret;
}

static int
test_sha256d(uint8_t data[64], uint32_t ref_hash[8])
{
    printf("test SHA256d\n");
    printf("REF:  ");
    hash_dump(ref_hash);

    struct {
        uint8_t h[32];
        uint8_t end;
        uint8_t pad[64-32-9];
        uint64_t len_be;
    } r2 = {
            .end = 0x80,
            .len_be = htobe64(32 * 8),
    };

    SHA256_CTX ctx0, ctx1;
    SHA256_Init(&ctx0);
    SHA256_Init(&ctx1);
    SHA256_Transform(&ctx0, data);
    memcpy(r2.h, ctx0.h, 32);
    hash_swap((void *)r2.h);
    SHA256_Transform(&ctx1, r2.h);
    printf("oSSL: ");
    hash_dump(ctx1.h);

    uint32_t result[8];
    cuda_sha256d((uint32_t *)data, result);
    printf("CUDA: ");
    hash_dump(result);

    int ret = !(memcmp(ref_hash, ctx1.h, 32) || memcmp(ref_hash, result, 32));
    printf("%s\n\n", ret? "SUCCESS": "FAILED");
    return !ret;
}

static int
test_bitcoin_hash(uint8_t data[80], uint32_t ref_hash[8])
{
    printf("test SHA256d\n");
    printf("REF:  ");
    hash_dump(ref_hash);

    hash_t midstate_hash;
    block128_t midstate_template = {
            .full = {
                    .end = 0x80,
                    .pad = {},
                    .len_be = htobe64(BLOCK_SZ * 8),
            },
    };
    memcpy(midstate_template.u8, data, 80);

    // prepare midstate
    SHA256_CTX midstate_ctx;
    SHA256_Init(&midstate_ctx);
    SHA256_Transform(&midstate_ctx, midstate_template.u8);
    memcpy(midstate_hash.u8, midstate_ctx.h, 32);

    // oSSL
    SHA256_CTX r1_ctx, r2_ctx;
    memcpy(r1_ctx.h, midstate_hash.u8, 32);
    SHA256_Init(&r2_ctx);
    SHA256_Transform(&r1_ctx, (void *)&midstate_template.chunks.c2);
    struct {
        uint8_t h[32];
        uint8_t end;
        uint8_t pad[64-32-9];
        uint64_t len_be;
    } r2 = {
            .end = 0x80,
            .len_be = htobe64(32 * 8),
    };
    memcpy(r2.h, r1_ctx.h, 32);
    hash_swap((void *)r2.h);
    SHA256_Transform(&r2_ctx, r2.h);
    hash_swap(r2_ctx.h);
    printf("oSSL: ");
    hash_dump(r2_ctx.h);

    // CUDA
    uint32_t result[8];

#if CUDASHA256_NOSWAP
    for (int i = 16; i < 32; ++i)
        midstate_template.u32[i] = __builtin_bswap32(midstate_template.u32[i]);
#endif

    cuda_sha256d_cont(midstate_hash.u32, (void *)&midstate_template.chunks.c2, result);
    printf("CUDA: ");
    hash_dump(result);

    int ret = !(memcmp(ref_hash, r2_ctx.h, 32) || memcmp(ref_hash, result, 32));
    printf("%s\n\n", ret? "SUCCESS": "FAILED");
    return !ret;
}

static int
test_btc_block(uint8_t data[80], const uint32_t ref_hash[8], uint32_t ref_nonce)
{
    printf("test BTC block\n");

    hash_t midstate_hash;
    block128_t midstate_template = {
            .full = {
                    .end = 0x80,
                    .pad = {},
                    .len_be = htobe64(BLOCK_SZ * 8),
            },
    };
    memcpy(midstate_template.u8, data, 80);

    // prepare midstate
    SHA256_CTX midstate_ctx;
    SHA256_Init(&midstate_ctx);
    SHA256_Transform(&midstate_ctx, midstate_template.u8);
    memcpy(midstate_hash.u8, midstate_ctx.h, 32);

    hash_t result;
    hash_t target;
    uint32_t nonce = 0, block_found = 0;
    hash_target_create(midstate_template.full.bits, target.u32);

#ifdef DEBUG_PRINT
    printf("%12s: ", "target");
    hash_dump(target.u32);

    printf("%12s: ", "midstate");
    hash_dump(midstate_hash.u32);

    printf("%12s: ", "orig data");
    for (int i = 16; i--;)
        printf("%08x ", ((uint32_t *)&midstate_template.chunks.c2)[i]);
    putchar('\n');
#endif

#if CUDASHA256_NOSWAP
    chunk_swap32(&midstate_template.u32[16], &midstate_template.u32[16], 16);
#endif

    cuda_sha256d_btc(
            midstate_hash.u32,
            (void *)&midstate_template.chunks.c2,
            target.u32,
            0,
            4096000,
            0,
            &(uint32_t){1},
            &nonce,
            &block_found,
            result.u32);
    printf("found: %u\n", block_found);
    printf("nonce: %u\n", nonce);
    printf("CUDA: ");
    hash_dump(result.u32);

    int ret = (nonce == ref_nonce) && !memcmp(ref_hash, result.u32, 32);
    printf("%s\n\n", ret? "SUCCESS": "FAILED");
    return !ret;
}

int cuda_sha256_test() {
    cuda_init();

    int ret = 0;
    uint8_t data[128] = "\x01\x00\x00\x00\x81\xcd\x02\xab\x7e\x56\x9e\x8b\xcd\x93\x17\xe2\xfe\x99\xf2\xde\x44\xd4\x9a\xb2\xb8\x85\x1b\xa4\xa3\x08\x00\x00\x00\x00\x00\x00\xe3\x20\xb6\xc2\xff\xfc\x8d\x75\x04\x23\xdb\x8b\x1e\xb9\x42\xae\x71\x0e\x95\x1e\xd7\x97\xf7\xaf\xfc\x88\x92\xb0\xf1\xfc\x12\x2b\xc7\xf5\xd7\x4d\xf2\xb9\x44\x1a\x42\xa1\x46\x95";

    uint32_t test1_ref[8] = {
            0x9524c593, 0x05c56713, 0x16e669ba, 0x2d2810a0,
            0x07e86e37, 0x2f56a9da, 0xcd5bce69, 0x7a78da2d,
    };
    ret |= test_sha256(data, (void *)test1_ref);

    uint32_t test2_ref[8] = {
            0xc94d4075, 0x6837c349, 0xce8a3b28, 0xd2c77e96,
            0xffa00d3b, 0x6042464e, 0xacf4b639, 0xc78df3e1,
    };
    ret |= test_sha256d(data, (void *)test2_ref);

    // 00000000 00000000 1e8d6829 a8a21adc 5d38d0a4 73b144b6 765798e6 1f98bd1d
    uint32_t test3_ref[8] = {
            0x1f98bd1d, 0x765798e6, 0x73b144b6, 0x5d38d0a4,
            0xa8a21adc, 0x1e8d6829, 0x00000000, 0x00000000,
    };
    ret |= test_bitcoin_hash(data, (void *)test3_ref);

    ret |= test_btc_block(data, (void *)test3_ref, 0x9546a142);

    cuda_free();

    return ret;
}

#endif
