#include <cuda_runtime.h>
#include <nvml.h>

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

extern "C" {
#include "btc_miner.h"
}


#define cuda_swap32(x) __byte_perm((x), 0, 0x0123)

// Basic SHA-256 NIST spec
#define ROTR(x, n)   (((x) >> (n)) | ((x) << (32 - (n))))
#define Ch(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define Sigma0(x) (ROTR(x, 2)  ^ ROTR(x, 13) ^ ROTR(x, 22))
#define Sigma1(x) (ROTR(x, 6)  ^ ROTR(x, 11) ^ ROTR(x, 25))
#define sigma0(x) (ROTR(x, 7)  ^ ROTR(x, 18) ^ ((x) >> 3))
#define sigma1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

// Optimized (sliding window)
#define ROUND(a, b, c, d, e, f, g, h, k, w) ({ \
    uint32_t t1 = h + Sigma1(e) + Ch(e, f, g) + k + w; \
    uint32_t t2 = Sigma0(a) + Maj(a, b, c); \
    d += t1; \
    h = t1 + t2; \
})
#define SCHEDULE(w0, w1, w9, w14) (sigma1(w14) + w9 + sigma0(w1) + w0)

#ifdef CUDASHA256_NAIVE

static __device__ __forceinline__ void
_cuda_sha256_transform(uint32_t state[8], const uint32_t data[16])
{
    static __constant__ uint32_t K[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    uint32_t W[64];

    // convert inputs data to 32-bit Big-Endian words.
    for (int i = 0; i < 16; ++i)
        W[i] = cuda_swap32(data[i]);

    // expand W array to 64 items
    for (int i = 16; i < 64; ++i)
        W[i] = sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16];

    // registers init by current hash state
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    // main loop
    for (int i = 0; i < 64; ++i) {
        uint32_t t1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];
        uint32_t t2 = Sigma0(a) + Maj(a, b, c);
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

#endif

#if CUDASHA256_NOSWAP

static __device__ __forceinline__ void
_cuda_sha256_transform_optimized_noswap(uint32_t state[8], const uint32_t data[16])
{
    uint32_t a = state[0],
            b = state[1],
            c = state[2],
            d = state[3],
            e = state[4],
            f = state[5],
            g = state[6],
            h = state[7];

    uint32_t w0 = data[0],
            w1 = data[1],
            w2 = data[2],
            w3 = data[3],
            w4 = data[4],
            w5 = data[5],
            w6 = data[6],
            w7 = data[7],
            w8 = data[8],
            w9 = data[9],
            w10 = data[10],
            w11 = data[11],
            w12 = data[12],
            w13 = data[13],
            w14 = data[14],
            w15 = data[15];

    // rounds 0-15
    ROUND(a, b, c, d, e, f, g, h, 0x428a2f98, w0);
    ROUND(h, a, b, c, d, e, f, g, 0x71374491, w1);
    ROUND(g, h, a, b, c, d, e, f, 0xb5c0fbcf, w2);
    ROUND(f, g, h, a, b, c, d, e, 0xe9b5dba5, w3);
    ROUND(e, f, g, h, a, b, c, d, 0x3956c25b, w4);
    ROUND(d, e, f, g, h, a, b, c, 0x59f111f1, w5);
    ROUND(c, d, e, f, g, h, a, b, 0x923f82a4, w6);
    ROUND(b, c, d, e, f, g, h, a, 0xab1c5ed5, w7);
    ROUND(a, b, c, d, e, f, g, h, 0xd807aa98, w8);
    ROUND(h, a, b, c, d, e, f, g, 0x12835b01, w9);
    ROUND(g, h, a, b, c, d, e, f, 0x243185be, w10);
    ROUND(f, g, h, a, b, c, d, e, 0x550c7dc3, w11);
    ROUND(e, f, g, h, a, b, c, d, 0x72be5d74, w12);
    ROUND(d, e, f, g, h, a, b, c, 0x80deb1fe, w13);
    ROUND(c, d, e, f, g, h, a, b, 0x9bdc06a7, w14);
    ROUND(b, c, d, e, f, g, h, a, 0xc19bf174, w15);

    // rounds 16-31
    w0 = SCHEDULE(w0, w1, w9, w14);
    ROUND(a, b, c, d, e, f, g, h, 0xe49b69c1, w0);
    w1 = SCHEDULE(w1, w2, w10, w15);
    ROUND(h, a, b, c, d, e, f, g, 0xefbe4786, w1);
    w2 = SCHEDULE(w2, w3, w11, w0);
    ROUND(g, h, a, b, c, d, e, f, 0x0fc19dc6, w2);
    w3 = SCHEDULE(w3, w4, w12, w1);
    ROUND(f, g, h, a, b, c, d, e, 0x240ca1cc, w3);
    w4 = SCHEDULE(w4, w5, w13, w2);
    ROUND(e, f, g, h, a, b, c, d, 0x2de92c6f, w4);
    w5 = SCHEDULE(w5, w6, w14, w3);
    ROUND(d, e, f, g, h, a, b, c, 0x4a7484aa, w5);
    w6 = SCHEDULE(w6, w7, w15, w4);
    ROUND(c, d, e, f, g, h, a, b, 0x5cb0a9dc, w6);
    w7 = SCHEDULE(w7, w8, w0, w5);
    ROUND(b, c, d, e, f, g, h, a, 0x76f988da, w7);
    w8 = SCHEDULE(w8, w9, w1, w6);
    ROUND(a, b, c, d, e, f, g, h, 0x983e5152, w8);
    w9 = SCHEDULE(w9, w10, w2, w7);
    ROUND(h, a, b, c, d, e, f, g, 0xa831c66d, w9);
    w10 = SCHEDULE(w10, w11, w3, w8);
    ROUND(g, h, a, b, c, d, e, f, 0xb00327c8, w10);
    w11 = SCHEDULE(w11, w12, w4, w9);
    ROUND(f, g, h, a, b, c, d, e, 0xbf597fc7, w11);
    w12 = SCHEDULE(w12, w13, w5, w10);
    ROUND(e, f, g, h, a, b, c, d, 0xc6e00bf3, w12);
    w13 = SCHEDULE(w13, w14, w6, w11);
    ROUND(d, e, f, g, h, a, b, c, 0xd5a79147, w13);
    w14 = SCHEDULE(w14, w15, w7, w12);
    ROUND(c, d, e, f, g, h, a, b, 0x06ca6351, w14);
    w15 = SCHEDULE(w15, w0, w8, w13);
    ROUND(b, c, d, e, f, g, h, a, 0x14292967, w15);

    // rounds 32-47
    w0 = SCHEDULE(w0, w1, w9, w14);
    ROUND(a, b, c, d, e, f, g, h, 0x27b70a85, w0);
    w1 = SCHEDULE(w1, w2, w10, w15);
    ROUND(h, a, b, c, d, e, f, g, 0x2e1b2138, w1);
    w2 = SCHEDULE(w2, w3, w11, w0);
    ROUND(g, h, a, b, c, d, e, f, 0x4d2c6dfc, w2);
    w3 = SCHEDULE(w3, w4, w12, w1);
    ROUND(f, g, h, a, b, c, d, e, 0x53380d13, w3);
    w4 = SCHEDULE(w4, w5, w13, w2);
    ROUND(e, f, g, h, a, b, c, d, 0x650a7354, w4);
    w5 = SCHEDULE(w5, w6, w14, w3);
    ROUND(d, e, f, g, h, a, b, c, 0x766a0abb, w5);
    w6 = SCHEDULE(w6, w7, w15, w4);
    ROUND(c, d, e, f, g, h, a, b, 0x81c2c92e, w6);
    w7 = SCHEDULE(w7, w8, w0, w5);
    ROUND(b, c, d, e, f, g, h, a, 0x92722c85, w7);
    w8 = SCHEDULE(w8, w9, w1, w6);
    ROUND(a, b, c, d, e, f, g, h, 0xa2bfe8a1, w8);
    w9 = SCHEDULE(w9, w10, w2, w7);
    ROUND(h, a, b, c, d, e, f, g, 0xa81a664b, w9);
    w10 = SCHEDULE(w10, w11, w3, w8);
    ROUND(g, h, a, b, c, d, e, f, 0xc24b8b70, w10);
    w11 = SCHEDULE(w11, w12, w4, w9);
    ROUND(f, g, h, a, b, c, d, e, 0xc76c51a3, w11);
    w12 = SCHEDULE(w12, w13, w5, w10);
    ROUND(e, f, g, h, a, b, c, d, 0xd192e819, w12);
    w13 = SCHEDULE(w13, w14, w6, w11);
    ROUND(d, e, f, g, h, a, b, c, 0xd6990624, w13);
    w14 = SCHEDULE(w14, w15, w7, w12);
    ROUND(c, d, e, f, g, h, a, b, 0xf40e3585, w14);
    w15 = SCHEDULE(w15, w0, w8, w13);
    ROUND(b, c, d, e, f, g, h, a, 0x106aa070, w15);

    // rounds 48-63
    w0 = SCHEDULE(w0, w1, w9, w14);
    ROUND(a, b, c, d, e, f, g, h, 0x19a4c116, w0);
    w1 = SCHEDULE(w1, w2, w10, w15);
    ROUND(h, a, b, c, d, e, f, g, 0x1e376c08, w1);
    w2 = SCHEDULE(w2, w3, w11, w0);
    ROUND(g, h, a, b, c, d, e, f, 0x2748774c, w2);
    w3 = SCHEDULE(w3, w4, w12, w1);
    ROUND(f, g, h, a, b, c, d, e, 0x34b0bcb5, w3);
    w4 = SCHEDULE(w4, w5, w13, w2);
    ROUND(e, f, g, h, a, b, c, d, 0x391c0cb3, w4);
    w5 = SCHEDULE(w5, w6, w14, w3);
    ROUND(d, e, f, g, h, a, b, c, 0x4ed8aa4a, w5);
    w6 = SCHEDULE(w6, w7, w15, w4);
    ROUND(c, d, e, f, g, h, a, b, 0x5b9cca4f, w6);
    w7 = SCHEDULE(w7, w8, w0, w5);
    ROUND(b, c, d, e, f, g, h, a, 0x682e6ff3, w7);
    w8 = SCHEDULE(w8, w9, w1, w6);
    ROUND(a, b, c, d, e, f, g, h, 0x748f82ee, w8);
    w9 = SCHEDULE(w9, w10, w2, w7);
    ROUND(h, a, b, c, d, e, f, g, 0x78a5636f, w9);
    w10 = SCHEDULE(w10, w11, w3, w8);
    ROUND(g, h, a, b, c, d, e, f, 0x84c87814, w10);
    w11 = SCHEDULE(w11, w12, w4, w9);
    ROUND(f, g, h, a, b, c, d, e, 0x8cc70208, w11);
    w12 = SCHEDULE(w12, w13, w5, w10);
    ROUND(e, f, g, h, a, b, c, d, 0x90befffa, w12);
    w13 = SCHEDULE(w13, w14, w6, w11);
    ROUND(d, e, f, g, h, a, b, c, 0xa4506ceb, w13);
    w14 = SCHEDULE(w14, w15, w7, w12);
    ROUND(c, d, e, f, g, h, a, b, 0xbef9a3f7, w14);
    w15 = SCHEDULE(w15, w0, w8, w13);
    ROUND(b, c, d, e, f, g, h, a, 0xc67178f2, w15);

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

#endif

static __device__ __forceinline__ void
_cuda_sha256_transform_optimized(uint32_t state[8], const uint32_t data[16])
{
    uint32_t a = state[0],
            b = state[1],
            c = state[2],
            d = state[3],
            e = state[4],
            f = state[5],
            g = state[6],
            h = state[7];

    uint32_t w0 = cuda_swap32(data[0]),
            w1 = cuda_swap32(data[1]),
            w2 = cuda_swap32(data[2]),
            w3 = cuda_swap32(data[3]),
            w4 = cuda_swap32(data[4]),
            w5 = cuda_swap32(data[5]),
            w6 = cuda_swap32(data[6]),
            w7 = cuda_swap32(data[7]),
            w8 = cuda_swap32(data[8]),
            w9 = cuda_swap32(data[9]),
            w10 = cuda_swap32(data[10]),
            w11 = cuda_swap32(data[11]),
            w12 = cuda_swap32(data[12]),
            w13 = cuda_swap32(data[13]),
            w14 = cuda_swap32(data[14]),
            w15 = cuda_swap32(data[15]);

    // rounds 0-15
    ROUND(a, b, c, d, e, f, g, h, 0x428a2f98, w0);
    ROUND(h, a, b, c, d, e, f, g, 0x71374491, w1);
    ROUND(g, h, a, b, c, d, e, f, 0xb5c0fbcf, w2);
    ROUND(f, g, h, a, b, c, d, e, 0xe9b5dba5, w3);
    ROUND(e, f, g, h, a, b, c, d, 0x3956c25b, w4);
    ROUND(d, e, f, g, h, a, b, c, 0x59f111f1, w5);
    ROUND(c, d, e, f, g, h, a, b, 0x923f82a4, w6);
    ROUND(b, c, d, e, f, g, h, a, 0xab1c5ed5, w7);
    ROUND(a, b, c, d, e, f, g, h, 0xd807aa98, w8);
    ROUND(h, a, b, c, d, e, f, g, 0x12835b01, w9);
    ROUND(g, h, a, b, c, d, e, f, 0x243185be, w10);
    ROUND(f, g, h, a, b, c, d, e, 0x550c7dc3, w11);
    ROUND(e, f, g, h, a, b, c, d, 0x72be5d74, w12);
    ROUND(d, e, f, g, h, a, b, c, 0x80deb1fe, w13);
    ROUND(c, d, e, f, g, h, a, b, 0x9bdc06a7, w14);
    ROUND(b, c, d, e, f, g, h, a, 0xc19bf174, w15);

    // rounds 16-31
    w0 = SCHEDULE(w0, w1, w9, w14);
    ROUND(a, b, c, d, e, f, g, h, 0xe49b69c1, w0);
    w1 = SCHEDULE(w1, w2, w10, w15);
    ROUND(h, a, b, c, d, e, f, g, 0xefbe4786, w1);
    w2 = SCHEDULE(w2, w3, w11, w0);
    ROUND(g, h, a, b, c, d, e, f, 0x0fc19dc6, w2);
    w3 = SCHEDULE(w3, w4, w12, w1);
    ROUND(f, g, h, a, b, c, d, e, 0x240ca1cc, w3);
    w4 = SCHEDULE(w4, w5, w13, w2);
    ROUND(e, f, g, h, a, b, c, d, 0x2de92c6f, w4);
    w5 = SCHEDULE(w5, w6, w14, w3);
    ROUND(d, e, f, g, h, a, b, c, 0x4a7484aa, w5);
    w6 = SCHEDULE(w6, w7, w15, w4);
    ROUND(c, d, e, f, g, h, a, b, 0x5cb0a9dc, w6);
    w7 = SCHEDULE(w7, w8, w0, w5);
    ROUND(b, c, d, e, f, g, h, a, 0x76f988da, w7);
    w8 = SCHEDULE(w8, w9, w1, w6);
    ROUND(a, b, c, d, e, f, g, h, 0x983e5152, w8);
    w9 = SCHEDULE(w9, w10, w2, w7);
    ROUND(h, a, b, c, d, e, f, g, 0xa831c66d, w9);
    w10 = SCHEDULE(w10, w11, w3, w8);
    ROUND(g, h, a, b, c, d, e, f, 0xb00327c8, w10);
    w11 = SCHEDULE(w11, w12, w4, w9);
    ROUND(f, g, h, a, b, c, d, e, 0xbf597fc7, w11);
    w12 = SCHEDULE(w12, w13, w5, w10);
    ROUND(e, f, g, h, a, b, c, d, 0xc6e00bf3, w12);
    w13 = SCHEDULE(w13, w14, w6, w11);
    ROUND(d, e, f, g, h, a, b, c, 0xd5a79147, w13);
    w14 = SCHEDULE(w14, w15, w7, w12);
    ROUND(c, d, e, f, g, h, a, b, 0x06ca6351, w14);
    w15 = SCHEDULE(w15, w0, w8, w13);
    ROUND(b, c, d, e, f, g, h, a, 0x14292967, w15);

    // rounds 32-47
    w0 = SCHEDULE(w0, w1, w9, w14);
    ROUND(a, b, c, d, e, f, g, h, 0x27b70a85, w0);
    w1 = SCHEDULE(w1, w2, w10, w15);
    ROUND(h, a, b, c, d, e, f, g, 0x2e1b2138, w1);
    w2 = SCHEDULE(w2, w3, w11, w0);
    ROUND(g, h, a, b, c, d, e, f, 0x4d2c6dfc, w2);
    w3 = SCHEDULE(w3, w4, w12, w1);
    ROUND(f, g, h, a, b, c, d, e, 0x53380d13, w3);
    w4 = SCHEDULE(w4, w5, w13, w2);
    ROUND(e, f, g, h, a, b, c, d, 0x650a7354, w4);
    w5 = SCHEDULE(w5, w6, w14, w3);
    ROUND(d, e, f, g, h, a, b, c, 0x766a0abb, w5);
    w6 = SCHEDULE(w6, w7, w15, w4);
    ROUND(c, d, e, f, g, h, a, b, 0x81c2c92e, w6);
    w7 = SCHEDULE(w7, w8, w0, w5);
    ROUND(b, c, d, e, f, g, h, a, 0x92722c85, w7);
    w8 = SCHEDULE(w8, w9, w1, w6);
    ROUND(a, b, c, d, e, f, g, h, 0xa2bfe8a1, w8);
    w9 = SCHEDULE(w9, w10, w2, w7);
    ROUND(h, a, b, c, d, e, f, g, 0xa81a664b, w9);
    w10 = SCHEDULE(w10, w11, w3, w8);
    ROUND(g, h, a, b, c, d, e, f, 0xc24b8b70, w10);
    w11 = SCHEDULE(w11, w12, w4, w9);
    ROUND(f, g, h, a, b, c, d, e, 0xc76c51a3, w11);
    w12 = SCHEDULE(w12, w13, w5, w10);
    ROUND(e, f, g, h, a, b, c, d, 0xd192e819, w12);
    w13 = SCHEDULE(w13, w14, w6, w11);
    ROUND(d, e, f, g, h, a, b, c, 0xd6990624, w13);
    w14 = SCHEDULE(w14, w15, w7, w12);
    ROUND(c, d, e, f, g, h, a, b, 0xf40e3585, w14);
    w15 = SCHEDULE(w15, w0, w8, w13);
    ROUND(b, c, d, e, f, g, h, a, 0x106aa070, w15);

    // rounds 48-63
    w0 = SCHEDULE(w0, w1, w9, w14);
    ROUND(a, b, c, d, e, f, g, h, 0x19a4c116, w0);
    w1 = SCHEDULE(w1, w2, w10, w15);
    ROUND(h, a, b, c, d, e, f, g, 0x1e376c08, w1);
    w2 = SCHEDULE(w2, w3, w11, w0);
    ROUND(g, h, a, b, c, d, e, f, 0x2748774c, w2);
    w3 = SCHEDULE(w3, w4, w12, w1);
    ROUND(f, g, h, a, b, c, d, e, 0x34b0bcb5, w3);
    w4 = SCHEDULE(w4, w5, w13, w2);
    ROUND(e, f, g, h, a, b, c, d, 0x391c0cb3, w4);
    w5 = SCHEDULE(w5, w6, w14, w3);
    ROUND(d, e, f, g, h, a, b, c, 0x4ed8aa4a, w5);
    w6 = SCHEDULE(w6, w7, w15, w4);
    ROUND(c, d, e, f, g, h, a, b, 0x5b9cca4f, w6);
    w7 = SCHEDULE(w7, w8, w0, w5);
    ROUND(b, c, d, e, f, g, h, a, 0x682e6ff3, w7);
    w8 = SCHEDULE(w8, w9, w1, w6);
    ROUND(a, b, c, d, e, f, g, h, 0x748f82ee, w8);
    w9 = SCHEDULE(w9, w10, w2, w7);
    ROUND(h, a, b, c, d, e, f, g, 0x78a5636f, w9);
    w10 = SCHEDULE(w10, w11, w3, w8);
    ROUND(g, h, a, b, c, d, e, f, 0x84c87814, w10);
    w11 = SCHEDULE(w11, w12, w4, w9);
    ROUND(f, g, h, a, b, c, d, e, 0x8cc70208, w11);
    w12 = SCHEDULE(w12, w13, w5, w10);
    ROUND(e, f, g, h, a, b, c, d, 0x90befffa, w12);
    w13 = SCHEDULE(w13, w14, w6, w11);
    ROUND(d, e, f, g, h, a, b, c, 0xa4506ceb, w13);
    w14 = SCHEDULE(w14, w15, w7, w12);
    ROUND(c, d, e, f, g, h, a, b, 0xbef9a3f7, w14);
    w15 = SCHEDULE(w15, w0, w8, w13);
    ROUND(b, c, d, e, f, g, h, a, 0xc67178f2, w15);

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

static __device__ __forceinline__ void
_cuda_sha256_init(uint32_t state[8])
{
    state[0] = 0x6a09e667;
    state[1] = 0xbb67ae85;
    state[2] = 0x3c6ef372;
    state[3] = 0xa54ff53a;
    state[4] = 0x510e527f;
    state[5] = 0x9b05688c;
    state[6] = 0x1f83d9ab;
    state[7] = 0x5be0cd19;
}

static __global__ void
_cuda_sha256(const uint8_t data[64], uint32_t hash[8])
{
    uint32_t state[8];
    _cuda_sha256_init(state);
    _cuda_sha256_transform_optimized(state, (uint32_t *)data);
    for (int i = 0; i < 8; ++i)
        // hash[i] = cuda_swap32(state[i]);
        hash[i] = state[i];
}

static __global__ void
_cuda_sha256d(const uint8_t data[64], uint32_t hash[8])
{
    struct {
        union {
            uint8_t h8[32];
            uint32_t h32[8];
        };
        uint8_t end;
        uint8_t pad[64 - 32 - 9];
        uint64_t len_be;
    } r2 = {
            .end = 0x80,
            .len_be = 0x0001000000000000,
    };

    uint32_t state0[8], state1[8];
    _cuda_sha256_init(state0);
    _cuda_sha256_init(state1);

    _cuda_sha256_transform_optimized(state0, (uint32_t *) data);
    for (int i = 0; i < 8; ++i)
        r2.h32[i] = cuda_swap32(state0[i]);

    _cuda_sha256_transform_optimized(state1, r2.h32);
    for (int i = 0; i < 8; ++i)
        // hash[i] = cuda_swap32(state1[i]);
        hash[i] = state1[i];
}

static __device__ __forceinline__ void
__cuda_sha256d_cont(uint32_t state0[8], const uint8_t data[64], uint32_t hash[8])
{
    uint32_t r2[16] = {
#if CUDASHA256_NOSWAP
            [8] = 0x80000000,   // end
            [15] = 0x100,       // len
#else
            [8] = 0x80,         // end
            [15] = 0x00010000,  // len
#endif
    };
#if CUDASHA256_NOSWAP
    uint32_t state1[8];
    _cuda_sha256_init(state1);
#else
    _cuda_sha256_init(hash);
#endif

#if CUDASHA256_NOSWAP
    _cuda_sha256_transform_optimized_noswap(state0, (uint32_t *)data);
    for (int i = 0; i < 8; ++i)
        r2[i] = state0[i];

    _cuda_sha256_transform_optimized_noswap(state1, r2);
    for (int i = 0; i < 8; ++i)
        hash[i] = cuda_swap32(state1[i]);
#else
    _cuda_sha256_transform_optimized(state0, (uint32_t *)data);
    for (int i = 0; i < 8; ++i)
        r2[i] = cuda_swap32(state0[i]);

    _cuda_sha256_transform_optimized(hash, r2);
    for (int i = 0; i < 8; ++i)
        hash[i] = cuda_swap32(hash[i]);
#endif

#ifdef DEBUG_PRINT
    printf("CUDA:\n");
    printf("%12s: ", "midstate");
    for (int i = 8; i--;)
        printf("%08x ", state0[i]);
    printf("\n");

    printf("%12s: ", "data");
    for (int i = 16; i--;)
        printf("%08x ", ((uint32_t *)data)[i]);
    printf("\n");

    printf("%12s: ", "r1");
    for (int i = 8; i--;)
        printf("%08x ", r2[i]);
    printf("\n");

    printf("%12s: ", "result");
    for (int i = 8; i--;)
        printf("%08x ", hash[i]);
    printf("\n");
#endif
}

static __global__ void
_cuda_sha256d_cont(uint32_t state0[8], const uint8_t data[64], uint32_t hash[8])
{
    __cuda_sha256d_cont(state0, data, hash);
}

// static __global__ void
// _cuda_sha256d_cont_noswap(uint32_t state0[8], const uint8_t data[64], uint32_t hash[8])
// {
//     uint32_t r2[16] = {
//             [8] = 0x80000000,   // end
//             [15] = 0x100,       // len
//     };
//     uint32_t state1[8];
//     _cuda_sha256_init(state1);
//
//     _cuda_sha256_transform_optimized_noswap(state0, (uint32_t *)data);
//     for (int i = 0; i < 8; ++i)
//         r2[i] = state0[i];
//
//     _cuda_sha256_transform_optimized_noswap(state1, r2);
//     for (int i = 0; i < 8; ++i)
//         hash[i] = cuda_swap32(state1[i]);
// }

static __global__ void
_cuda_sha256d_btc(
        const uint32_t midstate[8],
        const uint32_t ch2_tmpl[16],
        const uint32_t *target,
        uint64_t start_nonce,
        uint32_t *winning_nonce,
        uint32_t *block_found,
        uint32_t *found_hash)
{
    uint64_t thread_id = (uint64_t)blockDim.x * blockIdx.x + threadIdx.x;
    uint64_t nonce = start_nonce + thread_id;

    if (*block_found || (nonce > UINT32_MAX))
        return;

    uint32_t state[8];
#pragma unroll
    for (int i = 0; i < 8; ++i)
        state[i] = midstate[i];

    uint32_t ch2_local[16];
#pragma unroll
    for (int i = 0; i < 16; ++i)
        ch2_local[i] = ch2_tmpl[i];
    ch2_local[3] = nonce;

    uint32_t hash[8];
    __cuda_sha256d_cont(state, (uint8_t *)ch2_local, hash);

    // target check
    int success = 1;
#pragma unroll
    for (int i = 8; i--;) {
        if (hash[i] > target[i]) {
            success = 0;
            break;
        }
        if (hash[i] < target[i])
            break;
    }
    if (success && !atomicCAS(block_found, 0, 1)) {
#if CUDASHA256_NOSWAP
        *winning_nonce = cuda_swap32(nonce);
#else
        *winning_nonce = nonce;
#endif
#pragma unroll
        for (int i = 0; i < 8; ++i)
            found_hash[i] = hash[i];

#ifdef DEBUG_PRINT
        printf("%12s: ", "result");
        for (int i = 8; i--;)
            printf("%08x ", found_hash[i]);
        printf("\n");
#endif
    }
}

static int init = 0;
static cudaStream_t streams[2] = {};
static uint32_t *d_midstate[2] = {},
        *d_data[2] = {},
        *d_target[2] = {},
        *d_winning_nonce[2] = {},
        *d_block_found[2] = {},
        *d_found_hash[2] = {};
static int threads_per_block = 768;
static int sm_count = 48;

extern "C" {

void
cuda_init()
{
    if (init)
        return;

    cudaSetDeviceFlags(cudaDeviceScheduleBlockingSync);
    for (int i = 0; i < 2; i++) {
        cudaMalloc(&d_midstate[i], 32);
        cudaMalloc(&d_data[i], 64);
        cudaMalloc(&d_target[i], 32);
        cudaMalloc(&d_winning_nonce[i], sizeof(uint32_t));
        cudaMalloc(&d_block_found[i], sizeof(uint32_t));
        cudaMalloc(&d_found_hash[i], 32);
        cudaStreamCreate(&streams[i]);
    }

    int min_grid_size;
    cudaOccupancyMaxPotentialBlockSize(
            &min_grid_size,
            &threads_per_block,
            _cuda_sha256d_btc,
            0,
            0
    );
    cudaDeviceGetAttribute(&sm_count, cudaDevAttrMultiProcessorCount, 0);
    printf("[CUDA] Auto-tuned: threads_per_block=%u sm_count=%i\n", threads_per_block, sm_count);

    init = 1;
}

void
cuda_free()
{
    if (!init)
        return;
    for (int i = 0; i < 2; i++) {
        cudaStreamDestroy(streams[i]);
        cudaFree(d_midstate[i]);
        cudaFree(d_data[i]);
        cudaFree(d_target[i]);
        cudaFree(d_winning_nonce[i]);
        cudaFree(d_block_found[i]);
        cudaFree(d_found_hash[i]);
        d_midstate[i] = 0;
        d_data[i] = 0;
        d_target[i] = 0;
        d_winning_nonce[i] = 0;
        d_block_found[i] = 0;
        d_found_hash[i] = 0;
    }
    init = 0;
}

void
cuda_sha256(const uint8_t data[64], uint32_t hash[8])
{
    uint8_t *cuda_data;
    uint32_t *cuda_hash;

    cudaMalloc(&cuda_data, 64);
    cudaMalloc(&cuda_hash, 32);
    cudaMemcpy(cuda_data, data, 64, cudaMemcpyHostToDevice);

    _cuda_sha256<<<1, 1>>>(cuda_data, cuda_hash);
    cudaDeviceSynchronize();

    cudaMemcpy(hash, cuda_hash, 32, cudaMemcpyDeviceToHost);
    cudaFree(cuda_data);
    cudaFree(cuda_hash);
}

void
cuda_sha256d(const uint8_t data[64], uint32_t hash[8])
{
    uint8_t *cuda_data;
    uint32_t *cuda_hash;

    cudaMalloc(&cuda_data, 64);
    cudaMalloc(&cuda_hash, 32);
    cudaMemcpy(cuda_data, data, 64, cudaMemcpyHostToDevice);

    _cuda_sha256d<<<1, 1>>>(cuda_data, cuda_hash);
    cudaDeviceSynchronize();

    cudaMemcpy(hash, cuda_hash, 32, cudaMemcpyDeviceToHost);
    cudaFree(cuda_data);
    cudaFree(cuda_hash);
}

void
cuda_sha256d_cont(uint32_t state[8], const uint8_t data[64], uint32_t hash[8])
{
    uint8_t *cuda_data;
    uint32_t *cuda_hash;
    uint32_t *cuda_state;

    cudaMalloc(&cuda_data, 64);
    cudaMalloc(&cuda_hash, 32);
    cudaMalloc(&cuda_state, 32);
    cudaMemcpy(cuda_data, data, 64, cudaMemcpyHostToDevice);
    cudaMemcpy(cuda_state, state, 32, cudaMemcpyHostToDevice);

    _cuda_sha256d_cont<<<1, 1>>>(cuda_state, cuda_data, cuda_hash);
    cudaDeviceSynchronize();

    cudaMemcpy(hash, cuda_hash, 32, cudaMemcpyDeviceToHost);
    cudaFree(cuda_data);
    cudaFree(cuda_hash);
    cudaFree(cuda_state);
}

void
cuda_sha256d_btc(
        uint32_t state[8],
        const uint8_t data[64],
        uint32_t target[8],
        uint64_t start_nonce,
        // uint32_t threads_per_block,
        // uint32_t total_blocks,
        uint32_t blocks_per_sm,
        uint32_t buf_idx,

        uint32_t *winning_nonce,
        uint32_t *block_found,
        uint32_t hash[8])
{
    if (!init) {
        fprintf(stderr, "init first!\n");
        return;
    }

    cudaStream_t stream = streams[buf_idx];
    cudaMemcpyAsync(d_midstate[buf_idx], state, 32, cudaMemcpyHostToDevice, stream);
    cudaMemcpyAsync(d_data[buf_idx], data, 64, cudaMemcpyHostToDevice, stream);
    cudaMemcpyAsync(d_target[buf_idx], target, 32, cudaMemcpyHostToDevice, stream);
    cudaMemsetAsync(d_block_found[buf_idx], 0, sizeof(uint32_t));

    // _cuda_sha256d_btc<<<total_blocks, threads_per_block, 0, stream>>>(
    _cuda_sha256d_btc<<<(sm_count * blocks_per_sm), threads_per_block, 0, stream>>>(
            d_midstate[buf_idx],
            d_data[buf_idx],
            d_target[buf_idx],
            start_nonce,
            d_winning_nonce[buf_idx],
            d_block_found[buf_idx],
            d_found_hash[buf_idx]
    );

    cudaMemcpyAsync(block_found, d_block_found[buf_idx], sizeof(uint32_t), cudaMemcpyDeviceToHost, stream);
    cudaStreamSynchronize(stream);
    if (*block_found) {
        cudaMemcpy(winning_nonce, d_winning_nonce[buf_idx], sizeof(uint32_t), cudaMemcpyDeviceToHost);
        cudaMemcpy(hash, d_found_hash[buf_idx], 32, cudaMemcpyDeviceToHost);
    }
    // cudaOccupancyMaxPotentialBlockSize()
}

void
cuda_get_tuned(int *h_threads_per_block, int *h_sm_count)
{
    *h_threads_per_block = threads_per_block;
    *h_sm_count = sm_count;
}

}
