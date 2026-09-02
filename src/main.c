#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <byteswap.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
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

#include <openssl/evp.h>


//#define BITS 0x1e00ffff
//#define BITS 0x1d00ffff
#define BITS 0x17023cc1

typedef uint64_t uint256_t[4];
typedef struct tpool_s tpool_t;

typedef struct {
    uint64_t ver;
    int64_t time;
    union {
        uint256_t u256;
        uint64_t u64[4];
        uint8_t u8[32];
    } prev_hash;
    uint32_t bits;
    uint32_t nonce;
} block_t;

typedef struct {
    union {
        uint256_t u256;
        uint64_t u64[4];
        uint8_t u8[32];
    } last_hash;
    uint256_t target;
    tpool_t *tpool;
    int evfd;

} mining_ctx;

typedef struct {
    EVP_MD_CTX *base_hash;
    uint64_t start, stop;
    int *round_done;
} tpool_task_t;

struct tpool_s {
    pthread_mutex_t lock;
    pthread_cond_t act_cond;
    pthread_cond_t done_cond;
    mining_ctx *ctx;
    int threads_cnt;
    int stop, tasks[2];
    int active_threads;
};

static void uint256_dump(const uint256_t a, int swap);
static int uint256_check(const uint256_t a, const uint256_t target);
static void create_target(uint32_t bits, uint256_t target);

////////////////////////////////////////////////////////////////////////////////

static ssize_t
_read(int fd, void *data, size_t len)
{
    ssize_t ret;
    while ((ret = read(fd, data, len)) == -1 && errno == EINTR);
    return ret;
}

int
_write_all(int fd, const void *data, size_t len)
{
    while (len) {
        errno = 0;
        ssize_t tmp = write(fd, data, len);
        if (tmp > 0) {
            len -= tmp;
            data = (char *)data + tmp;
        } else if (errno != EINTR)
            return -1;
    }
    return 0;
}

////////////////////////////////////////////////////////////////////////////////

static void *mining_woorker(void *arg);

static int
tpool_task_push(tpool_t *pool, EVP_MD_CTX *base_hash, uint32_t start, uint32_t stop, int *round_done)
{
    tpool_task_t task = {
            .base_hash = base_hash,
            .start = start,
            .stop = stop,
            .round_done = round_done,
    };
    return _write_all(pool->tasks[1], &task, sizeof(task));
}

static void
clear_tasks(tpool_t *pool)
{
    pthread_mutex_lock(&pool->lock);
//    ioctl(pool->tasks[0], TCFLSH, TCIOFLUSH);
//    ioctl(pool->tasks[1], TCFLSH, TCIOFLUSH);
    int flags = fcntl(pool->tasks[0], F_GETFL, 0);
    fcntl(pool->tasks[0], F_SETFL, flags | O_NONBLOCK);

    tpool_task_t task;
    while (read(pool->tasks[0], &task, sizeof(task)) > 0);

    fcntl(pool->tasks[0], F_SETFL, flags);
    pthread_mutex_unlock(&pool->lock);
}

static void
tpool_free(tpool_t *pool)
{
    close(pool->tasks[0]);
    close(pool->tasks[1]);
    close(pool->stop);
    pthread_cond_destroy(&pool->done_cond);
    pthread_cond_destroy(&pool->act_cond);
    pthread_mutex_destroy(&pool->lock);
    free(pool);
}

static void
tpool_stop(tpool_t *pool)
{
    if (pool)
        eventfd_write(pool->stop, 1);
}

static tpool_t *
tpool_create(mining_ctx *ctx, int threads)
{
    if (threads <= 0)
        threads = get_nprocs() - 1;

    tpool_t *pool = calloc(1, sizeof(*pool));
    if (pool) {
        if (pthread_mutex_init(&pool->lock, 0)
                || pthread_cond_init(&pool->act_cond, 0)
                || pthread_cond_init(&pool->done_cond, 0)) {
            tpool_free(pool);
            return 0;
        }

        pool->threads_cnt = threads;
        pool->ctx = ctx;
        ctx->tpool = pool;
        pool->stop = pool->tasks[0] = pool->tasks[1] = -1;

        int e = 0;
        pthread_t tid;
        if ((pool->stop = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK)) == -1
                || pipe2(pool->tasks, O_CLOEXEC | O_DIRECT)
                || fcntl(pool->tasks[1], F_SETFL, fcntl(pool->tasks[1], F_GETFL) | O_NONBLOCK)
                || fcntl(pool->tasks[1], F_SETPIPE_SZ, 1<<20) == -1
                || fcntl(pool->tasks[0], F_SETPIPE_SZ, 1<<20) == -1
//                || (e = pthread_create(&tid, 0, tpool_attractor, pool))
                ) {
            fprintf(stderr, "ERROR threadpool create: %s\n", strerror(e ?: errno));
            tpool_free(pool);
            return 0;
        }
//        if ((e = pthread_detach(tid))) {
//            q_debug(ctx, "ERROR threadpool create: %s", strerror(e));
//            tpool_stop(pool);
//            tpool_free(pool);
//            return 0;
//        }
    }
    return pool;
}

static void *
mining_woorker(void *arg)
{
    tpool_t *pool = arg;
    mining_ctx *ctx = pool->ctx;
    uint256_t sha256;
    int dummy_done = 0;
    int n;
    ssize_t x;
    time_t t;
    char t_buf[80];

    tpool_task_t task = { .round_done = &dummy_done, };

    while (1) {
        pthread_mutex_lock(&pool->lock);
        while (*task.round_done)
            pthread_cond_wait(&pool->done_cond, &pool->lock);
        pthread_mutex_unlock(&pool->lock);
        if (ioctl(pool->tasks[0], FIONREAD, &n)) {
            perror("ioctl thread");
            break;
        }
        pthread_mutex_lock(&pool->lock);
        if (n > 0)
            x = _read(pool->tasks[0], &task, sizeof(task));
        else {
            pthread_mutex_unlock(&pool->lock);
            continue;
        }
        if (x <= 0) {
            pthread_mutex_unlock(&pool->lock);
            break;
        }
        ++pool->active_threads;
        pthread_mutex_unlock(&pool->lock);

        EVP_MD_CTX *hash0 = EVP_MD_CTX_new();
        EVP_MD_CTX *hash1 = EVP_MD_CTX_new();
        EVP_DigestInit_ex(hash1, EVP_MD_CTX_get1_md(task.base_hash), NULL);
//        printf("run task (%li-%li)\n", task.start, task.stop);

        for (uint64_t nonce = task.start; nonce < task.stop; ++nonce) {
            if (*task.round_done)
                break;

            EVP_MD_CTX_copy_ex(hash0, task.base_hash);
            EVP_DigestUpdate(hash0, &nonce, sizeof(nonce));
            EVP_DigestFinal_ex(hash0, (void *)sha256, NULL);
            EVP_MD_CTX_reset(hash1);
            EVP_DigestUpdate(hash1, sha256, sizeof(sha256));
            EVP_DigestFinal_ex(hash1, (void *)sha256, NULL);

            if (uint256_check(sha256, ctx->target)) {
                pthread_mutex_lock(&pool->lock);
                if (*task.round_done) {
                    pthread_mutex_unlock(&pool->lock);
                    break;
                }
                *task.round_done = 1;
                pthread_cond_broadcast(&pool->done_cond);
//                clear_tasks(pool);
//                printf("tasks flushed\n");
                pthread_mutex_unlock(&pool->lock);

                time(&t);
                strftime(t_buf, sizeof(t_buf), "%Y-%m-%d %H:%M:%S", localtime(&t));
                printf("%s: WIN! nonce=%lu ", t_buf, nonce);
                uint256_dump(sha256, 1);
                memcpy(&ctx->last_hash, sha256, sizeof(ctx->last_hash));

                break;
            }
        }
        pthread_mutex_lock(&pool->lock);
        --pool->active_threads;
        if (!pool->active_threads)
            pthread_cond_signal(&pool->act_cond);
        pthread_mutex_unlock(&pool->lock);
    }
    pthread_exit(0);
}

static void *
mining_attractor(void *arg)
{
    tpool_t *pool = arg;
    mining_ctx *ctx = pool->ctx;
    int round_done = 1;
    int ti = 0;

    pthread_t *threads = alloca(pool->threads_cnt * sizeof(*threads));
    for (int n = pool->threads_cnt; n--;)
        if (!pthread_create(&threads[ti], 0, mining_woorker, pool))
            ++ti;
    pool->threads_cnt = ti;

    while (1) {
        block_t b = {.ver = 1, .time = time(0), .bits = BITS,};
        memcpy(&b.prev_hash, &ctx->last_hash, sizeof(ctx->last_hash));
        printf("search for ");
        uint256_dump(ctx->last_hash.u256, 1);
        create_target(b.bits, ctx->target);

        EVP_MD_CTX *base_hash = EVP_MD_CTX_new();
        const EVP_MD *md = EVP_sha256();

        EVP_DigestInit_ex(base_hash, md, NULL);
        EVP_DigestUpdate(base_hash, &b, sizeof(b) - sizeof(b.nonce));

        uint64_t d = 1UL << 25; // 128 parts
        uint64_t to = 0;
        for (uint64_t i = 0; i <= UINT32_MAX; i = to) {
            to = i + d;
            if (to > UINT32_MAX)
                to = (uint64_t)UINT32_MAX + 1;
//            printf("push (%li-%li)\n", i, to);
            if (tpool_task_push(pool, base_hash, i, to, &round_done) != 0) {
//                perror("push");
            }
        }
        pthread_mutex_lock(&pool->lock);
        round_done = 0;
        pthread_cond_broadcast(&pool->done_cond);
        pthread_mutex_unlock(&pool->lock);

//        printf("runned\n");
        uint32_t xxx = 0;
        int n = 1;
        while (!round_done && (n || pool->active_threads)) {
            if (ioctl(pool->tasks[0], FIONREAD, &n)) {
                perror("FIONREAD");
                break;
            }
//            if (!xxx--) {
//                xxx = 1 << 22;
//                printf("active=%i done=%i n=%i\n", pool->active_threads, round_done, n);
//            }
        }
//        printf("active=%i done=%i n=%i\n", pool->active_threads, round_done, n);
//        if (round_done)
        pthread_mutex_lock(&pool->lock);
        round_done = 1;
        pthread_cond_broadcast(&pool->done_cond);
        pthread_mutex_unlock(&pool->lock);
        clear_tasks(pool);
        pthread_mutex_lock(&pool->lock);
        while (pool->active_threads)
            pthread_cond_wait(&pool->act_cond, &pool->lock);
        pthread_mutex_unlock(&pool->lock);
        ioctl(pool->tasks[0], FIONREAD, &n);
//        printf("active=%i done=%i n=%i ;;;\n", pool->active_threads, round_done, n);
//        printf("again\n");
    }
}

////////////////////////////////////////////////////////////////////////////////


static void
uint256_dump(const uint256_t a, int swap)
{
    for (int i = 0; i < 4; ++i)
        printf("%016lx ", swap? bswap_64(a[i]): a[i]);
    printf("\n");
}

static int
uint256_check(const uint256_t a, const uint256_t target)
{
    for (int i = 0; i < 4; i++) {
        if (bswap_64(a[i]) < target[i])
            return 1;
        if (bswap_64(a[i]) > target[i])
            return 0;
    }
    return 1;
}

static void
create_target(uint32_t bits, uint256_t target)
{
    memset(target, 0, sizeof(uint256_t));
    uint64_t e = bits >> 24;
    uint64_t c = bits & 0xffffff;
    uint64_t shift = 8 * (e - 3);
    uint64_t a_idx = 3 - shift / 64;
    uint64_t a_sh = shift % 64;
    target[a_idx] = c << a_sh;
//    printf("a_idx=%lu a_sh=%lu\n", a_idx, a_sh);
    if (a_idx && (a_sh > (3*8))) {
//        printf("cont...\n");
        a_sh = 64 - a_sh;
        target[a_idx-1] = c >> a_sh;
    }
//    printf("done\n");
}

//static void mine(uint256_t last_hash, block_t *last_block)
//static void
//mine(uint64_t *n, uint256_t last_hash)
//{
//    block_t b = { .ver = 1, .time = time(0), .bits = BITS, };
//
//    memcpy(&b.prev_hash, last_hash, 32);
//    printf("search for ");
//    uint256_dump(last_hash, 1);
//    uint256_t target, result;
//    create_target(b.bits, target);
//
//    EVP_MD_CTX *ctx0 = EVP_MD_CTX_new();
//    EVP_MD_CTX *ctx1 = EVP_MD_CTX_new();
//    const EVP_MD *md = EVP_sha256();
//
//    EVP_DigestInit_ex(ctx0, md, NULL);
//    EVP_DigestUpdate(ctx0, &b, sizeof(b) - sizeof(b.nonce));
//
//    for (uint64_t nonce = 0;  nonce <= UINT32_MAX; ++nonce) {
//        b.nonce = nonce;
//        EVP_MD_CTX_copy_ex(ctx1, ctx0);
//        EVP_DigestUpdate(ctx1, &b.nonce, sizeof(b.nonce));
//        EVP_DigestFinal_ex(ctx1, (void *)result, NULL);
//
//        if (uint256_check(result, target)) {
//            printf("WIN! n=%lu nonce=%u ", *n, b.nonce);
//            uint256_dump(result, 1);
//            memcpy(last_hash, result, 32);
////            memcpy(last_block, &b, sizeof(b));
//            ++*n;
//            break;
//        }
//    }
//
//    EVP_MD_CTX_free(ctx1);
//    EVP_MD_CTX_free(ctx0);
//}


int
main()
{
//    {
//        block_t b;
//        create_target(BITS, b.prev_hash.u256);
//        printf("target:\n");
//        uint256_dump(b.prev_hash.u256, 0);
//        printf("\n");
//    }
//
//    block_t b = { .ver = 1, .time = (0), .bits = 0x1f00ffff};
//    uint256_t last_hash = {};
//    uint64_t n = 0;
//    while (1)
//        mine(&n, last_hash);

    mining_ctx ctx = {};
    create_target(BITS, ctx.target);
    printf("target:\n");
    uint256_dump(ctx.target, 0);
    printf("\n");

    tpool_t *pool = tpool_create(&ctx, 0);
    if (pool)
        mining_attractor(pool);

    return 0;
}
