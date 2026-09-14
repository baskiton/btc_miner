#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <pthread.h>

#include "btc_miner.h"

void *
miner_worker_cuda(void *arg)
{
    pthread_setname_np(pthread_self(), "worker");
    worker_cfg_t *cfg = arg;

    cuda_init();

    uint32_t job_id_local = 0;
    uint32_t job_upd = 0;
    chunk2_t chunk2;
    hash_t midstate_local;

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
            job_upd = 2;
#if CUDASHA256_NOSWAP
            chunk_swap32((void *)&chunk2, (void *)&master_template.chunks.c2, 16);
            memcpy(midstate_local.u32, master_midstate.u32, sizeof(midstate_local));
#else
            memcpy(&chunk2, &master_template.chunks.c2, sizeof(chunk2));
            memcpy(midstate_local.u32, master_midstate.u32, sizeof(midstate_local));
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
                midstate_local.u32,
                (void *)&chunk2,
                global_target.u32,
                start,
                // threads_per_block,
                // total_blocks,
                bpsm,
                loop_cnt++ & 1,
                &job_upd,
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
