#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include "btc_miner.h"

int
main()
{
#ifdef CUDASHA256_TEST
    // cuda_sha256_test();
    if (cuda_sha256_test())
        return 1;
    // return 0;
#endif

    nprocs = 1;

    return miner_loop(miner_worker_cuda, 1, 60);
}
