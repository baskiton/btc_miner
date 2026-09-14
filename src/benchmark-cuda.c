#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include "btc_miner.h"

int
main()
{
    nprocs = 1;
    return miner_loop(miner_worker_cuda, 0, 10);
}
