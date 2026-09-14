#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include "btc_miner.h"

int
main()
{
    return miner_loop(miner_worker_cpu, 0, 10);
}
