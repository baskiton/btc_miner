cmake_minimum_required(VERSION 3.23)
project(btcminer C)

set(CMAKE_C_STANDARD 99)

set(CMAKE_CUDA_STANDARD 14)
set(CMAKE_CUDA_ARCHITECTURES 86)

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(CUDAToolkit)

add_compile_definitions(
        CMAKE_BUILD_TYPE=Release
#        CMAKE_BUILD_TYPE=RelWithDebInfo
#        CMAKE_BUILD_TYPE=Debug

        OPENSSL_SUPPRESS_DEPRECATED
#        DEBUG_PRINT
        WITH_CUDA=$<BOOL:${CUDAToolkit_FOUND}>
        CUDASHA256_NOSWAP=1
        CUDASHA256_TEST
        CUDASHA256_BITCOIN_ONLY
)
#set(CMAKE_CUDA_FLAGS_DEBUG "${CMAKE_CUDA_FLAGS_DEBUG} -g -G")

add_executable(btcminer
        src/btc_miner.h
        src/main2.c
        src/common.c
)
target_link_libraries(btcminer
        PRIVATE
        Threads::Threads
        OpenSSL::Crypto
)

add_executable(benchmark
        src/btc_miner.h
        src/benchmark.c
        src/common.c
)
target_link_libraries(benchmark
        PRIVATE
        Threads::Threads
        OpenSSL::Crypto
)

if (CUDAToolkit_FOUND)
    enable_language(CUDA)

    add_library(cuda_miner STATIC
            src/sha256.cu
    )
    set_target_properties(cuda_miner PROPERTIES
            CUDA_SEPARABLE_COMPILATION ON
    )
    target_compile_options(cuda_miner
            PRIVATE --ptxas-options=-v
    )

    add_executable(btcminer-cuda
            src/btc_miner.h
            src/main-cuda.c
            src/test_cuda.c
            src/common.c
    )
    target_link_libraries(btcminer-cuda
            PRIVATE
            cuda_miner
            Threads::Threads
            OpenSSL::Crypto
            CUDA::nvml
    )
else ()
    message(WARNING "CUDA Toolkit NOT found")
endif ()
