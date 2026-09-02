cmake_minimum_required(VERSION 3.23)
project(btcminer C CUDA)

set(CMAKE_C_STANDARD 99)

set(CMAKE_CUDA_STANDARD 14)
set(CMAKE_CUDA_ARCHITECTURES native)

add_compile_definitions(
        CMAKE_BUILD_TYPE=Release
#        CMAKE_BUILD_TYPE=RelWithDebInfo
#        CMAKE_BUILD_TYPE=Debug

#        DEBUG_PRINT
        CUDASHA256_NOSWAP=1
        CUDASHA256_TEST
#        CUDASHA256_NAIVE
)

add_library(cuda_miner STATIC
        src/sha256.cu
)
set_target_properties(cuda_miner PROPERTIES
        CUDA_SEPARABLE_COMPILATION ON)

add_executable(btcminer
        btc_miner.h
#        main.c
        main2.c
        src/btc_miner.h
#        src/main.c
        src/main2.c
)

add_executable(btcminer-cuda
        src/btc_miner.h
        src/main-cuda.c
        src/test_cuda.c
)

target_compile_definitions(btcminer
        PRIVATE CMAKE_C_COMPILER=gcc
)
target_compile_definitions(btcminer-cuda
        PRIVATE CMAKE_C_COMPILER=gcc
)

target_compile_options(btcminer
        PRIVATE -pthread
)

target_compile_options(btcminer-cuda
        PRIVATE -pthread
)

target_link_libraries(btcminer
        crypto
)

target_link_libraries(btcminer-cuda
        PRIVATE cuda_miner
        crypto
        nvidia-ml
)
