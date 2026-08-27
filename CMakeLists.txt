cmake_minimum_required(VERSION 3.23)
project(btc_like C)

set(CMAKE_C_STANDARD 99)

add_compile_definitions(
        CMAKE_C_COMPILER=gcc
        CMAKE_BUILD_TYPE=Release
#        CMAKE_BUILD_TYPE=RelWithDebInfo
#        CMAKE_BUILD_TYPE=Debug
)

add_executable(btc_like
#        main.c
        main2.c
)

target_link_libraries(btc_like
        crypto
)