cmake_minimum_required(VERSION 3.22)
project(mirith)
enable_language(ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_VERBOSE_MAKEFILE ON)

# needed for nvim
set(CMAKE_EXPORT_COMPILE_COMMANDS ON CACHE INTERNAL "")
if(CMAKE_EXPORT_COMPILE_COMMANDS)
    set(CMAKE_CXX_STANDARD_INCLUDE_DIRECTORIES
            ${CMAKE_CXX_IMPLICIT_INCLUDE_DIRECTORIES})
endif()

set(CMAKE_C_FLAGS_DEBUG "-g -DDEBUG -O0 -Wall -mavx2 -mavx")
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG -Wall -flto -march=native -mavx2 -mavx -ftree-vectorize -funroll-loops -fomit-frame-pointer -fno-stack-protector")

set(COMMON_SOURCES
        ${PROJECT_SOURCE_DIR}/matrix.c
        ${PROJECT_SOURCE_DIR}/hash.c
        ${PROJECT_SOURCE_DIR}/packing.c
        ${PROJECT_SOURCE_DIR}/prng.c
        ${PROJECT_SOURCE_DIR}/random.c
        ${PROJECT_SOURCE_DIR}/seed_tree.c
        ${PROJECT_SOURCE_DIR}/sign.c
        ${PROJECT_SOURCE_DIR}/challenges.c
        ${PROJECT_SOURCE_DIR}/KeccakHash.c
        ${PROJECT_SOURCE_DIR}/internal_get_cycles.c
        ${PROJECT_SOURCE_DIR}/KeccakP-1600-AVX2.s
        )

add_executable(bench bench/bench_mirith.c ${COMMON_SOURCES})
add_executable(bench_noinline bench/bench_mirith.c ${COMMON_SOURCES})
target_compile_options(bench_noinline PRIVATE -fno-inline)
add_executable(test test/test_mirith.c ${COMMON_SOURCES})
