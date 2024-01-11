cmake_minimum_required(VERSION 3.22)
project(mirith_cpp)
enable_language(CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_VERBOSE_MAKEFILE ON)

# needed for nvim
set(CMAKE_EXPORT_COMPILE_COMMANDS ON CACHE INTERNAL "")
if(CMAKE_EXPORT_COMPILE_COMMANDS)
    set(CMAKE_CXX_STANDARD_INCLUDE_DIRECTORIES
            ${CMAKE_CXX_IMPLICIT_INCLUDE_DIRECTORIES})
endif()

include_directories(../../../XKCP/bin/AVX2/libXKCP.a.headers)
link_directories(../../../XKCP/bin/AVX2/)

set(CMAKE_C_FLAGS_DEBUG "-g -DDEBUG -O0 -Wall -flax-vector-conversions")
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG -Wall -flto -march=native -mfpu=neon -flax-vector-conversions -ftree-vectorize -funroll-loops -fomit-frame-pointer -fno-stack-protector")
set(CMAKE_CXX_FLAGS_DEBUG "-g -DDEBUG -O0 -Wall -flax-vector-conversions")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -Wall -flto -march=native -mfpu=neon -flax-vector-conversions -ftree-vectorize -funroll-loops -fomit-frame-pointer -fno-stack-protector")

set(NIST_SOURCES
        ${PROJECT_SOURCE_DIR}/matrix.c
        ${PROJECT_SOURCE_DIR}/hash.c
        ${PROJECT_SOURCE_DIR}/packing.c
        ${PROJECT_SOURCE_DIR}/prng.c
        ${PROJECT_SOURCE_DIR}/nist/rng.c
        ${PROJECT_SOURCE_DIR}/seed_tree.c
        ${PROJECT_SOURCE_DIR}/sign.c
        ${PROJECT_SOURCE_DIR}/challenges.c
        ${PROJECT_SOURCE_DIR}/KeccakHash.c
        ${PROJECT_SOURCE_DIR}/KeccakP-1600-opt64.c
        )
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
        ${PROJECT_SOURCE_DIR}/KeccakP-1600-opt64.c
        )

add_executable(test test/test_mirith.c ${COMMON_SOURCES})
add_executable(nist nist/PQCgenKAT_sign.c ${NIST_SOURCES})
target_link_libraries(nist crypto)
