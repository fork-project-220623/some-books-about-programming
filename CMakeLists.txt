cmake_minimum_required(VERSION 4.0)
project(CLionCrack C)

set(CMAKE_C_STANDARD 11)

set(MINHOOK_PATH "") # your path to minhook.

file(GLOB_RECURSE MINHOOK_SOURCES CONFIGURE_DEPENDS "${MINHOOK_PATH}/src/*.c")

add_library(CLionCrack SHARED library.c ${MINHOOK_SOURCES}
        injector.c)
target_include_directories(CLionCrack PRIVATE "${MINHOOK_PATH}/include")
add_executable(Injector injector.c)
