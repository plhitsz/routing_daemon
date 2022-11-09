cmake_minimum_required(VERSION 3.22)

project(routing_sync)

# Settings and Checking
# build binay in the root of source dir IS NOT ALLOWED
if("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")
    message(FATAL_ERROR "
    FATAL: In-source builds are not allowed.
           You should create a separate directory for build files.
           ")
endif()

# c++17 checking
include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG("-std=c++17" COMPILER_SUPPORTS_CXX17)
if (COMPILER_SUPPORTS_CXX17)
    message(STATUS "c++17 supported")
else ()
    message(FATAL_ERROR "
            FATAL: gcc or g++ do not support c++17")
endif ()

# specify the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Release default
# change it to Debug by `cmake -DCMAKE_BUILD_TYPE=Debug ..`
option(CMAKE_BUILD_TYPE "Release")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror -O3 -fPIC")
###########################################################

# more compile info dump if set it to true
set(CMAKE_VERBOSE_MAKEFILE false)

include_directories(src)

set(CMAKE_C_VISIBILITY_PRESET default)
set(CMAKE_CXX_VISIBILITY_PRESET default)

aux_source_directory(src DIR_SRCS)
add_executable(routing_sync
    ${DIR_SRCS}
)
target_include_directories(routing_sync
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
# link the new routing_sync target with the test_binary target
target_link_libraries(routing_sync
    Threads::Threads
)