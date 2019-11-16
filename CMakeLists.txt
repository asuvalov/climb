cmake_minimum_required(VERSION 3.8.0)

project(climb)

find_package(OpenSSL REQUIRED)

set(CMAKE_C_COMPILER /usr/bin/gcc-8)
set(CMAKE_CXX_COMPILER /usr/bin/g++-8)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(LIBRARY_OUTPUT_PATH "${CMAKE_BINARY_DIR}/lib")
set(ARCHIVE_OUTPUT_PATH "${CMAKE_BINARY_DIR}/lib")

add_subdirectory(climb/src)
add_subdirectory(tests)
