project(tethealla CXX)
cmake_minimum_required(VERSION 2.6)

# Includes for libtethealla.
include_directories(${CMAKE_SOURCE_DIR}/libtethealla/include)

# Invoke CMake build instructions from subdirectories to modularize
# building each individual project.
add_subdirectory(libtethealla)
add_subdirectory(patch_server)