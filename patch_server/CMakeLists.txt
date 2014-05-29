project(patch_server CXX)
cmake_minimum_required(VERSION 2.6)

add_executable(patch_server
    main.cc
    patch_packets.cc
    patch_server.h
    patch_packets.h
    )
target_link_libraries(patch_server tethealla)