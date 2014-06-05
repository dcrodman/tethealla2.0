project(patch_server CXX)
cmake_minimum_required(VERSION 2.6)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(patch_server
    main.cc
    patch_packets.cc
    patch_server.h
    patch_packets.h
    )

find_package(Iconv REQUIRED)

if (ICONV_FOUND)
	include_directories(${ICONV_INCLUDE_DIR})
	target_link_libraries(patch_server ${ICONV_LIBRARIES})
else (ICONV_FOUND)
	message("Unable to locate Iconv, please make sure that it's installed" 
		" and accessible in your system's include directories.")
endif (ICONV_FOUND)

# Allow patch_server to be built by itself by including the exported
# LIBTETHEALLA_INCLUDE_DIR from the libtethealla CMakeLists.
add_subdirectory(./../libtethealla tethealla)
include_directories(${LIBTETHEALLA_INCLUDE_DIR})

target_link_libraries(patch_server tethealla)