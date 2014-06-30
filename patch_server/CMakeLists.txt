project(patch_server CXX)
cmake_minimum_required(VERSION 2.6)

set(CMAKE_MODULE_PATH ./../cmake_modules)

# !!NOTE!! Set this variable to False if building for production.
set(DEBUGGING False)

if (DEBUGGING)
    add_definitions(-DDEBUGGING)
endif(DEBUGGING)

add_executable(patch_server
    patch_server.cc
    patch_packets.cc
    patch_server.h
    patch_packets.h)

# Use the CMake module to find the Iconv library.
find_package(Iconv REQUIRED)

if (ICONV_FOUND)
	include_directories(${ICONV_INCLUDE_DIR})
	target_link_libraries(patch_server ${ICONV_LIBRARIES})
else (ICONV_FOUND)
	message("Unable to locate Iconv, please make sure that it's installed" 
		" and accessible in your system's include directories.")
endif (ICONV_FOUND)

# Use the CMake module to find Jansson.
find_package(Jansson REQUIRED)

if (JANSSON_FOUND)
    include_directories(${JANSSON_INCLUDE_DIR})
    target_link_libraries(patch_server ${JANSSON_LIBRARIES})
else (JANSSON_FOUND)
    message("Unable to locate Jansson, please make sure that it's installed"
        " and accessible in your system's include directories.")
endif (JANSSON_FOUND)

# Allow patch_server to be built by itself by including the exported
# LIBTETHEALLA_INCLUDE_DIR from the libtethealla CMakeLists.
add_subdirectory(./../libtethealla tethealla)
include_directories(${LIBTETHEALLA_INCLUDE_DIR})

target_link_libraries(patch_server tethealla)