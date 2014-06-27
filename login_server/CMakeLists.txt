project(login_server CXX)
cmake_minimum_required(VERSION 2.6)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR})

# !!NOTE!! Set this variable to False if building for production.
set(DEBUGGING True)

if (DEBUGGING)
    add_definitions(-DDEBUGGING)
endif(DEBUGGING)

add_executable(login_server
    bbtable.h
    clientmsg.h
    pso_crypt.h
    servermsg.h
    login_server.c
    )

# Allow patch_server to be built by itself by including the exported
# LIBTETHEALLA_INCLUDE_DIR from the libtethealla CMakeLists.
add_subdirectory(./../libtethealla tethealla)
include_directories(${LIBTETHEALLA_INCLUDE_DIR})

# TODO: Implement finding libjansson instead of hardcoding path.
include_directories(/usr/local/include/)
link_directories(/usr/local/lib/)

target_link_libraries(login_server jansson)
target_link_libraries(login_server tethealla)