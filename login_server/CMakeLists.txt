project(login_server CXX)
cmake_minimum_required(VERSION 2.6)

set(CMAKE_MODULE_PATH ./../cmake_modules)

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
    login.h
    login.cc
    login_server.h
    login_server.cc)

# Allow patch_server to be built by itself by including the exported
# LIBTETHEALLA_INCLUDE_DIR from the libtethealla CMakeLists.
add_subdirectory(./../libtethealla tethealla)
include_directories(${LIBTETHEALLA_INCLUDE_DIR})

# Use the CMake module to find Jansson.
find_package(Jansson REQUIRED)

if (JANSSON_FOUND)
    include_directories(${JANSSON_INCLUDE_DIRS})
    target_link_libraries(login_server ${JANSSON_LIBRARIES})
else (JANSSON_FOUND)
    message("Unable to locate Jansson, please make sure that it's installed"
        " and accessible in your system's include directories.")
endif (JANSSON_FOUND)

# Use the CMake module to find MySQLConnectorC.
find_package(MySQLConnector REQUIRED)

if (MYSQLCONNECTORC_FOUND)
    include_directories(${MYSQLCONNECTORC_INCLUDE_DIRS})
    target_link_libraries(login_server ${MYSQLCONNECTORC_LIBRARIES})
endif(MYSQLCONNECTORC_FOUND)

target_link_libraries(login_server tethealla)