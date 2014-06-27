# Build all sources within this directory into a staitc library (libtethealla.a).
project(libtethealla C)
cmake_minimum_required(VERSION 2.6)

set(INCL_DR include/)
set(ENC_DR encryption/)

set(ENCRYPTION_SOURCES 
	${ENC_DR}/psobb-crypt.c
	${ENC_DR}/psogc-crypt.c
	${ENC_DR}/psopc-crypt.c
	${ENC_DR}/encryption.c
    ${INCL_DR}/encryption.h
	)

set (SNIFFEX_SOURCES
	sniffex/sniffex.c
    ${INCL_DR}/sniffex.h
	)

set (MD5_SOURCES 
	md5/md5.c
	${INCL_DR}/md5.h
	)

# Export this directory to the parent scope so that other binaries
# in the project can be built individually and include this library.
set(LIBTETHEALLA_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/${INCL_DR})
set(LIBTETHEALLA_INCLUDE_DIR ${SHARED_LIB_INCLUDE_DIR} PARENT_SCOPE)

if (TARGET tethealla)
	message('libtethealla is already defined.')
else(TARGET tethealla)
	include_directories(${LIBTETHEALLA_INCLUDE_DIR})
	add_library(tethealla STATIC ${ENCRYPTION_SOURCES} ${SNIFFEX_SOURCES} ${MD5_SOURCES})
endif(TARGET tethealla)