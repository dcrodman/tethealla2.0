# Build all sources within this directory into a staitc library (libtethealla.a).
project(libtethealla C)
cmake_minimum_required(VERSION 2.6)

set(INCL_DR include/)
set(ENC_DR encryption/)
set(UTILS_DR utils/)

set(ENCRYPTION_SOURCES 
	${ENC_DR}/psobb-crypt.c
	${ENC_DR}/psogc-crypt.c
	${ENC_DR}/psopc-crypt.c
	${ENC_DR}/encryption.c
    ${INCL_DR}/encryption.h
	)

set(UTILS_SOURCES
	${UTILS_DR}/mtwist.c
	${INCL_DR}/mtwist.h
	)

add_library(tethealla STATIC ${ENCRYPTION_SOURCES} ${UTILS_SOURCES})