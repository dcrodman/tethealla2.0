# Build all sources within this directory into a staitc library (libtethealla.a).
project(libtethealla C)
cmake_minimum_required(VERSION 2.6)

set(ENC_DR encryption/)

set(ENCRYPTION_SOURCES 
	${ENC_DR}/psobb-crypt.c
	${ENC_DR}/psogc-crypt.c
	${ENC_DR}/psopc-crypt.c
	${ENC_DR}/encryption.c
	)

add_library(tethealla STATIC ${ENCRYPTION_SOURCES})