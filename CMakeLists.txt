cmake_minimum_required(VERSION 3.2)
project(snell_server_reversed)

set(CMAKE_CXX_STANDARD 14)

list(APPEND SRCS
    src/chacha20_poly1305_ietf_cipher.cc
    src/crypto_context.cc
    src/snell_server.cc
    src/snell_service.cc
    )

list(APPEND DEPS
    sodium
    gflags
    glog
    boost_system
    )

add_executable(${PROJECT_NAME} ${SRCS})
target_link_libraries(${PROJECT_NAME} ${DEPS})

