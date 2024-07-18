cmake_minimum_required(VERSION 3.10)
project(ECIES_OpenSSL_example)

set(CMAKE_CXX_STANDARD 11)

find_package(OpenSSL REQUIRED)

add_executable(ecies_example encryptor.cpp)

target_link_libraries(ecies_example OpenSSL::Crypto)
