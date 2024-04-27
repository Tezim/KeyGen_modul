cmake_minimum_required(VERSION 3.24)
project(KeyGen_modul)
include_directories(.)
link_directories(.)

set(CMAKE_CXX_STANDARD 17)
file(GLOB SRCS src/*.cpp)
add_executable(KeyGen_modul ${SRCS})
target_link_libraries(KeyGen_modul libNTL_lib.a)