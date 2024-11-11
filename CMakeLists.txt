# CMakeList.txt : CMake project for crypto_lab2, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.15)

project ("crypto_lab2")
set(CMAKE_CXX_STANDARD 20)

#in case Windows is used with MinGW or similar layer
#set(CMAKE_EXE_LINKER_FLAGS ${CMAKE_EXE_LINKER_FLAGS} "-static")

add_executable (crypto_lab2 "crypto_lab2.cpp" "crypto_lab2.h")
