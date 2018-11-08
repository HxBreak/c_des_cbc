cmake_minimum_required(VERSION 3.12)
project(des_cbc)

set(CMAKE_CXX_STANDARD 11)

add_executable(des_cbc main.cpp
        des.c
        platform.c
        platform_util.c)