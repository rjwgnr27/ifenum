cmake_minimum_required(VERSION 3.0)

project(ifenum)

add_executable(ifenum main.cpp)

install(TARGETS ifenum RUNTIME DESTINATION bin)
