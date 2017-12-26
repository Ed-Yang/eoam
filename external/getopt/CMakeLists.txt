cmake_minimum_required(VERSION 3.0.2)
project(getopt)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
SET(CMAKE_BUILD_TYPE Debug)

file(GLOB SOURCES "*.c")

# vscode cmake tools
include(CMakeToolsHelpers OPTIONAL)

add_library(getopt STATIC ${SOURCES})


