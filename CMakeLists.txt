cmake_minimum_required(VERSION 3.0.2)

project(eoam)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_DEFAULT_STARTUP_PROJECT eoam)
set(CMAKE_BUILD_TYPE Debug)

# googletest
enable_testing()
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

# vscode cmake tools
include(CMakeToolsHelpers OPTIONAL)

# include
include_directories("./" "./src" "./include" "./src/xutl/include")
include_directories("./external/uthash/include" "./external/getopt/include")

# global flags
SET( GCC_COVERAGE_COMPILE_FLAGS "-g -Wall -Wextra -Werror")
SET( CMAKE_C_FLAGS  ${CMAKE_C_FLAGS} ${GCC_COVERAGE_COMPILE_FLAGS})
SET( CMAKE_CXX_FLAGS  ${CMAKE_CXX_FLAGS} ${GCC_COVERAGE_COMPILE_FLAGS})

IF (APPLE)
    SET(GCC_COVERAGE_LINK_FLAGS    "-lpcap -Wall")
ELSE ()
    SET(GCC_COVERAGE_LINK_FLAGS    "-lpcap -pthread")
ENDIF()

SET( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} ${GCC_COVERAGE_LINK_FLAGS}" )

add_subdirectory(./src/xutl)
add_subdirectory(./src/eoamlib)
add_subdirectory(external)
add_subdirectory(./example)
add_subdirectory(./test)







