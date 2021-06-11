cmake_minimum_required(VERSION 3.0.2)
project(xutl)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
SET(CMAKE_BUILD_TYPE Debug)

add_definitions("-std=c++11")

file(GLOB SOURCES "./src/*.cpp")

# for GTest/GMock
SET( GCC_COVERAGE_COMPILE_FLAGS ${GCC_COVERAGE_COMPILE_FLAGS})

# vscode cmake tools
include(CMakeToolsHelpers OPTIONAL)

add_library(xutl STATIC ${SOURCES})

add_executable(test_net "./test/test_net.cpp")
add_executable(test_xdev "./test/test_xdev.cpp")
add_executable(test_xipc "./test/test_xipc.cpp")
add_executable(test_ipc "./test/test_ipc.cpp")

target_link_libraries(test_net xutl)
target_link_libraries(test_xdev xutl ${GCC_COVERAGE_LINK_FLAGS})
target_link_libraries(test_xipc xutl ${GCC_COVERAGE_LINK_FLAGS})
target_link_libraries(test_ipc xutl ${GCC_COVERAGE_LINK_FLAGS})

# Google Test
add_executable(gt_xdev "./test/gt_xdev.cpp")
add_executable(gt_xipc "./test/gt_xipc.cpp")
add_executable(gt_xnet "./test/gt_xnet.cpp")

target_link_libraries(gt_xdev xutl ${GTEST_BOTH_LIBRARIES} ${GCC_COVERAGE_LINK_FLAGS})
target_link_libraries(gt_xipc xutl ${GTEST_BOTH_LIBRARIES} ${GCC_COVERAGE_LINK_FLAGS})
target_link_libraries(gt_xnet xutl ${GTEST_BOTH_LIBRARIES})

add_test(gt-xdev ${EXECUTABLE_OUTPUT_PATH}/gt_xdev)
add_test(gt-xipc ${EXECUTABLE_OUTPUT_PATH}/gt_xipc)
add_test(gt-xnet ${EXECUTABLE_OUTPUT_PATH}/gt_xnet)

add_test(test_net ${EXECUTABLE_OUTPUT_PATH}/test_net)
add_test(test_xdev ${EXECUTABLE_OUTPUT_PATH}/test_xdev)
add_test(test_xipc ${EXECUTABLE_OUTPUT_PATH}/test_xipc)
add_test(test_ipc ${EXECUTABLE_OUTPUT_PATH}/test_ipc)
