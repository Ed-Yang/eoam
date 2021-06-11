cmake_minimum_required(VERSION 3.0.2)
project(gt_eoam)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
SET(CMAKE_BUILD_TYPE Debug)

# for GTest/GMock
add_definitions("-std=c++11")

#SET( GCC_COVERAGE_COMPILE_FLAGS ${GCC_COVERAGE_COMPILE_FLAGS} "-std=c++11")

# vscode cmake tools
include(CMakeToolsHelpers OPTIONAL)

# include user_params (user_params.h)
include_directories("./")

# eoamapi
file(GLOB EOAMAPI_SRC "../src/eoamapi/*.cpp")

# test
file(GLOB TEST_SRC "./*.cpp")

# Google Test
add_executable(gt_eoam ${TEST_SRC} ${EOAMAPI_SRC})

#target_link_libraries(gt_eoam eoamlib eoamapi xutl ${GTEST_BOTH_LIBRARIES})
target_link_libraries(gt_eoam eoamlib xutl ${GTEST_BOTH_LIBRARIES} ${GCC_COVERAGE_LINK_FLAGS})

add_test(gt-eoam ${EXECUTABLE_OUTPUT_PATH}/gt_eoam)