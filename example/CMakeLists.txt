cmake_minimum_required(VERSION 3.0.2)

project(example)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_DEFAULT_STARTUP_PROJECT eoam)
set(CMAKE_BUILD_TYPE Debug)

# vscode cmake tools
include(CMakeToolsHelpers OPTIONAL)

# include user_params (user_params.h)
include_directories("./server")

# eoamapi
file(GLOB EOAMAPI_SRC "../src/eoamapi/*.cpp")

# server
file(GLOB SERVER_SRC "./server/*.cpp" "./server/*.c")

# client
file(GLOB CLIENT_SRC "./client/*.cpp")

add_executable(eoam ${SERVER_SRC} ${EOAMAPI_SRC})
add_executable(ctrl_eoam ${CLIENT_SRC} ${EOAMAPI_SRC})

target_link_libraries(eoam eoamlib xutl)
target_link_libraries(ctrl_eoam getopt xutl)





