cmake_minimum_required(VERSION 3.13)
project(SHAFTDB LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")
set(SHAFTDB_SOURCE_FILES "")
set(SHAFTDB_INCLUDES_DIR ${CMAKE_CURRENT_LIST_DIR}/src/shaftdb)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)

add_subdirectory(src/shaftdb)
add_subdirectory(thirdparty/SEAL)

add_library(shaftdb STATIC ${SHAFTDB_SOURCE_FILES})
include_directories(${CMAKE_CURRENT_LIST_DIR}/src/)
target_include_directories(shaftdb PUBLIC ${CMAKE_CURRENT_LIST_DIR}/thirdparty/SEAL/natice/src)
target_link_libraries(shaftdb seal)

add_subdirectory(app)