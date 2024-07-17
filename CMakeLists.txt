cmake_minimum_required(VERSION 3.13)
project(NSHEDB LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")
set(NSHEDB_SOURCE_FILES "")
set(NSHEDB_INCLUDES_DIR ${CMAKE_CURRENT_LIST_DIR}/src/nshedb)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)
option(SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT ${SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT_STR} OFF)
add_subdirectory(src/nshedb)
add_subdirectory(thirdparty/SEAL)

add_library(nshedb STATIC ${NSHEDB_SOURCE_FILES})
include_directories(${CMAKE_CURRENT_LIST_DIR}/src/)
target_include_directories(nshedb PUBLIC ${CMAKE_CURRENT_LIST_DIR}/thirdparty/SEAL/natice/src)
target_link_libraries(nshedb seal)

add_subdirectory(app)