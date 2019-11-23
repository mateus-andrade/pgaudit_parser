cmake_minimum_required(VERSION 3.2)

### Paths

set(PROJECT_DIR pgaudit_parser)

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib/static)
set(PROJECT_BINARY_DIR ${CMAKE_SOURCE_DIR}/build)
set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/build)

### C Flags

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -W -Wall -g")

if(DEBUG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")
endif()

link_directories(lib)
include_directories(inc)
add_subdirectory(src)
