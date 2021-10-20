
FILE(GLOB SRCS *.c)

include_directories(/usr/local/include)
add_executable(pgaudit_parserd ${SRCS})
find_library(LIB_JANSSON jansson)
target_link_libraries(pgaudit_parserd ${LIB_JANSSON})
