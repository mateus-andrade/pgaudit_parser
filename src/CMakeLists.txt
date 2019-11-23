
FILE(GLOB SRCS *.c)

add_executable(pgaudit_parserd ${SRCS})
target_link_libraries(pgaudit_parserd jansson)
