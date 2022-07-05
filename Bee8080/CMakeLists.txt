set(BEE8080_HEADER
	bee8080.h)

set(BEE8080_SOURCE
	bee8080.cpp)

add_library(bee8080 ${BEE8080_SOURCE} ${BEE8080_HEADER})
target_include_directories(bee8080 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(bee8080 PRIVATE BEE8080_STATIC=1 _CRT_SECURE_NO_WARNINGS=1)
add_library(libbee8080 ALIAS bee8080)