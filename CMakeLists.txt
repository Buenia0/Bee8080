cmake_minimum_required(VERSION 3.1)
project(bee8080)

option(BUILD_TESTS "Enables the Bee8080 test suite." ON)

if (WIN32)
	message(STATUS "Operating system is Windows.")
elseif(UNIX AND NOT APPLE)
	message(STATUS "Operating system is Linux.")
elseif(APPLE)
	message(STATUS "Operating system is Mac.")
else()
	message(SEND_ERROR "Operating system not supported.")
	return()
endif()

set(BEE8080_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release")
endif()

set(BEE8080_TEST_SOURCES
	bee8080-tests.cpp)

set(BEE8080_HEADER
	bee8080.h)

set(BEE8080_SOURCE
	bee8080.cpp)

if (WIN32)
	if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -std=c++11 -Wno-format-security")
		message(STATUS "Compiler is MinGW.")
	else()
		message(SEND_ERROR "Compiler not supported.")
		return()
	endif()
elseif (UNIX AND NOT APPLE)
	if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -std=c++11 -Wno-format-security")
		message(STATUS "Compiler is GCC.")
	elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -std=c++11 -Wno-format-security")
		message(STATUS "Compiler is Clang.")
	else()
		message(SEND_ERROR "Compiler not supported.")
		return()
	endif()
elseif (APPLE)
	if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "AppleClang")
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -std=c++17 -Wno-format-security")
		message(STATUS "Compiler is AppleClang.")
	else()
		message(SEND_ERROR "Compiler not supported.")
		return()
	endif()
endif()

add_library(8080 ${BEE8080_SOURCE} ${BEE8080_HEADERS})
target_include_directories(8080 PUBLIC ${BEE8080_INCLUDE_DIR})

add_library(bee8080 ALIAS 8080)

if (BUILD_TESTS STREQUAL "ON")
    project(bee8080-tests)
    add_executable(bee8080-tests ${BEE8080_TEST_SOURCES})
    include_directories(bee8080-tests ${BEE8080_INCLUDE_DIR})
    target_link_libraries(bee8080-tests bee8080)
endif()