cmake_minimum_required(VERSION 3.20)
project(Bayan LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Boost 1.70 REQUIRED COMPONENTS filesystem program_options)

add_executable(bayan
    bayan.cpp
)

target_link_libraries(bayan PRIVATE
    Boost::filesystem
    Boost::program_options
)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_link_libraries(bayan PRIVATE stdc++fs)
endif()
