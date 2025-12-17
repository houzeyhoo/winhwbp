cmake_minimum_required(VERSION 3.28)
project(winhwbp LANGUAGES C)

add_library(winhwbp STATIC
    src/winhwbp.c
)

target_include_directories(winhwbp PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
