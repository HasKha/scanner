cmake_minimum_required(VERSION 3.31)
project(scanner CXX)

# Builds on its own, or added by a parent project.
add_library(scanner STATIC
    "include/scanner/pattern.h"
    "include/scanner/image.h"
    "include/scanner/thread_local.h"
    "src/image.cpp"
    "src/thread_local.cpp"
)
target_include_directories(scanner PUBLIC "include/")
target_compile_features(scanner PUBLIC cxx_std_20)

# Off under a parent unless it asks, so a project that only links the scanner needs no Catch2.
option(SCANNER_BUILD_TESTS "Build scanner_tests" ${PROJECT_IS_TOP_LEVEL})
if(SCANNER_BUILD_TESTS)
    # Appended, so a parent's own cmake/catch2.cmake comes first, and Catch2 is configured once, its way.
    list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
    if(PROJECT_IS_TOP_LEVEL)
        enable_testing()
    endif()
    add_subdirectory(tests)
endif()
