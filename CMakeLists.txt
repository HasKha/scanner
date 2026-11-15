cmake_minimum_required(VERSION 3.31)
project(scanner CXX)

# Pattern scans over an executable's file, mapped read-only: its own library, with nothing of any one program in it.
# Signatures are memtools', include/scanner/pattern.h says how. Builds on its own, or added by a parent project.
add_library(scanner STATIC
    "include/scanner/pattern.h"
    "include/scanner/image.h"
    "src/image.cpp"
)
target_include_directories(scanner PUBLIC "include/")
target_compile_features(scanner PUBLIC cxx_std_20)

# The unit tests, with the parent's Catch2 when it has one.
if(NOT TARGET Catch2::Catch2)
    include(FetchContent)
    FetchContent_Declare(catch2 GIT_REPOSITORY https://github.com/catchorg/Catch2.git GIT_TAG v3.8.1 GIT_SHALLOW TRUE)
    FetchContent_MakeAvailable(catch2)
endif()
add_executable(scanner_tests "tests/scanner_test.cpp")
target_link_libraries(scanner_tests PRIVATE scanner Catch2::Catch2WithMain)
enable_testing()
add_test(NAME scanner_tests COMMAND scanner_tests)
