cmake_minimum_required(VERSION 3.31)
project(scanner CXX)

# Builds on its own, or added by a parent project.
add_library(scanner STATIC
    "include/scanner/pattern.h"
    "include/scanner/image.h"
    "src/image.cpp"
)
target_include_directories(scanner PUBLIC "include/")
target_compile_features(scanner PUBLIC cxx_std_20)

# Under a parent, the parent's Catch2, configured once for the whole build.
if(PROJECT_IS_TOP_LEVEL)
    include(FetchContent)
    FetchContent_Declare(catch2 GIT_REPOSITORY https://github.com/catchorg/Catch2.git GIT_TAG v3.8.1 GIT_SHALLOW TRUE)
    FetchContent_MakeAvailable(catch2)
    enable_testing()
else()
    include(catch2)
endif()
add_executable(scanner_tests "tests/scanner_test.cpp")
target_link_libraries(scanner_tests PRIVATE scanner Catch2::Catch2WithMain)
add_test(NAME scanner_tests COMMAND scanner_tests)
