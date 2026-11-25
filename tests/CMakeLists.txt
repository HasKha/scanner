include(catch2)

add_executable(scanner_tests "scanner_test.cpp")
target_link_libraries(scanner_tests PRIVATE scanner Catch2::Catch2WithMain)
add_test(NAME scanner_tests COMMAND scanner_tests)
