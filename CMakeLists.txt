cmake_minimum_required(VERSION 3.20)
project(Cstream CXX C)

set(CMAKE_CXX_STANDARD 20)

add_subdirectory(cpr)
include("doctest/scripts/cmake/doctest.cmake")
add_subdirectory(doctest)
add_subdirectory(glaze)

add_library(cstream STATIC "thirdparty/sha256.cpp")
target_link_libraries(cstream PUBLIC cpr::cpr glaze::glaze)

if(true) # TODO: Replace with build tests option

    add_executable(tst "test.cpp")
    target_link_libraries(tst PUBLIC cstream doctest::doctest)
    enable_testing()
    doctest_discover_tests(tst)

    if (MSVC)
        target_compile_options(tst PRIVATE /W4)
    else()
        target_compile_options(tst PRIVATE -Wall -Wextra -pedantic)
    endif()

endif()
