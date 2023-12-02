cmake_minimum_required(VERSION 3.20)
project(Cstream CXX C)

set(CMAKE_CXX_STANDARD 20)

option(CSTREAM_BUILD_TESTS "Weather or not the tests should be built" ${PROJECT_IS_TOP_LEVEL})

add_subdirectory(thirdparty/cpr)
include("thirdparty/doctest/scripts/cmake/doctest.cmake")
add_subdirectory(thirdparty/doctest)
add_subdirectory(thirdparty/glaze)

add_library(cstream "authorization.cpp" "thirdparty/sha256.cpp")
target_link_libraries(cstream PUBLIC cpr::cpr glaze::glaze)
target_include_directories(cstream PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

if(${CSTREAM_BUILD_TESTS})

    add_executable(tst "tests/test.cpp")
    target_link_libraries(tst PUBLIC cstream)
    target_link_libraries(cstream PUBLIC doctest::doctest)
    enable_testing()
    doctest_discover_tests(tst)

    if (MSVC)
        target_compile_options(tst PRIVATE /W4)
    else()
        target_compile_options(tst PRIVATE -Wall -Wextra -pedantic)
    endif()

endif()
