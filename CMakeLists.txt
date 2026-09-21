cmake_minimum_required(VERSION 3.20)
project(jwks_cpp_server VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(ENABLE_COVERAGE "Build with GCC/Clang coverage instrumentation" OFF)
option(ENABLE_CLANG_TIDY "Run clang-tidy while compiling" OFF)

find_package(OpenSSL REQUIRED)

if(ENABLE_CLANG_TIDY)
    find_program(CLANG_TIDY_EXE NAMES clang-tidy REQUIRED)
    set(CMAKE_CXX_CLANG_TIDY "${CLANG_TIDY_EXE}")
endif()

add_library(jwks_core
    src/Base64Url.cpp
    src/KeyManager.cpp
    src/JwtService.cpp
    src/RequestRouter.cpp
)

target_include_directories(jwks_core PUBLIC include)
target_link_libraries(jwks_core PUBLIC OpenSSL::Crypto)
target_compile_options(jwks_core PRIVATE -Wall -Wextra -Wpedantic)
add_executable(jwks_server
    src/main.cpp
    src/HttpServer.cpp
)

target_include_directories(jwks_server PRIVATE include)
target_link_libraries(jwks_server PRIVATE jwks_core)
target_compile_options(jwks_server PRIVATE -Wall -Wextra -Wpedantic)

if(ENABLE_COVERAGE)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(jwks_core PUBLIC --coverage -O0 -g)
        target_link_options(jwks_core PUBLIC --coverage)
    else()
        message(FATAL_ERROR "Coverage is supported only with GCC or Clang")
    endif()
endif()

include(CTest)
if(BUILD_TESTING)
    add_executable(jwks_tests tests/tests.cpp)
    target_link_libraries(jwks_tests PRIVATE jwks_core OpenSSL::Crypto)
    target_compile_options(jwks_tests PRIVATE -Wall -Wextra -Wpedantic)
    add_test(NAME jwks_tests COMMAND jwks_tests)
endif()
