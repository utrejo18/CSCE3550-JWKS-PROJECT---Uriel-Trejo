#!/bin/bash

# make the coverage build
cmake -S . -B build-coverage -DENABLE_COVERAGE=ON

# build and run the tests
cmake --build build-coverage
ctest --test-dir build-coverage

# show the coverage for the code being tested
gcovr -r . --filter "src/(Base64Url|KeyManager|JwtService|RequestRouter)\.cpp" --print-summary