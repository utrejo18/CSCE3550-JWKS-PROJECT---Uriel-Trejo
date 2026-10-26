# JWKS PROJECT
## Made by Uriel Trejo uht0001

#### UPDATES: For project 2, I added SQLite so the private keys are saved in a database instead of only being kept in memory. Updates were made to KeyManager.h, KeyManager.cpp, and JwtService.cpp to implement SQLite.

This project is a small HTTP server I made in C++. It creates RSA keys, shows
the public key in JWKS format, and creates signed JWTs. OpenSSL is used for the
RSA keys and signatures.

What my project does:
- Makes one valid RSA key and one expired RSA key
- Gives each key its own kid
- Runs the server on port 8080
- GET /.well-known/jwks.json shows the valid public key
- The expired key is not shown in the JWKS response
- POST /auth creates a valid JWT
- POST /auth?expired=true creates an expired JWT
- The JWT header includes the kid for the key that signed it
- Tests are included for the main parts of the project like needed

## How to build:
Open the terminal in the project folder and run this FIRST:
```bash
cmake -S . -B build
cmake --build build
```

My project uses OpenSSL and SQLite. If CMake can't find OpenSSL, use this below:

```bash
cmake -S . -B build -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"
```

## How to run:
Input this:
```bash
./build/jwks_server
```

The server should say that it is running on port 8080. Just leave that terminal
open because closing it stops the server. To quit: ctrl + c

You can open another terminal window to run these: 
```bash
curl http://localhost:8080/.well-known/jwks.json
curl -X POST http://localhost:8080/auth
curl -X POST "http://localhost:8080/auth?expired=true"
```

To check keys stored in the database:
```bash
sqlite3 totally_not_my_privateKeys.db "SELECT kid, exp FROM keys;"
```

To run the tests:
```bash
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

## To check coverage:
First install "gcovr" if it is not already installed:
```bash
python3 -m pip install gcovr
```

Then run:
```bash
./coverage.sh
```

The script runs the tests displays results

## Running Gradebot
Make sure gradebot is in project folder.
```bash
./gradebot project-2 --run="./build/jwks_server"
```
## Project Files
- include/ has the header files.
- src/ has the C++ source files.
- tests/tests.cpp/ has the file that holds tests.
- coverage.sh runs the coverage check.
- COVERAGE.md explains the coverage results
- CMakeLists.txt tells CMake how to build everything.
- README.md explains how to build, run, and test my project
build/ and build-coverage/ folders are generated when building or testing.
