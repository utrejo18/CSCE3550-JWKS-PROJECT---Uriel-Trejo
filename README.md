Intro:
TO RUN WITH GRADEBOT: ./gradebot project-1 --run="./build/jwks_server" !!!!!!!!!

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

How to build:
Open the terminal in the project folder and run:
```bash
cmake -S . -B build
cmake --build build
```

If CMake cannot find OpenSSL, use this first:

```bash
cmake -S . -B build -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"
```

How to run:
```bash
./build/jwks_server
```

The server should say that it is running on port 8080. Just leave that terminal
open because closing it stops the server.
You can open another terminal to run these:i 
```bash
curl http://localhost:8080/.well-known/jwks.json
curl -X POST http://localhost:8080/auth
curl -X POST "http://localhost:8080/auth?expired=true"
```

To run the tests:
```bash
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

To check coverage:
First install "gcovr" if it is not already installed:
```bash
python3 -m pip install gcovr
```

Then run:
```bash
./scripts/coverage.sh
```

The script runs the tests displays results

- include has the header files.
- src has the C++ source files.
- tests/tests.cpp has the tests.
- scripts/coverage.sh runs the coverage check.
- CMakeLists.txt tells CMake how to build everything.
