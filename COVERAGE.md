TESTING COVERAGE:
I ran the tests with coverage turned on. The tests cover the code that makes
the keys, makes the JWTs, handles the routes, and does the base64 encoding.

| File | Coverage |
| --- | ---: |
| `Base64Url.cpp` | 37 out of 38 lines (97%) |
| `KeyManager.cpp` | 141 out of 165 lines (85%) |
| `JwtService.cpp` | 40 out of 52 lines (76%) |
| `RequestRouter.cpp` | 56 out of 62 lines (90%) |
| **Total** | **274 out of 317 lines (86.4%)** |

The total coverage is above 80%

HttpServer.cpp is not included in this number because it keeps waiting for
real network connections. The route handling was separated into
RequestRouter.cpp so it could be tested without starting the whole server.

To run the coverage check, just use:

```bash
./coverage.sh
```

To get a fresh report in case there is problem with old coverage, use instead:
```bash
rm -rf build-coverage
./coverage.sh
```