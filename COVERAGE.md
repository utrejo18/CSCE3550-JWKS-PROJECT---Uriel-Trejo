TESTING COVERAGE:
I ran the tests with coverage turned on. The tests cover the code that makes
the keys, makes the JWTs, handles the routes, and does the base64 encoding.

| File | Coverage |
| --- | ---: |
| `Base64Url.cpp` | 35 out of 36 lines (97.22%) |
| `KeyManager.cpp` | 63 out of 73 lines (86.30%) |
| `JwtService.cpp` | 36 out of 43 lines (83.72%) |
| `RequestRouter.cpp` | 49 out of 56 lines (87.50%) |
| **Total** | **183 out of 208 lines (87.98%)** |

The total coverage is above 80%

HttpServer.cpp is not included in this number because it keeps waiting for
real network connections. The route handling was separated into
RequestRouter.cpp so it could be tested without starting the whole server.

To run the coverage check again, just use:

```bash
./scripts/coverage.sh
```