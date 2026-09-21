#include <chrono>
#include <iostream>
#include <string>
#include <vector>
#include <openssl/evp.h>
#include "Base64Url.h"
#include "JwtService.h"
#include "KeyManager.h"
#include "RequestRouter.h"
using namespace std;

namespace {

int failures = 0;

//This replaces a large testing library with one small helper function.
void expect(bool condition, const string& message) {
    if (!condition) {
        ++failures;
       cerr << "FAIL: " << message << '\n';
    }
}

vector<string> splitJwt(const string& token) {
    vector<string> pieces;
    size_t start = 0;
    while (true) {
        const size_t dot = token.find('.', start);
        pieces.push_back(token.substr(start, dot - start));
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    return pieces;
}

string decodedText(const string& value) {
    // Turn a base64url JWT section back into readable text.
    vector<unsigned char> bytes = base64UrlDecode(value);
    return {bytes.begin(), bytes.end()};
}
//This tests the verification of a JWT using a given RSA public key 
bool verifyJwt(const string& token, EVP_PKEY* key) {
    //Verify the signature using the public part of the RSA key.
    vector<string> pieces = splitJwt(token);
    if (pieces.size() != 3) return false;
    const string input = pieces[0] + "." + pieces[1];
    vector<unsigned char> signature = base64UrlDecode(pieces[2]);

    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (context == nullptr) return false;
    const bool initialized =
        EVP_DigestVerifyInit(context, nullptr, EVP_sha256(), nullptr, key) == 1 &&
        EVP_DigestVerifyUpdate(context, input.data(), input.size()) == 1;
    const bool valid = initialized &&
        EVP_DigestVerifyFinal(context, signature.data(), signature.size()) == 1;
    EVP_MD_CTX_free(context);
    return valid;
}
//This retrieves an integer value from a JSON string by its name
long jsonInteger(const string& json, const string& name) {
    const string prefix = "\"" + name + "\":";
    const size_t start = json.find(prefix);
    if (start == string::npos) return 0;
    return stol(json.substr(start + prefix.size()));
}
//This tests the base64url encoding and decoding
void testBase64Url() {
    expect(base64UrlEncode("hello") == "aGVsbG8", "base64url encodes without padding");
    expect(decodedText("aGVsbG8") == "hello", "base64url decodes");
    expect(base64UrlEncode("").empty(), "empty base64url input stays empty");
    expect(base64UrlDecode("!!!!").empty(),
           "invalid base64url returns an empty result");
}
//This tests the key management and JWKS functionality
void testKeysAndJwks(const KeyManager& keys) {
    const std::time_t now = std::time(nullptr);
    expect(keys.getValidKey().expiresAt > now, "valid key is not expired");
    expect(keys.getExpiredKey().expiresAt < now, "expired key is expired");
    expect(keys.getValidKey().kid != keys.getExpiredKey().kid,
           "key IDs are unique");

    const string jwks = keys.getJWKS();
    expect(jwks.find(keys.getValidKey().kid) != string::npos,
           "JWKS has valid kid");
    expect(jwks.find(keys.getExpiredKey().kid) == string::npos,
           "JWKS hides expired kid");
    expect(jwks.find("\"kty\":\"RSA\"") != string::npos, "JWK is RSA");
    expect(jwks.find("\"e\":\"AQAB\"") != string::npos, "JWK exponent is present");
    expect(keys.getJWKS(keys.getValidKey().kid).find(keys.getValidKey().kid) !=
               string::npos,
           "kid filtering returns matching valid key");
    expect(keys.getJWKS("does-not-exist") == "{\"keys\":[]}",
           "unknown kid returns an empty key set");
    expect(keys.getJWKS(keys.getExpiredKey().kid) == "{\"keys\":[]}",
           "kid filtering never exposes expired key");
}

//This tests the creation and verification of JWTs
void testTokens(const KeyManager& keys, const JwtService& jwt) {
    const time_t now = time(nullptr);

    const string valid = jwt.createToken(false, now);
    vector<string> validParts = splitJwt(valid);
    expect(validParts.size() == 3, "valid JWT has three sections");
    expect(decodedText(validParts[0]).find(keys.getValidKey().kid) != string::npos,
           "valid JWT header has valid kid");
    expect(jsonInteger(decodedText(validParts[1]), "exp") > now,
           "valid JWT expiration is in the future");
    expect(verifyJwt(valid, keys.getValidKey().keyPair),
           "valid JWT verifies with valid public key");

    const string expired = jwt.createToken(true, now);
    vector<string> expiredParts = splitJwt(expired);
    expect(decodedText(expiredParts[0]).find(keys.getExpiredKey().kid) != string::npos,
           "expired JWT header has expired kid");
    expect(jsonInteger(decodedText(expiredParts[1]), "exp") < now,
           "expired JWT expiration is in the past");
    expect(verifyJwt(expired, keys.getExpiredKey().keyPair),
           "expired JWT verifies with expired public key");
    expect(!verifyJwt(expired, keys.getValidKey().keyPair),
           "expired JWT does not verify with valid key");
}

//This tests the request routing functionality
void testRouter(const KeyManager& keys, const JwtService& jwt) {
    const RequestRouter router(keys, jwt);
    const HttpResponse jwks =
        router.handleRequest({"GET", "/.well-known/jwks.json", ""});
    expect(jwks.status == 200 && jwks.contentType == "application/json",
           "JWKS GET succeeds with JSON");
    expect(router.handleRequest({"GET", "/.well-known/jwks.json?kid=" +
                                 keys.getValidKey().kid, ""})
               .body.find(keys.getValidKey().kid) != string::npos,
           "JWKS route accepts kid filtering");

    const HttpResponse auth = router.handleRequest({"POST", "/auth", ""});
    expect(auth.status == 200 && splitJwt(auth.body).size() == 3,
           "POST /auth returns a JWT without a body");
    const HttpResponse expired =
        router.handleRequest({"POST", "/auth?expired", ""});
    expect(decodedText(splitJwt(expired.body)[0]).find(keys.getExpiredKey().kid) !=
               string::npos,
           "presence of expired parameter selects expired key");
    expect(router.handleRequest({"GET", "/auth", ""}).status == 405,
           "GET /auth is rejected");
    expect(router.handleRequest({"POST", "/.well-known/jwks.json", ""}).status == 405,
           "POST JWKS is rejected");
    expect(router.handleRequest({"GET", "/missing", ""}).status == 404,
           "unknown path returns 404");

    expect(RequestRouter::getQueryValue("/path?a=1&kid=valid-key", "kid") ==
               "valid-key",
           "query value can be read");
    expect(RequestRouter::hasQueryParameter("/path?expired=true", "expired"),
           "query parameter can be found");
    expect(RequestRouter::hasQueryParameter("/path?expired", "expired"),
           "presence-only query parameter can be found");
    expect(!RequestRouter::hasQueryParameter("/path", "expired"),
           "missing query parameter is not found");
}

}

int main() {
    testBase64Url();
    KeyManager keys;
    JwtService jwt(keys);
    testKeysAndJwks(keys);
    testTokens(keys, jwt);
    testRouter(keys, jwt);

    if (failures != 0) {
        cerr << failures << " test(s) failed\n";
        return 1;
    }
    cout << "All tests passed\n";
    return 0;
}
