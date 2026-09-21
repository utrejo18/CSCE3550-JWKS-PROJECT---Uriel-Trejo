#include "KeyManager.h"
#include <cstdlib>
#include <iostream>
#include <vector>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/rsa.h>
#include "Base64Url.h"
using namespace std;

//This converts an OpenSSL BIGNUM into a base64url encoded string that can be used in a JWK
string numberToBase64Url(const BIGNUM* number) {
    int numberOfBytes = BN_num_bytes(number);
    vector<unsigned char> bytes(numberOfBytes);

    //This copies the OpenSSL BIGNUM into a normal byte vector
    BN_bn2bin(number, bytes.data());
    return base64UrlEncode(bytes.data(), bytes.size());
}

KeyManager::KeyManager() {
    time_t now = time(nullptr);

    //The valid key would expire one hour from now
    validKey = createRSAKey("valid-key", now + 3600);

    //The expired key had expired one hour ago
    expiredKey = createRSAKey("expired-key", now - 3600);
}

KeyManager::~KeyManager() {
    //OpenSSL created these keys, so OpenSSL must also free them
    EVP_PKEY_free(validKey.keyPair);
    EVP_PKEY_free(expiredKey.keyPair);
}

const RSAKey& KeyManager::getValidKey() const { //Returns the currently valid RSA key
    return validKey;
}

const RSAKey& KeyManager::getExpiredKey() const { //Returns the expired RSA key
    return expiredKey;
}

RSAKey KeyManager::createRSAKey(const string& kid, time_t expiration) {
    //Create a context for RSA key generation
    EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);

    if (context == nullptr) {
        cerr << "Could not create the RSA context" << endl;
        exit(1);
    }

    //Setting up RSA key generation with a 2048-bit key size
    if (EVP_PKEY_keygen_init(context) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(context, 2048) <= 0) {
        EVP_PKEY_CTX_free(context);
        cerr << "Could not set up RSA key generation" << endl;
        exit(1);
    }

    EVP_PKEY* newKeyPair = nullptr;

    //Generating both the public and private key parts
    if (EVP_PKEY_generate(context, &newKeyPair) <= 0) {
        EVP_PKEY_CTX_free(context);
        cerr << "Could not generate the RSA key" << endl;
        exit(1);
    }

    EVP_PKEY_CTX_free(context);

    RSAKey result;
    result.kid = kid;
    result.expiresAt = expiration;
    result.keyPair = newKeyPair;
    return result;
}

string KeyManager::keyToJWK(const RSAKey& rsaKey) const {
    BIGNUM* modulus = nullptr;
    BIGNUM* exponent = nullptr;

    //n is the RSA modulus and e is the RSA public exponent.
    //These are the public values a JWT verifier would need
    int gotModulus = EVP_PKEY_get_bn_param(
        rsaKey.keyPair, OSSL_PKEY_PARAM_RSA_N, &modulus);
    int gotExponent = EVP_PKEY_get_bn_param(
        rsaKey.keyPair, OSSL_PKEY_PARAM_RSA_E, &exponent);

    if (gotModulus != 1 || gotExponent != 1) {
        BN_free(modulus);
        BN_free(exponent);
        cerr << "Could not read the RSA public key" << endl;
        exit(1);
    }

    string n = numberToBase64Url(modulus);
    string e = numberToBase64Url(exponent);

    BN_free(modulus);
    BN_free(exponent);

    //Only public information is placed in the JWK
    //The private key is never sent to the client
    string json = "{";
    json += "\"kty\":\"RSA\",";
    json += "\"use\":\"sig\",";
    json += "\"alg\":\"RS256\",";
    json += "\"kid\":\"" + rsaKey.kid + "\",";
    json += "\"n\":\"" + n + "\",";
    json += "\"e\":\"" + e + "\"";
    json += "}";

    return json;
}

string KeyManager::getJWKS(const string& wantedKid) const {
    time_t now = time(nullptr);
    string json = "{\"keys\":[";

    //There is only one active key at a time. Can be returned only if it is still valid
    //If a kid was requested, it must match the key's kid
    bool keyIsValid = validKey.expiresAt > now;
    bool kidMatches = wantedKid.empty() || wantedKid == validKey.kid;

    if (keyIsValid && kidMatches) {
        json += keyToJWK(validKey);
    }

    //The expired key is not included in the JWKS
    json += "]}";
    return json;
}
