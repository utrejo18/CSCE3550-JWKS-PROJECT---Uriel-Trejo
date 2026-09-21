#include "JwtService.h"
#include <cstdlib>
#include <iostream>
#include <vector>
#include <openssl/evp.h>
#include "Base64Url.h"
using namespace std;

JwtService::JwtService(const KeyManager& manager) : keyManager(manager) {

}

string JwtService::createToken(bool useExpiredKey, time_t currentTime) const {
    //Choose which key to use for signing the JWT. Expired key used if requested
    const RSAKey* chosenKey;

    if (useExpiredKey) {
        chosenKey = &keyManager.getExpiredKey();
    } else {
        chosenKey = &keyManager.getValidKey();
    }
    //This section creates the JWT header and also the payload as JSON strings
    string header = "{";
    header += "\"alg\":\"RS256\",";
    header += "\"typ\":\"JWT\",";
    header += "\"kid\":\"" + chosenKey->kid + "\"";
    header += "}";

    //The payload finds a fake user and includes the required times
    //The expired key already has an expiration that is in the past
    string payload = "{";
    payload += "\"sub\":\"fake-user\",";
    payload += "\"iat\":" + to_string(currentTime) + ",";
    payload += "\"exp\":" + to_string(chosenKey->expiresAt);
    payload += "}";

    //A JWT has three base64url sections separated by periods.
    string encodedHeader = base64UrlEncode(header);
    string encodedPayload = base64UrlEncode(payload);
    string textToSign = encodedHeader + "." + encodedPayload;
    string signature = signWithRSA(textToSign, chosenKey->keyPair);
    return textToSign + "." + signature;
}
//
string JwtService::signWithRSA(const string& text, EVP_PKEY* keyPair) const {
    //EVP_MD_CTX stores the progress of the SHA-256/RSA signing
    EVP_MD_CTX* context = EVP_MD_CTX_new();

    if (context == nullptr) {
        cerr << "Could not create the signing context" << endl;
        exit(1);
    }

    //RS256 means RSA signing with a SHA-256 hash
    if (EVP_DigestSignInit(context, nullptr, EVP_sha256(), nullptr, keyPair) != 1 ||
        EVP_DigestSignUpdate(context, text.data(), text.size()) != 1) {
        EVP_MD_CTX_free(context);
        cerr << "Could not start the JWT signature" << endl;
        exit(1);
    }

    //This asks OpenSSL how many bytes would be needed for the signature
    size_t signatureSize = 0;
    if (EVP_DigestSignFinal(context, nullptr, &signatureSize) != 1) {
        EVP_MD_CTX_free(context);
        cerr << "Could not get the signature size" << endl;
        exit(1);
    }

    vector<unsigned char> signatureBytes(signatureSize);

    //This creates the actual signature
    if (EVP_DigestSignFinal(
            context, signatureBytes.data(), &signatureSize) != 1) {
        EVP_MD_CTX_free(context);
        cerr << "Could not sign the JWT" << endl;
        exit(1);
    }

    EVP_MD_CTX_free(context);
    signatureBytes.resize(signatureSize);

    return base64UrlEncode(signatureBytes.data(), signatureBytes.size());
}
