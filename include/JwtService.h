#ifndef JWT_SERVICE_H
#define JWT_SERVICE_H

#include <ctime>
#include <string>
#include "KeyManager.h"

//Jwt service class, this creates a JWT token using the keys from KeyManager and then signs it with the private key
class JwtService {
public:
    //JwtService needs KeyManager so that it can choose a key to sign the JWT with
    JwtService(const KeyManager& manager);

    //false makes a normal token, true makes the required expired token
    std::string createToken(bool useExpiredKey,
                            std::time_t currentTime = std::time(nullptr)) const;

private:
    const KeyManager& keyManager;

    //signs the first two JWT sections using RSA and SHA-256.
    std::string signWithRSA(const std::string& text, EVP_PKEY* keyPair) const;
};

#endif
