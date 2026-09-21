#ifndef KEY_MANAGER_H
#define KEY_MANAGER_H

#include <ctime> //For time_t in line 12 and 37
#include <string>
#include <openssl/evp.h>

//This struct keeps all the information that belongs to one RSA key
//What EVP_PKEY does is that it stores both the public and private parts of the RSA key pair, which is used for signing and verifying JWTs
struct RSAKey {
    std::string kid;
    std::time_t expiresAt;
    EVP_PKEY* keyPair;
};

class KeyManager {
public:
    //The constructor creates one valid key and also one expired key
    KeyManager();

    //The destructor releases the OpenSSL keys from memory
    ~KeyManager();

    //Return references so that the large key data is not copied.
    const RSAKey& getValidKey() const;
    const RSAKey& getExpiredKey() const;

    //Makes the JSON returned by /.well-known/jwks.json.
    //Leaving wantedKid empty returns every valid key.
    std::string getJWKS(const std::string& wantedKid = "") const;

private:
    RSAKey validKey;
    RSAKey expiredKey;

    //Creates a new RSA key pair with the given ID and expiration time.
    RSAKey createRSAKey(const std::string& kid, std::time_t expiration);
    std::string keyToJWK(const RSAKey& rsaKey) const;

};

#endif
