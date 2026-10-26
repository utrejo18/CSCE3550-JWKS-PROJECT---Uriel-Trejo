#ifndef KEY_MANAGER_H
#define KEY_MANAGER_H

#include <ctime> //For time_t in line 12 and 37
#include <string>
#include <openssl/evp.h>
#include <sqlite3.h>

//This struct keeps all the information that belongs to one RSA key
//What EVP_PKEY does is that it stores both the public and private parts of the RSA key pair, which is used for signing and verifying JWTs
struct RSAKey {
    std::string kid;
    std::time_t expiresAt;
    EVP_PKEY* keyPair;
};

//Where changes were made to extend the JWKS server to meet project 2 requirements
class KeyManager {
public:
    KeyManager(const std::string& databaseFile = "totally_not_my_privateKeys.db");
    ~KeyManager();

    RSAKey getValidKey() const;
    RSAKey getExpiredKey() const;
    std::string getJWKS(const std::string& wantedKid = "") const;

    KeyManager(const KeyManager&) = delete;
    KeyManager& operator=(const KeyManager&) = delete;

private:
    sqlite3* database;
    void createTable();
    void ensureKeys();
    void saveKey(std::time_t expiration);
    RSAKey readKey(bool expired) const;
    std::string keyToJWK(const RSAKey& rsaKey) const;

};

#endif
