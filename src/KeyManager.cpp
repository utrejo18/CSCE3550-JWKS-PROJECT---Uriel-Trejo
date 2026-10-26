#include "KeyManager.h"
#include <cstdlib>
#include <iostream>
#include <vector>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/rsa.h>
#include "Base64Url.h"
#include <sqlite3.h>
#include <openssl/pem.h>
#include <openssl/buffer.h>
using namespace std;

//This converts an OpenSSL BIGNUM into a base64url encoded string that can be used in a JWK
string numberToBase64Url(const BIGNUM* number) {
    int numberOfBytes = BN_num_bytes(number);
    vector<unsigned char> bytes(numberOfBytes);

    //This copies the OpenSSL BIGNUM into a normal byte vector
    BN_bn2bin(number, bytes.data());
    return base64UrlEncode(bytes.data(), bytes.size());
}

//Checks if SQLite completed the database command correctly
void checkSQLite(int result, sqlite3* database) {
    if (result != SQLITE_OK && result != SQLITE_DONE && result != SQLITE_ROW) {
        throw runtime_error(sqlite3_errmsg(database));
    }
}

//This constructor opens the database and makes sure there is a valid and expired key
KeyManager::KeyManager(const string& databaseFile) : database(nullptr) {
    //SQLite creates the database file if it does not already exist
    if (sqlite3_open(databaseFile.c_str(), &database) != SQLITE_OK) {
        string error = database ? sqlite3_errmsg(database) : "Could not open database";
        sqlite3_close(database);
        database = nullptr;
        throw runtime_error(error);
    }
    try {
        createTable();
        ensureKeys();
    } catch (...) {
        sqlite3_close(database);
        database = nullptr;
        throw;
    }
}

//The destructor closes the SQLite database when the program ends
KeyManager::~KeyManager() {
    if (database != nullptr) sqlite3_close(database);
}

//Creates the required keys table if it does not already exist
void KeyManager::createTable() {
    const char* sql = "CREATE TABLE IF NOT EXISTS keys("
                      "kid INTEGER PRIMARY KEY AUTOINCREMENT,"
                      "key BLOB NOT NULL,"
                      "exp INTEGER NOT NULL)";
    checkSQLite(sqlite3_exec(database, sql, nullptr, nullptr, nullptr), database);
}

//Checks the database for valid and expired keys, then creates missing ones
void KeyManager::ensureKeys() {
    sqlite3_stmt* statement = nullptr;
    const char* sql = "SELECT COUNT(*) FROM keys WHERE exp > ?";
    checkSQLite(sqlite3_prepare_v2(database, sql, -1, &statement, nullptr), database);
    sqlite3_bind_int64(statement, 1, static_cast<sqlite3_int64>(time(nullptr)));
    int result = sqlite3_step(statement);
    bool hasValid = result == SQLITE_ROW && sqlite3_column_int(statement, 0) > 0;
    sqlite3_finalize(statement);
    //The valid key would expire one hour from now
    if (!hasValid) saveKey(time(nullptr) + 3600);

    sql = "SELECT COUNT(*) FROM keys WHERE exp <= ?";
    checkSQLite(sqlite3_prepare_v2(database, sql, -1, &statement, nullptr), database);
    sqlite3_bind_int64(statement, 1, static_cast<sqlite3_int64>(time(nullptr)));
    result = sqlite3_step(statement);
    bool hasExpired = result == SQLITE_ROW && sqlite3_column_int(statement, 0) > 0;
    sqlite3_finalize(statement);
    //The expired key had expired one hour ago
    if (!hasExpired) saveKey(time(nullptr) - 3600);
}

//Creates a new RSA key pair and saves its private key in SQLite
void KeyManager::saveKey(time_t expiration) {
    //Create a context for RSA key generation
    EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);

    if (context == nullptr) {
        throw runtime_error("Could not create the RSA context");
    }

    //This sets up RSA key generation with a 2048-bit key size
    if (EVP_PKEY_keygen_init(context) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(context, 2048) <= 0) {
        EVP_PKEY_CTX_free(context);
        throw runtime_error("Could not set up RSA key generation");
    }

    EVP_PKEY* newKeyPair = nullptr;

    //This generates both the public and private key parts
    if (EVP_PKEY_generate(context, &newKeyPair) <= 0) {
        EVP_PKEY_CTX_free(context);
        throw runtime_error("Could not generate the RSA key");
    }

    EVP_PKEY_CTX_free(context);

    //This converts the private key to PKCS8 PEM that way it can be stored in the database
    BIO* memory = BIO_new(BIO_s_mem());
    if (memory == nullptr || PEM_write_bio_PKCS8PrivateKey(
            memory, newKeyPair, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        BIO_free(memory);
        EVP_PKEY_free(newKeyPair);
        throw runtime_error("Could not convert the private key");
    }

    BUF_MEM* buffer = nullptr;
    BIO_get_mem_ptr(memory, &buffer);

    //This inserts the private key and expiration time into the keys table
    sqlite3_stmt* statement = nullptr;
    int result = sqlite3_prepare_v2(database,
        "INSERT INTO keys (key, exp) VALUES (?, ?)", -1, &statement, nullptr);
    if (result == SQLITE_OK) {
        result = sqlite3_bind_blob(statement, 1, buffer->data,
                                   static_cast<int>(buffer->length), SQLITE_TRANSIENT);
        if (result == SQLITE_OK) result = sqlite3_bind_int64(statement, 2, expiration);
        if (result == SQLITE_OK) result = sqlite3_step(statement);
    }

    sqlite3_finalize(statement);
    BIO_free(memory);
    EVP_PKEY_free(newKeyPair);
    if (result != SQLITE_DONE) throw runtime_error("Could not save private key");
}

//This reads a valid or expired private key from the database
RSAKey KeyManager::readKey(bool expired) const {
    sqlite3_stmt* statement = nullptr;
    const char* sql = expired
        ? "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY kid DESC LIMIT 1"
        : "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid DESC LIMIT 1";
    checkSQLite(sqlite3_prepare_v2(database, sql, -1, &statement, nullptr), database);
    sqlite3_bind_int64(statement, 1, static_cast<sqlite3_int64>(time(nullptr)));
    if (sqlite3_step(statement) != SQLITE_ROW) {
        sqlite3_finalize(statement);
        throw runtime_error("No matching key found in database");
    }
    string kid = to_string(sqlite3_column_int64(statement, 0));
    const void* data = sqlite3_column_blob(statement, 1);
    int length = sqlite3_column_bytes(statement, 1);
    time_t expiration = static_cast<time_t>(sqlite3_column_int64(statement, 2));
    BIO* memory = BIO_new_mem_buf(data, length);
    EVP_PKEY* keyPair = memory ? PEM_read_bio_PrivateKey(memory, nullptr, nullptr, nullptr) : nullptr;
    BIO_free(memory);
    sqlite3_finalize(statement);
    if (!keyPair) throw runtime_error("Could not read private key from database");
    return {kid, expiration, keyPair};
}

RSAKey KeyManager::getValidKey() const { //Returns the currently valid RSA key
    return readKey(false);
}

RSAKey KeyManager::getExpiredKey() const { //Returns the expired RSA key
    return readKey(true);
}

//This converts an RSA key into a JWK JSON string that can be sent to clients
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

//This makes the JSON returned by /.well-known/jwks.json using unexpired keys from SQLite
string KeyManager::getJWKS(const string& wantedKid) const {
    sqlite3_stmt* statement = nullptr;
    //Only keys that have not expired are included in the JWKS
    const char* sql = "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid";
    checkSQLite(sqlite3_prepare_v2(database, sql, -1, &statement, nullptr), database);
    sqlite3_bind_int64(statement, 1, static_cast<sqlite3_int64>(time(nullptr)));
    string json = "{\"keys\":[";
    bool first = true;
    int result;
    while ((result = sqlite3_step(statement)) == SQLITE_ROW) { //Iterates through all the unexpired keys in the database
        string kid = to_string(sqlite3_column_int64(statement, 0));
        //If a kid was requested, it must match the key's kid
        if (!wantedKid.empty() && wantedKid != kid) continue;
        const void* data = sqlite3_column_blob(statement, 1);
        int length = sqlite3_column_bytes(statement, 1);
        BIO* memory = BIO_new_mem_buf(data, length);
        EVP_PKEY* keyPair = memory ? PEM_read_bio_PrivateKey(memory, nullptr, nullptr, nullptr) : nullptr;
        BIO_free(memory);
        if (!keyPair) {
            sqlite3_finalize(statement);
            throw runtime_error("Could not read stored private key");
        }
        RSAKey key{kid, static_cast<time_t>(sqlite3_column_int64(statement, 2)), keyPair};
        string jwk;
        try { jwk = keyToJWK(key); }
        catch (...) { EVP_PKEY_free(keyPair); sqlite3_finalize(statement); throw; }
        EVP_PKEY_free(keyPair);
        if (!first) json += ",";
        json += jwk;
        first = false;
    }
    if (result != SQLITE_DONE) {
        sqlite3_finalize(statement);
        throw runtime_error("Could not query JWKS keys");
    }
    sqlite3_finalize(statement);
    return json + "]}";
}
