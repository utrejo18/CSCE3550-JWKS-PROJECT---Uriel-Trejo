#include "Base64Url.h"
#include <openssl/evp.h>
using namespace std;

//This converts raw bytes into the URL-safe base64 format that is used by JWT and JWK
string base64UrlEncode(const unsigned char* data, size_t length) {
    //There is nothing to encode if the input is empty
    if (length == 0) {
        return "";
    }

    //Regular base64 may need four output characters for every three bytes.
    string output(4 * ((length + 2) / 3), '\0');
    int written = EVP_EncodeBlock(
        reinterpret_cast<unsigned char*>(output.data()), data,
        static_cast<int>(length));
    if (written < 0) {
        return "";
    }
    output.resize(static_cast<size_t>(written));

    //Change regular base64 into base64url.
    for (char& character : output) {
        if (character == '+') character = '-';
        if (character == '/') character = '_';
    }

    //JWTs do not include the normal base64 padding characters.
    while (!output.empty() && output.back() == '=') {
        output.pop_back();
    }
    return output;
}

//This converts a string into base64url format, which is then used in JWTs and also JWks
string base64UrlEncode(const string& text) {
    return base64UrlEncode(
        reinterpret_cast<const unsigned char*>(text.data()), text.size());
}

//This decodes a base64url string into a vector made up of bytes
//If the input is invalid, then an empty vector is returned
vector<unsigned char> base64UrlDecode(const string& text) {
    //Changes base64url characters back to regular base64 characters.
    string padded = text;
    for (char& character : padded) {
        if (character == '-') character = '+';
        if (character == '_') character = '/';
    }

    // OpenSSL expects base64 input to be a multiple of four characters
    while (padded.size() % 4 != 0) padded.push_back('=');

    //Vector the hold the decodes bytes
    //The +1 is to make sure that the vector has enough space for the decoded bytes
    vector<unsigned char> output(3 * padded.size() / 4 + 1);
    int decoded = EVP_DecodeBlock(
        output.data(), reinterpret_cast<const unsigned char*>(padded.data()),
        static_cast<int>(padded.size()));
    if (decoded < 0) {
        return vector<unsigned char>();
    }

    //EVP_DecodeBlock counts the padding characters as part of the decoded length
    //so eventually they need to be removed from the output vector
    size_t padding = 0;
    if (!padded.empty() && padded.back() == '=') ++padding;
    if (padded.size() > 1 && padded[padded.size() - 2] == '=') ++padding;
    output.resize(static_cast<size_t>(decoded) - padding);
    return output;
}
