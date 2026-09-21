#ifndef BASE64_URL_H
#define BASE64_URL_H

#include <string>
#include <vector>

//JWTs and JWKs using base64url instead of regular base64.
std::string base64UrlEncode(const unsigned char* data, std::size_t length);
std::string base64UrlEncode(const std::string& text);

//Decodes a base64url string into a vector of bytes. If input is invalid, empty vector is returned
std::vector<unsigned char> base64UrlDecode(const std::string& text);

#endif
