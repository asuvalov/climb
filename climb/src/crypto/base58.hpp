#pragma once

#include <string>
#include <vector>

namespace crypto
{

std::string encode_base58(const unsigned char* data, size_t size);
std::string encode_base58(const std::string& data);
std::string encode_base58(const std::vector<char>& data);

std::vector<char> decode_base58(const char* data, size_t size);
std::vector<char> decode_base58(const std::string& base58);

} // crypto
