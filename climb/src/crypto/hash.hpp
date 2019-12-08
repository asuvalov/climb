#pragma once

#include <crypto/base_hash.hpp>

namespace crypto
{

// SHA256
using  sha256    = base_hash<uint64_t[4], char>;
using usha256    = base_hash<uint64_t[4], unsigned char>;


// RIPEMD160
using  ripemd160 = base_hash<uint32_t[5], char>;
using uripemd160 = base_hash<uint32_t[5], unsigned char>;


} // crypto

