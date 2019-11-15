#pragma once

#include <crypto/base_hash.hpp>

namespace crypto
{

template <typename serialize_t>
class base_ripemd160 : public base_hash<uint32_t[5], serialize_t, base_ripemd160<serialize_t>>
{
public:
    base_ripemd160() : base_hash<uint32_t[5], serialize_t, base_ripemd160<serialize_t>>() {}
    base_ripemd160(const base_ripemd160& another) = default;
    base_ripemd160(const serialize_t* data, size_t size) : base_hash<uint32_t[5], serialize_t, base_ripemd160<serialize_t>>(data, size) {}
};

using  ripemd160 = base_ripemd160<char>;
using uripemd160 = base_ripemd160<unsigned char>;

} // crypto
