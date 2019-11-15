#pragma once

#include <crypto/base_hash.hpp>

namespace crypto
{

template <class serialize_t>
class base_sha256 : public base_hash<uint64_t[4], serialize_t, base_sha256<serialize_t>>
{
public:
    base_sha256() : base_hash<uint64_t[4], serialize_t, base_sha256<serialize_t>>() {}
    base_sha256(const base_sha256&) = default;
    base_sha256(const serialize_t* data, size_t size) : base_hash<uint64_t[4], serialize_t, base_sha256<serialize_t>>(data, size) {}
};

using  sha256 = base_sha256<char>;
using usha256 = base_sha256<unsigned char>;

} // crypto
