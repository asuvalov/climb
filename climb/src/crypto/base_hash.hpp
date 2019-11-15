#pragma once

#include <cstring>
#include <vector>
#include <string>
#include <assert.h>
#include <algorithm>

#include <crypto/hex.hpp>
#include <crypto/utils.hpp>

#include <openssl/sha.h>
#include <openssl/ripemd.h>

namespace crypto
{

template <typename storage_t, typename serialize_t, class derived_t>
class base_hash
{
public:
    using iterator = serialize_t*;
    using const_iterator = const serialize_t*;
    using reverse_iterator = std::reverse_iterator<iterator>;
    using const_reverse_iterator = std::reverse_iterator<const_iterator>;

    base_hash() { memset(static_cast<void*>(_hash), 0, sizeof(storage_t)); }
    base_hash(const base_hash& rs) = default;
    base_hash(const serialize_t* data, size_t size);
    
    virtual ~base_hash() = default;

    const serialize_t* data() const { return reinterpret_cast<const serialize_t*>(_hash); }
    serialize_t* data() { return reinterpret_cast<serialize_t*>(_hash); }

    iterator begin() { return data(); }
    iterator   end() { return data() + size(); }

    const_iterator cbegin() const { return data(); }
    const_iterator   cend() const { return data() + size(); }

    reverse_iterator rbegin() { return reverse_iterator(end()); }
    reverse_iterator   rend() { return reverse_iterator(begin());}

    const_reverse_iterator crbegin() const { return const_reverse_iterator(cend()); }
    const_reverse_iterator   crend() const { return const_reverse_iterator(cbegin()); }

    static constexpr size_t size() noexcept { return sizeof(storage_t); }

    std::vector<storage_t> to_vector() const;
    const derived_t& reverse();

    std::string to_hex() const { return crypto::to_hex(data(), size()); }
    static derived_t from_hex(const std::string& hex);

    friend bool operator== (const base_hash& lhs, const base_hash& rhs) {
        return memcmp(static_cast<const void*>(lhs._hash), static_cast<const void*>(rhs._hash), sizeof(storage_t)) == 0;
    }

    friend bool operator< (const base_hash& lhs, const base_hash& rhs) {
        return memcmp(static_cast<const void*>(lhs._hash), static_cast<const void*>(rhs._hash), sizeof(storage_t)) < 0;
    }

    friend bool operator<= (const base_hash& lhs, const base_hash& rhs) {
        return memcmp(static_cast<const void*>(lhs._hash), static_cast<const void*>(rhs._hash), sizeof(storage_t)) <= 0;
    }

    friend bool operator> (const base_hash& lhs, const base_hash& rhs) {
        return memcmp(static_cast<const void*>(lhs._hash), static_cast<const void*>(rhs._hash), sizeof(storage_t)) > 0;
    }

    friend bool operator>= (const base_hash& lhs, const base_hash& rhs) {
        return memcmp(static_cast<const void*>(lhs._hash), static_cast<const void*>(rhs._hash), sizeof(storage_t)) >= 0;
    }

    friend bool operator!= (const base_hash& lhs, const base_hash& rhs) {
        return memcmp(static_cast<const void*>(lhs._hash), static_cast<const void*>(rhs._hash), sizeof(storage_t)) != 0;
    }

    friend std::ostream& operator<<(std::ostream& os, const base_hash& hash) {
        return os << hash.to_hex();
    }

    template <class V>
    static derived_t hash(const std::vector<V>& data) {
        return hash(reinterpret_cast<const unsigned char*>(data.data()), data.size()*sizeof(storage_t));
    }

    static derived_t hash(const std::string& data) {
        return hash(reinterpret_cast<const unsigned char*>(data.data()), data.size());
    }

    template <class V>
    static derived_t hash(const V* data, size_t size);

protected:
    storage_t _hash;
};

template <typename storage_t, typename serialize_t, class derived_t>
base_hash<storage_t, serialize_t, derived_t>::base_hash(const serialize_t* data, size_t size)
{
    assert(sizeof(serialize_t)*size == sizeof(storage_t));
    memcpy(static_cast<void*>(_hash), static_cast<const void*>(data), sizeof(storage_t));
}

template <typename storage_t, typename serialize_t, class derived_t>
std::vector<storage_t> base_hash<storage_t, serialize_t, derived_t>::to_vector() const
{
    std::vector<storage_t> vec;
    vec.insert(vec.end(), cbegin(), cend());
    return vec;
}

template <typename storage_t, typename serialize_t, class derived_t>
const derived_t& base_hash<storage_t, serialize_t, derived_t>::reverse() {
    std::reverse(begin(), end());
    return dynamic_cast<const derived_t&>(*this);
}

template <typename storage_t, typename serialize_t, class derived_t>
derived_t base_hash<storage_t, serialize_t, derived_t>::from_hex(const std::string& hex)
{
    std::vector<serialize_t> vec = crypto::from_hex<serialize_t>(hex);
    return derived_t(vec.data(), vec.size());
}

template <typename storage_t, typename serialize_t, class derived_t>
template <class V>
derived_t base_hash<storage_t, serialize_t, derived_t>::hash(const V* data, size_t size)
{
    derived_t hash;

    if constexpr (sizeof(storage_t) == 20) {
        RIPEMD160_CTX ctx;
        RIPEMD160_Init(&ctx);
        RIPEMD160_Update(&ctx, static_cast<const void*>(data), sizeof(serialize_t)*size);
        RIPEMD160_Final(reinterpret_cast<unsigned char*>(hash.data()), &ctx);
    }
    else if constexpr (sizeof(storage_t) == 32) {
        SHA256_CTX ctx;
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, static_cast<const void*>(data), sizeof(serialize_t)*size);
        SHA256_Final(reinterpret_cast<unsigned char*>(hash.data()), &ctx);
    }
    else {
        static_assert(dependent_false<storage_t>::value);
    }

    return hash;
}

} // crypto
