#pragma once

#include <vector>
#include <string>
#include <cstring>

namespace ecdsa
{

class public_key
{
public:
    explicit public_key(const std::vector<char>& data);
    explicit public_key(const std::string& hex);

    std::vector<char> to_vector() const;
    std::string to_hex() const;

    const char* data() const { return _key.data(); }
    size_t size() const { return _key.size(); }

    friend bool operator== (const public_key& lhs, const public_key& rhs) {
        return memcmp(static_cast<const void*>(lhs._key.data()), static_cast<const void*>(rhs._key.data()), lhs.size()) == 0;
    }

    friend std::ostream& operator<<(std::ostream& os, const ecdsa::public_key& pubkey) { return os << pubkey.to_hex(); }

private:
    std::vector<char> _key;
};

}
