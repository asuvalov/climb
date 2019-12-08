#pragma once

#include <openssl/ec.h>
#include <openssl/bn.h>

#include <crypto/hash.hpp>
#include <elliptic/public_key.hpp>

#include <vector>
#include <string>

namespace ecdsa
{

class private_key
{
public:
    private_key();
    private_key(const private_key&) = delete;
    explicit private_key(const crypto::sha256& secret);
    explicit private_key(const std::vector<char>& data);
    explicit private_key(const std::string& hex);

    ~private_key();

    std::vector<char> to_vector() const;
    std::string to_hex() const;

    public_key pub_key() const;

    void set_compressed();
    void set_uncompressed();

private:
    void _create(const std::vector<char>& data);

private:
    EC_KEY* _key; 
};

}

