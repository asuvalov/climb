#pragma once

#include <openssl/bn.h>
#include <stdexcept>

class bignum_helper
{
public:
    bignum_helper() : _ctx(nullptr) {
        _ctx = BN_CTX_new();
        if (_ctx == nullptr)
            throw std::runtime_error("Failed BN_CTX_new\n");
        BN_CTX_start(_ctx);
    }

    ~bignum_helper() { BN_CTX_end(_ctx); }

    BIGNUM* create_bignum() {
        auto* bn = BN_CTX_get(_ctx);
        if (bn == nullptr)
            throw std::runtime_error("Failed BN_CTX_get\n");
        return bn;
    }

    BIGNUM* create_bignum(unsigned long n) {
        auto* bn = create_bignum();
        if (BN_set_word(bn, n) != 1)
            throw std::runtime_error("Failed BN_set_word\n");
        return bn;
    }

    BIGNUM* create_bignum(const unsigned char* data, size_t size) {
        auto* bn = create_bignum();
        if (BN_bin2bn(data, static_cast<int>(size), bn) == nullptr)
            throw std::runtime_error("Failed BN_bin2bn\n");
        return bn;
    }

    static std::vector<char> to_bin(const BIGNUM* bn)
    {
        auto bn_size = static_cast<size_t>(BN_num_bytes(bn));
        std::vector<char> vec(bn_size);
        if (static_cast<size_t>(BN_bn2bin(bn, reinterpret_cast<unsigned char*>(vec.data()))) != bn_size)
            throw std::runtime_error("Failed BN_bn2bin\n");
        return vec;
    }

    BN_CTX* ctx() { return _ctx; }

private:
    BN_CTX* _ctx;
};
