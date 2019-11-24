#pragma once

#include <openssl/bn.h>
#include <elliptic/exception.hpp>

class bignum_helper
{
public:
    bignum_helper() : _ctx(nullptr) {
        _ctx = BN_CTX_new();
        CLIMB_THROW_IF(_ctx == nullptr);
        BN_CTX_start(_ctx);
    }

    ~bignum_helper() { BN_CTX_end(_ctx); }

    BIGNUM* create_bignum() {
        auto* bn = BN_CTX_get(_ctx);
        CLIMB_THROW_IF(bn == nullptr);
        return bn;
    }

    BIGNUM* create_bignum(unsigned long n) {
        auto* bn = create_bignum();
        CLIMB_THROW_IF(BN_set_word(bn, n) != 1);
        return bn;
    }

    BIGNUM* create_bignum(const unsigned char* data, size_t size) {
        auto* bn = create_bignum();
        CLIMB_THROW_IF(BN_bin2bn(data, static_cast<int>(size), bn) == nullptr);
        return bn;
    }

    static std::vector<char> to_bin(const BIGNUM* bn)
    {
        auto bn_size = (BN_num_bytes(bn));
        std::vector<char> vec(static_cast<size_t>(bn_size));
        CLIMB_THROW_IF(BN_bn2bin(bn, reinterpret_cast<unsigned char*>(vec.data())) != bn_size);
        return vec;
    }

    BN_CTX* ctx() { return _ctx; }

private:
    BN_CTX* _ctx;
};
