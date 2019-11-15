#include <crypto/base58.hpp>
#include <openssl/bn.h>
#include <cmath>
#include <algorithm>
#include <stdexcept>

namespace crypto
{

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

    BN_CTX* ctx() { return _ctx; }

private:
    BN_CTX* _ctx;
};

static const std::string base58_syms = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

std::string encode_base58(const unsigned char* data, size_t size)
{
    bignum_helper bn_helper;

    BIGNUM* data_bn = bn_helper.create_bignum(data, size);
    BIGNUM* dv      = bn_helper.create_bignum();
    BIGNUM* rem     = bn_helper.create_bignum();
    BIGNUM* zero    = bn_helper.create_bignum(0);
    BIGNUM* base58  = bn_helper.create_bignum(58); 

    std::string res;
    size_t reserve_size = std::llrint(log(256)/log(58) * size);
    res.reserve(reserve_size);

    while (BN_cmp(data_bn, zero) == 1) {
        if (BN_div(dv, rem, data_bn, base58, bn_helper.ctx()) != 1)
            throw std::runtime_error("Failed BN_div\n");
        res += base58_syms[BN_get_word(rem)];
        data_bn = dv;
    }

    auto* beg = const_cast<unsigned char*>(data);
    const auto* end = beg + size;
    while (beg != end && *beg == 0U) {
        res += base58_syms[0];
        ++beg;
    }

    std::reverse(res.begin(), res.end());
    return res;
}

std::string encode_base58(const std::string& data)
{
    return encode_base58(reinterpret_cast<const unsigned char*>(data.c_str()), data.size());
}

std::string encode_base58(const std::vector<char>& data)
{
    return encode_base58(reinterpret_cast<const unsigned char*>(data.data()), data.size());
}

std::vector<char> decode_base58(const char* data, size_t size)
{
    bignum_helper bn_helper;

    BIGNUM* result  = bn_helper.create_bignum(0);
    BIGNUM* base58  = bn_helper.create_bignum(58); 
    BIGNUM* buff    = bn_helper.create_bignum();

    auto* beg = data;
    const auto* end = beg + size;

    while (beg != end) {
        auto pos = base58_syms.find(*beg);
        if (pos == std::string::npos)
            throw std::runtime_error("Failed decode_base58: invalid symbol\n");
        if (BN_mul(result, result, base58, bn_helper.ctx()) != 1)
            throw std::runtime_error("Failed BN_mul\n");
        if (BN_set_word(buff, pos) != 1)
            throw std::runtime_error("Failed BN_set_word\n");
        if (BN_add(result, result, buff) != 1)
            throw std::runtime_error("Failed BN_add\n");
        ++beg;
    }

    beg = data;

    size_t zeros_size = 0;
    while (*beg == base58_syms[0]) {
        ++zeros_size;
        ++beg;
    }

    auto bn_size = static_cast<size_t>(BN_num_bytes(result));
    std::vector<char> bn_vec(bn_size + zeros_size, 0);
    if (static_cast<size_t>(BN_bn2bin(result, reinterpret_cast<unsigned char*>(bn_vec.data() + zeros_size))) != bn_size)
        throw std::runtime_error("Failed BN_bn2bin\n");

    return bn_vec;
}

std::vector<char> decode_base58(const std::string& base58)
{
    return decode_base58(base58.data(), base58.size());
}

} // crypto
