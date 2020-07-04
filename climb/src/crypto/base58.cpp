#include <crypto/base58.hpp>
#include <crypto/hash.hpp>
#include <elliptic/bignum.hpp>
#include <elliptic/exception.hpp>

#include <openssl/bn.h>

#include <algorithm>
#include <cmath>
#include <cstring>

namespace crypto
{

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
        CLIMB_THROW_IF(1 != BN_div(dv, rem, data_bn, base58, bn_helper.ctx()));
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

    const auto* beg = data;
    const auto* end = beg + size;

    size_t zeros_size = 0;
    while (beg != end && *beg == base58_syms[0]) {
        ++zeros_size;
        ++beg;
    }

    while (beg != end) {
        auto pos = base58_syms.find(*beg);
        CLIMB_THROW_IF(pos == std::string::npos);

        CLIMB_THROW_IF(1 != BN_mul(result, result, base58, bn_helper.ctx()));
        CLIMB_THROW_IF(1 != BN_set_word(buff, pos));
        CLIMB_THROW_IF(1 != BN_add(result, result, buff));

        ++beg;
    }
    
    auto bn_size = BN_num_bytes(result);
    std::vector<char> bn_vec(static_cast<size_t>(bn_size) + zeros_size, 0);
    CLIMB_THROW_IF(bn_size != BN_bn2bin(result, reinterpret_cast<unsigned char*>(bn_vec.data() + zeros_size)));

    return bn_vec;
}

std::vector<char> decode_base58(const std::string& base58)
{
    return decode_base58(base58.data(), base58.size());
}

std::string encode_base58_check(unsigned char version, const unsigned char* data, size_t size)
{
    const size_t checksum_size = 4U;
    std::vector<unsigned char> address;
    address.reserve(sizeof(version) + size + checksum_size);

    address.push_back(version);
    std::copy(data, data + size, std::back_inserter(address));

    const auto& dsha256 = crypto::usha256::dhash(address.data(), address.size());
    std::copy(dsha256.data(), dsha256.data() + checksum_size, std::back_inserter(address));

    return encode_base58(address.data(), address.size());
}

std::pair<unsigned char, std::vector<char>> decode_base58_check(const std::string& base58)
{
    const auto& data = decode_base58(base58.c_str(), base58.size());
    const size_t checksum_size = 4U;
    const size_t payload_size = data.size() - checksum_size;
    const auto& dsha256 = crypto::sha256::dhash(data.data(), payload_size);
    CLIMB_THROW_IF(strncmp(dsha256.data(), data.data() + payload_size, checksum_size) != 0)
    return {data[0], std::vector<char>(data.data() + 1, data.data() + payload_size)};
}

} // crypto
