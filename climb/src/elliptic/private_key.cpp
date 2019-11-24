#include <elliptic/private_key.hpp>
#include <elliptic/bignum.hpp>
#include <elliptic/exception.hpp>
#include <crypto/hex.hpp>

#include <openssl/obj_mac.h>

namespace ecdsa
{

private_key::private_key() : _key(nullptr)
{
    _key = EC_KEY_new_by_curve_name(NID_secp256k1);
    CLIMB_THROW_IF(_key == nullptr);

    CLIMB_THROW_IF(1 != EC_KEY_generate_key(_key));
}

private_key::private_key(const crypto::sha256& secret) : _key(nullptr)
{
    _create(secret.to_vector());
}

private_key::private_key(const std::vector<char>& data) : _key(nullptr)
{
    _create(data);
}

private_key::private_key(const std::string& hex) : _key(nullptr)
{
    _create(crypto::from_hex<char>(hex));
}

void private_key::_create(const std::vector<char>& data)
{
    _key = EC_KEY_new_by_curve_name(NID_secp256k1);
    CLIMB_THROW_IF(_key == nullptr);

    bignum_helper bignum_helper;
    BIGNUM* bn = bignum_helper.create_bignum(reinterpret_cast<const unsigned char*>(data.data()), data.size());

    const EC_GROUP* group = EC_KEY_get0_group(_key);
    CLIMB_THROW_IF(group == nullptr);

    EC_POINT* point = EC_POINT_new(group);
    CLIMB_THROW_IF(point == nullptr);

    CLIMB_THROW_IF(1 != EC_POINT_mul(group, point, bn, nullptr, nullptr, bignum_helper.ctx()));
    CLIMB_THROW_IF(1 != EC_KEY_set_private_key(_key, bn));
    CLIMB_THROW_IF(1 != EC_KEY_set_public_key(_key, point));

    EC_POINT_free(point);
}

std::vector<char> private_key::to_vector() const
{
    const BIGNUM* bn = EC_KEY_get0_private_key(_key);
    CLIMB_THROW_IF(bn == nullptr);

    return bignum_helper::to_bin(bn);
}

std::string private_key::to_hex() const
{
    const auto& vec = to_vector();
    return crypto::to_hex(vec);
}

public_key private_key::pub_key() const
{
    const EC_POINT* point = EC_KEY_get0_public_key(_key);
    CLIMB_THROW_IF(point == nullptr);

    const EC_GROUP* group = EC_KEY_get0_group(_key);
    CLIMB_THROW_IF(group == nullptr);

    point_conversion_form_t conv = EC_KEY_get_conv_form(_key);

    bignum_helper bignum_helper;
    BIGNUM* bn = bignum_helper.create_bignum();

    CLIMB_THROW_IF(nullptr == EC_POINT_point2bn(group, point, conv, bn, bignum_helper.ctx()));
    const auto& vec = bignum_helper::to_bin(bn);

    return public_key(vec);
}

void private_key::set_compressed()
{
    EC_KEY_set_conv_form(_key, point_conversion_form_t::POINT_CONVERSION_COMPRESSED);
}

void private_key::set_uncompressed()
{
    EC_KEY_set_conv_form(_key, point_conversion_form_t::POINT_CONVERSION_UNCOMPRESSED);
}

private_key::~private_key()
{
    EC_KEY_free(_key);
}

} // ecdsa

