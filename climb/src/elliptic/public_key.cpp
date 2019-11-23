#include <elliptic/public_key.hpp>
#include <crypto/hex.hpp>

namespace ecdsa
{

public_key::public_key(const std::vector<char>& data)
    : _key(data)
{
}

public_key::public_key(const std::string& hex)
{
    _key = crypto::from_hex<char>(hex);
}

std::vector<char> public_key::to_vector() const
{
    return _key;
}

std::string public_key::to_hex() const
{
    return crypto::to_hex(_key);
}

} // ecdsa
