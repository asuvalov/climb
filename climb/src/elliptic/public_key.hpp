#pragma once

#include <vector>
#include <string>

namespace ecdsa
{

class public_key
{
public:
    public_key(const std::vector<char>& data);
    public_key(const std::string& hex);

    std::vector<char> to_vector() const;
    std::string to_hex() const;

private:
    std::vector<char> _key;
};

}
