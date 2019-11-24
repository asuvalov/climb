#pragma once

#include <crypto/utils.hpp>

#include <vector>
#include <string>
#include <sstream>
#include <charconv>
#include <iomanip>
#include <type_traits>

namespace crypto {

template <typename serialize_t>
std::vector<serialize_t> from_hex(const std::string& hex)
{
    constexpr size_t chars_per_num = sizeof(serialize_t)*2U;
    auto size = hex.size()/chars_per_num;
    std::vector<serialize_t> res(size);

    const auto* beg = hex.c_str();
    uint64_t val = 0UL;
    for (size_t i = 0; i < size; ++i) {
        std::from_chars<uint64_t>(beg, beg + chars_per_num, val, 16);
        beg += chars_per_num;
        res[i] = static_cast<serialize_t>(val);
    }

    return res;
}

template <typename serialize_t>
const auto* cast_to_unsigned(const serialize_t* ptr)
{
    if constexpr (std::is_same<char, serialize_t>::value || std::is_same<int8_t, serialize_t>::value)
        return reinterpret_cast<const uint8_t*>(ptr);
    else if constexpr (std::is_same<unsigned char, serialize_t>::value || std::is_same<uint8_t, serialize_t>::value)
        return ptr;
    else
        static_assert(dependent_false<serialize_t>::value);
}

template <typename serialize_t>
std::string to_hex(const serialize_t* data, size_t size)
{
    std::stringstream ss;
    ss << std::setfill('0');

    const auto* beg = cast_to_unsigned(data);
    const auto* end = beg + size;

    constexpr int w = 2*sizeof(*beg);

    while (beg != end) {
        ss << std::setw(w) << std::hex << static_cast<uint64_t>(*beg);
        ++beg;
    }
    
    return ss.str();
}

template <typename serialize_t>
std::string to_hex(const std::vector<serialize_t>& data)
{
    return to_hex<serialize_t>(data.data(), data.size());
}

} // crypto

