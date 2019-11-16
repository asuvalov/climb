#include <boost/test/unit_test.hpp>

#include <test_block.hpp>
#include <timer.hpp>
#include <utils.hpp>

#include <crypto/base58.hpp>
#include <crypto/hex.hpp>

BOOST_AUTO_TEST_CASE(base58_test)
{
    std::string test_data = "hello world";
    auto base = crypto::encode_base58(test_data);
    auto data = crypto::decode_base58(base);

    BOOST_CHECK_EQUAL(base, "StV1DL6CwTryKyV");
    BOOST_CHECK_EQUAL(std::string(data.cbegin(), data.cend()), test_data);

    auto bytes = crypto::from_hex<char>(test_block);
    size_t test_size = 1000UL;

    std::string base58;
    auto to_base58_f = [&](){ base58 = crypto::encode_base58(reinterpret_cast<const unsigned char*>(bytes.data()), test_size); };

    std::vector<char> decoded;
    auto from_base58_f = [&](){ decoded = crypto::decode_base58(base58); };

    write_result("encode_base58", timer::estimate(to_base58_f));
    write_result("decode_base58", timer::estimate(from_base58_f));

    BOOST_CHECK_EQUAL(decoded.size(), test_size);
    bool is_equal = true;
    for (size_t i = 0; i < test_size; ++i) {
        if (decoded[i] != bytes[i])
            is_equal = false;
    }
    BOOST_CHECK(is_equal);
}
