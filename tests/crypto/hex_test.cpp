#include <boost/test/unit_test.hpp>

#include <test_block.hpp>
#include <timer.hpp>
#include <utils.hpp>

#include <crypto/hex.hpp>

BOOST_AUTO_TEST_CASE(hex_test)
{
    std::vector<uint8_t> bytes;
    auto from_hex_f = [&]() { bytes = std::move(crypto::from_hex<uint8_t>(test_block)); };

    std::string hex;
    auto to_hex_f = [&]() { hex = std::move(crypto::to_hex(bytes)); };

    [[maybe_unused]] auto from_hex_secs = timer::estimate(from_hex_f);
    [[maybe_unused]] auto to_hex_secs = timer::estimate(to_hex_f);

    write_result("from_hex", from_hex_secs);
    write_result("to_hex", to_hex_secs);

    BOOST_CHECK(test_block == hex);
}
