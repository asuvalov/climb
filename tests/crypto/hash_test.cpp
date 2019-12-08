#include <boost/test/unit_test.hpp>

#include <test_block.hpp>
#include <timer.hpp>
#include <utils.hpp>

#include <crypto/hash.hpp>

BOOST_AUTO_TEST_CASE(sha256_test)
{
    crypto::sha256 hash;
    auto hash_f = [&](){ hash = crypto::sha256::hash(test_block); };

    [[maybe_unused]] auto hash_secs = timer::estimate(hash_f);
    write_result("sha256", hash_secs);

    BOOST_CHECK_EQUAL(hash.to_hex(), "e586b640dc6e941ed7498b407ff9a716c55462dbf4d242a6255e184640f46f4d");
    BOOST_CHECK_EQUAL(hash, crypto::sha256::from_hex("e586b640dc6e941ed7498b407ff9a716c55462dbf4d242a6255e184640f46f4d"));
}

BOOST_AUTO_TEST_CASE(ripemd160_test)
{
    crypto::ripemd160 hash;
    auto hash_f = [&]() { hash = crypto::ripemd160::hash(test_block); };

    [[maybe_unused]] auto hash_secs = timer::estimate(hash_f);
    write_result("ripemd160", hash_secs);

    BOOST_CHECK_EQUAL(hash.to_hex(), "b9922c4e03b5768cf27ce25d16bfc535d055696a");
    BOOST_CHECK_EQUAL(hash, crypto::ripemd160::from_hex("b9922c4e03b5768cf27ce25d16bfc535d055696a"));
}

