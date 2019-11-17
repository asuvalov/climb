#include <boost/test/unit_test.hpp>

#include <test_block.hpp>
#include <timer.hpp>
#include <utils.hpp>

#include <elliptic/private_key.hpp>

BOOST_AUTO_TEST_CASE(private_key_test)
{
    ecdsa::private_key priv_key;

    // serialize to bytes
    std::vector<char> vec;
    BOOST_CHECK_NO_THROW(vec = priv_key.to_vector());
    BOOST_CHECK_EQUAL(vec.size(), 32UL);

    // serialize to hex string
    std::string hex;
    BOOST_CHECK_NO_THROW(hex = priv_key.to_hex());
    BOOST_CHECK_EQUAL(hex.size(), 64UL);

    auto secret = crypto::sha256::hash("secret");
    ecdsa::private_key priv_key_with_secret(secret);

    BOOST_CHECK_EQUAL(secret.to_vector(), priv_key_with_secret.to_vector());
    BOOST_CHECK_EQUAL(secret.to_hex(), priv_key_with_secret.to_hex());

    //std::cout << priv_key.pub_key().to_hex();
    //std::cout << priv_key_with_secret.to_vector() << std::endl;
}
