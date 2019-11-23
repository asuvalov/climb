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

    // create priv key from secret
    auto secret = crypto::sha256::hash("secret");
    ecdsa::private_key priv_key_with_secret(secret);

    BOOST_CHECK_EQUAL(secret.to_vector(), priv_key_with_secret.to_vector());
    BOOST_CHECK_EQUAL(secret.to_hex(), priv_key_with_secret.to_hex());
    BOOST_CHECK_EQUAL(priv_key_with_secret.pub_key().to_hex(), "04a02b9d5fdd1307c2ee4652ba54d492d1fd11a7d1bb3f3a44c4a05e79f19de933924aa2580069952b0140d88de21c367ee4af7c4a906e1498f20ab8f62e4c2921");
    priv_key_with_secret.set_compressed();
    BOOST_CHECK_EQUAL(priv_key_with_secret.pub_key().to_hex(), "03a02b9d5fdd1307c2ee4652ba54d492d1fd11a7d1bb3f3a44c4a05e79f19de933");
}
