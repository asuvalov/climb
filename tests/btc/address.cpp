/*
  @author Andrus Suvalau
  @date 4 Jul 2020
  @brief Tests for Bitcoin addresses
*/

#include <boost/test/unit_test.hpp>

#include <timer.hpp>
#include <utils.hpp>

#include <elliptic/public_key.hpp>
#include <btc/address.hpp>
#include <crypto/hex.hpp>
#include <crypto/hash.hpp>
#include <crypto/base58.hpp>

BOOST_AUTO_TEST_CASE(p2pkh_test)
{
    std::string hex = "025c0de3b9c8ab18dd04e3511243ec2952002dbfadc864b9628910169d9b9b00ec";
    auto pubkey = ecdsa::public_key(crypto::from_hex<char>(hex));
    auto net_type = net_t::MAINNET;
    auto addr = climb::btc::p2pkh(pubkey, net_type);
    BOOST_CHECK_EQUAL(addr.base58(), "14cxpo3MBCYYWCgF74SWTdcmxipnGUsPw3");
    BOOST_CHECK_NO_THROW(climb::btc::p2pkh(addr.base58()));
}
