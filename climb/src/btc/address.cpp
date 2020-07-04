/*
  @author Andrus Suvalau
  @date 4 Jul 2020
  @brief Implementation of Bitcoin addresses
*/

#include <elliptic/public_key.hpp>
#include <btc/address.hpp>
#include <crypto/hash.hpp>
#include <crypto/base58.hpp>

namespace climb { namespace btc {

p2pkh::p2pkh(const ecdsa::public_key& pubkey, net_t net) : _net(net) {
  const auto& sha256 = crypto::sha256::hash(pubkey.data(), pubkey.size());
  const auto& ripemd160 = crypto::ripemd160::hash(sha256.data(), sha256.size());
  unsigned char prefix = net == net_t::MAINNET ? 0x00 : 0x6f;
  _base58 = crypto::encode_base58_check(prefix, reinterpret_cast<const unsigned char*>(ripemd160.data()), ripemd160.size());
}

p2pkh::p2pkh(const std::string& base58) {
  auto[prefix, pubkey] = crypto::decode_base58_check(base58);
  auto _net = prefix == 0x00 ? net_t::MAINNET : net_t::TESTNET;
  _base58 = base58;
}

}} // climb::btc
