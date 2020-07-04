/*
  @author Andrus Suvalau
  @date 4 Jul 2020
  @brief Implementation of Bitcoin addresses
*/

#include <string>
#include <btc/utils.hpp>

namespace ecdsa {
class public_key;
}

namespace climb { namespace btc {

class p2pkh {
public:
  explicit p2pkh(const ecdsa::public_key& pubkey, net_t net);
  explicit p2pkh(const std::string& base58);
  const std::string& base58() const { return _base58; }
  net_t net_type() const { return _net; }
private:
  std::string _base58;
  net_t _net;
};

}} // climb::btc
