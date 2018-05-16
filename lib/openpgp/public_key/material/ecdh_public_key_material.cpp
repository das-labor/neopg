// OpenPGP ECDH public key material (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/ecdh_public_key_material.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

using namespace NeoPG;

namespace NeoPG {
namespace public_key_material {
using namespace pegtl;

struct ecdh_kdf : must<one<(char)0x03>, one<(char)0x01>, any, any> {};

template <typename Rule>
struct action : nothing<Rule> {};

template <>
struct action<ecdh_kdf> {
  template <typename Input>
  static void apply(const Input& in, uint8_t& m_hash, uint8_t& m_sym) {
    m_hash = in.peek_byte(2);
    m_sym = in.peek_byte(3);
  }
};  // namespace public_key_material

}  // namespace public_key_material
}  // namespace NeoPG

using namespace NeoPG;

std::unique_ptr<EcdhPublicKeyMaterial> EcdhPublicKeyMaterial::create_or_throw(
    ParserInput& in) {
  auto data = make_unique<EcdhPublicKeyMaterial>();
  data->m_curve.parse(in);
  data->m_key.parse(in);
  pegtl::parse<public_key_material::ecdh_kdf, public_key_material::action>(
      in.m_impl->m_input, data->m_hash, data->m_sym);
  return data;
}

void EcdhPublicKeyMaterial::write(std::ostream& out) const {
  m_curve.write(out);
  m_key.write(out);
  out << static_cast<uint8_t>(0x03) << static_cast<uint8_t>(0x01)
      << static_cast<uint8_t>(m_hash) << static_cast<uint8_t>(m_sym);
}
