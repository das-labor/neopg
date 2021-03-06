// OpenPGP DSA public key material
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

/// \file
/// This file contains the DSA specific key material for public key packets.

#pragma once

#include <neopg/openpgp/public_key/public_key_material.h>

#include <neopg/openpgp/multiprecision_integer.h>
#include <neopg/parser/parser_input.h>

#include <memory>

namespace NeoPG {

/// Key material for DSA public keys.
class NEOPG_UNSTABLE_API DsaPublicKeyMaterial : public PublicKeyMaterial {
 public:
  MultiprecisionInteger m_p;
  MultiprecisionInteger m_q;
  MultiprecisionInteger m_g;
  MultiprecisionInteger m_y;  // g**x mod p (x secret)

  /// Create a new instance from \p input.
  ///
  /// \param input parser input with key material
  ///
  /// Throws ParserError if input can not be parsed.
  static std::unique_ptr<DsaPublicKeyMaterial> create_or_throw(
      ParserInput& input);

  /// Return the public key algorithm.
  ///
  /// \return the value PublicKeyAlgorithm::Dsa
  PublicKeyAlgorithm algorithm() const override {
    return PublicKeyAlgorithm::Dsa;
  };

  /// Write the key material to the output stream.
  ///
  /// \param out the output stream to write to
  void write(std::ostream& out) const override;
};

}  // namespace NeoPG
