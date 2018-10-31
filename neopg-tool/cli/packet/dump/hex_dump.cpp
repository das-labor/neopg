// hex dump format (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg-tool/cli/packet/dump/hex_dump.h>

#include <neopg/openpgp/public_key/data/v3_public_key_data.h>
#include <neopg/openpgp/public_key/data/v4_public_key_data.h>

#include <neopg/openpgp/public_key/material/dsa_public_key_material.h>
#include <neopg/openpgp/public_key/material/ecdh_public_key_material.h>
#include <neopg/openpgp/public_key/material/ecdsa_public_key_material.h>
#include <neopg/openpgp/public_key/material/eddsa_public_key_material.h>
#include <neopg/openpgp/public_key/material/elgamal_public_key_material.h>
#include <neopg/openpgp/public_key/material/raw_public_key_material.h>
#include <neopg/openpgp/public_key/material/rsa_public_key_material.h>

#include <neopg/openpgp/public_key/material/dsa_public_key_material.h>
#include <neopg/openpgp/public_key/material/ecdh_public_key_material.h>
#include <neopg/openpgp/public_key/material/ecdsa_public_key_material.h>
#include <neopg/openpgp/public_key/material/eddsa_public_key_material.h>
#include <neopg/openpgp/public_key/material/elgamal_public_key_material.h>
#include <neopg/openpgp/public_key/material/rsa_public_key_material.h>

#include <neopg/openpgp/signature/data/v3_signature_data.h>
#include <neopg/openpgp/signature/data/v4_signature_data.h>

#include <neopg/openpgp/signature/subpacket/embedded_signature_subpacket.h>
#include <neopg/openpgp/signature/subpacket/exportable_certification_subpacket.h>
#include <neopg/openpgp/signature/subpacket/features_subpacket.h>
#include <neopg/openpgp/signature/subpacket/issuer_subpacket.h>
#include <neopg/openpgp/signature/subpacket/key_expiration_time_subpacket.h>
#include <neopg/openpgp/signature/subpacket/key_flags_subpacket.h>
#include <neopg/openpgp/signature/subpacket/key_server_preferences_subpacket.h>
#include <neopg/openpgp/signature/subpacket/notation_data_subpacket.h>
#include <neopg/openpgp/signature/subpacket/policy_uri_subpacket.h>
#include <neopg/openpgp/signature/subpacket/preferred_compression_algorithms_subpacket.h>
#include <neopg/openpgp/signature/subpacket/preferred_hash_algorithms_subpacket.h>
#include <neopg/openpgp/signature/subpacket/preferred_key_server_subpacket.h>
#include <neopg/openpgp/signature/subpacket/preferred_symmetric_algorithms_subpacket.h>
#include <neopg/openpgp/signature/subpacket/primary_user_id_subpacket.h>
#include <neopg/openpgp/signature/subpacket/reason_for_revocation_subpacket.h>
#include <neopg/openpgp/signature/subpacket/regular_expression_subpacket.h>
#include <neopg/openpgp/signature/subpacket/revocable_subpacket.h>
#include <neopg/openpgp/signature/subpacket/revocation_key_subpacket.h>
#include <neopg/openpgp/signature/subpacket/signature_creation_time_subpacket.h>
#include <neopg/openpgp/signature/subpacket/signature_expiration_time_subpacket.h>
#include <neopg/openpgp/signature/subpacket/signature_target_subpacket.h>
#include <neopg/openpgp/signature/subpacket/signers_user_id_subpacket.h>
#include <neopg/openpgp/signature/subpacket/trust_signature_subpacket.h>

#include <neopg/openpgp/signature/material/dsa_signature_material.h>
#include <neopg/openpgp/signature/material/ecdsa_signature_material.h>
#include <neopg/openpgp/signature/material/eddsa_signature_material.h>
#include <neopg/openpgp/signature/material/raw_signature_material.h>
#include <neopg/openpgp/signature/material/rsa_signature_material.h>

#include <neopg/openpgp/user_attribute/subpacket/image_attribute_subpacket.h>

#include <neopg/utils/stream.h>

#include <botan/data_snk.h>
#include <botan/data_src.h>
#include <botan/hex.h>

#include <botan/ber_dec.h>
#include <botan/oids.h>

#include <CLI11.hpp>

#include <spdlog/fmt/fmt.h>

#include <rang.hpp>

#include <tao/json.hpp>

#include <iostream>

using namespace NeoPG;

#define LINELEN 16

class HexDump::Formatter {
 public:
  size_t m_offset{0};
  std::ostream& m_out;

  void header(const PacketHeader* header, const std::string& comment);
  void comment(const std::string& comment);
  void hex(const std::vector<uint8_t>& raw);
  void hex(const std::vector<uint8_t>& raw, const std::string& comment);
  void hex(const std::string& raw);
  void hex(const std::string& raw, const std::string& comment);
  void hex(uint8_t val, const std::string& comment);
  void hex(uint8_t val);
  void hex(uint16_t val, const std::string& comment);
  void hex(uint32_t val, const std::string& comment);
  void hex(const MultiprecisionInteger& val, const std::string& comment);
  void hex(const ObjectIdentifier& val, const std::string& comment);
  void hex(const PublicKeyAlgorithm& val, const std::string& comment);
  // void hex(const SymmetricKeyAlgorithm& val, const std::string& comment);
  void hex(const HashAlgorithm& val, const std::string& comment);
  void hex(const SignatureSubpacket* subpacket);
  void hex(const V4SignatureSubpacketData* subpackets,
           const std::string& comment);
  Formatter(std::ostream& out, uint64_t offset = 0)
      : m_out{out}, m_offset{offset} {};
};

void HexDump::Formatter::header(const PacketHeader* header,
                                const std::string& name) {
  m_out << "\n";
  // FIXME: Generate default header if necessary.
  assert(header != nullptr);

  switch (header->format()) {
    case PacketFormat::Old: {
      auto hdr = dynamic_cast<const OldPacketHeader*>(header);
      assert(hdr != nullptr);
      auto length = hdr->length();

      std::stringstream hdr_raw;
      hdr->write(hdr_raw);
      hex(hdr_raw.str(),
          fmt::format("{:s} ({:d}, old, length {:d})", name,
                      static_cast<uint8_t>(hdr->type()), length));
    } break;
    case PacketFormat::New: {
      auto hdr = dynamic_cast<const NewPacketHeader*>(header);
      assert(hdr != nullptr);
      auto length = hdr->length();

      std::stringstream hdr_raw;
      hdr->write(hdr_raw);
      hex(hdr_raw.str(),
          fmt::format("{:s} ({:d}, new, length {:d})", name,
                      static_cast<uint8_t>(hdr->type()), length));
    } break;
    default:
      throw std::logic_error("unknown header type");
      // Unreachable.
  }
}

void HexDump::Formatter::comment(const std::string& comment) {
  m_out << std::string(8 + 2 + LINELEN * 3 + 2 + LINELEN, ' ') << "; "
        << comment << "\n";
}

void HexDump::Formatter::hex(const std::string& raw) { hex(raw, ""); }

static std::string _escaped(const uint8_t* in, size_t sz) {
  std::string result;
  for (size_t i = 0; i < sz; i++) {
    auto chr = (char)(in[i]);
    if (std::isgraph(chr))
      result.push_back(chr);
    else if (chr == ' ')
      result.append("␣");
    else
      result.append("⬚");
  }
  return result;
}

static void _line(std::ostream& out, size_t& offset, const std::string& raw,
                  size_t& idx, const std::string& comment) {
  auto left = raw.size() - idx;
  if (left >= LINELEN) left = LINELEN;

  auto data = reinterpret_cast<const uint8_t*>(raw.data() + idx);
  out << rang::fg::gray << fmt::format("{:08x}:", offset) << rang::style::reset;
  for (int i = 0; i < left; i++) out << fmt::format(" {:02x}", data[i]);
  out << std::string((LINELEN - left) * 3 + 2, ' ');
  out << rang::fg::gray << _escaped(data, left)
      << std::string(LINELEN - left, ' ') << rang::style::reset;

  if (comment != "") out << " ; " << comment;
  out << "\n";
  offset += left;
  idx += left;
}

void HexDump::Formatter::hex(const std::string& raw,
                             const std::string& comment) {
  auto left{raw.size()};
  size_t idx{0};

  _line(m_out, m_offset, raw, idx, comment);
  while (idx < raw.size()) {
    _line(m_out, m_offset, raw, idx, "");
  }
}

void HexDump::Formatter::hex(const std::vector<uint8_t>& raw) {
  std::string str(reinterpret_cast<const char*>(raw.data()), raw.size());
  hex(str);
}

void HexDump::Formatter::hex(const std::vector<uint8_t>& raw,
                             const std::string& comment) {
  std::string str(reinterpret_cast<const char*>(raw.data()), raw.size());
  hex(str, comment);
}

void HexDump::Formatter::hex(uint8_t val, const std::string& comment) {
  std::string str;
  str.push_back(val);
  hex(str, comment);
}

void HexDump::Formatter::hex(uint8_t val) {
  std::string str;
  str.push_back(val);
  hex(str, "");
}

void HexDump::Formatter::hex(uint16_t val, const std::string& comment) {
  std::string str;
  str.push_back(static_cast<uint8_t>(val >> 8));
  str.push_back(static_cast<uint8_t>(val));
  hex(str, comment);
}

void HexDump::Formatter::hex(uint32_t val, const std::string& comment) {
  std::string str;
  str.push_back(static_cast<uint8_t>(val >> 24));
  str.push_back(static_cast<uint8_t>(val >> 16));
  str.push_back(static_cast<uint8_t>(val >> 8));
  str.push_back(static_cast<uint8_t>(val));
  hex(str, comment);
}

void HexDump::Formatter::hex(const MultiprecisionInteger& val,
                             const std::string& comment) {
  hex(val.m_length, fmt::format("{:s} ({:d} bits)", comment, val.m_length));
  hex(val.m_bits);
}

void HexDump::Formatter::hex(const ObjectIdentifier& val,
                             const std::string& comment) {
  const std::string oidstr = val.as_string();
  Botan::OID oid(oidstr);
  hex(static_cast<uint8_t>(val.m_data.size()), comment);
  hex(val.m_data, fmt::format("{:s} = {:s}", oidstr, Botan::OIDS::lookup(oid)));
}

void HexDump::Formatter::hex(const PublicKeyAlgorithm& val,
                             const std::string& comment) {
  hex(static_cast<uint8_t>(val), comment);
}

// void HexDump::Formatter::hex(const SymmetricKeyAlgorithm& val,
//                              const std::string& comment) {
//   hex(static_cast<uint8_t>(val), comment);
// }

void HexDump::Formatter::hex(const HashAlgorithm& val,
                             const std::string& comment) {
  hex(static_cast<uint8_t>(val), comment);
}

void HexDump::Formatter::hex(const SignatureSubpacket* subpacket) {
  std::stringstream raw_stream;
  subpacket->write(raw_stream);
  auto raw = raw_stream.str();

  switch (subpacket->type()) {
    case SignatureSubpacketType::SignatureCreationTime: {
      auto sub = dynamic_cast<const SignatureCreationTimeSubpacket*>(subpacket);
      assert(sub != nullptr);
      hex(raw, fmt::format("- sig created {:d}", sub->m_created));
    } break;
    case SignatureSubpacketType::SignatureExpirationTime: {
      auto sub =
          dynamic_cast<const SignatureExpirationTimeSubpacket*>(subpacket);
      assert(sub != nullptr);
      if (sub->m_expiration)
        hex(raw, fmt::format("- sig expires after {:d}", sub->m_expiration));
      else
        hex(raw, "- sig does not expire");
    } break;
    case SignatureSubpacketType::ExportableCertification: {
      auto sub =
          dynamic_cast<const ExportableCertificationSubpacket*>(subpacket);
      assert(sub != nullptr);
      if (sub->m_exportable)
        hex(raw, "- exportable");
      else
        hex(raw, "- not exportable");
    } break;
    case SignatureSubpacketType::TrustSignature: {
      auto sub = dynamic_cast<const TrustSignatureSubpacket*>(subpacket);
      assert(sub != nullptr);
      hex(raw, fmt::format("- trust signature of depth {:d}, value {:d}",
                           sub->m_level, sub->m_amount));
    } break;
    case SignatureSubpacketType::RegularExpression: {
      auto sub = dynamic_cast<const RegularExpressionSubpacket*>(subpacket);
      assert(sub != nullptr);
      const tao::json::value str = sub->m_regex;
      hex(raw,
          fmt::format("- regular expression: {:s}", tao::json::to_string(str)));
    } break;
    case SignatureSubpacketType::Revocable: {
      auto sub = dynamic_cast<const RevocableSubpacket*>(subpacket);
      assert(sub != nullptr);
      if (sub->m_revocable)
        hex(raw, "- revocable");
      else
        hex(raw, "- not revocable");
    } break;
    case SignatureSubpacketType::KeyExpirationTime: {
      auto sub = dynamic_cast<const KeyExpirationTimeSubpacket*>(subpacket);
      assert(sub != nullptr);
      if (sub->m_expiration) {
        int seconds = sub->m_expiration;
        int minutes = seconds / 60;
        int hours = minutes / 60;
        int days = hours / 24;
        int years = days / 365;
        hex(raw, fmt::format("- key expires after {:d}y {:d}d {:d}h {:d}m",
                             years, days % 365, hours % 24, minutes % 60));
      } else
        hex(raw, "- key does not expire");
    } break;
    case SignatureSubpacketType::PreferredSymmetricAlgorithms: {
      auto sub =
          dynamic_cast<const PreferredSymmetricAlgorithmsSubpacket*>(subpacket);
      assert(sub != nullptr);
      std::string msg("- pref-sym-algos:");
      for (auto& algorithm : sub->m_algorithms)
        msg.append(fmt::format(" {:d}", algorithm));
      hex(raw, msg);
    } break;
    case SignatureSubpacketType::RevocationKey: {
      auto sub = dynamic_cast<const RevocationKeySubpacket*>(subpacket);
      assert(sub != nullptr);
      hex(raw, fmt::format("- revocation key: c={:02x} a={:d} f={:s}",
                           static_cast<int>(sub->m_class),
                           static_cast<int>(sub->m_algorithm),
                           Botan::hex_encode(sub->m_fingerprint.data(),
                                             sub->m_fingerprint.size())));

    } break;
    case SignatureSubpacketType::Issuer: {
      auto sub = dynamic_cast<const IssuerSubpacket*>(subpacket);
      assert(sub != nullptr);
      hex(raw, fmt::format("- issuer key ID {:s}",
                           Botan::hex_encode(sub->m_issuer.data(),
                                             sub->m_issuer.size())));
    } break;
    case SignatureSubpacketType::NotationData: {
      auto sub = dynamic_cast<const NotationDataSubpacket*>(subpacket);
      assert(sub != nullptr);
      // FIXME: Avoid copy?
      const tao::json::value name =
          std::string{reinterpret_cast<const char*>(sub->m_name.data()),
                      sub->m_name.size()};
      const tao::json::value value =
          std::string{reinterpret_cast<const char*>(sub->m_value.data()),
                      sub->m_value.size()};
      hex(raw,
          fmt::format("- notation: {:s} = {:s}", tao::json::to_string(name),
                      tao::json::to_string(value)));
    } break;
    case SignatureSubpacketType::PreferredHashAlgorithms: {
      auto sub =
          dynamic_cast<const PreferredHashAlgorithmsSubpacket*>(subpacket);
      assert(sub != nullptr);
      std::string msg = "- pref-hash-algos:";
      for (auto& algorithm : sub->m_algorithms)
        msg.append(fmt::format(" {:d}", (int)algorithm));
    } break;
    case SignatureSubpacketType::PreferredCompressionAlgorithms: {
      auto sub = dynamic_cast<const PreferredCompressionAlgorithmsSubpacket*>(
          subpacket);
      assert(sub != nullptr);
      std::string msg = "- pref-zip-algos:";
      for (auto& algorithm : sub->m_algorithms)
        msg.append(fmt::format("{:d}", algorithm));
    } break;
    case SignatureSubpacketType::KeyServerPreferences: {
      auto sub = dynamic_cast<const KeyServerPreferencesSubpacket*>(subpacket);
      assert(sub != nullptr);
      hex(raw, fmt::format("- keyserver preferences: {:s}",
                           Botan::hex_encode(sub->m_flags.data(),
                                             sub->m_flags.size())));
    } break;
    case SignatureSubpacketType::PreferredKeyServer: {
      auto sub = dynamic_cast<const PreferredKeyServerSubpacket*>(subpacket);
      assert(sub != nullptr);
      const tao::json::value str = sub->m_uri;
      hex(raw, fmt::format("- preferred keyserver: {:s}",
                           tao::json::to_string(str)));
    } break;
    case SignatureSubpacketType::PrimaryUserId: {
      auto sub = dynamic_cast<const PrimaryUserIdSubpacket*>(subpacket);
      assert(sub != nullptr);
      hex(raw, fmt::format("- primary user ID: {:02x}",
                           static_cast<int>(sub->m_primary)));
    } break;
    case SignatureSubpacketType::PolicyUri: {
      auto sub = dynamic_cast<const PolicyUriSubpacket*>(subpacket);
      assert(sub != nullptr);
      const tao::json::value str = sub->m_uri;
      hex(raw, fmt::format("- policy: {:s}", tao::json::to_string(str)));
    } break;
    case SignatureSubpacketType::KeyFlags: {
      auto sub = dynamic_cast<const KeyFlagsSubpacket*>(subpacket);
      assert(sub != nullptr);
      hex(raw, fmt::format("- key flags: {:s}",
                           Botan::hex_encode(sub->m_flags.data(),
                                             sub->m_flags.size())));

    } break;
    case SignatureSubpacketType::SignersUserId: {
      auto sub = dynamic_cast<const SignersUserIdSubpacket*>(subpacket);
      assert(sub != nullptr);
      const tao::json::value str = sub->m_user_id;
      hex(raw,
          fmt::format("- signer's user ID: {:s}", tao::json::to_string(str)));
    } break;
    case SignatureSubpacketType::ReasonForRevocation: {
      auto sub = dynamic_cast<const ReasonForRevocationSubpacket*>(subpacket);
      assert(sub != nullptr);
      const tao::json::value str = sub->m_reason;
      hex(raw, fmt::format("- revocation reason 0x{:02x} {:s}",
                           static_cast<int>(sub->m_code),
                           tao::json::to_string(str)));
    } break;
    case SignatureSubpacketType::Features: {
      auto sub = dynamic_cast<const FeaturesSubpacket*>(subpacket);
      assert(sub != nullptr);
      hex(raw, fmt::format("- features: {:s}",
                           Botan::hex_encode(sub->m_features.data(),
                                             sub->m_features.size())));

    } break;
    case SignatureSubpacketType::SignatureTarget: {
      auto sub = dynamic_cast<const SignatureTargetSubpacket*>(subpacket);
      assert(sub != nullptr);
      hex(raw, fmt::format(
                   "- signature target: pubkey_algo {:d}, digest algo "
                   "{:d}), digest ",
                   static_cast<uint8_t>(sub->m_public_key_algorithm),
                   static_cast<uint8_t>(sub->m_hash_algorithm),
                   Botan::hex_encode(sub->m_hash.data(), sub->m_hash.size())));

    } break;
    case SignatureSubpacketType::EmbeddedSignature: {
      auto sub = dynamic_cast<const EmbeddedSignatureSubpacket*>(subpacket);
      assert(sub != nullptr);
      ParserInput in(sub->m_signature.data(), sub->m_signature.size());
      auto sig = SignaturePacket::create(in);

      if (sig == nullptr || !sig->m_signature)
        hex(raw, "- signature: invalid");
      else {
        switch (sig->m_signature->version()) {
          case SignatureVersion::V2:
          case SignatureVersion::V3: {
            auto v3sig =
                dynamic_cast<const V3SignatureData*>(sig->m_signature.get());
            assert(v3sig != nullptr);
            hex(raw,
                fmt::format("- signature: v{:d}, class 0x{:02x}, algo {:d}, "
                            "digest algo {:d}",
                            static_cast<uint8_t>(v3sig->version()),
                            static_cast<uint8_t>(v3sig->signature_type()),
                            static_cast<uint8_t>(v3sig->public_key_algorithm()),
                            static_cast<uint8_t>(v3sig->hash_algorithm())));
            break;
          }
          case SignatureVersion::V4: {
            auto v4sig =
                dynamic_cast<const V4SignatureData*>(sig->m_signature.get());
            assert(v4sig != nullptr);
            hex(raw,
                fmt::format("- signature: v{:d}, class 0x{:02x}, algo {:d}, "
                            "digest algo {:d}",
                            static_cast<uint8_t>(v4sig->version()),
                            static_cast<uint8_t>(v4sig->signature_type()),
                            static_cast<uint8_t>(v4sig->public_key_algorithm()),
                            static_cast<uint8_t>(v4sig->hash_algorithm())));
            break;
          }
          default:
            hex(raw, fmt::format("- signature: v{:d}",
                                 static_cast<uint8_t>(sig->version())));
            break;
        }
      }
      break;
    }
    default:
      hex(raw,
          fmt::format("- raw ({:d})", static_cast<uint8_t>(subpacket->type())));
      break;
  }
}

void HexDump::Formatter::hex(const V4SignatureSubpacketData* subpackets,
                             const std::string& comment) {
  CountingStream cnt;
  subpackets->write(cnt);
  auto bytes = cnt.bytes_written();
  hex(static_cast<uint16_t>(bytes), comment);

  for (const auto& subpacket : subpackets->m_subpackets) {
    hex(subpacket.get());
  }
}

// Output helpers
static void output_public_key_data(HexDump::Formatter* fmt,
                                   const PublicKeyData* pub) {
  auto keyid = pub->keyid();
  fmt->hex(
      static_cast<uint8_t>(pub->version()),
      fmt::format("version {:d}, key id {:s}", static_cast<int>(pub->version()),
                  Botan::hex_encode(keyid.data(), keyid.size())));
  PublicKeyMaterial* key = nullptr;
  switch (pub->version()) {
    case PublicKeyVersion::V2:
    case PublicKeyVersion::V3: {
      auto v3pub = dynamic_cast<const V3PublicKeyData*>(pub);
      fmt->hex(v3pub->m_created, "creation time");
      fmt->hex(v3pub->m_days_valid,
               fmt::format("days valid ({:s})",
                           v3pub->m_days_valid
                               ? fmt::format("{:d}d", v3pub->m_days_valid)
                               : "forever"));
      fmt->hex(v3pub->m_algorithm, "public key algorithm");
      key = v3pub->m_key.get();
    } break;
    case PublicKeyVersion::V4: {
      auto v4pub = dynamic_cast<const V4PublicKeyData*>(pub);
      fmt->hex(v4pub->m_created, "creation time");
      fmt->hex(v4pub->m_algorithm, "public key algorithm");
      key = v4pub->m_key.get();
    } break;
    default:
      throw std::logic_error("unknown public key version");
      // Unreachable.
  }
  if (key) {
    switch (key->algorithm()) {
      case PublicKeyAlgorithm::Rsa: {
        auto rsa = dynamic_cast<const RsaPublicKeyMaterial*>(key);
        fmt->hex(rsa->m_n, "rsa n");
        fmt->hex(rsa->m_e, "rsa e");
      } break;
      case PublicKeyAlgorithm::Dsa: {
        auto dsa = dynamic_cast<const DsaPublicKeyMaterial*>(key);
        fmt->hex(dsa->m_p, "dsa p");
        fmt->hex(dsa->m_q, "dsa q");
        fmt->hex(dsa->m_g, "dsa g");
        fmt->hex(dsa->m_y, "dsa y");
      } break;
      case PublicKeyAlgorithm::Elgamal: {
        auto elgamal = dynamic_cast<const ElgamalPublicKeyMaterial*>(key);
        fmt->hex(elgamal->m_p, "elgamal p");
        fmt->hex(elgamal->m_g, "elgamal g");
        fmt->hex(elgamal->m_y, "elgamal y");
      } break;
      case PublicKeyAlgorithm::Ecdsa: {
        auto ecdsa = dynamic_cast<const EcdsaPublicKeyMaterial*>(key);
        const std::string oidstr = ecdsa->m_curve.as_string();
        Botan::OID oid(oidstr);
        fmt->hex(ecdsa->m_curve, "ecdsa curve");
        fmt->hex(ecdsa->m_key, "ecdsa key");
      } break;
      case PublicKeyAlgorithm::Ecdh: {
        auto ecdh = dynamic_cast<const EcdhPublicKeyMaterial*>(key);
        const std::string oidstr = ecdh->m_curve.as_string();
        Botan::OID oid(oidstr);
        fmt->hex(ecdh->m_curve, "ecdh curve");
        fmt->hex(ecdh->m_key, "ecdh key");
        std::string hdr;
        hdr.push_back(0x03);
        hdr.push_back(0x01);
        fmt->hex(hdr);
        fmt->hex(ecdh->m_hash, "ecdh hash algorithm");
        fmt->hex(ecdh->m_sym, "ecdh symmetric key algorithm");
      } break;
      case PublicKeyAlgorithm::Eddsa: {
        auto eddsa = dynamic_cast<const EddsaPublicKeyMaterial*>(key);
        const std::string oidstr = eddsa->m_curve.as_string();
        Botan::OID oid(oidstr);
        fmt->hex(eddsa->m_curve, "curve");
        fmt->hex(eddsa->m_key, "key");
      } break;
      default:
        auto raw = dynamic_cast<const RawPublicKeyMaterial*>(key);
        assert(raw != nullptr);
        fmt->hex(raw->m_content, "raw");
    }
  }
}

static void output_signature_data(HexDump::Formatter* fmt,
                                  const SignatureData* sig) {
  const SignatureMaterial* sigmat = nullptr;
  fmt->hex(static_cast<uint8_t>(sig->version()),
           fmt::format("version {:d}", static_cast<int>(sig->version())));

  switch (sig->version()) {
    case SignatureVersion::V2:
    case SignatureVersion::V3: {
      auto v3sig = dynamic_cast<const V3SignatureData*>(sig);
      assert(v3sig != nullptr);
      fmt->hex(0x05);
      fmt->hex(
          static_cast<uint8_t>(v3sig->signature_type()),
          fmt::format("type {:d}", static_cast<int>(v3sig->signature_type())));
      fmt->hex(v3sig->m_created, "creation time");
      fmt->hex(
          std::vector<uint8_t>(v3sig->m_signer.begin(), v3sig->m_signer.end()),
          "signer's key id");
      fmt->hex(v3sig->m_public_key_algorithm, "public key algorithm");
      fmt->hex(v3sig->m_hash_algorithm, "hash algorithm");
      fmt->hex(
          std::vector<uint8_t>(v3sig->m_quick.begin(), v3sig->m_quick.end()),
          "quick check");
      sigmat = v3sig->m_signature.get();
    } break;
    case SignatureVersion::V4: {
      auto v4sig = dynamic_cast<const V4SignatureData*>(sig);
      assert(v4sig != nullptr);

      fmt->hex(
          static_cast<uint8_t>(v4sig->signature_type()),
          fmt::format("type {:d}", static_cast<int>(v4sig->signature_type())));
      fmt->hex(v4sig->m_public_key_algorithm, "public key algorithm");
      fmt->hex(v4sig->m_hash_algorithm, "hash algorithm");
      fmt->hex(v4sig->m_hashed_subpackets.get(), "hashed subpackets");
      fmt->hex(v4sig->m_unhashed_subpackets.get(), "unhashed subpackets");
      fmt->hex(
          std::vector<uint8_t>(v4sig->m_quick.begin(), v4sig->m_quick.end()),
          "quick check");
      sigmat = v4sig->m_signature.get();
    } break;
    default:
      std::logic_error("unknown signature version");
      // Not reached.
      break;
  }
  if (sigmat) {
    switch (sigmat->algorithm()) {
      case PublicKeyAlgorithm::Rsa: {
        auto rsa = dynamic_cast<const RsaSignatureMaterial*>(sigmat);
        fmt->hex(rsa->m_m_pow_d, "rsa m^d");
      } break;
      case PublicKeyAlgorithm::Dsa: {
        auto dsa = dynamic_cast<const DsaSignatureMaterial*>(sigmat);
        fmt->hex(dsa->m_r, "dsa r");
        fmt->hex(dsa->m_s, "dsa s");
      } break;
      case PublicKeyAlgorithm::Ecdsa: {
        auto ecdsa = dynamic_cast<const EcdsaSignatureMaterial*>(sigmat);
        fmt->hex(ecdsa->m_r, "ecdsa r");
        fmt->hex(ecdsa->m_s, "ecdsa s");
      } break;
      case PublicKeyAlgorithm::Eddsa: {
        auto eddsa = dynamic_cast<const EddsaSignatureMaterial*>(sigmat);
        fmt->hex(eddsa->m_r, "eddsa r");
        fmt->hex(eddsa->m_s, "eddsa s");
      } break;
      default:
        std::logic_error("x");
        // Never reached.
        return;
    }
  }
}

namespace NeoPG {
// https://herbsutter.com/gotw/_102/
template <typename T, typename... Args>
std::unique_ptr<T> make_unique(Args&&... args) {
  return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}
}  // namespace NeoPG

HexDump::~HexDump() = default;

HexDump::HexDump(std::ostream& out) : DumpPacketSink(out) {}

void HexDump::dump(const Packet* packet) const {
  std::stringstream str;

  m_fmt = NeoPG::make_unique<Formatter>(str, packet->m_header->m_offset);
  DumpPacketSink::dump(packet);
  m_fmt.reset();

  m_out << str.str();
}

void HexDump::dump(const MarkerPacket* packet) const {
  m_fmt->header(packet->m_header.get(), "marker");
  m_fmt->hex("PGP");
}

void HexDump::dump(const UserIdPacket* uid) const {
  m_fmt->header(uid->m_header.get(), "user id");
  const tao::json::value str = uid->m_content;
  m_fmt->hex(uid->m_content, tao::json::to_string(str));
}

void HexDump::dump(const UserAttributePacket* attr) const {}

void HexDump::dump(const PublicKeyPacket* pubkey) const {
  m_fmt->header(pubkey->m_header.get(), "public key");
  auto pub = dynamic_cast<const PublicKeyData*>(pubkey->m_public_key.get());
  assert(pub != nullptr);
  output_public_key_data(m_fmt.get(), pub);
}

void HexDump::dump(const PublicSubkeyPacket* pubkey) const {
  m_fmt->header(pubkey->m_header.get(), "public sub key");
  auto pub = dynamic_cast<const PublicKeyData*>(pubkey->m_public_key.get());
  assert(pub != nullptr);
  output_public_key_data(m_fmt.get(), pub);
}

void HexDump::dump(const SignaturePacket* signature) const {
  m_fmt->header(signature->m_header.get(), "signature");
  auto sig = dynamic_cast<const SignatureData*>(signature->m_signature.get());
  assert(sig);
  output_signature_data(m_fmt.get(), sig);
}
