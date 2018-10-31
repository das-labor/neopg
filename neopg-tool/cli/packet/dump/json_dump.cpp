// json dump format (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg-tool/cli/packet/dump/json_dump.h>

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

static tao::json::value make_header(const PacketHeader* header) {
  if (header == nullptr) return tao::json::empty_object;

  switch (header->format()) {
    case PacketFormat::Old: {
      auto hdr = dynamic_cast<const OldPacketHeader*>(header);
      assert(hdr != nullptr);
      auto length = hdr->length();

      tao::json::value packet_header(
          {{"format", "old"},
           {"type", static_cast<uint8_t>(hdr->type())},
           {"length", length},
           {"_offset", hdr->m_offset}});
      if (hdr->m_length_type != OldPacketHeader::best_length_type(length))
        // FIXME: replace static cast
        packet_header.insert(
            {{"length_type", static_cast<uint8_t>(hdr->m_length_type)}});
      return {{"_packet_header", packet_header}};
    }
    case PacketFormat::New: {
      auto hdr = dynamic_cast<const NewPacketHeader*>(header);
      assert(hdr != nullptr);
      auto length = hdr->length();

      tao::json::value packet_header(
          {{"format", "new"},
           {"type", static_cast<uint8_t>(hdr->type())},
           {"length", length},
           {"_offset", hdr->m_offset}});
      if (hdr->m_length.m_length_type !=
          NewPacketLength::best_length_type(length))
        // FIXME: replace static cast
        packet_header.insert(
            {{"length_type",
              static_cast<uint8_t>(hdr->m_length.m_length_type)}});
      return {{"_packet_header", packet_header}};
    }
    default:
      throw std::logic_error("unknown header type");
      // Unreachable.
      return tao::json::null;
  }
}

static void output_public_key_data(std::ostream& out,
                                   const PublicKeyData* pub) {
  PublicKeyMaterial* key = nullptr;
  switch (pub->version()) {
    case PublicKeyVersion::V2:
    case PublicKeyVersion::V3: {
      auto v3pub = dynamic_cast<const V3PublicKeyData*>(pub);
      out << "\tversion " << static_cast<int>(pub->version()) << ", algo "
          << static_cast<int>(v3pub->m_algorithm) << ", created "
          << v3pub->m_created << ", expires " << v3pub->m_days_valid << "\n";
      key = v3pub->m_key.get();
    } break;
    case PublicKeyVersion::V4: {
      auto v4pub = dynamic_cast<const V4PublicKeyData*>(pub);
      out << "\tversion " << static_cast<int>(pub->version()) << ", algo "
          << static_cast<int>(v4pub->m_algorithm) << ", created "
          << v4pub->m_created << ", expires 0"
          << "\n";
      key = v4pub->m_key.get();
    } break;
    default:
      out << "\tversion " << static_cast<int>(pub->version()) << "\n";
      break;
  }
  if (key) {
    switch (key->algorithm()) {
      case PublicKeyAlgorithm::Rsa: {
        auto rsa = dynamic_cast<const RsaPublicKeyMaterial*>(key);
        out << "\tpkey[0]: [" << rsa->m_n.length() << " bits]\n";
        out << "\tpkey[1]: [" << rsa->m_e.length() << " bits]\n";
      } break;
      case PublicKeyAlgorithm::Dsa: {
        auto dsa = dynamic_cast<const DsaPublicKeyMaterial*>(key);
        out << "\tpkey[0]: [" << dsa->m_p.length() << " bits]\n";
        out << "\tpkey[1]: [" << dsa->m_q.length() << " bits]\n";
        out << "\tpkey[2]: [" << dsa->m_g.length() << " bits]\n";
        out << "\tpkey[3]: [" << dsa->m_y.length() << " bits]\n";
      } break;
      case PublicKeyAlgorithm::Elgamal: {
        auto elgamal = dynamic_cast<const ElgamalPublicKeyMaterial*>(key);
        out << "\tpkey[0]: [" << elgamal->m_p.length() << " bits]\n";
        out << "\tpkey[1]: [" << elgamal->m_g.length() << " bits]\n";
        out << "\tpkey[2]: [" << elgamal->m_y.length() << " bits]\n";
      } break;
      case PublicKeyAlgorithm::Ecdsa: {
        auto ecdsa = dynamic_cast<const EcdsaPublicKeyMaterial*>(key);
        const std::string oidstr = ecdsa->m_curve.as_string();
        Botan::OID oid(oidstr);
        out << "\tpkey[0]: [" << (1 + ecdsa->m_curve.length()) * 8 << " bits] "
            << Botan::OIDS::lookup(oid) << " (" << oidstr << ")\n";
        out << "\tpkey[1]: [" << ecdsa->m_key.length() << " bits]\n";
      } break;
      case PublicKeyAlgorithm::Eddsa: {
        auto eddsa = dynamic_cast<const EddsaPublicKeyMaterial*>(key);
        const std::string oidstr = eddsa->m_curve.as_string();
        Botan::OID oid(oidstr);
        out << "\tpkey[0]: [" << (1 + eddsa->m_curve.length()) * 8 << " bits] "
            << Botan::OIDS::lookup(oid) << " (" << oidstr << ")\n";
        out << "\tpkey[1]: [" << eddsa->m_key.length() << " bits]\n";
      } break;
      default:
        out << "\tunknown algorithm " << static_cast<int>(key->algorithm())
            << "\n";
        break;
    }
    auto keyid = pub->keyid();
    out << "\tkeyid: " << Botan::hex_encode(keyid.data(), keyid.size()) << "\n";
  }
}

static void output_signature_subpacket(std::ostream& out,
                                       const std::string& variant,
                                       SignatureSubpacket* subpacket) {
  out << "\t" << (subpacket->m_critical ? "critical " : "") << variant << " "
      << static_cast<int>(subpacket->type()) << " len "
      << subpacket->body_length();
  switch (subpacket->type()) {
    case SignatureSubpacketType::SignatureCreationTime: {
      auto sub = dynamic_cast<const SignatureCreationTimeSubpacket*>(subpacket);
      assert(sub != nullptr);
      out << " (sig created " << sub->m_created << ")";
      break;
    }
    case SignatureSubpacketType::SignatureExpirationTime: {
      auto sub =
          dynamic_cast<const SignatureExpirationTimeSubpacket*>(subpacket);
      assert(sub != nullptr);
      if (sub->m_expiration)
        out << " (sig expires after " << sub->m_expiration << ")";
      else
        out << " (sig does not expire)";
      break;
    }
    case SignatureSubpacketType::ExportableCertification: {
      auto sub =
          dynamic_cast<const ExportableCertificationSubpacket*>(subpacket);
      assert(sub != nullptr);
      if (sub->m_exportable)
        out << " (exportable)";
      else
        out << " (not exportable)";
      break;
    }
    case SignatureSubpacketType::TrustSignature: {
      auto sub = dynamic_cast<const TrustSignatureSubpacket*>(subpacket);
      assert(sub != nullptr);
      out << " (trust signature of depth " << (int)sub->m_level << ", value "
          << (int)sub->m_amount << ")";
      break;
    }
    case SignatureSubpacketType::RegularExpression: {
      auto sub = dynamic_cast<const RegularExpressionSubpacket*>(subpacket);
      assert(sub != nullptr);
      const tao::json::value str = sub->m_regex;
      out << " (regular expression: " << str << ")";
      break;
    }
    case SignatureSubpacketType::Revocable: {
      auto sub = dynamic_cast<const RevocableSubpacket*>(subpacket);
      assert(sub != nullptr);
      if (sub->m_revocable)
        out << " (revocable)";
      else
        out << " (not revocable)";
      break;
    }
    case SignatureSubpacketType::KeyExpirationTime: {
      auto sub = dynamic_cast<const KeyExpirationTimeSubpacket*>(subpacket);
      assert(sub != nullptr);
      if (sub->m_expiration) {
        int seconds = sub->m_expiration;
        int minutes = seconds / 60;
        int hours = minutes / 60;
        int days = hours / 24;
        int years = days / 365;
        out << " (key expires after " << years << "y" << (days % 365) << "d"
            << (hours % 24) << "h" << (minutes % 60) << "m)";
      } else
        out << " (key does not expire)";
      break;
    }
    case SignatureSubpacketType::PreferredSymmetricAlgorithms: {
      auto sub =
          dynamic_cast<const PreferredSymmetricAlgorithmsSubpacket*>(subpacket);
      assert(sub != nullptr);
      out << " (pref-sym-algos:";
      for (auto& algorithm : sub->m_algorithms) out << " " << (int)algorithm;
      out << ")";
      break;
    }
    case SignatureSubpacketType::RevocationKey: {
      auto sub = dynamic_cast<const RevocationKeySubpacket*>(subpacket);
      assert(sub != nullptr);
      out << " (revocation key: c="
          << fmt::format("{:02x}", static_cast<int>(sub->m_class))
          << " a=" << static_cast<int>(sub->m_algorithm) << " f="
          << Botan::hex_encode(sub->m_fingerprint.data(),
                               sub->m_fingerprint.size())
          << ")";
      break;
    }
    case SignatureSubpacketType::Issuer: {
      auto sub = dynamic_cast<const IssuerSubpacket*>(subpacket);
      assert(sub != nullptr);
      out << " (issuer key ID "
          << Botan::hex_encode(sub->m_issuer.data(), sub->m_issuer.size())
          << ")";
      break;
    }
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
      out << " (notation: " << name << " = " << value << ")";
      break;
    }
    case SignatureSubpacketType::PreferredHashAlgorithms: {
      auto sub =
          dynamic_cast<const PreferredHashAlgorithmsSubpacket*>(subpacket);
      assert(sub != nullptr);
      out << " (pref-hash-algos:";
      for (auto& algorithm : sub->m_algorithms) out << " " << (int)algorithm;
      out << ")";
      break;
    }
    case SignatureSubpacketType::PreferredCompressionAlgorithms: {
      auto sub = dynamic_cast<const PreferredCompressionAlgorithmsSubpacket*>(
          subpacket);
      assert(sub != nullptr);
      out << " (pref-zip-algos:";
      for (auto& algorithm : sub->m_algorithms) out << " " << (int)algorithm;
      out << ")";
      break;
    }
    case SignatureSubpacketType::KeyServerPreferences: {
      auto sub = dynamic_cast<const KeyServerPreferencesSubpacket*>(subpacket);
      assert(sub != nullptr);
      out << " (keyserver preferences: "
          << Botan::hex_encode(sub->m_flags.data(), sub->m_flags.size()) << ")";
      break;
    }
    case SignatureSubpacketType::PreferredKeyServer: {
      auto sub = dynamic_cast<const PreferredKeyServerSubpacket*>(subpacket);
      assert(sub != nullptr);
      const tao::json::value str = sub->m_uri;
      out << " (preferred keyserver: " << str << ")";
      break;
    }
    case SignatureSubpacketType::PrimaryUserId: {
      auto sub = dynamic_cast<const PrimaryUserIdSubpacket*>(subpacket);
      assert(sub != nullptr);
      out << " (primary user ID: "
          << fmt::format("{:02x}", static_cast<int>(sub->m_primary)) << ")";
      break;
    }
    case SignatureSubpacketType::PolicyUri: {
      auto sub = dynamic_cast<const PolicyUriSubpacket*>(subpacket);
      assert(sub != nullptr);
      const tao::json::value str = sub->m_uri;
      out << " (policy: " << str << ")";
      break;
    }
    case SignatureSubpacketType::KeyFlags: {
      auto sub = dynamic_cast<const KeyFlagsSubpacket*>(subpacket);
      assert(sub != nullptr);
      out << " (key flags: "
          << Botan::hex_encode(sub->m_flags.data(), sub->m_flags.size()) << ")";
      break;
    }
    case SignatureSubpacketType::SignersUserId: {
      auto sub = dynamic_cast<const SignersUserIdSubpacket*>(subpacket);
      assert(sub != nullptr);
      const tao::json::value str = sub->m_user_id;
      out << " (signer's user ID: " << str << ")";
      break;
    }
    case SignatureSubpacketType::ReasonForRevocation: {
      auto sub = dynamic_cast<const ReasonForRevocationSubpacket*>(subpacket);
      assert(sub != nullptr);
      const tao::json::value str = sub->m_reason;
      out << " (revocation reason 0x"
          << fmt::format("{:02x}", static_cast<int>(sub->m_code)) << " " << str
          << ")";
      break;
    }
    case SignatureSubpacketType::Features: {
      auto sub = dynamic_cast<const FeaturesSubpacket*>(subpacket);
      assert(sub != nullptr);
      out << " (features: "
          << Botan::hex_encode(sub->m_features.data(), sub->m_features.size())
          << ")";
      break;
    }
    case SignatureSubpacketType::SignatureTarget: {
      auto sub = dynamic_cast<const SignatureTargetSubpacket*>(subpacket);
      assert(sub != nullptr);
      out << fmt::format(
                 " (signature target: pubkey_algo {:d}, digest algo "
                 "{:d}), digest ",
                 static_cast<uint8_t>(sub->m_public_key_algorithm),
                 static_cast<uint8_t>(sub->m_hash_algorithm))
          << Botan::hex_encode(sub->m_hash.data(), sub->m_hash.size()) << ")";
      break;
    }
    case SignatureSubpacketType::EmbeddedSignature: {
      auto sub = dynamic_cast<const EmbeddedSignatureSubpacket*>(subpacket);
      assert(sub != nullptr);
      ParserInput in(sub->m_signature.data(), sub->m_signature.size());
      auto sig = SignaturePacket::create(in);

      if (sig == nullptr || !sig->m_signature)
        out << " (signature: invalid)";
      else {
        switch (sig->m_signature->version()) {
          case SignatureVersion::V2:
          case SignatureVersion::V3: {
            auto v3sig =
                dynamic_cast<const V3SignatureData*>(sig->m_signature.get());
            assert(v3sig != nullptr);
            out << fmt::format(
                " (signature: v{:d}, class 0x{:02x}, algo {:d}, digest algo "
                "{:d})",
                static_cast<uint8_t>(v3sig->version()),
                static_cast<uint8_t>(v3sig->signature_type()),
                static_cast<uint8_t>(v3sig->public_key_algorithm()),
                static_cast<uint8_t>(v3sig->hash_algorithm()));
            break;
          }
          case SignatureVersion::V4: {
            auto v4sig =
                dynamic_cast<const V4SignatureData*>(sig->m_signature.get());
            assert(v4sig != nullptr);
            out << fmt::format(
                " (signature: v{:d}, class 0x{:02x}, algo {:d}, digest algo "
                "{:d})",
                static_cast<uint8_t>(v4sig->version()),
                static_cast<uint8_t>(v4sig->signature_type()),
                static_cast<uint8_t>(v4sig->public_key_algorithm()),
                static_cast<uint8_t>(v4sig->hash_algorithm()));
            break;
          }
          default:
            out << fmt::format(" (signature: v{:d})",
                               static_cast<uint8_t>(sig->version()));
            break;
        }
      }
      break;
    }
    default:
      break;
  }
  out << "\n";
}

static void output_signature_data(std::ostream& out, const SignatureData* sig) {
  const SignatureMaterial* sigmat = nullptr;
  switch (sig->version()) {
    case SignatureVersion::V2:
    case SignatureVersion::V3: {
      auto v3sig = dynamic_cast<const V3SignatureData*>(sig);
      assert(v3sig != nullptr);
      out << ":signature packet: algo "
          << static_cast<int>(v3sig->public_key_algorithm()) << "\n";
      out << "\tversion 3, created " << v3sig->m_created
          << ", md5len 5, sigclass 0x"
          << fmt::format("{:02x}", static_cast<int>(v3sig->signature_type()))
          << "\n";
      out << "\tdigest algo " << static_cast<int>(v3sig->hash_algorithm())
          << ", begin of digest "
          << fmt::format("{:02x}", static_cast<int>(v3sig->m_quick.data()[0]))
          << " "
          << fmt::format("{:02x}", static_cast<int>(v3sig->m_quick.data()[1]))
          << "\n";
      sigmat = v3sig->m_signature.get();
    } break;
    case SignatureVersion::V4: {
      auto v4sig = dynamic_cast<const V4SignatureData*>(sig);
      assert(v4sig != nullptr);
      // FIXME: Try to get created from subpackets.
      out << ":signature packet: algo "
          << static_cast<int>(v4sig->public_key_algorithm()) << "\n";
      out << "\tversion 4, created " << v4sig->m_created
          << ", md5len 0, sigclass 0x"
          << fmt::format("{:02x}", static_cast<int>(v4sig->signature_type()))
          << "\n";
      out << "\tdigest algo " << static_cast<int>(v4sig->hash_algorithm())
          << ", begin of digest "
          << fmt::format("{:02x}", static_cast<int>(v4sig->m_quick.data()[0]))
          << " "
          << fmt::format("{:02x}", static_cast<int>(v4sig->m_quick.data()[1]))
          << "\n";
      for (auto& subpacket : v4sig->m_hashed_subpackets->m_subpackets) {
        output_signature_subpacket(out, "hashed subpkt", subpacket.get());
      }
      for (auto& subpacket : v4sig->m_unhashed_subpackets->m_subpackets) {
        output_signature_subpacket(out, "subpkt", subpacket.get());
      }
      sigmat = v4sig->m_signature.get();
    } break;
    default:
      break;
  }
  if (sigmat) {
    switch (sigmat->algorithm()) {
      case PublicKeyAlgorithm::Rsa: {
        auto rsa = dynamic_cast<const RsaSignatureMaterial*>(sigmat);
        out << "\tdata: [" << rsa->m_m_pow_d.length() << " bits]\n";
      } break;
      case PublicKeyAlgorithm::Dsa: {
        auto dsa = dynamic_cast<const DsaSignatureMaterial*>(sigmat);
        out << "\tdata: [" << dsa->m_r.length() << " bits]\n";
        out << "\tdata: [" << dsa->m_s.length() << " bits]\n";
      } break;
      case PublicKeyAlgorithm::Ecdsa: {
        auto ecdsa = dynamic_cast<const EcdsaSignatureMaterial*>(sigmat);
        out << "\tdata: [" << ecdsa->m_r.length() << " bits]\n";
        out << "\tdata: [" << ecdsa->m_s.length() << " bits]\n";
      } break;
      case PublicKeyAlgorithm::Eddsa: {
        auto eddsa = dynamic_cast<const EddsaSignatureMaterial*>(sigmat);
        out << "\tdata: [" << eddsa->m_r.length() << " bits]\n";
        out << "\tdata: [" << eddsa->m_s.length() << " bits]\n";
      } break;
      default:
        out << "\tunknown algorithm " << static_cast<int>(sigmat->algorithm())
            << "\n";
        break;
    }
  }
}

void JsonDump::dump(const Packet* packet) const {
  DumpPacketSink::dump(packet);
  m_out << "\n";
}

void JsonDump::dump(const MarkerPacket* packet) const {
  auto val = make_header(packet->m_header.get());
  val.insert({{"_packet", "Marker"}});
  m_out << val;
}

void JsonDump::dump(const UserIdPacket* uid) const {
  auto val = make_header(uid->m_header.get());
  val.insert({{"_packet", "UserId"}, {"content", uid->m_content}});
  m_out << val;
}

void JsonDump::dump(const UserAttributePacket* attr) const {
  auto val = make_header(attr->m_header.get());
  tao::json::value subpackets = tao::json::empty_array;
  for (const auto& sub : attr->m_subpackets) {
    switch (sub->type()) {
      case UserAttributeSubpacketType::Image: {
        auto img = dynamic_cast<const ImageAttributeSubpacket*>(sub.get());
        assert(img != nullptr);
        // FIXME: replace static cast, add subpacket header data
        tao::json::value subpacket = {
            {"type", "Image"},
            {"encoding", static_cast<uint8_t>(img->m_encoding)},
            {"size", img->m_image.size()}};
        subpackets.append({subpacket});
      } break;
      default: {
        tao::json::value subpacket = {
            // FIXME: replace static cast, add subpacket header data
            {"type", "Raw"},
            {"_type", static_cast<uint8_t>(sub->type())},
            {"size", sub->body_length()}};
        subpackets.append({subpacket});

        break;
      }
    }
  }
  val.insert({{"_packet", "UserAttribute"}, {"subpackets", subpackets}});
  m_out << val;
}

void JsonDump::dump(const PublicKeyPacket* pubkey) const {
  m_out << ":public key packet:\n";
  auto pub = dynamic_cast<const PublicKeyData*>(pubkey->m_public_key.get());
  assert(pub != nullptr);
  output_public_key_data(m_out, pub);
}

void JsonDump::dump(const PublicSubkeyPacket* pubkey) const {
  m_out << ":public sub key packet:\n";
  auto pub = dynamic_cast<const PublicKeyData*>(pubkey->m_public_key.get());
  assert(pub != nullptr);
  output_public_key_data(m_out, pub);
}

void JsonDump::dump(const SignaturePacket* signature) const {
  auto sig = dynamic_cast<const SignatureData*>(signature->m_signature.get());
  assert(sig);
  output_signature_data(m_out, sig);
}
