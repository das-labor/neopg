/* OpenPGP format
   Copyright 2017 Marcus Brinkmann

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#ifndef NEOPG_OPENPGP_TAG_H__
#define NEOPG_OPENPGP_TAG_H__

#include <cstdint>
#include <iostream>
#include <stdexcept>

namespace NeoPG {
  namespace OpenPGP {

    enum class PacketType : uint8_t {
      Reserved = 0,
      PublicKeyEncryptedSessionKey = 1,
      Signature = 2,
      SymmetricKeyEncryptedSessionKey = 3,
      OnePassSignature = 4,
      SecretKey = 5,
      PublicKey = 6,
      SecretSubkey = 7,
      CompressedData = 8,
      SymmetricallyEncryptedData = 9,
      Marker = 10,
      LiteralData = 11,
      Trust = 12,
      UserID = 13,
      PublicSubkey = 14,
      UserAttribute = 17,
      SymmetricallyEncryptedAndIntegrityProtectedData = 18,
      ModificationDetectionCode = 19,
      Private60 = 60,
      Private61 = 61,
      Private62 = 62,
      Private63 = 63
    };

    enum class PacketLengthType : uint8_t {
      OneOctet = 0,
      TwoOctet = 1,
      FiveOctet = 2,
      FourOctet = 2,
      Partial = 3,
      Indeterminate = 3, /* Old Format */
      Default
    };

    struct PacketHeader
    {
      virtual void write(std::ostream& out) = 0;
    };

    struct OldPacketHeader : PacketHeader
    {
      PacketType m_packet_type;
      PacketLengthType m_length_type;
      uint32_t m_length;

      static void verify_length(uint32_t length,
				PacketLengthType length_type);

      static PacketLengthType best_length_type(uint32_t length);

      OldPacketHeader(PacketType packet_type,
		      uint32_t length,
		      PacketLengthType length_type = PacketLengthType::Default);

      void set_packet_type(PacketType packet_type);

      void set_length(uint32_t length,
		      PacketLengthType length_type = PacketLengthType::Default);

      void write(std::ostream& out);
    };

    struct NewPacketTag
    {
      PacketType m_packet_type;

      void set_packet_type(PacketType packet_type);

      NewPacketTag(PacketType packet_type);

      void write(std::ostream& out);
    };

    struct NewPacketLength
    {
      PacketLengthType m_length_type;
      uint32_t m_length;

      static void verify_length(uint32_t length,
				PacketLengthType length_type);

      static PacketLengthType best_length_type(uint32_t length);

      void set_length(uint32_t length,
		      PacketLengthType length_type = PacketLengthType::Default);

      NewPacketLength(uint32_t length,
		      PacketLengthType length_type = PacketLengthType::Default);

      void write(std::ostream& out);
    };

    struct NewPacketHeader : PacketHeader
    {
      NewPacketTag m_tag;
      NewPacketLength m_length;

      NewPacketHeader(NewPacketTag tag,
		      NewPacketLength length)
	: m_tag(tag), m_length(length)
	{
	}

      NewPacketHeader(PacketType packet_type,
		      uint32_t length,
		      PacketLengthType length_type = PacketLengthType::Default)
	: m_tag(packet_type), m_length(length, length_type)
	{
	}

      void write(std::ostream& out);
    };
  }
}
#endif
