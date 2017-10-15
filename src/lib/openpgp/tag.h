/* OpenPGP format
   Copyright 2017 Marcus Brinkmann

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#ifndef NEOPG_OPENPGP_TAG_H__
#define NEOPG_OPENPGP_TAG_H__

#include <cstdint>
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
      PacketType packet_type;
      PacketLengthType length_type;
      uint32_t length;

      static void verify_length(uint32_t length_,
				PacketLengthType length_type_)
      {
	if (length_type_ == PacketLengthType::OneOctet and length_ > 0xff)
	  throw std::logic_error("Invalid packet length for one octet");
	if (length_type_ == PacketLengthType::TwoOctet and length_ > 0xffff)
	  throw std::logic_error("Invalid packet length for two octets");
	if (length_type_ == PacketLengthType::Indeterminate)
	  throw std::logic_error("Indeterminate packet length not supported");
      }

      static PacketLengthType best_length_type(uint32_t length_)
      {
	if (length_ <= 0xff)
	  return PacketLengthType::OneOctet;
	else if (length_ <= 0xffff)
	  return PacketLengthType::TwoOctet;
	else
	  return PacketLengthType::FourOctet;
      }


      OldPacketHeader(PacketType packet_type_,
		      uint32_t length_,
		      PacketLengthType length_type_ = PacketLengthType::Default)
      {
	set_packet_type(packet_type_);
	set_length(length_, length_type_);
      }

      void set_packet_type(PacketType packet_type_)
      {
	if ((uint8_t) packet_type_ >= 16)
	  throw std::logic_error("Invalid tag");
	packet_type = packet_type_;
      }

      void set_length(uint32_t length_,
		      PacketLengthType length_type_ = PacketLengthType::Default)

      {
	verify_length(length_, length_type_);
	length_type = length_type_;
	length = length_;
      }

      void write(std::ostream& out) {
	PacketLengthType lentype = length_type;
	if (lentype == PacketLengthType::Default)
	  lentype = best_length_type(length);

	uint8_t tag = 0x80 | ((uint8_t) packet_type << 2);
	switch (lentype)
	  {
	  case PacketLengthType::OneOctet:
	    out << (uint8_t) (tag | 0x00)
		<< ((uint8_t) (length & 0xff));
	    break;

	  case PacketLengthType::TwoOctet:
	    out << (uint8_t) (tag | 0x01)
		<< ((uint8_t) ((length >> 8) & 0xff))
		<< ((uint8_t) (length & 0xff));
	    break;

	  case PacketLengthType::FourOctet:
	    out << (uint8_t) (tag | 0x02)
		<< ((uint8_t) ((length >> 24) & 0xff))
		<< ((uint8_t) ((length >> 16) & 0xff))
		<< ((uint8_t) ((length >> 8) & 0xff))
		<< ((uint8_t) (length & 0xff));
	    break;

	  case PacketLengthType::Indeterminate:
	    throw std::logic_error("Indeterminate packet length type (shouldn't happen).");

	  case PacketLengthType::Default:
	    throw std::logic_error("Unspecific packet length type (shouldn't happen).");
	  }
      }
    };

    struct NewPacketTag
    {
      PacketType packet_type;

      void set_packet_type(PacketType packet_type_)
      {
	if ((uint8_t) packet_type_ >= 64)
	  throw std::logic_error("Invalid tag");
	packet_type = packet_type_;
      }

      NewPacketTag(PacketType packet_type_)
      {
	set_packet_type(packet_type_);
      }

      void write(std::ostream& out) {
	uint8_t tag = 0x80 | 0x40 | (uint8_t) packet_type;
	out << (uint8_t) tag;
      }
    };

    struct NewPacketLength
    {
      PacketLengthType length_type;
      uint32_t length;

      static void verify_length(uint32_t length_,
				PacketLengthType length_type_)
      {
	if (length_type_ == PacketLengthType::OneOctet
	    and not (length_ <= 0xbf))
	  {
	    throw std::logic_error("Invalid packet length for one octet");
	  }
	else if (length_type_ == PacketLengthType::TwoOctet
		 and not (length_ >= 0xc0 and length_ <= 0x20bf))
	  {
	    throw std::logic_error("Invalid packet length for two octets");
	  }
	else if (length_type_ == PacketLengthType::Partial
		 and not (length_ != 0
			  and length_ == (1U << __builtin_ctz(length_))
			  and length_ != (1U << 31)))
	  {
	    throw std::logic_error("Invalid indeterminate packet length");
	  }
      }

      static PacketLengthType best_length_type(uint32_t length_)
      {
	if (length_ <= 0xbf)
	  return PacketLengthType::OneOctet;
	else if (length_ <= 0x20bf)
	  return PacketLengthType::TwoOctet;
	else
	  return PacketLengthType::FiveOctet;
      }

      void set_length(uint32_t length_,
		      PacketLengthType length_type_ = PacketLengthType::Default)

      {
	verify_length(length_, length_type_);
	length_type = length_type_;
	length = length_;
      }

      NewPacketLength(uint32_t length_,
		      PacketLengthType length_type_ = PacketLengthType::Default)
      {
	set_length(length_, length_type_);
      }

      void write(std::ostream& out) {
	PacketLengthType lentype = length_type;
	if (lentype == PacketLengthType::Default)
	  lentype = best_length_type(length);

	switch (lentype)
	  {
	  case PacketLengthType::OneOctet:
	    out << (uint8_t) length;
	    break;

	  case PacketLengthType::TwoOctet:
	    {
	      uint32_t adj_length = length - 192;
	      out << (uint8_t) (((adj_length >> 8) & 0x1f) + 0xc0)
		  << ((uint8_t) (adj_length & 0xff));
	    }
	    break;

	  case PacketLengthType::FourOctet:
	    out << (uint8_t) 0xff
		<< ((uint8_t) ((length >> 24) & 0xff))
		<< ((uint8_t) ((length >> 16) & 0xff))
		<< ((uint8_t) ((length >> 8) & 0xff))
		<< ((uint8_t) (length & 0xff));
	    break;

	  case PacketLengthType::Partial:
	    {
	      uint8_t exp = __builtin_ctz(length);
	      out << (uint8_t) ((exp & 0x1f) + 0xe0);
	    }
	    break;

	  case PacketLengthType::Default:
	    throw std::logic_error("Unspecific packet length type (shouldn't happen).");
	  }
      }
    };

    struct NewPacketHeader : PacketHeader
    {
      NewPacketTag tag;
      NewPacketLength length;

      NewPacketHeader(NewPacketTag tag_,
		      NewPacketLength length_)
	: tag(tag_), length(length_)
	{
	}

      NewPacketHeader(PacketType packet_type_,
		      uint32_t length_,
		      PacketLengthType length_type_ = PacketLengthType::Default)
	: tag(packet_type_), length(length_, length_type_)
	{
	}

      void write(std::ostream& out) {
	tag.write(out);
	length.write(out);
      }
    };
  }
}
#endif
