// OpenPGP parser
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg/raw_packet.h>

#include <botan/data_snk.h>
#include <botan/data_src.h>

namespace NeoPG {

class NEOPG_UNSTABLE_API RawPacketSink {
 public:
  // Takes ownership of HEADER.  Data is passed by reference and only valid
  // during execution of this function.
  virtual void next_packet(std::unique_ptr<PacketHeader> header,
                           const char* data, size_t length) = 0;

  // Takes ownership of HEADER.  The data follows with continue_packet calls.
  virtual void start_packet(std::unique_ptr<PacketHeader> header) = 0;

  // Called after start_packet. Data is passed by
  // reference and only valid during execution of this function.
  virtual void continue_packet(const char* data, size_t length) = 0;

  // Called eventually after start_packet and zero or more continue_packet
  // calls.  The LENGTH_INFO allows to reconstruct the original binary stream
  // (only valid for new packet format)..
  virtual void finish_packet(std::unique_ptr<NewPacketLength> length_info,
                             const char* data, size_t length) = 0;
};

class NEOPG_UNSTABLE_API RawPacketParser {
  RawPacketSink& m_sink;

 public:
  // This must be at least as many bytes as the parser needs to see between two
  // discard rules.
  // This is dominated by variable length fields and partial data packets.
  // OpenPGP does not impose limits on fields such as the user ID, so we have
  // our own limits, see the NeoPG OpenPGP profile. Post-quantum cryptography
  // will require some large key packets, so this limit will go up eventually.
  // For partial length data packets, GnuPG emits at most 8KiB.
  const size_t MAX_PARSER_BUFFER = 1024 * 1024;  // 1 MiB.

  RawPacketParser(RawPacketSink& sink) : m_sink(sink) {}

  void process(Botan::DataSource& source);
  void process(std::istream& source);
  void process(const std::string& source);
};

}  // namespace NeoPG
