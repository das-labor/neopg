// hex dump format
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#pragma once

#include <neopg-tool/cli/packet/dump_packet_sink.h>

namespace NeoPG {

/// Hex dump format like GnuPG.
class HexDump : public DumpPacketSink {
 public:
  class Formatter;
  mutable std::unique_ptr<Formatter> m_fmt;

  /// Dispatcher.
  void dump(const Packet* packet) const override;

  void dump(const MarkerPacket* packet) const override;
  void dump(const UserIdPacket* packet) const override;
  void dump(const UserAttributePacket* packet) const override;
  void dump(const PublicKeyPacket* packet) const override;
  void dump(const PublicSubkeyPacket* packet) const override;
  void dump(const SignaturePacket* packet) const override;

  HexDump(std::ostream& out);
  ~HexDump();
};

}  // Namespace NeoPG
