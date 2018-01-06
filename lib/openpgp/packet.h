/* OpenPGP format
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#pragma once

#include <neopg/packet_header.h>
#include <memory>

namespace NeoPG {

struct NEOPG_UNSTABLE_API Packet {
  /*! Use this to overwrite the default header.
   */
  std::unique_ptr<PacketHeader> m_header;

  void write(std::ostream& out) const;
  virtual void write_body(std::ostream& out) const = 0;
  virtual PacketType type() const = 0;
};

}  // namespace NeoPG
