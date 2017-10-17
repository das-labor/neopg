/* OpenPGP format
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#ifndef NEOPG_OPENPGP_MARKER_PACKET_H__
#define NEOPG_OPENPGP_MARKER_PACKET_H__

#include <neopg/openpgp/packet.h>

namespace NeoPG {
namespace OpenPGP {

struct MarkerPacket : Packet {
  void write(std::ostream& out) override;
};

}  // namespace OpenPGP
}  // namespace NeoPG

#endif
