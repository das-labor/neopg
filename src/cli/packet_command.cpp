/* NeoPG
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#include <iostream>

#include <neopg/cli/command.h>
#include <neopg/cli/packet_command.h>

#include <neopg/openpgp/marker_packet.h>
#include <neopg/openpgp/user_id_packet.h>

namespace NeoPG {
namespace CLI {

void MarkerPacketCommand::run() {
  OpenPGP::MarkerPacket packet;
  packet.write(std::cout);
}

void UserIdPacketCommand::run() {
  OpenPGP::UserIdPacket packet;
  packet.m_content = m_uid;
  packet.write(std::cout);
}

PacketCommand::PacketCommand(CLI::App& app, const std::string& flag,
                             const std::string& description,
                             const std::string& group_name)
    : Command(app, flag, description, group_name),
      cmd_marker(m_cmd, "marker", "output a Marker Package", group),
      cmd_uid(m_cmd, "uid", "output a User ID Package", group) {}

void PacketCommand::run() {
  //  std::cout << "PACKET\n";
}

}  // Namespace CLI
}  // Namespace NeoPG
