/* NeoPG
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#include <neopg-tool/command.h>
#include <neopg-tool/packet_command.h>

#include <neopg/marker_packet.h>
#include <neopg/openpgp.h>
#include <neopg/raw_packet.h>
#include <neopg/user_id_packet.h>

#include <botan/data_snk.h>
#include <botan/data_src.h>

#include <CLI11.hpp>

#include <iostream>

namespace NeoPG {

void MarkerPacketCommand::run() {
  MarkerPacket packet;
  packet.write(std::cout);
}

void UserIdPacketCommand::run() {
  UserIdPacket packet;
  packet.m_content = m_uid;
  packet.write(std::cout);
}

#if 0
class PacketSink {
  void next_packet(std::unique_ptr<NeoPG::RawPacket>& packet);
};
void PacketSink::next_packet(std::unique_ptr<NeoPG::RawPacket>& packet) {
  std::cerr << "P"
            << "\n";
}
#endif

struct PacketSink : public RawPacketSink {
  void next_packet(std::unique_ptr<PacketHeader> header, const char* data,
                   size_t length) {}
  void start_packet(std::unique_ptr<PacketHeader> header){};
  void continue_packet(const char* data, size_t length){};
  void finish_packet(std::unique_ptr<NewPacketLength> length_info,
                     const char* data, size_t length){};
};

static void process_msg(Botan::DataSource& source, Botan::DataSink& out) {
  out.start_msg();
  PacketSink sink;
  RawPacketParser parser(sink);
  parser.process(source);

  // Botan::secure_vector<uint8_t> buffer(Botan::DEFAULT_BUFFERSIZE);
  // while (!source.end_of_data()) {
  //   size_t got = source.read(buffer.data(), buffer.size());
  //   std::cerr << "XXX " << got << "\n";
  //   out.write(buffer.data(), got);
  // }
  out.end_msg();
}

void FilterPacketCommand::run() {
  Botan::DataSink_Stream out{std::cout};

  if (m_files.empty()) m_files.emplace_back("-");
  for (auto& file : m_files) {
    if (file == "-") {
      Botan::DataSource_Stream in{std::cin};
      process_msg(in, out);
    } else {
      // Open in binary mode.
      Botan::DataSource_Stream in{file, true};
      process_msg(in, out);
    }
  }
}

PacketCommand::PacketCommand(CLI::App& app, const std::string& flag,
                             const std::string& description,
                             const std::string& group_name)
    : Command(app, flag, description, group_name),
      cmd_marker(m_cmd, "marker", "output a Marker Packet", group_write),
      cmd_uid(m_cmd, "uid", "output a User ID Packet", group_write),
      cmd_filter(m_cmd, "filter", "process packet data", group_process) {}

void PacketCommand::run() {
  if (m_cmd.get_subcommands().empty()) throw CLI::CallForHelp();
}

}  // Namespace NeoPG
