// NeoPG
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg-tool/cli/packet/dump_packet_command.h>

#include <neopg-tool/cli/packet/dump/hex_dump.h>
#include <neopg-tool/cli/packet/dump/json_dump.h>
#include <neopg-tool/cli/packet/dump/legacy_dump.h>

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

namespace NeoPG {
template <typename T, typename... Args>
std::unique_ptr<T> make_unique(Args&&... args) {
  return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}
}  // namespace NeoPG

using namespace NeoPG;

#include <botan/comp_filter.h>
#include <botan/pipe.h>

static void process_msg(const std::string& format, Botan::DataSource& source,
                        Botan::DataSink& out) {
  out.start_msg();
  std::unique_ptr<RawPacketSink> sink;
  if (format == "legacy")
    sink = NeoPG::make_unique<LegacyDump>(std::cout);
  else if (format == "hex")
    sink = NeoPG::make_unique<HexDump>(std::cout);
  else
    sink = NeoPG::make_unique<JsonDump>(std::cout);
  RawPacketParser parser(*sink);

  //  Botan::Pipe parser(new Botan::Decompression_Filter("zlib"));

  try {
    parser.process(source);
  } catch (const ParserError& exc) {
    std::cout << rang::style::bold << rang::fgB::red << "ERROR"
              << rang::style::reset
              << ":unrecoverable error:" << exc.as_string() << "\n";
  }
  out.end_msg();
}

void DumpPacketCommand::run() {
  Botan::DataSink_Stream out{std::cout};

  if (m_files.empty()) m_files.emplace_back("-");
  for (auto& file : m_files) {
    if (file == "-") {
      Botan::DataSource_Stream in{std::cin};
      process_msg(m_format, in, out);
    } else {
      // Open in binary mode.
      Botan::DataSource_Stream in{file, true};
      process_msg(m_format, in, out);
    }
  }
}
