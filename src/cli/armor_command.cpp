/* NeoPG
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#include <iostream>

#include <botan/base64.h>
#include <botan/hash.h>
#include <neopg/cli/armor_command.h>

namespace NeoPG {
namespace CLI {

void ArmorCommand::encode() {
  bool title = !m_title.empty();

  // We process in chunks by output line.  76 characters = 19 * 4 output bytes
  // are 19 * 3 = 57 input bytes.
  std::vector<uint8_t> buf(76 / 4 * 3);
  std::unique_ptr<Botan::HashFunction> hash{
      Botan::HashFunction::create_or_throw("CRC24")};

  if (title) std::cout << "-----BEGIN " << m_title << "-----\n\n";
  while (std::cin.good()) {
    std::cin.read(reinterpret_cast<char*>(buf.data()), buf.size());
    const size_t count = std::cin.gcount();
    hash->update(buf.data(), count);
    std::cout << Botan::base64_encode(buf.data(), count) << "\n";
  }
  while (!std::cin.eof())
    ;
  std::vector<uint8_t> crc24{hash->final_stdvec()};
  if (m_crc24)
    std::cout << "=" << Botan::base64_encode(crc24.data(), crc24.size())
              << "\n";
  if (title) std::cout << "-----END " << m_title << "-----\n";
}

void ArmorCommand::decode() {
  // TODO
}

void ArmorCommand::run() {
#ifdef __WIN32__
  _setmode(_fileno(stdin), _O_BINARY);
#endif

  if (m_decode)
    decode();
  else
    encode();
}
}  // Namespace CLI
}  // Namespace NeoPG
