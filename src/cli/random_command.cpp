/* NeoPG
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#include <iostream>

#include <neopg/cli/random_command.h>
#include <neopg/crypto/rng.h>

namespace NeoPG {
namespace CLI {

void RandomCommand::run() {
  bool infinite = m_cmd.count("count") == 0;

  std::vector<uint8_t> block(4096);
  while (infinite || m_count > 0) {
    int next_blocksize = m_count < block.size() ? m_count : block.size();
    NeoPG::Crypto::rng()->randomize(block.data(), next_blocksize);
    std::cout.write((const char*)block.data(), next_blocksize);
    m_count -= next_blocksize;
  }
}

}  // Namespace CLI
}  // Namespace NeoPG
