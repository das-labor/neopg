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
  const int blocksize = 128;
  Botan::byte block[blocksize];
  while (true) {
    NeoPG::Crypto::rng->randomize(block, blocksize);
    std::cout.write((const char*)block, blocksize);
  }
}

}  // Namespace CLI
}  // Namespace NeoPG
