/* NeoPG
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#include <iostream>

#include <neopg/cli/version_command.h>

namespace NeoPG {
namespace CLI {

void VersionCommand::run() { std::cout << "NeoPG 0.0\n"; }

}  // Namespace CLI
}  // Namespace NeoPG
