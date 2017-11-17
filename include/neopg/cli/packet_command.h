/* Command line parsing
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#pragma once

#include <neopg/cli/command.h>

namespace NeoPG {
namespace CLI {

class PacketCommand : public SimpleCommand {
 public:
  virtual int run(args::ArgumentParser& parser);

  PacketCommand(args::CommandGroup<Command*>& group_, const std::string& name_,
                const std::string& help_, args::Options options_ = {})
      : SimpleCommand(group_, name_, help_, options_) {}
  virtual ~PacketCommand() {}
};

}  // Namespace CLI
}  // Namespace NeoPG
