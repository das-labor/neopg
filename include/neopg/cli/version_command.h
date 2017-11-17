/* Command line parsing
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#pragma once

#include <neopg/cli/command.h>

namespace NeoPG {
namespace CLI {

class VersionCommand : public SimpleCommand {
 public:
  /* This is a method so it can be used independend of the normal command
   * mechanism.  */
  int run();

  virtual int run(args::ArgumentParser& parser);

  VersionCommand(args::CommandGroup<Command*>& group_, const std::string& name_,
                 const std::string& help_, args::Options options_ = {})
      : SimpleCommand(group_, name_, help_, options_) {}
  virtual ~VersionCommand() {}
};

}  // Namespace CLI
}  // Namespace NeoPG
