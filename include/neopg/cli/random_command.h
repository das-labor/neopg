/* Command line parsing
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#pragma once

#include <neopg/cli/command.h>

namespace NeoPG {
namespace CLI {

class RandomCommand : public Command {
 public:
  void run() override;
  RandomCommand(CLI::App& app, const std::string& flag,
                const std::string& description,
                const std::string& group_name = "")
      : Command(app, flag, description, group_name) {}
  virtual ~RandomCommand() {}
};

}  // Namespace CLI
}  // Namespace NeoPG
