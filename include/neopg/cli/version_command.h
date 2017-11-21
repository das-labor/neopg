/* Command line parsing
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#pragma once

#include <neopg/cli/command.h>

namespace NeoPG {
namespace CLI {

class VersionCommand : public Command {
 public:
  void run() override;
  VersionCommand(CLI::App& app, const std::string& flag,
                 const std::string& description)
      : Command(app, flag, description) {
    m_cmd.group("");
  }
  virtual ~VersionCommand() {}
};

}  // Namespace CLI
}  // Namespace NeoPG
