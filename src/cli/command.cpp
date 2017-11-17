/* NeoPG
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#include <iostream>

#include <neopg/cli/command.h>

namespace NeoPG {
namespace CLI {

int SimpleCommand::run(const std::string& progname, arg_iter_t begin_args,
                       arg_iter_t end_args) {
  args::ArgumentParser parser("");
  parser.Prog(progname + " " + Name().c_str());
  args::HelpFlag help(parser, "help", "display this help and exit", {"help"});
  setup(parser);
  try {
    auto next = parser.ParseArgs(begin_args, end_args);
    return run(parser);
  } catch (args::Help) {
    std::cout << parser;
    return 0;
  } catch (args::ParseError e) {
    std::cerr << e.what() << std::endl;
    std::cerr << parser;
    return 1;
  }
}

int LegacyCommand::run(const std::string& progname, arg_iter_t begin_args,
                       arg_iter_t end_args) {
  std::vector<char*> args = {(char*)Name().c_str()};
  while (begin_args != end_args)
    args.push_back(const_cast<char*>((begin_args++)->c_str()));
  main_fnc(args.size(), args.data());
  return 0;
}

}  // Namespace CLI
}  // Namespace NeoPG
