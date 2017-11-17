/* Command line parsing
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#pragma once

#include <neopg/cli/args.h>

namespace NeoPG {
namespace CLI {

using arg_iter_t = std::vector<std::string>::const_iterator;

class Command : public args::Command<Command*> {
 public:
  virtual int run(const std::string& progname, arg_iter_t begin_args,
                  arg_iter_t end_args) = 0;
  Command(args::CommandGroup<Command*>& group_, const std::string& name_,
          const std::string& help_, args::Options options_ = {})
      : args::Command<Command*>(group_, this, name_, help_, options_) {}
  virtual ~Command() {}
};

class SimpleCommand : public Command {
 public:
  virtual void setup(args::ArgumentParser& parser) {}
  virtual int run(args::ArgumentParser& parser) = 0;

  virtual int run(const std::string& progname, arg_iter_t begin_args,
                  arg_iter_t end_args);

  SimpleCommand(args::CommandGroup<Command*>& group_, const std::string& name_,
                const std::string& help_, args::Options options_ = {})
      : Command(group_, name_, help_, options_){};
  virtual ~SimpleCommand(){};
};

class LegacyCommand : public Command {
 public:
  using main_fnc_t = std::function<int(int argc, char** argv)>;

 private:
  const main_fnc_t main_fnc;

 public:
  virtual int run(const std::string& progname, arg_iter_t begin_args,
                  arg_iter_t end_args) override;

  LegacyCommand(args::CommandGroup<Command*>& group_,
                const main_fnc_t& main_fnc_, const std::string& name_,
                const std::string& help_, args::Options options_ = {})
      : Command(group_, name_, help_, options_), main_fnc(main_fnc_){};
  virtual ~LegacyCommand(){};
};

}  // Namespace CLI
}  // Namespace NeoPG
