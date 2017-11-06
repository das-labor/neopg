/* NeoPG
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#include <iostream>

#include "args.h"

int gpg_main(int argc, char** argv);
int agent_main(int argc, char** argv);
int dirmngr_main(int argc, char** argv);
int dirmngr_client_main(int argc, char** argv);
int gpgsm_main(int argc, char** argv);
int scd_main(int argc, char** argv);

using arg_iter_t = std::vector<std::string>::const_iterator;

class Command : public args::Command<Command*> {
 public:
  virtual int run(const std::string& progname, arg_iter_t begin_args,
                  arg_iter_t end_args) = 0;
  Command(args::CommandGroup<Command*>& group_, const std::string& name_,
          const std::string& help_, args::Options options_ = {})
      : args::Command<Command*>(group_, this, name_, help_, options_){};
  virtual ~Command(){};
};

class LegacyCommand : public Command {
 public:
  using main_fnc_t = std::function<int(int argc, char** argv)>;

 private:
  const main_fnc_t main_fnc;

 public:
  virtual int run(const std::string& progname, arg_iter_t begin_args,
                  arg_iter_t end_args) override {
    std::vector<char*> args = {(char*)Name().c_str()};
    while (begin_args != end_args)
      args.push_back(const_cast<char*>((begin_args++)->c_str()));
    main_fnc(args.size(), args.data());
    return 0;
  }
  LegacyCommand(args::CommandGroup<Command*>& group_,
                const main_fnc_t& main_fnc_, const std::string& name_,
                const std::string& help_, args::Options options_ = {})
      : Command(group_, name_, help_, options_), main_fnc(main_fnc_){};
  virtual ~LegacyCommand(){};
};

class SimpleCommand : public Command {
 public:
  virtual void setup(args::ArgumentParser& parser){};
  virtual int run(args::ArgumentParser& parser) = 0;

  virtual int run(const std::string& progname, arg_iter_t begin_args,
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

  SimpleCommand(args::CommandGroup<Command*>& group_, const std::string& name_,
                const std::string& help_, args::Options options_ = {})
      : Command(group_, name_, help_, options_){};
  virtual ~SimpleCommand(){};
};

class VersionCommand : public SimpleCommand {
 public:
  int run() {
    std::cout << "NeoPG 0.0\n";
    return 0;
  }

  virtual int run(args::ArgumentParser& parser) { return run(); }

  VersionCommand(args::CommandGroup<Command*>& group_, const std::string& name_,
                 const std::string& help_, args::Options options_ = {})
      : SimpleCommand(group_, name_, help_, options_){};
  virtual ~VersionCommand(){};
};

char* neopg_program;

#if 0
struct openpgp : cli::command<openpgp>
{
    static const char* help()
    {
        return "Invoke openpgp";
    }

    void run()
    {
        openpgp_args.insert(openpgp_args.begin(), std::string("openpgp"));
        int argc = openpgp_args.size();
        std::vector<char*> argv;
        for(auto&& value:openpgp_args) argv.push_back((char*)value.data());

	std::string integer;
	std::string id;
	std::string body;

	tao::neopg_pegtl::argv_input<> in( argv.data(), 1 );
	// tao::neopg_pegtl::parse< NeoPG::grammar, NeoPG::action >( in, integer );
	// std::cout << "Parse result: " << integer << std::endl;
	tao::neopg_pegtl::parse< NeoPG::grammar, NeoPG::action >( in, id, body );
	std::cout << "long literal id was: " << id << std::endl;
	std::cout << "long literal body was: " << body << std::endl;

    }
};
#endif

int main(int argc, char const* argv[]) {
  neopg_program = (char*)"neopg";

  const std::vector<std::string> args(argv + 1, argv + argc);

  args::ArgumentParser parser(
      "NeoPG implements the OpenPGP standard.",
      "Report bugs to https://github.com/das-labor/neopg");
  parser.helpParams.showTerminator = false;
  args::HelpFlag o_help(parser, "help", "display this help and exit", {"help"});
  args::Flag o_version(parser, "version", "output version information and exit",
                       {"version"});

  parser.Prog(neopg_program);
  parser.ProglinePostfix("[<args>]");

  args::CommandGroup<Command*> cmd(parser, "command",
                                   "command to execute (GnuPG-compatible)");
  cmd.KickOut(true);

  LegacyCommand cmd_gpg2(cmd, gpg_main, "gpg2", "invoke gpg2");
  LegacyCommand cmd_gpgsm(cmd, gpgsm_main, "gpgsm", "invoke gpgsm");
  LegacyCommand cmd_agent(cmd, agent_main, "agent", "invoke agent");
  LegacyCommand cmd_scd(cmd, scd_main, "scd", "invoke scd");
  LegacyCommand cmd_dirmngr(cmd, dirmngr_main, "dirmngr", "invoke dirmngr");
  LegacyCommand cmd_dirmngr_client(cmd, dirmngr_client_main, "dirmngr-client",
                                   "invoke dirmngr-client");

  VersionCommand cmd_version(cmd, "version", "show version info and exit",
                             args::Options::Hidden);

  try {
    auto next = parser.ParseArgs(args);
    std::cout << std::boolalpha;
    if (o_version) {
      return cmd_version.run();
    }
    if (cmd) {
      args::get(cmd)->run(neopg_program, next, std::end(args));
    } else {
      throw args::Help("");
    }
  } catch (args::Help) {
    std::cout << parser;
    return 0;
  } catch (args::ParseError e) {
    std::cerr << e.what() << std::endl;
    std::cerr << parser;
    return 1;
  }
  return 0;
}
