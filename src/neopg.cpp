/* NeoPG
   Copyright 2017 The NeoPG developers

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#include <iostream>

#include <neopg/cli/command.h>
#include <neopg/cli/packet_command.h>
#include <neopg/cli/version_command.h>

using namespace NeoPG::CLI;

int gpg_main(int argc, char** argv);
int agent_main(int argc, char** argv);
int dirmngr_main(int argc, char** argv);
int dirmngr_client_main(int argc, char** argv);
int gpgsm_main(int argc, char** argv);
int scd_main(int argc, char** argv);

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

#define GPGRT_ATTR_SENTINEL(a)
#include "../legacy/gnupg/common/stringhelp.h"

int main(int argc, char const* argv[]) {
  /* This is also used to invoke ourself.  */
  neopg_program = make_absfilename(argv[0], NULL);

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

  PacketCommand cmd_packet(cmd, "packet", "read and write OpenPGP packets",
                           args::Options::Hidden);
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
