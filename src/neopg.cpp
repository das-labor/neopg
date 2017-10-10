/* NeoPG
   Copyright 2017 Marcus Brinkmann

   NeoPG is released under the Simplified BSD License (see license.txt)
*/

#include <iostream>

#include "args.hpp"

int gpg_main(int argc, char **argv);
int agent_main(int argc, char **argv);
int dirmngr_main(int argc, char **argv);
int dirmngr_client_main(int argc, char **argv);
int gpgsm_main(int argc, char **argv);
int scd_main(int argc, char **argv);


struct cli : args::group<cli>
{
    static const char* help()
    {
        return "NeoPG implements the OpenPGP standard.";
    }
};


struct version : cli::command<version>
{
    version() {}

    static const char* help()
    {
        return "output version information and exit";
    }

    void run()
    {
        printf("NeoPG 0.0\n");
    }
};

struct gpg2 : cli::command<gpg2>
{
    gpg2() {}
    static bool no_help;
    std::vector<std::string> gpg2args;
    template<class F>
    void parse(F f)
    {
        f(gpg2args, args::help("arguments"), args::take_unknown());
    }

    static const char* help()
    {
        return "Invoke gpg2";
    }

    void run()
    {
        gpg2args.insert(gpg2args.begin(), std::string("gpg2"));
        int argc = gpg2args.size();
        std::vector<char*> argv;
        for(auto&& value:gpg2args) argv.push_back((char*)value.data());
        // Return value
        gpg_main(argc, argv.data());
    }
};
/* Suppress help output.  */
bool gpg2::no_help = true;

struct agent : cli::command<agent>
{
    agent() {}
    static bool no_help;
    std::vector<std::string> agent_args;
    template<class F>
    void parse(F f)
    {
        f(agent_args, args::help("arguments"), args::take_unknown());
    }

    static const char* help()
    {
        return "Invoke agent";
    }

    void run()
    {
        agent_args.insert(agent_args.begin(), std::string("agent"));
        int argc = agent_args.size();
        std::vector<char*> argv;
        for(auto&& value:agent_args) argv.push_back((char*)value.data());
        // Return value
        agent_main(argc, argv.data());
    }
};
/* Suppress help output.  */
bool agent::no_help = true;

struct dirmngr : cli::command<dirmngr>
{
    dirmngr() {}
    static bool no_help;
    std::vector<std::string> dirmngr_args;
    template<class F>
    void parse(F f)
    {
        f(dirmngr_args, args::help("arguments"), args::take_unknown());
    }

    static const char* help()
    {
        return "Invoke dirmngr";
    }

    void run()
    {
        dirmngr_args.insert(dirmngr_args.begin(), std::string("dirmngr"));
        int argc = dirmngr_args.size();
        std::vector<char*> argv;
        for(auto&& value:dirmngr_args) argv.push_back((char*)value.data());
        // Return value
        dirmngr_main(argc, argv.data());
    }
};
/* Suppress help output.  */
bool dirmngr::no_help = true;

struct gpgsm : cli::command<gpgsm>
{
    gpgsm() {}
    static bool no_help;
    std::vector<std::string> gpgsm_args;
    template<class F>
    void parse(F f)
    {
        f(gpgsm_args, args::help("arguments"), args::take_unknown());
    }

    static const char* help()
    {
        return "Invoke gpgsm";
    }

    void run()
    {
        gpgsm_args.insert(gpgsm_args.begin(), std::string("gpgsm"));
        int argc = gpgsm_args.size();
        std::vector<char*> argv;
        for(auto&& value:gpgsm_args) argv.push_back((char*)value.data());
        // Return value
        gpgsm_main(argc, argv.data());
    }
};
/* Suppress help output.  */
bool gpgsm::no_help = true;

struct scd : cli::command<scd>
{
    scd() {}
    static bool no_help;
    std::vector<std::string> scd_args;
    template<class F>
    void parse(F f)
    {
        f(scd_args, args::help("arguments"), args::take_unknown());
    }

    static const char* help()
    {
        return "Invoke scd";
    }

    void run()
    {
        scd_args.insert(scd_args.begin(), std::string("scd"));
        int argc = scd_args.size();
        std::vector<char*> argv;
        for(auto&& value:scd_args) argv.push_back((char*)value.data());
        // Return value
        scd_main(argc, argv.data());
    }
};
/* Suppress help output.  */
bool scd::no_help = true;

struct dirmngr_client : cli::command<dirmngr_client>
{
    dirmngr_client() {}
    static bool no_help;
    std::vector<std::string> dirmngr_client_args;
    template<class F>
    void parse(F f)
    {
        f(dirmngr_client_args, args::help("arguments"), args::take_unknown());
    }

    static const char* help()
    {
        return "Invoke dirmngr_client";
    }

    void run()
    {
        dirmngr_client_args.insert(dirmngr_client_args.begin(), std::string("dirmngr_client"));
        int argc = dirmngr_client_args.size();
        std::vector<char*> argv;
        for(auto&& value:dirmngr_client_args) argv.push_back((char*)value.data());
        // Return value
        dirmngr_client_main(argc, argv.data());
    }
};
/* Suppress help output.  */
bool dirmngr_client::no_help = true;

char *neopg_program;
#define GPGRT_ATTR_SENTINEL(a)
#include "../gnupg/common/stringhelp.h"

int
main(int argc, char const *argv[])
{
    neopg_program = make_absfilename(argv[0], NULL);
    args::parse<cli>(argc, argv);
}
