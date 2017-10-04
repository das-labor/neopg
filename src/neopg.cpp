#include <iostream>

#include "args.hpp"

int gpg_main(int argc, char **argv);
int agent_main(int argc, char **argv);


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

int
main(int argc, char const *argv[])
{
    args::parse<cli>(argc, argv);
}
