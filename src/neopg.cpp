#include <iostream>

#include "args.hpp"

int gpg_main(int argc, char **argv);

struct cli : args::group<cli>
{
    static const char* help()
    {
        return "Command-line interface to manage a database";
    }
};

struct initdb : cli::command<initdb>
{
    initdb() {}

    int count;
    std::string name;

    static const char* help()
    {
        return "Initialize database";
    }

    template<class F>
    void parse(F f)
    {
        f(count, "--count", "-C", args::help("Number of greetings."), args::show("xxXz"));
        f(name, "--name", "-N", args::help("The person to greet."), args::required());
    }
    void run()
    {
        printf("Initialize database\n");
    }
};

struct gpg2 : cli::command<gpg2>
{
    gpg2() {}

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

int main(int argc, char const *argv[])
{
    args::parse<cli>(argc, argv);
}
