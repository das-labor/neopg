# Changelog

## [v0.0.5](https://github.com/das-labor/neopg/tree/v0.0.5) (2018-05-15)

[Full Changelog](https://github.com/das-labor/neopg/compare/v0.0.4...v0.0.5)

**Closed issues:**

- Please summarize project "status" in the README [\#65](https://github.com/das-labor/neopg/issues/65)
- ensure NeoPG::URI and NeoPG::Http agree on URL parsing. [\#61](https://github.com/das-labor/neopg/issues/61)
- Interpret http timeout as milliseconds instead of seconds. [\#45](https://github.com/das-labor/neopg/issues/45)

**Merged pull requests:**

- Run a legacy subcommand directly if neopg is called through a program name that ends in that subcommand. [\#71](https://github.com/das-labor/neopg/pull/71) ([lambdafu](https://github.com/lambdafu))
- Integrate taocpp::json [\#69](https://github.com/das-labor/neopg/pull/69) ([ColinH](https://github.com/ColinH))
- Disable support for IDEA. [\#68](https://github.com/das-labor/neopg/pull/68) ([lambdafu](https://github.com/lambdafu))
- Fix a logging message when starting the agent [\#67](https://github.com/das-labor/neopg/pull/67) ([romanz](https://github.com/romanz))
- Add test case for URI parser for WHATWG compliance \(issue \#61\). [\#62](https://github.com/das-labor/neopg/pull/62) ([lambdafu](https://github.com/lambdafu))
- Update PEGTL to 2.4.0. [\#59](https://github.com/das-labor/neopg/pull/59) ([lambdafu](https://github.com/lambdafu))
- Reorganize header files and unit tests. [\#52](https://github.com/das-labor/neopg/pull/52) ([lambdafu](https://github.com/lambdafu))
- Build libneopg as shared library, and fix interface visibility. [\#50](https://github.com/das-labor/neopg/pull/50) ([lambdafu](https://github.com/lambdafu))
- mention force-linking of gettext tools on macOS for homebrew [\#49](https://github.com/das-labor/neopg/pull/49) ([fkr](https://github.com/fkr))
- Remove support for fake v3 key IDs. [\#47](https://github.com/das-labor/neopg/pull/47) ([lambdafu](https://github.com/lambdafu))
- Set maximum filesize for Http transfers. [\#40](https://github.com/das-labor/neopg/pull/40) ([lambdafu](https://github.com/lambdafu))
- Remove use of es\_fopencookie from dirmngr. [\#38](https://github.com/das-labor/neopg/pull/38) ([lambdafu](https://github.com/lambdafu))

## [v0.0.4](https://github.com/das-labor/neopg/tree/v0.0.4) (2017-12-15)

[Full Changelog](https://github.com/das-labor/neopg/compare/v0.0.3...v0.0.4)

**Implemented enhancements:**

- Support MacOS Xcode 9.1. [\#15](https://github.com/das-labor/neopg/pull/15) ([lambdafu](https://github.com/lambdafu))
- Implement cmake release and changelog targets. [\#11](https://github.com/das-labor/neopg/pull/11) ([lambdafu](https://github.com/lambdafu))

**Merged pull requests:**

- Remove special tor mode. [\#37](https://github.com/das-labor/neopg/pull/37) ([lambdafu](https://github.com/lambdafu))
- Remove support for preferred keyserver. [\#36](https://github.com/das-labor/neopg/pull/36) ([lambdafu](https://github.com/lambdafu))
- Remove custom DNS resolver [\#34](https://github.com/das-labor/neopg/pull/34) ([lambdafu](https://github.com/lambdafu))
- Clarify license in readme even more and move legacy config settings to legacy/ folder. [\#33](https://github.com/das-labor/neopg/pull/33) ([lambdafu](https://github.com/lambdafu))
- Replace custom http client with libcurl [\#28](https://github.com/das-labor/neopg/pull/28) ([lambdafu](https://github.com/lambdafu))
- Remove support for SRV records. [\#25](https://github.com/das-labor/neopg/pull/25) ([lambdafu](https://github.com/lambdafu))
- Remove support for web key directory \(WKD\). [\#24](https://github.com/das-labor/neopg/pull/24) ([lambdafu](https://github.com/lambdafu))
- Fix typo [\#22](https://github.com/das-labor/neopg/pull/22) ([jwilk](https://github.com/jwilk))
- Remove DNS CERT support. [\#18](https://github.com/das-labor/neopg/pull/18) ([lambdafu](https://github.com/lambdafu))
- Remove DANE/OPENPGPKEY support. [\#17](https://github.com/das-labor/neopg/pull/17) ([lambdafu](https://github.com/lambdafu))
- Remove PKA support. [\#16](https://github.com/das-labor/neopg/pull/16) ([lambdafu](https://github.com/lambdafu))
- Completely remove npth and all associated code. [\#14](https://github.com/das-labor/neopg/pull/14) ([lambdafu](https://github.com/lambdafu))
- Remove unused functions from libgpg-error. [\#13](https://github.com/das-labor/neopg/pull/13) ([lambdafu](https://github.com/lambdafu))
- Fix travis, support more compilers, and check code formatting. [\#12](https://github.com/das-labor/neopg/pull/12) ([lambdafu](https://github.com/lambdafu))

## [v0.0.3](https://github.com/das-labor/neopg/tree/v0.0.3) (2017-11-25)

[Full Changelog](https://github.com/das-labor/neopg/compare/v0.0.2...v0.0.3)

**Merged pull requests:**

- build instructions for macOS [\#9](https://github.com/das-labor/neopg/pull/9) ([fkr](https://github.com/fkr))
- point back to the original repo [\#8](https://github.com/das-labor/neopg/pull/8) ([fkr](https://github.com/fkr))
- fixing missing include causing unknown 'unique\_ptr' in legacy/gnupg/g10/keyid.cpp [\#7](https://github.com/das-labor/neopg/pull/7) ([bitpick](https://github.com/bitpick))

## [v0.0.2](https://github.com/das-labor/neopg/tree/v0.0.2) (2017-10-29)

[Full Changelog](https://github.com/das-labor/neopg/compare/v0.0.1...v0.0.2)

**Merged pull requests:**

- Travis CI [\#5](https://github.com/das-labor/neopg/pull/5) ([flanfly](https://github.com/flanfly))
- downgrade cmake req. to 3.5 [\#4](https://github.com/das-labor/neopg/pull/4) ([flanfly](https://github.com/flanfly))
- really fix gtest includes [\#3](https://github.com/das-labor/neopg/pull/3) ([flanfly](https://github.com/flanfly))

## [v0.0.1](https://github.com/das-labor/neopg/tree/v0.0.1) (2017-10-28)

[Full Changelog](https://github.com/das-labor/neopg/compare/a087039e7a959b33f0edfd9319b585a6eabdab2c...v0.0.1)

**Merged pull requests:**

- fix gtest includes [\#2](https://github.com/das-labor/neopg/pull/2) ([flanfly](https://github.com/flanfly))
- doc dev dependencies [\#1](https://github.com/das-labor/neopg/pull/1) ([flanfly](https://github.com/flanfly))



