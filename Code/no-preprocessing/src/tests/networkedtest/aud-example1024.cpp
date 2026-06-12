
#include "DpsiUtils.hpp"
#include "actors/Auditor.hpp"
#include <boost/lexical_cast.hpp>
#include <boost/lexical_cast/bad_lexical_cast.hpp>
#include <boost/program_options.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <fstream>

int main(int argc, char *argv[]) {

  namespace po = boost::program_options;
  po::options_description desc("Allowed options");

  desc.add_options()("help,h", "produce help message")(
      "blocklist,b", po::value<std::string>(), "Blocklist file with pHashes");

  po::variables_map vm;
  po::store(po::parse_command_line(argc, argv, desc), vm);
  po::notify(vm);

  std::string blocklistPath;

  if (vm.count("blocklist")) {
    blocklistPath = vm["blocklist"].as<std::string>();
  }
  int numbits = 1024;

  // SetSeed(ZZ(10));
  //  Auditor
  std::filesystem::path hashfile(blocklistPath);
  actors::IOAuditorJSON aud(numbits);
  aud.parseHashFile(hashfile);
  aud.generateConfigJSON();
  return 0;
}
