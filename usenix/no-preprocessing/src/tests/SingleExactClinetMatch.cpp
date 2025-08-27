
#include "actors/Client.hpp"
#include <boost/lexical_cast.hpp>
#include <boost/lexical_cast/bad_lexical_cast.hpp>
#include <boost/program_options.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

int main(int argc, char *argv[]) {
  
  namespace po = boost::program_options;
  po::options_description desc("Allowed options");

  desc.add_options()("help,h", "produce help message")(
      "clientlist,l", po::value<std::string>(), "File of Hashes for the client to send")(
      "config,c", po::value<std::string>()->default_value("config.json"),
      "JSON config file to read from");


  po::variables_map vm;
  po::store(po::parse_command_line(argc, argv, desc), vm);
  po::notify(vm);

  if (vm.count("help")) {
    std::cout << desc << std::endl;
    return 0;
  }

  std::string configPath;
  std::string clientlistPath;

  if (vm.count("config")) {
    configPath = vm["config"].as<std::string>();
  }

  if (vm.count("clientlist")) {
    clientlistPath = vm["clientlist"].as<std::string>();
  }

  std::filesystem::path config(configPath);
  //std::filesystem::path clientlist(clientlistPath);
  actors::JSONBasicClientFactory cfac(config);
  std::string item = "01f5cd852f2100fcaf4a0abbbaf438dc790fc2fe7a255d8d15b328b598f75a51";
  std::string dummyTest = "This is a tests string!";
  std::unique_ptr<actors::BasicDpsiClient> clientTest = cfac.CreateClient();
  std::ifstream inputFile(clientlistPath);

  //set up timer
  std::chrono::high_resolution_clock::time_point start;
  std::chrono::high_resolution_clock::time_point end;
  start = std::chrono::high_resolution_clock::now();

  clientTest->computeAndEncrypt(item, dummyTest);

  end = std::chrono::high_resolution_clock::now();

  std::chrono::milliseconds client_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
  std::cout << "Time: " << client_time_ms.count() << " ms" << std::endl;
}
