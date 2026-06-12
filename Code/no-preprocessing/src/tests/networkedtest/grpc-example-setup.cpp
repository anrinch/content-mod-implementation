#include "actors/Client.hpp"
#include "actors/Server.hpp"
#include <boost/lexical_cast.hpp>
#include <boost/lexical_cast/bad_lexical_cast.hpp>
#include <boost/program_options.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

int main(int argc, char *argv[]) {
  const int SERVER = 1;
  const int CLIENT = 0;
  namespace po = boost::program_options;
  po::options_description desc("Allowed options");

  // FIXME: the formatting is always off here
  desc.add_options()("help,h", "produce help message")(
      "blocklist,b", po::value<std::string>(), "Blocklist file with pHashes")(
      "config,c", po::value<std::string>()->default_value("config.json"),
      "JSON config file to read from")("addr,a", po::value<std::string>(),
                                       "<IPv4 server address>:<port>")(
      "role,r", po::value<std::string>(), "1 for server, 0 for client")(
      "einput,e", po::value<std::string>(),
      "input embedding for the client to send to the server")(
      "pinput,p", po::value<std::string>(), "plaintext value for the client");

  po::variables_map vm;
  po::store(po::parse_command_line(argc, argv, desc), vm);
  po::notify(vm);

  std::string rolestr;
  std::string serverAddr;
  std::string blocklistPath;
  std::string configPath;
  std::string clientPlaintext;
  std::string clientEmbedding;
  int role = -1;

  if (vm.count("help")) {
    std::cout << desc << std::endl;
    return 0;
  }

  // Example of how to access parsed options
  if (vm.count("blocklist")) {
    blocklistPath = vm["blocklist"].as<std::string>();
  }

  if (vm.count("config")) {
    configPath = vm["config"].as<std::string>();
  }

  if (vm.count("addr")) {
    serverAddr = vm["addr"].as<std::string>();
  }

  if (vm.count("role")) {
    rolestr = vm["role"].as<std::string>();
    role = std::stoi(rolestr);
  }

  if (vm.count("pinput")) {
    clientPlaintext = vm["pinput"].as<std::string>();
  }

  if (vm.count("einput")) {
    clientEmbedding = vm["einput"].as<std::string>();
  }

  std::filesystem::path config(configPath);
  std::filesystem::path blocklist(blocklistPath);

  if (role == SERVER) {
    // set up the gRPC server
    actors::JSONBasicSearchServerFactory sfac(config, blocklist);
    actors::GrpcBasicServer serv(serverAddr);
    serv.setSearchServer(sfac.CreateBasicSearchServer());

    std::cout << "server running @ " << serverAddr << std::endl;
    actors::RunServer(serv);
  } else if (role == CLIENT) {

    // set up gRPC client
    actors::JSONBasicClientFactory cfac(config);
    actors::BasicgRPCClientChannel clientChan(serverAddr);
    clientChan.setClient(cfac.CreateClient());
    clientChan.sendMessage(clientEmbedding, clientPlaintext);
  } else {
    std::cerr
        << "Invalid role, please use 1 or 0 for SERVER or CLIENT respecitivly"
        << std::endl;
  }
}
