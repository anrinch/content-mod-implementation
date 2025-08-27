#include "DpsiUtils.hpp"
#include "actors/Auditor.hpp"
#include "actors/Client.hpp"
#include "actors/Server.hpp"
#include <DetectableHashFunction.hpp>
#include <DynamicBlockList.hpp>
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/ZZ_pX.h>
#include <NTL/mat_ZZ_p.h>
#include <NTL/vec_ZZ_p.h>
#include <cstdio>
#include <fstream>
#include <filesystem>
#include <sstream>
#include <vector>
#include <chrono>
#include <boost/lexical_cast.hpp>
#include <boost/lexical_cast/bad_lexical_cast.hpp>
#include <boost/program_options.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

int main(int argc, char *argv[]) {
  NTL::SetSeed(NTL::ZZ(0));
  namespace po = boost::program_options;
  po::options_description desc("Allowed options");
  desc.add_options()
      ("help,h", "produce help message")
      ("blocklist,b", po::value<std::string>(), "Blocklist file with pHashes")
      ("numbits,n", po::value<int>()->default_value(1024), "Number of bits")
      ("numproj,p", po::value<int>()->default_value(10), "Number of bits");

  po::variables_map vm;
  po::store(po::parse_command_line(argc, argv, desc), vm);
  po::notify(vm);

  if (argc == 1 || vm.count("help")) {
    std::cout << desc << "\n";
    return 0;
  }

  std::string blocklistPath;
  if (vm.count("blocklist")) {
    blocklistPath = vm["blocklist"].as<std::string>();
  } else {
    std::cerr << "Error: Blocklist file not provided.\n";
    std::cout << desc << "\n";
    return 1;
  }

  int numbits = vm["numbits"].as<int>();
  int numproj = vm["numproj"].as<int>();

  std::ifstream infile(blocklistPath);
  if (!infile) {
    std::cerr << "Failed to open file: " << blocklistPath << '\n';
    return 1;
  }

  std::filesystem::path hashfile(blocklistPath);
  actors::IOFuzzyAuditorJSON aud(numbits, numproj, 256, 50);
  aud.parseHashFile(hashfile);

  std::vector<std::string> lines;
  std::string line;
  while (std::getline(infile, line)) {
    if (!line.empty()) {
      lines.push_back(line);
    }
  }

  std::string firstline = lines.front();

  // Set up Server
  actors::FullSearchServer serv(256, aud.getN(), aud.getSigs(), aud.getProjections());

  std::vector<NTL::ZZ> blocklist;
  for( auto line : lines) {
      blocklist.push_back(GetZZfromHexString(line));
  }

  serv.fullInitBlockList(blocklist);

  std::chrono::high_resolution_clock::time_point start;
  std::chrono::high_resolution_clock::time_point end;

  // set up Client
  actors::FullDpsiClient client(256, aud.getN(), aud.getG(), aud.getSigs(), aud.getProjections());

  // set timer here
  std::string plaintext = "This is a test!";

  // edit the string ever so slightly
  if(firstline[0] == 'a') {
    firstline[0] = 'b';
  } else {
    firstline[0] = 'a';
  }

  
  start = std::chrono::high_resolution_clock::now();
  client.computeAndEncrypt(firstline, plaintext);
  end = std::chrono::high_resolution_clock::now();
  std::chrono::milliseconds client_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);


  start = std::chrono::high_resolution_clock::now();
  std::atomic_thread_fence(std::memory_order_seq_cst);

  //set timer here
  bool res1 = serv.checkMatches(client.getCprime_ss(), client.getCprime_dhf(), client.getCprime(), client.getC());
  end = std::chrono::high_resolution_clock::now();
  std::atomic_thread_fence(std::memory_order_seq_cst);

  std::chrono::milliseconds time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);


  std::cout << "Number of elemets: " << aud.GetBlockListSize() << std::endl;
  std::cout << "Mod N bits: " << (numbits * 2) << std::endl;
  std::cout << "Projection number: " << numproj << std::endl;
  std::cout << "Number of Signatures: " << aud.getSigs().size() << std::endl;
  std::cout << "Client compute time: " << client_ms.count() << " ms"<< std::endl;
  std::cout << "Client compute DHF time: " << client.getDHFtime().count() << " ms"<< std::endl;
  std::cout << "Server time for match: " << time_ms.count()  << " ms"<< std::endl;
  std::cout << "Server time spent on DHF: " << serv.getDHFtime().count()  << " ms"<< std::endl;
  std::cout << "Server time spent on Exponentiation: " << serv.getExptime().count()  << " ms"<< std::endl;
  if (res1 == true) {
    std::cout << "MATCH FOUND" << std::endl;
  }else {
    std::cout << "NO MATCH FOUND" << std::endl;

  }
  std::cout << "===============================" << std::endl;

  
}
