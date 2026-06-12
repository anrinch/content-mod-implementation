
#include "DpsiUtils.hpp"
#include "Projections.hpp"
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

int main(int argc, char *argv[]) { NTL::SetSeed(NTL::ZZ(0));
  namespace po = boost::program_options;
  po::options_description desc("Allowed options");
  desc.add_options()
      ("help,h", "produce help message")
      ("projections,p", po::value<int>(), "number of projections")
      ("numbits,n", po::value<int>()->default_value(1024), "Number of bits");

  po::variables_map vm;
  po::store(po::parse_command_line(argc, argv, desc), vm);
  po::notify(vm);

  if (argc == 1 || vm.count("help")) {
    std::cout << desc << "\n";
    return 0;
  }

  int numbits = vm["numbits"].as<int>();
  int projections = vm["projections"].as<int>();

  actors::FuzzyAuditor aud(numbits); 

  //make a single block list item
  aud.AuditorInit(projections, 256, 50);
 
  std::string testhash = "083bf3fec698dad766a50436605b7a9f6a8a51b66f5717dedf3eb0ca01b22f0c";
  NTL::ZZ b = GetZZfromHexString(testhash);

  std::vector<NTL::ZZ> blocklist;
  blocklist.push_back(b);

  aud.SignBlockList(blocklist);


  //set up the client
  actors::FullDpsiClient client(256, aud.getN(), aud.getG(), aud.getSigs(), aud.getProjections());
  std::string plaintext = "This is a test!";
  std::string embedding = "5ea173c236a67d3532f11a9888b54a2a37f4fc6b712d504eb258a342526e8969";

  std::chrono::high_resolution_clock::time_point start;
  std::chrono::high_resolution_clock::time_point end;

  start = std::chrono::high_resolution_clock::now();
  std::atomic_thread_fence(std::memory_order_seq_cst);
  
  client.computeAndEncrypt(embedding, plaintext);

  end = std::chrono::high_resolution_clock::now();
  std::atomic_thread_fence(std::memory_order_seq_cst);

  std::chrono::milliseconds compute_time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

  std::cout << "Number of projections: " << projections << std::endl;
  std::cout << "Mod N bits: " << (numbits * 2) << std::endl;
  std::cout << "Cleint Side compute time: " << compute_time.count()  << " ms"<< std::endl;
  std::cout << "===============================" << std::endl;
}

