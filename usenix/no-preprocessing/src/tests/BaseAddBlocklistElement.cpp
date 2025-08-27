
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
      ("numbits,n", po::value<int>()->default_value(1024), "Number of bits");

  po::variables_map vm;
  po::store(po::parse_command_line(argc, argv, desc), vm);
  po::notify(vm);

  if ( vm.count("help")) {
    std::cout << desc << "\n";
    return 0;
  }

  int numbits = vm["numbits"].as<int>();

  std::chrono::high_resolution_clock::time_point start;
  std::chrono::high_resolution_clock::time_point end;

  actors::Auditor aud(numbits);
  aud.AuditorInit();

  std::string b1string = "12345";
  std::string b2string = "abcdef";
  NTL::ZZ b1 = GetZZfromHexString(b1string); ;
  NTL::ZZ b2 = GetZZfromHexString(b2string); ;

  std::string b3string = "DEADBEEF";
  NTL::ZZ b3 = GetZZfromHexString(b3string);
  std::vector<NTL::ZZ> blist;
  std::vector<NTL::ZZ> applist;

  blist.push_back(b1);
  blist.push_back(b2);
  applist.push_back(b3);

  aud.SignBlockList(blist);

  start = std::chrono::high_resolution_clock::now();
  aud.AddToBlockList(applist);
  end = std::chrono::high_resolution_clock::now();
  
  std::chrono::milliseconds append_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
  std::cout << "Time to append to a block list: " << append_ms.count()  << " ms"<< std::endl;
}
