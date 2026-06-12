#include "DpsiUtils.hpp"
#include "actors/Auditor.hpp"
#include "actors/Client.hpp"
#include "actors/Server.hpp"
#include <NTL/ZZ.h>
#include <exception>
#include <fstream>
#include <vector>

int main(int argc, char *argv[]) {
  // SetSeed(ZZ(10));
  int numbits = 1024;
  //  tested this with another blocklist of 100 hashses and it still works
  std::filesystem::path blockListFileName("TestBlockList");
  // std::filesystem::path configPath("testConfig.json");
  GenTestHashFile(blockListFileName);
  std::string match =
      "01f5cd852f2100fcaf4a0abbbaf438dc790fc2fe7a255d8d15b328b598f75a51";
  std::string plaintextMatch = "Match Found!";

  // add an extra hexvalue that we will match on
  // you can have a block list of however long you want
  // std::ofstream hashfile(blockListFileName, std::ios::app);
  // hashfile << match << std::endl;
  // hashfile.close();

  // Auditor
  actors::IOAuditorJSON aud(numbits);
  aud.parseHashFile(blockListFileName);
  // aud.generateConfigJSON(configPath);
  aud.generateConfigJSON();

  // create a client (or multiple clients with a Client Factory)
  actors::JSONBasicClientFactory clientFactory(aud.GetJSONConfigFile());
  std::unique_ptr<actors::BasicDpsiClient> clientMatch =
      clientFactory.CreateClient();
  clientMatch->computeAndEncrypt(match, plaintextMatch);

  // Client sends its payload to the server
  // ............................................
  // Server receives each client and processes it

  // Here the client information has been loaded
  std::string recoveredtext;
  std::string cprime = clientMatch->getCprime();
  NTL::ZZ_p c = clientMatch->getC();
  NTL::ZZ iv = clientMatch->getIV();

  std::cout << cprime.length() << std::endl;

  std::cout << "CLIENT GRMN: " << clientMatch->getgrmN() << std::endl;
  // Init server factory through the JSON config file
  actors::JSONBasicSearchServerFactory serverFactory(aud.GetJSONConfigFile(),
                                                     blockListFileName);
  std::cout << "CPRIME Length: " << cprime.length() << std::endl;
  unsigned char ivbytes[AES_IV_SIZE * 8];
  NTL::BytesFromZZ(ivbytes, iv, AES_IV_SIZE);

  // server is craeted through the Factory
  // multiple server isntaces can be spawned from the same factory
  std::unique_ptr<actors::BasicSearchServer> testServer =
      serverFactory.CreateBasicSearchServer();

  testServer->enable_benchmarking(true);

  bool matchTrue;
  try {
    matchTrue = testServer->checkMatches(cprime, recoveredtext, c, ivbytes);
  } catch (...) {
    std::cout << "Something went wrong" << std::endl;
  }

  if (matchTrue) {
    std::cout
        << "server was able to decrypt the plaintext provided by the client"
        << "\n"
        << "server took " << testServer->gettime().count() << "ms" << std::endl;
  } else {
    std::cout << "no match found" << std::endl;
  }

  // clean up, get rid of the test file
  // std::filesystem::remove(blockListFileName);
  // std::filesystem::remove(configPath);

  return 0;
}
