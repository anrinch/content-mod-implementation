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
#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/benchmark/catch_benchmark_all.hpp>
#include <catch2/catch_test_macros.hpp>
#include <cryptopp/cryptlib.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/gcm.h>
#include <cryptopp/hex.h>
#include <cryptopp/misc.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rijndael.h>
#include <cstdio>
#include <fstream>
#include <memory>
#include <sstream>
#include <vector>
#include <Projections.hpp>

using namespace NTL;

TEST_CASE("Polyshare fail" , "[Share]") {
  NTL::SetSeed(NTL::ZZ(0));

  long NUM_SHARES = 26;
  NTL::ZZ_pX poly = getRandPoly(50);
  
  NTL::ZZ key =  getKeyFromPoly(poly);
  REQUIRE(NTL::IsZero(key) == 0);

  std::vector<NTL::ZZ> ycoords = PolySecretShare(NUM_SHARES, poly);

  //we will need to keep track of the x coords too
  std::vector<NTL::ZZ> xcoords;

  for(long x = 1; x <= NUM_SHARES; x++ ) {
    xcoords.push_back(NTL::ZZ(x));
  }

  NTL::ZZ secret = PolyShareInterpolate(xcoords, ycoords);
  REQUIRE(secret != key);
}

TEST_CASE("Polyshare test degree 100" , "[Share]") {
  NTL::SetSeed(NTL::ZZ(0));

  long NUM_SHARES = 256;
  NTL::ZZ_pX poly = getRandPoly(100);
  
NTL::ZZ key =  getKeyFromPoly(poly);
  REQUIRE(NTL::IsZero(key) == 0);

  std::vector<NTL::ZZ> ycoords = PolySecretShare(NUM_SHARES, poly);

  //we will need to keep track of the x coords too
  std::vector<NTL::ZZ> xcoords;

  for(long x = 1; x <= NUM_SHARES; x++ ) {
    xcoords.push_back(NTL::ZZ(x));
  }

  NTL::ZZ secret = PolyShareInterpolate(xcoords, ycoords);
  REQUIRE(secret == key);
}

TEST_CASE("Polyshare test" , "[Share]") {
  NTL::SetSeed(NTL::ZZ(0));

  long NUM_SHARES = 4;
  NTL::ZZ_pX poly = getRandPoly(NUM_SHARES-1);
  
  NTL::ZZ key =  getKeyFromPoly(poly);
  REQUIRE(NTL::IsZero(key) == 0);

  std::vector<NTL::ZZ> ycoords = PolySecretShare(NUM_SHARES, poly);

  //we will need to keep track of the x coords too
  std::vector<NTL::ZZ> xcoords;

  for(long x = 1; x <= NUM_SHARES; x++ ) {
    xcoords.push_back(NTL::ZZ(x));
  }

  NTL::ZZ secret = PolyShareInterpolate(xcoords, ycoords);
  REQUIRE(secret == key);
}

TEST_CASE("random projection test" , "[Proj]") {
  NTL::SetSeed(NTL::ZZ(0));
 
  //4 functions to map 256 to 100
  std::vector<NTL::ZZ> projections = psi_proj::getProjections(4, 256, 100);

  NTL::ZZ element0(0);

  for(auto mask : projections) {
    NTL::ZZ test = psi_proj::evalProjectionFunc(mask, element0);
    REQUIRE(test == element0);
  } 

  for(auto mask : projections) {
    NTL::ZZ test = psi_proj::evalProjectionFunc(mask, mask);
    REQUIRE(test == mask);
  } 

  for(auto mask : projections) {
    REQUIRE(NTL::weight(mask) == 100);
  }

}

TEST_CASE("cprime as a byte string") {
  // debugging how a string cipher text is stored
  // we care about this for serialization over the network

  // set up Auditor
  int numbits = 128;
  std::string stringblocklist[] = {
      "083bf3fec698dad766a50436605b7a9f6a8a51b66f5717dedf3eb0ca01b22f0c",
      "8009c4ade6f9da066b786896d13d1b144ca40d1c16bfc983f765db7e2f4d7552",
      "01f5cd852f2100fcaf4a0abbbaf438dc790fc2fe7a255d8d15b328b598f75a51"};

  actors::Auditor aud(numbits);
  aud.AuditorInit();
  std::vector<NTL::ZZ> blocklist;
  for (auto item : stringblocklist) {
    std::cout << item << std::endl;
    blocklist.push_back(GetZZfromHexString(item));
  }
  // init the ZZ_p or else this won't work
  aud.SignBlockList(blocklist);

  // Set up client
  actors::BasicDpsiClient cl(aud.getSig(), aud.getG(), aud.getN());
  std::string embedding =
      "01f5cd852f2100fcaf4a0abbbaf438dc790fc2fe7a255d8d15b328b598f75a51";
  std::string pltext = "test";
  cl.computeAndEncrypt(embedding, pltext);

  std::string ciphertext = cl.getCprime();

  // make sure we can actually decrpyt and recover
  // unsigned char key[AES_KEY_SIZE];
  // unsigned char ivbytes[AES_IV_SIZE];
  // std::string recv;
  // cl.getIV();
  // NTL::ZZ keyZZ = GetKey(cl.getC(), AES_KEY_SIZE * 8);
  // AES128KEY256DecryptStrings(rcv, ciphertext, key, iv);

  std::cout << cl.getCprime() << std::endl;

  REQUIRE(true);
}

TEST_CASE("SHA-256 from CryptoPP") {
  std::string plaintext = "this is a test";
  std::string digest;
  std::string encodedDigest; // Hex output will be stored here

  CryptoPP::SHA256 hash;
  hash.Update((const CryptoPP::byte *)plaintext.data(), plaintext.size());
  digest.resize(hash.DigestSize());
  hash.Final((CryptoPP::byte *)&digest[0]);

  // Convert digest to hex string
  CryptoPP::StringSource(
      digest, true,
      new CryptoPP::HexEncoder(new CryptoPP::StringSink(encodedDigest)));

  // Output to verify
  REQUIRE(encodedDigest ==
          "2E99758548972A8E8822AD47FA1017FF72F06F3FF6A016851F45C398732BC50C");
}

TEST_CASE("Base mod blocklist", "[append]") {

  // Set up
  SetSeed(ZZ(10));
  int numbits = 128;

  // Auditor
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
  aud.AddToBlockList(applist);

  actors::BasicDpsiClient client(aud.getSig(), aud.getG(), aud.getN());
  std::string pltext = "this is a test!";
  client.computeAndEncrypt(b3string, pltext);

  NTL::ZZ N = aud.getN();
  NTL::ZZ_p sig = aud.getSig();
  actors::BasicSearchServer serv(N, sig);

  //Set up Server with updated blocklist
  std::vector<NTL::ZZ> server_embeddings;
  server_embeddings.push_back(b1);
  server_embeddings.push_back(b2);
  server_embeddings.push_back(b3);

  serv.basicInitBlockList(server_embeddings);

  std::string recoveredtext;
  std::string cprime = client.getCprime();
  NTL::ZZ_p c = client.getC();
  NTL::ZZ iv = client.getIV();
  unsigned char ivbytes[AES_IV_SIZE];
  NTL::BytesFromZZ(ivbytes, iv, AES_IV_SIZE);
  bool match;

  try {
    match = serv.checkMatches(cprime, recoveredtext, c, ivbytes);
  } catch (CryptoPP::Exception &e) {
    std::cout << "Here is what went wrong: " << e.GetWhat() << std::endl;
  }

  REQUIRE(match==true);
}



TEST_CASE("Basic AuditorClientServer") {
  // this is an example test to show how you can call the and build the Auditor,
  // Server and Client

  // Set up
  SetSeed(ZZ(10));
  int numbits = 128;
  std::filesystem::path blockListFileName("testBlockList");
  std::filesystem::path configPath("testConfig.json");
  GenTestHashFile(blockListFileName);
  std::string match = "11111111";
  std::string plaintextMatch = "Match Found!";

  // add an extra hexvalue that we will match on
  std::ofstream hashfile(blockListFileName, std::ios::app);
  hashfile << match << std::endl;
  hashfile.close();

  // Auditor
  actors::IOAuditorJSON aud(numbits);
  aud.parseHashFile(blockListFileName);
  aud.generateConfigJSON(configPath);

  // create a client (or multiple clients with a Client Factory)
  actors::JSONBasicClientFactory clientFactory(aud.GetJSONConfigFile());
  std::unique_ptr<actors::BasicDpsiClient> clientMatch =
      clientFactory.CreateClient();
  clientMatch->computeAndEncrypt(match, plaintextMatch);
  // actors::BasicDpsiClient clientNoMatch = clientFactory.CreateClient();
  // clientNoMatch.computeAndEncrypt(NoMatch, plaintextMatch);

  // Client sends its payload to the server
  // ............................................
  // Server receives each client and processes it

  // Server set up

  // manually follow what should be happening:

  actors::JSONBasicSearchServerFactory serverFactory(aud.GetJSONConfigFile(),
                                                     blockListFileName);

  std::unique_ptr<actors::BasicSearchServer> testServer =
      serverFactory.CreateBasicSearchServer();

  std::string recoveredtext;
  std::string cprime = clientMatch->getCprime();
  NTL::ZZ_p c = clientMatch->getC();
  NTL::ZZ iv = clientMatch->getIV();
  unsigned char ivbytes[AES_IV_SIZE];
  NTL::BytesFromZZ(ivbytes, iv, AES_IV_SIZE);
  bool matchTrue;

  try {
    matchTrue = testServer->checkMatches(cprime, recoveredtext, c, ivbytes);
  } catch (CryptoPP::Exception &e) {
    std::cout << "Here is what went wrong: " << e.GetWhat() << std::endl;
  }

  REQUIRE(matchTrue == true);
  REQUIRE(recoveredtext == plaintextMatch);

  // clean up, get rid of the test file
  std::filesystem::remove(blockListFileName);
  std::filesystem::remove(configPath);
}

TEST_CASE("String Encryption/Decryption test") {
  unsigned char key[AES_KEY_SIZE];
  unsigned char iv[AES_IV_SIZE];

  std::string enc("Encrypt me!");
  std::string output;
  std::string recover;

  AES128KEY256EncryptStrings(output, enc, key, iv);
  AES128KEY256DecryptStrings(recover, output, key, iv);
  REQUIRE(enc == recover);

  unsigned char key2[AES_KEY_SIZE] = {1};
  AES128KEY256EncryptStrings(output, enc, key, iv);

  REQUIRE_THROWS_AS(AES128KEY256DecryptStrings(recover, output, key2, iv),
                    CryptoPP::HashVerificationFilter::HashVerificationFailed);
}

TEST_CASE("Auditor Setup") { actors::Auditor aud(1024); }

TEST_CASE("DHF expansion test", "[DHF]") {

  NTL::ZZ field = DHF::GetField();
  NTL::ZZ_p::init(field);

  int t = 3;
  int s = 3;
  //std::vector<NTL::ZZ_p> inputs = {NTL::ZZ_p(2),NTL::ZZ_p(3),NTL::ZZ_p(4),NTL::ZZ_p(5),NTL::ZZ_p(6)};
  std::vector<NTL::ZZ_p> inputs = {NTL::ZZ_p(2),NTL::ZZ_p(3),NTL::ZZ_p(4),NTL::ZZ_p(5),NTL::ZZ_p(6),NTL::ZZ_p(7)};
  //std::vector<NTL::ZZ_p> inputs = {NTL::ZZ_p(2),NTL::ZZ_p(3),NTL::ZZ_p(4),NTL::ZZ_p(5)};
  int m = inputs.size();
  NTL::ZZ_pX s0;
  NTL::ZZ_pX s1;
  NTL::ZZ_pX s2;

  NTL::SetCoeff(s0, 0, 1);
  NTL::SetCoeff(s0, 1, 2);
  NTL::SetCoeff(s0, 2, 3);
  NTL::SetCoeff(s0, 3, 4);

  NTL::SetCoeff(s1, 0, 6);
  NTL::SetCoeff(s1, 1, 7);
  NTL::SetCoeff(s1, 2, 8);
  NTL::SetCoeff(s1, 3, 9);

  NTL::SetCoeff(s2, 0, 10);
  NTL::SetCoeff(s2, 1, 11);
  NTL::SetCoeff(s2, 2, 12);
  NTL::SetCoeff(s2, 3, 13);

  std::vector<NTL::ZZ_pX> key;
  key.push_back(s0);
  key.push_back(s1);
  key.push_back(s2);

  //generate inputs
  std::vector<vec_ZZ_p> inputvectors;
  for (int i = 0; i < m; i++) {
    vec_ZZ_p invec;
    invec = DHF::DHFk_xi(key, inputs.at(i));
    inputvectors.push_back(invec);
  }

  NTL::mat_ZZ_p expanded;
  expanded = DHF::ExpandNTLVecsIntoNTLMatrix(inputvectors,t);

  NTL::mat_ZZ_p testker;
  NTL::mat_ZZ_p expandedtranspose = NTL::transpose(expanded);
  NTL::kernel(testker, expandedtranspose);

  //test right kernel
  NTL::vec_ZZ_p res = expanded * testker[0];
  REQUIRE(NTL::IsZero(res) == 1);

  NTL::SetSeed(NTL::ZZ(0));
  std::vector<vec_ZZ_p> randvectors;
  
  for (int i = 0; i < (s+t); i++) {
    vec_ZZ_p invec;
    invec = NTL::random_vec_ZZ_p(key.size()+1);
    randvectors.push_back(invec);
  }

  // Expanding random vectors yields nothing
  NTL::mat_ZZ_p expandedrandom;
  expandedrandom = DHF::ExpandNTLVecsIntoNTLMatrix(randvectors,t);
  NTL::mat_ZZ_p expandedrandomtranspose = NTL::transpose(expandedrandom);
  NTL::mat_ZZ_p randomker;
  NTL::kernel(randomker, expandedrandomtranspose);
  REQUIRE(NTL::IsZero(randomker) == 1);
 
  // take all non-zero indicies of a vector in the right kernel
  std::vector<int> subidxs;
  for(int i = 0; i < testker[0].length(); i++) {
    if(testker[0][i] != 0) {
      subidxs.push_back(i);
    }
  }

  NTL::mat_ZZ_p submatrix;
  submatrix.SetDims(subidxs.size(), (s+t));
  for(int i = 0; i < subidxs.size(); i++) {
    submatrix[i] = expandedtranspose[subidxs.at(i)];
  }

  //figure out which of the vectors are in the linear span of the submatrix
  std::vector<int> outidx;
  for(int i = 0; i < expandedtranspose.NumRows(); i++) {
    NTL::mat_ZZ_p augmentedtranspose;
    augmentedtranspose.SetDims(submatrix.NumRows() + 1, (s+t));

    for(int j = 0; j < submatrix.NumRows(); j++) {
      augmentedtranspose[j] = submatrix[j];
    }

    augmentedtranspose[submatrix.NumRows()] = expandedtranspose[i];
    NTL::mat_ZZ_p augmented = NTL::transpose(augmentedtranspose);

    long rank = NTL::gauss(augmented);
    if (DHF::IsInLinearSpan(augmented, rank)) {
      outidx.push_back(i);
    }
  }

  REQUIRE(outidx.size() == expanded.NumCols());
}

TEST_CASE("Some DHF and some fake vectors", "[DHF]") {
  SetSeed(ZZ(0));
  ZZ l = DHF::GetField();
  ZZ_p::init(l);

  long s, t, real;
  t = 200;
  s = 56;
  real = 200;

  std::vector<ZZ_pX> key = DHF::DHFGenKey(s, t-1);
  std::vector<vec_ZZ_p> inputvectors;

  // need a certain amount of inputs for detection
  for (int i = 0; i < real; i++) {
    vec_ZZ_p invec;
    invec = DHF::DHFk_xi(key, NTL::random_ZZ_p());
    inputvectors.push_back(invec);
  }

  for (int i = real; i < 256; i++) {
    vec_ZZ_p fake;
    fake = NTL::random_vec_ZZ_p(key.size() + 1);
    inputvectors.push_back(fake);
  }

  std::vector<int> outputidx = DHF::DHFdetect(inputvectors, t-1);

  //No detection
  std::vector<NTL::vec_ZZ_p> inputfail(inputvectors.begin(), inputvectors.begin() + 3);
  std::vector<int> detectfail = DHF::DHFdetect(inputfail, t-1);
  REQUIRE(detectfail.size() == 0);

  //detection
  std::vector<NTL::vec_ZZ_p> inputsuccess(inputvectors.begin(), inputvectors.begin() + 256);
  std::vector<int> detectsuccess = DHF::DHFdetect(inputsuccess, t-1);
  REQUIRE(detectsuccess.size() > 0);
  REQUIRE(outputidx.size() == real);
}

TEST_CASE("DHF all DHF vectors", "[DHF]") {
  SetSeed(ZZ(0));
  ZZ l = DHF::GetField();
  ZZ_p::init(l);

  long s, t;
  t = 3;
  s = 3;

  std::vector<ZZ_pX> key = DHF::DHFGenKey(s, t);
  std::vector<vec_ZZ_p> inputvectors;

  // need a certain amount of inputs for detection
  for (int i = 0; i < (s+t); i++) {
    vec_ZZ_p invec;
    invec = DHF::DHFk_xi(key, NTL::random_ZZ_p());
    inputvectors.push_back(invec);
  }

  std::vector<int> outputidx = DHF::DHFdetect(inputvectors, t);

  //No detection
  std::vector<NTL::vec_ZZ_p> inputfail(inputvectors.begin(), inputvectors.begin() + 3);
  std::vector<int> detectfail = DHF::DHFdetect(inputfail, t);
  REQUIRE(detectfail.size() == 0);

  //detection
  std::vector<NTL::vec_ZZ_p> inputsuccess(inputvectors.begin(), inputvectors.begin() + 4);
  std::vector<int> detectsuccess = DHF::DHFdetect(inputsuccess, t);
  REQUIRE(detectsuccess.size() > 0);

  REQUIRE(outputidx.size() == inputvectors.size());
}

TEST_CASE("DHF two fake vectors", "[DHF]") {
  SetSeed(ZZ(0));
  ZZ l = DHF::GetField();
  ZZ_p::init(l);

  long s, t;
  t = 3;
  s = 3;

  std::vector<ZZ_pX> key = DHF::DHFGenKey(s, t);

  std::vector<vec_ZZ_p> inputvectors;

  // t+1 vectors should ensure detetction
  for (int i = 0; i < (s+t-2); i++) {
    vec_ZZ_p invec;
    invec = DHF::DHFk_xi(key, random_ZZ_p());
    inputvectors.push_back(invec);
  }

  // create a fake vector
  vec_ZZ_p fake1;
  vec_ZZ_p fake2;
  fake1 = NTL::random_vec_ZZ_p(key.size() + 1);
  fake2 = NTL::random_vec_ZZ_p(key.size() + 1);

  inputvectors.push_back(fake1);
  inputvectors.push_back(fake2);

  std::vector<int> outputidx = DHF::DHFdetect(inputvectors, t);

  //No detection
  std::vector<NTL::vec_ZZ_p> inputfail(inputvectors.begin(), inputvectors.begin() + 3);
  std::vector<int> detectfail = DHF::DHFdetect(inputfail, t);
  REQUIRE(detectfail.size() == 0);

  //detection
  std::vector<NTL::vec_ZZ_p> inputsuccess(inputvectors.begin(), inputvectors.begin() + 4);
  std::vector<int> detectsuccess = DHF::DHFdetect(inputsuccess, t);
  REQUIRE(detectsuccess.size() > 0);

  std::vector<int> expected = {0,1,2,3}; 
  REQUIRE(outputidx.size() == (s+t-2));
  REQUIRE(outputidx == expected);
}

TEST_CASE("DHF all fake vectors", "[DHF]") {
  SetSeed(ZZ(0));
  ZZ l = DHF::GetField();
  ZZ_p::init(l);

  long s, t;
  t = 3;
  s = 3;

  std::vector<ZZ_pX> key = DHF::DHFGenKey(s, t);

  std::vector<vec_ZZ_p> inputvectors;

  for (int i = 0; i < (s+t); i++) {
    vec_ZZ_p invec;
    invec = NTL::random_vec_ZZ_p(key.size()+1);
    inputvectors.push_back(invec);
  }

  std::vector<int> outputidx = DHF::DHFdetect(inputvectors, t);

  REQUIRE(outputidx.size() == 0);
}

TEST_CASE("fuzzy calculation", "[OTP]") {
  NTL::SetSeed(NTL::ZZ(0));
  //actors::FuzzyAuditor aud(512); 

  //make a single block list item
  //aud.AuditorInit(1, 256, 100);
  int numbits = 512;
  long l = 256; 
  std::string testhash = "083bf3fec698dad766a50436605b7a9f6a8a51b66f5717dedf3eb0ca01b22f0c";
  NTL::ZZ b = GetZZfromHexString(testhash);

  NTL::ZZ p;
  NTL::ZZ q;
  NTL::ZZ N;
  NTL::ZZ pprime;
  NTL::ZZ qprime;
  NTL::ZZ QRorder;
  NTL::ZZ Norder;
  NTL::ZZ_p g;

  SetUpInputs(numbits,p,q,N,pprime,qprime,QRorder,Norder,g); 

  std::vector<NTL::ZZ> blocklist;
  blocklist.push_back(b);

  //just one projection
  std::vector<NTL::ZZ> projs = psi_proj::getProjections(1, l, 200);
  std::vector<std::vector<NTL::ZZ>> evalprojections;

  //What the auditor should do:
  for(auto proj: projs) {
    std::vector<NTL::ZZ> evalprojections_j;
    for(auto b : blocklist) {
      evalprojections_j.push_back(psi_proj::evalProjectionFunc(proj, b));
    }
    evalprojections.push_back(evalprojections_j);
  }

  
  // perform hashing
  std::vector<std::vector<NTL::ZZ>> elementsToAccumulate;

  for(long j = 0; j < projs.size(); j++) {
    NTL::ZZ proj = projs[j];
    std::vector<NTL::ZZ> elements_j;
    for( long i = 0; i < evalprojections[j].size(); i++) {
      NTL::ZZ z = evalprojections[j][i];
      for(long k = 0; k < l; k++) {
        long zk = NTL::bit(z,k);
        NTL::ZZ hashPreImg = fuzzyConcatInputs(proj, zk, k, z);       
        elements_j.push_back(GetPrimeLessThanN(hashPreImg, NUM_OF_PRIME_ORACLE_BITS));
      }
    }
    elementsToAccumulate.push_back(elements_j); 
  }
  
  //generate the signatures
  NTL::ZZ_p::init(QRorder);

  std::vector<NTL::ZZ_p> sigs;
  std::vector<NTL::ZZ> exps;
  for(long j = 0; j < projs.size(); j++) {
    NTL::ZZ_p bprod = NTL::ZZ_p(1);
    for(long i = 0; i < elementsToAccumulate[j].size(); i++) {
      bprod *= NTL::conv<ZZ_p>(elementsToAccumulate[j][i]);
    }
    exps.push_back(NTL::conv<ZZ>(NTL::inv(bprod)));
  }
  

  NTL::ZZ_p::init(N);
  for(auto exp : exps) {
    sigs.push_back(NTL::power(g, exp));
  }

  //NOW TEST IF THE SIG ACTUALLY WORKS
  
  NTL::ZZ_p sigtest(sigs[0]);
  for(auto element : elementsToAccumulate[0]) {
    sigtest = NTL::power(sigtest, element);
  }
  
  REQUIRE(g == sigtest);
}

TEST_CASE("Simple Fuzzy protocol test", "[Fuzzy]") {
  NTL::SetSeed(NTL::ZZ(0));
  actors::FuzzyAuditor aud(512); 

  //make a single block list item
  aud.AuditorInit(1, 256, 50);

  std::string testhash = "083bf3fec698dad766a50436605b7a9f6a8a51b66f5717dedf3eb0ca01b22f0c";
  NTL::ZZ b = GetZZfromHexString(testhash);
  NTL::ZZ b1 = GetZZfromHexString("8009c4ade6f9da066b786896d13d1b144ca40d1c16bfc983f765db7e2f4d7552");
  NTL::ZZ b2 = GetZZfromHexString("01f5cd852f2100fcaf4a0abbbaf438dc790fc2fe7a255d8d15b328b598f75a51");

  std::vector<NTL::ZZ> blocklist;
  blocklist.push_back(b);
  blocklist.push_back(b1);
  blocklist.push_back(b2);

  aud.SignBlockList(blocklist);

  //create the server
  actors::FullSearchServer serv(256, aud.getN(), aud.getSigs(), aud.getProjections());
  serv.fullInitBlockList(blocklist);

  //make the client + input
  actors::FullDpsiClient client(256, aud.getN(), aud.getG(), aud.getSigs(), aud.getProjections());
  std::string plaintext = "This is a test!";
  client.computeAndEncrypt(testhash, plaintext);

  bool res = serv.checkMatches(client.getCprime_ss(), client.getCprime_dhf(), client.getCprime(), client.getC());
  REQUIRE(res == true);
}

TEST_CASE("Fuzzy protocol test", "[Fuzzy]") {
  NTL::SetSeed(NTL::ZZ(0));
  actors::FuzzyAuditor aud(512); 

  //make a single block list item
  aud.AuditorInit(3, 256, 50);
 
  std::string testhash = "083bf3fec698dad766a50436605b7a9f6a8a51b66f5717dedf3eb0ca01b22f0c";
  NTL::ZZ b1 = GetZZfromHexString("8009c4ade6f9da066b786896d13d1b144ca40d1c16bfc983f765db7e2f4d7552");
  std::string testhashprime = "083bf3fec698dad766a50436605b7a9f6a8a51b66f5717dedf3eb0ca01b22f0d";
  NTL::ZZ b = GetZZfromHexString(testhash);

  std::vector<NTL::ZZ> blocklist;
  blocklist.push_back(b);
  blocklist.push_back(b1);

  aud.SignBlockList(blocklist);

  //create the server
  actors::FullSearchServer serv(256, aud.getN(), aud.getSigs(), aud.getProjections());
  serv.fullInitBlockList(blocklist);

  //make the client + input
  actors::FullDpsiClient client(256, aud.getN(), aud.getG(), aud.getSigs(), aud.getProjections());
  std::string plaintext = "This is a test!";
  client.computeAndEncrypt(testhashprime, plaintext);

  bool res = serv.checkMatches(client.getCprime_ss(), client.getCprime_dhf(), client.getCprime(), client.getC());

  REQUIRE(res == true);
  //REQUIRE(serv.getKey() == client.getKey());
}

TEST_CASE("Fuzzy protocol test more projections", "[Fuzzy]") {
  NTL::SetSeed(NTL::ZZ(0));
  actors::FuzzyAuditor aud(512); 

  //make a single block list item
  aud.AuditorInit(3, 256, 50);
 
  std::string testhash = "083bf3fec698dad766a50436605b7a9f6a8a51b66f5717dedf3eb0ca01b22f0c";
  NTL::ZZ b1 = GetZZfromHexString("8009c4ade6f9da066b786896d13d1b144ca40d1c16bfc983f765db7e2f4d7552");
  NTL::ZZ b = GetZZfromHexString(testhash);

  std::vector<NTL::ZZ> blocklist;
  blocklist.push_back(b);
  blocklist.push_back(b1);

  aud.SignBlockList(blocklist);

  //create the server
  actors::FullSearchServer serv(256, aud.getN(), aud.getSigs(), aud.getProjections());
  serv.fullInitBlockList(blocklist);

  //make the client + input
  std::vector<NTL::ZZ> dummyprojections;
  dummyprojections.push_back(NTL::ZZ(1234));
  dummyprojections.push_back(NTL::ZZ(6789));
  dummyprojections.push_back(aud.getProjections().back());

  actors::FullDpsiClient client(256, aud.getN(), aud.getG(), aud.getSigs(), dummyprojections);
  std::string plaintext = "This is a test!";
  client.computeAndEncrypt(testhash, plaintext);

  bool res = serv.checkMatches(client.getCprime_ss(), client.getCprime_dhf(), client.getCprime(), client.getC());

  REQUIRE(res == true);
  //REQUIRE(serv.getKey() == client.getKey());
}

TEST_CASE("Fuzzy protocol longerlist", "[Fuzzy]") {
  NTL::SetSeed(NTL::ZZ(0));
  actors::FuzzyAuditor aud(512); 

  //make a single block list item
  aud.AuditorInit(1, 256, 50);
 
  std::string testhash = "083bf3fec698dad766a50436605b7a9f6a8a51b66f5717dedf3eb0ca01b22f0c";
  std::string testhashprime = "093b03fec698dad766a50436605b7a9f6a8a51b66f5717dedf3eb0ca01b22f0d";
  NTL::ZZ b = GetZZfromHexString(testhash);
  NTL::ZZ b1 = GetZZfromHexString("8009c4ade6f9da066b786896d13d1b144ca40d1c16bfc983f765db7e2f4d7552");
  NTL::ZZ b2 = GetZZfromHexString("01f5cd852f2100fcaf4a0abbbaf438dc790fc2fe7a255d8d15b328b598f75a51");

  std::vector<NTL::ZZ> blocklist;
  blocklist.push_back(b);
  blocklist.push_back(b1);
  blocklist.push_back(b2);

  aud.SignBlockList(blocklist);

  //create the server
  actors::FullSearchServer serv(256, aud.getN(), aud.getSigs(), aud.getProjections());
  serv.fullInitBlockList(blocklist);

  //make the client + input
  actors::FullDpsiClient client(256, aud.getN(), aud.getG(), aud.getSigs(), aud.getProjections());
  std::string plaintext = "This is a test!";
  client.computeAndEncrypt(testhashprime, plaintext);

  bool res = serv.checkMatches(client.getCprime_ss(), client.getCprime_dhf(), client.getCprime(), client.getC());

  //REQUIRE(res == true);
  REQUIRE(serv.getKey() == client.getKey());
}

TEST_CASE("Fuzzy protocol test Fail", "[Fuzzy]") {
  NTL::SetSeed(NTL::ZZ(0));
  actors::FuzzyAuditor aud(512); 

  //make a single block list item
  aud.AuditorInit(1, 256, 50);
 
  std::string testhash = "083bf3fec698dad766a50436605b7a9f6a8a51b66f5717dedf3eb0ca01b22f0c";
  NTL::ZZ b1 = GetZZfromHexString("8009c4ade6f9da066b786896d13d1b144ca40d1c16bfc983f765db7e2f4d7552");
  std::string testhashprime ="083bf3fec698dad766a511111111111111111111111111111111111111111111" ;
  NTL::ZZ b = GetZZfromHexString(testhash);

  std::vector<NTL::ZZ> blocklist;
  blocklist.push_back(b);
  blocklist.push_back(b1);

  aud.SignBlockList(blocklist);

  //create the server
  actors::FullSearchServer serv(256, aud.getN(), aud.getSigs(), aud.getProjections());
  serv.fullInitBlockList(blocklist);

  //make the client + input
  actors::FullDpsiClient client(256, aud.getN(), aud.getG(), aud.getSigs(), aud.getProjections());
  std::string plaintext = "This is a test!";
  client.computeAndEncrypt(testhashprime, plaintext);

  bool res = serv.checkMatches(client.getCprime_ss(), client.getCprime_dhf(), client.getCprime(), client.getC());

  //REQUIRE(res == true);
  REQUIRE(serv.getKey() != client.getKey());
}

TEST_CASE("Get ZZ from a hexstring/hash") {
  std::string hexstr = "DEADBEEF";
  ZZ deadbeef = ZZ(3735928559);
  ZZ testval = GetZZfromHexString(hexstr);
  REQUIRE(deadbeef == testval);
  hexstr = "DEADBEEF7";
  ZZ deadbeef7 = ZZ(59774856951);
  testval = GetZZfromHexString(hexstr);
  REQUIRE(deadbeef7 == testval);

  hexstr = "abcd";
  ZZ abcd = ZZ(43981);
  testval = GetZZfromHexString(hexstr);
  REQUIRE(abcd == testval);

  hexstr = "abcd123";
  ZZ abcd123 = ZZ(180146467);
  testval = GetZZfromHexString(hexstr);
  REQUIRE(abcd123 == testval);

  hexstr = "083bf3fec698";
  ZZ partialshaHash = ZZ(9053589653144);
  testval = GetZZfromHexString(hexstr);
  REQUIRE(partialshaHash == testval);

  hexstr = "083bf3fec698dad766a50436605b7a9f6a8a51b66f5717dedf3eb0ca01b22f0c";
  // too long to init from an int
  std::string string_rep = "372443075859149393383475084797496371791796645911750"
                           "2476645192032861841141516";
  testval = GetZZfromHexString(hexstr);
  std::stringstream ss;
  ss << testval;
  REQUIRE(string_rep == ss.str());
}

TEST_CASE("AES file encrypt/decrypt") {
  // set 0 keys for testing
  unsigned char key[AES_KEY_SIZE];
  memset(key, 0, AES_KEY_SIZE);
  unsigned char iv[AES_IV_SIZE];
  memset(iv, 0, AES_IV_SIZE);

  // plaintext for encryption
  std::string plaintext = "plaintext";
  std::string filecontnet = "Please, Encrypt Me!";
  std::ofstream outFile(plaintext);
  outFile << filecontnet;
  outFile.close();

  // name for ciphertext file
  std::string ciphertext = "plaintext-encrypted";
  std::string recoveredtext = "plaintext-encrypted-decrypted";

  SECTION("Decryption Success") {
    AES128KEY256EncryptFile(plaintext, key, iv);
    AES128KEY256DecryptFile(ciphertext, key, iv);
    std::ifstream inFile(recoveredtext.c_str());
    std::string test;
    std::getline(inFile, test);
    inFile.close();
    REQUIRE(test == filecontnet);
  }

  // clean up
  std::remove(plaintext.c_str());
  std::remove(ciphertext.c_str());
  std::remove(recoveredtext.c_str());
}

TEST_CASE("dynamicblocklist sha256 test") {
  const std::string CLIENTHASH =
      "01f5cd852f2100fcaf4a0abbbaf438dc790fc2fe7a255d8d15b328b598f75a51";

  //  std::string testBlockList[] = {"fffefffefebafeef", "bffefffefebebeed",
  //                                 "fffeffdeeecafe7d", "fffefefe7e9adbfd",
  //                                 "bffefffefebafedf", "fffefffefefefeff",
  //                                 "fffefffefebafeef", "e311c31c997186fc",
  //                                 "fffefffebfbefeff", "fffefffefffefeff"};
  std::string testBlockList[] = {
      "083bf3fec698dad766a50436605b7a9f6a8a51b66f5717dedf3eb0ca01b22f0c",
      "8009c4ade6f9da066b786896d13d1b144ca40d1c16bfc983f765db7e2f4d7552",
      "01f5cd852f2100fcaf4a0abbbaf438dc790fc2fe7a255d8d15b328b598f75a51"};
  // set seed for NTL
  SetSeed(ZZ(0));

  // have to make a mini block list
  ZZ p, q, N;
  ZZ pprime, qprime;
  ZZ QRorder, Norder;
  ZZ_p g;

  const int NUMBITS = 1024;
  SetUpInputs(NUMBITS, p, q, N, pprime, qprime, QRorder, Norder, g);

  ZZ_p::init(QRorder);
  ZZ_p inverse;
  ZZ_p bprod = ZZ_p(1);

  for (auto item : testBlockList) {
    ZZ seed = GetZZfromHexString(item);
    ZZ b = GetPrimeLessThanN(seed, NUM_OF_PRIME_ORACLE_BITS);
    bprod *= conv<ZZ_p>(b);
  }

  inv(inverse, conv<ZZ_p>(bprod));

  // going to mod N
  ZZ_p::init(N);
  ZZ exp = conv<ZZ>(inverse);
  ZZ_p sig = power(g, exp);

  ZZ seed = GetZZfromHexString(CLIENTHASH);
  ZZ hp = GetPrimeLessThanN(seed, NUM_OF_PRIME_ORACLE_BITS);

  // ZZ r = RandomBnd(power(N, 2));
  // std::cout << r << std::endl;
  ZZ r(4);
  ZZ_p v;
  power(v, sig, (r * hp));

  // this the value we want to recover
  ZZ_p grmN = power(g, r);

  // client get its key, encrypts the data, serializes
  // server get the data, deserializes it, and starts comparing it against
  // the block list

  // This is where the server will start to calculate
  std::vector<ZZ> blocklistZZvec = {};
  for (auto hashvalue : testBlockList) {
    ZZ blistseed = GetZZfromHexString(hashvalue);
    ZZ blocklistZZ = GetPrimeLessThanN(blistseed, NUM_OF_PRIME_ORACLE_BITS);
    blocklistZZvec.push_back(blocklistZZ);
  }

  // std::cout << "sig: " << sig << std::endl;
  // std::cout << "hp: " << hp << std::endl;
  // std::cout << "g: " << g << std::endl;
  // std::cout << "grmN: " << grmN << std::endl;
  // std::cout << "v : " << v << std::endl;
  // std::cout << "N : " << N << std::endl;
  // for (auto vals : blocklistZZvec) {
  //  std::cout << vals << std::endl;
  //}
  std::vector<ZZ_p> valstocheck =
      dynamicblocklist::MakeBlockListforClientInput(blocklistZZvec, v, N);

  // std::cout << "value to compare to: " << grmN << std::endl;
  int matches = 0;
  for (auto val : valstocheck) {
    if (val == grmN) {
      matches++;
    }
  }

  REQUIRE(matches == 1);
}

TEST_CASE("dynamicblocklist realhashes test") {
  const std::string CLIENTHASH = "fffefefe7e9adbfd";

  std::string testBlockList[] = {"fffefffefebafeef", "bffefffefebebeed",
                                 "fffeffdeeecafe7d", "fffefefe7e9adbfd",
                                 "bffefffefebafedf", "fffefffefefefeff",
                                 "fffefffefebafeef", "e311c31c997186fc",
                                 "fffefffebfbefeff", "fffefffefffefeff"};
  // set seed for NTL
  SetSeed(ZZ(0));

  // have to make a mini block list
  ZZ p, q, N;
  ZZ pprime, qprime;
  ZZ QRorder, Norder;
  ZZ_p g;

  const int NUMBITS = 1024;
  SetUpInputs(NUMBITS, p, q, N, pprime, qprime, QRorder, Norder, g);

  ZZ_p::init(QRorder);
  ZZ_p inverse;
  ZZ_p bprod = ZZ_p(1);

  for (auto item : testBlockList) {
    ZZ seed = GetZZfromHexString(item);
    ZZ b = GetPrimeLessThanN(seed, NUM_OF_PRIME_ORACLE_BITS);
    bprod *= conv<ZZ_p>(b);
  }

  inv(inverse, conv<ZZ_p>(bprod));

  // going to mod N
  ZZ_p::init(N);
  ZZ exp = conv<ZZ>(inverse);
  ZZ_p sig = power(g, exp);

  ZZ seed = GetZZfromHexString(CLIENTHASH);
  ZZ hp = GetPrimeLessThanN(seed, NUM_OF_PRIME_ORACLE_BITS);

  // ZZ r = RandomBnd(power(N, 2));
  // std::cout << r << std::endl;
  ZZ r(4);
  ZZ_p v;
  power(v, sig, (r * hp));

  // this the value we want to recover
  ZZ_p grmN = power(g, r);

  // client get its key, encrypts the data, serializes
  // server get the data, deserializes it, and starts comparing it against
  // the block list

  // This is where the server will start to calculate
  std::vector<ZZ> blocklistZZvec = {};
  for (auto hashvalue : testBlockList) {
    ZZ blistseed = GetZZfromHexString(hashvalue);
    ZZ blocklistZZ = GetPrimeLessThanN(blistseed, NUM_OF_PRIME_ORACLE_BITS);
    blocklistZZvec.push_back(blocklistZZ);
  }

  // std::cout << "sig: " << sig << std::endl;
  // std::cout << "hp: " << hp << std::endl;
  // std::cout << "g: " << g << std::endl;
  // std::cout << "grmN: " << grmN << std::endl;
  // std::cout << "v : " << v << std::endl;
  // std::cout << "N : " << N << std::endl;
  // for (auto vals : blocklistZZvec) {
  //  std::cout << vals << std::endl;
  //}
  std::vector<ZZ_p> valstocheck =
      dynamicblocklist::MakeBlockListforClientInput(blocklistZZvec, v, N);

  // std::cout << "value to compare to: " << grmN << std::endl;
  int matches = 0;
  for (auto val : valstocheck) {
    if (val == grmN) {
      matches++;
    }
  }

  REQUIRE(matches == 1);
}

TEST_CASE("dynamicblocklist basic test") {
  const std::string CLIENTHASH = "ABCDEF";

  // Pi{b}
  std::string testBlockList[] = {"ABC",      "123DEF", "DEF",   "ABCDEF",
                                 "DEADBEEF", "123ABC", "123",   "345",
                                 "DEEEE",    "123DEF", "10AE20"};

  // set seed for NTL
  SetSeed(ZZ(0));

  // have to make a mini block list
  ZZ p, q, N;
  ZZ pprime, qprime;
  ZZ QRorder, Norder;
  ZZ_p g;

  const int NUMBITS = 128;
  SetUpInputs(NUMBITS, p, q, N, pprime, qprime, QRorder, Norder, g);

  ZZ_p::init(QRorder);
  ZZ_p inverse;
  ZZ bprod = ZZ(1);
  ZZ bi;

  for (auto item : testBlockList) {
    ZZ seed = GetZZfromHexString(item);
    ZZ b = GetPrimeLessThanN(seed, NUM_OF_PRIME_ORACLE_BITS);
    bprod *= b;

    if (item == CLIENTHASH) {
      bi = ZZ(b);
    }
  }

  inv(inverse, conv<ZZ_p>(bprod));

  // going to mod N
  ZZ_p::init(N);
  ZZ exp = conv<ZZ>(inverse);
  ZZ_p sig = power(g, exp);

  ZZ seed = GetZZfromHexString(CLIENTHASH);
  ZZ hp = GetPrimeLessThanN(seed, NUM_OF_PRIME_ORACLE_BITS);

  ZZ r = RandomBnd(power(N, 2));
  ZZ_p v;
  power(v, sig, (r * hp));

  // this the value we want to recover
  ZZ_p grmN = power(g, r);

  // client get its key, encrypts the data, serializes
  // server get the data, deserializes it, and starts comparing it against
  // the block list

  // This is where the server will start to calculate
  std::vector<ZZ> blocklistZZvec = {};
  for (auto hashvalue : testBlockList) {
    ZZ blistseed = GetZZfromHexString(hashvalue);
    ZZ blocklistZZ = GetPrimeLessThanN(blistseed, NUM_OF_PRIME_ORACLE_BITS);
    blocklistZZvec.push_back(blocklistZZ);
  }

  std::vector<ZZ_p> valstocheck =
      dynamicblocklist::MakeBlockListforClientInput(blocklistZZvec, v, N);

  std::cout << "value to compare to: " << grmN << std::endl;
  int matches = 0;
  for (auto val : valstocheck) {
    if (val == grmN) {
      matches++;
    }
  }

  REQUIRE(matches == 1);
}

TEST_CASE("SimulateBaseProtocol1024bits") {
  // SETUP
  //  we will use this value to generate a key
  // 0xABCDEF in decimal
  const std::string CLIENTHASH = "ABCDEF";

  // Pi{b}
  std::string testBlockList[] = {"ABC", "DEF", "ABCDEF"};

  // set seed for NTL
  SetSeed(ZZ(0));

  // have to make a mini block list
  ZZ p, q, N;
  ZZ pprime, qprime;
  ZZ QRorder, Norder;
  ZZ_p g;

  // choosing small primes for testing purposes
  const int NUMBITS = 1024;
  SetUpInputs(NUMBITS, p, q, N, pprime, qprime, QRorder, Norder, g);

  SECTION("Verify Orders") {
    // Verify that QRorder = Norder/4
    ZZ testQRorder = QRorder * 4;
    ZZ testNorder = (p - 1) * (q - 1);
    REQUIRE(testNorder == Norder);
    REQUIRE(testQRorder == Norder);
  }

  // create a test signature
  ZZ_p::init(QRorder);
  ZZ_p inverse;
  ZZ bprod = ZZ(1);
  ZZ bi;

  // sanity check that we did not change g by mistake
  //  generate a block list
  for (auto item : testBlockList) {
    ZZ seed = GetZZfromHexString(item);
    ZZ b = GetPrimeLessThanN(seed, NUM_OF_PRIME_ORACLE_BITS);
    bprod *= b;

    // this is for sanity checking purposes
    if (item == CLIENTHASH) {
      bi = ZZ(b);
    }
  }

  inv(inverse, conv<ZZ_p>(bprod));

  // going to mod N
  ZZ_p::init(N);
  ZZ exp = conv<ZZ>(inverse);
  ZZ_p sig = power(g, exp);

  // alternate way to calculate the signature
  // for sanity checking purposes
  ZZ_p altsig = ZZ_p(g);
  for (auto item : testBlockList) {
    ZZ seed = GetZZfromHexString(item);
    ZZ b = GetPrimeLessThanN(seed, NUM_OF_PRIME_ORACLE_BITS);
    ZZ_p::init(QRorder);
    inv(inverse, conv<ZZ_p>(b));
    ZZ_p::init(N);
    altsig = power(altsig, conv<ZZ>(inverse));
  }

  SECTION("Verify signature") {
    ZZ_p sigtest = power(sig, bprod);
    REQUIRE(sigtest == g);
    REQUIRE(altsig == sig);
  }

  // FINISH SETUP

  // now we have a signature, we can actually start doing the protocol
  // we will use this value to generate a key
  std::string clientval = "ENCRYPT THIS FILE!!!";
  std::ofstream outFile("plaintext");
  outFile << clientval;
  outFile.close();

  ZZ seed = GetZZfromHexString(CLIENTHASH);
  ZZ hp = GetPrimeLessThanN(seed, NUM_OF_PRIME_ORACLE_BITS);
  REQUIRE(hp == bi);

  // C.2 Randomize
  ZZ r = RandomBnd(power(N, 2));
  ZZ_p v;
  power(v, sig, (r * hp));
  ZZ_p grmN = power(g, r);

  // use our H_G Oracle
  ZZ wZZ = GetKey(conv<ZZ>(grmN), AES_KEY_SIZE * 8);
  // just make the seed a little differnt so that the IV is different
  ZZ wivZZ = GetKey(conv<ZZ>(grmN + 1), AES_IV_SIZE * 8);

  unsigned char w[AES_KEY_SIZE];
  unsigned char wiv[AES_IV_SIZE];
  BytesFromZZ(w, wZZ, AES_KEY_SIZE);
  BytesFromZZ(wiv, wivZZ, AES_IV_SIZE);
  // v is our c
  // the out outputfile is our c'

  AES128KEY256EncryptFile("plaintext", w, wiv);

  SECTION("Match") {
    // pretend that that our c and c' have been transmitted over grpc

    // recalcualte blocklist, but we don't have have bi
    // this is the same as the signature, but we are now working with mod N
    // instead
    ZZ_p::init(N);
    ZZ bprodWithoutbi = ZZ(1);

    // sanity check that we did not change g by mistake
    //  generate a block list
    for (auto item : testBlockList) {
      if (item != CLIENTHASH) {
        ZZ seed = GetZZfromHexString(item);
        ZZ b = GetPrimeLessThanN(seed, NUM_OF_PRIME_ORACLE_BITS);
        bprodWithoutbi *= b;
      }
    }

    SECTION("Verify that bprodWithoutbi was correclty calcuculated") {
      ZZ siginv = hp * bprodWithoutbi;
      ZZ_p gtest = power(sig, siginv);
      REQUIRE(gtest == g);
    }

    // S.1
    ZZ_p vb = power(v, bprodWithoutbi);
    ZZ rkeyZZ = GetKey(conv<ZZ>(vb), AES_KEY_SIZE * 8);
    ZZ rivZZ = GetKey(conv<ZZ>(vb + 1), AES_IV_SIZE * 8);

    unsigned char rkey[AES_KEY_SIZE];
    unsigned char riv[AES_IV_SIZE];
    BytesFromZZ(rkey, rkeyZZ, AES_KEY_SIZE);
    BytesFromZZ(riv, rivZZ, AES_IV_SIZE);
    REQUIRE(rkeyZZ == wZZ);
    REQUIRE(rivZZ == wivZZ);

    // S.2
    AES128KEY256DecryptFile("plaintext-encrypted", rkey, riv);

    // Check the values
    std::ifstream inFile("plaintext-encrypted-decrypted");
    std::string test;
    std::getline(inFile, test);
    inFile.close();
    REQUIRE(test == clientval);
  }

  std::remove("plaintext");
  std::remove("plaintext-encrypted");
  std::remove("plaintext-encrypted-decrypted");
}

TEST_CASE("SimulateBaseProtocol128bitsx1000") {
  // SETUP
  //  we will use this value to generate a key
  // 0xABCDEF in decimal
  const std::string CLIENTHASH = "ABCDEF";

  // Pi{b}
  std::string testBlockList[] = {"ABC", "DEF", "ABCDEF"};

  // set seed for NTL
  SetSeed(ZZ(0));

  // have to make a mini block list
  ZZ p, q, N;
  ZZ pprime, qprime;
  ZZ QRorder, Norder;
  ZZ_p g;

  for (int i = 0; i < 1000; i++) {
    SetSeed(ZZ(i));
    // choosing small primes for testing purposes
    const int NUMBITS = 128;
    SetUpInputs(NUMBITS, p, q, N, pprime, qprime, QRorder, Norder, g);

    // create a test signature
    ZZ_p::init(QRorder);
    ZZ_p inverse;
    ZZ bprod = ZZ(1);
    ZZ bi;

    // sanity check that we did not change g by mistake
    //  generate a block list
    for (auto item : testBlockList) {
      ZZ seed = GetZZfromHexString(item);
      ZZ b = GetPrimeLessThanN(seed, NUM_OF_PRIME_ORACLE_BITS);
      bprod *= b;

      // this is for sanity checking purposes
      if (item == CLIENTHASH) {
        bi = ZZ(b);
      }
    }

    inv(inverse, conv<ZZ_p>(bprod));

    // going to mod N
    ZZ_p::init(N);
    ZZ exp = conv<ZZ>(inverse);
    ZZ_p sig = power(g, exp);

    // now we have a signature, we can actually start doing the protocol
    // we will use this value to generate a key
    ZZ seed = GetZZfromHexString(CLIENTHASH);
    ZZ hp = GetPrimeLessThanN(seed, NUM_OF_PRIME_ORACLE_BITS);

    // C.2 Randomize
    ZZ r = RandomBnd(power(N, 2));
    ZZ_p v;
    power(v, sig, (r * hp));
    ZZ_p grmN = power(g, r);

    // use our H_G Oracle
    ZZ wZZ = GetKey(conv<ZZ>(grmN), AES_KEY_SIZE * 8);
    // just make the seed a little differnt so that the IV is different
    ZZ wivZZ = GetKey(conv<ZZ>(grmN + 1), AES_IV_SIZE * 8);

    unsigned char w[AES_KEY_SIZE];
    unsigned char wiv[AES_IV_SIZE];
    BytesFromZZ(w, wZZ, AES_KEY_SIZE);
    BytesFromZZ(wiv, wivZZ, AES_IV_SIZE);
    // v is our c
    // the out outputfile is our c'
    ZZ_p::init(N);
    ZZ bprodWithoutbi = ZZ(1);

    // sanity check that we did not change g by mistake
    //  generate a block list
    for (auto item : testBlockList) {
      if (item != CLIENTHASH) {
        ZZ seed = GetZZfromHexString(item);
        ZZ b = GetPrimeLessThanN(seed, NUM_OF_PRIME_ORACLE_BITS);
        bprodWithoutbi *= b;
      }
    }

    // S.1
    ZZ_p vb = power(v, bprodWithoutbi);
    ZZ rkeyZZ = GetKey(conv<ZZ>(vb), AES_KEY_SIZE * 8);
    ZZ rivZZ = GetKey(conv<ZZ>(vb + 1), AES_IV_SIZE * 8);

    unsigned char rkey[AES_KEY_SIZE];
    unsigned char riv[AES_IV_SIZE];
    BytesFromZZ(rkey, rkeyZZ, AES_KEY_SIZE);
    BytesFromZZ(riv, rivZZ, AES_IV_SIZE);
    if (rkeyZZ != wZZ) {
      std::cerr << "There in the way we are calling the a base protocol"
                << std::endl;
      std::cerr << "The problem seed value is: " << i << std::endl;
    }
    REQUIRE(rkeyZZ == wZZ);
  }
}


TEST_CASE("benchmarkfor1024bits") {
  // SETUP
  //  we will use this value to generate a key
  // 0xABCDEF in decimal
  const std::string CLIENTHASH = "ABCDEF";

  // Pi{b}
  std::string testBlockList[] = {"ABC", "DEF", "ABCDEF"};

  // set seed for NTL
  SetSeed(ZZ(1234));

  // have to make a mini block list
  ZZ p, q, N;
  ZZ pprime, qprime;
  ZZ QRorder, Norder;
  ZZ_p g;

  SetSeed(ZZ(0));
  // choosing small primes for testing purposes
  const int NUMBITS = 1024;
  SetUpInputs(NUMBITS, p, q, N, pprime, qprime, QRorder, Norder, g);

  // create a test signature
  ZZ_p::init(QRorder);
  ZZ_p inverse;
  ZZ bprod = ZZ(1);
  ZZ bi;

  // sanity check that we did not change g by mistake
  //  generate a block list
  for (auto item : testBlockList) {
    ZZ seed = GetZZfromHexString(item);
    ZZ b = GetPrimeLessThanN(seed, NUM_OF_PRIME_ORACLE_BITS);
    bprod *= b;

    // this is for sanity checking purposes
    if (item == CLIENTHASH) {
      bi = ZZ(b);
    }
  }

  inv(inverse, conv<ZZ_p>(bprod));

  // going to mod N
  ZZ_p::init(N);
  ZZ exp = conv<ZZ>(inverse);
  ZZ_p sig = power(g, exp);

  // set up file for encryption so we get an idea how long it takes
  std::string clientval = "ENCRYPT THIS FILE!!!";
  std::ofstream outFile("plaintext");
  outFile << clientval;
  outFile.close();

  // now we have a signature, we can actually start doing the protocol
  // we will use this value to generate a key
  // BENCHMARK("Check speed of exponentiation and key generation") {
  ZZ seed = GetZZfromHexString(CLIENTHASH);
  ZZ hp = GetPrimeLessThanN(seed, NUM_OF_PRIME_ORACLE_BITS);

  BENCHMARK("Check speed of exponentiation and key generation") {
    // C.2 Randomize
    ZZ r = RandomBnd(power(N, 2));
    ZZ_p v;
    power(v, sig, (r * hp));
    ZZ_p grmN = power(g, r);

    // use our H_G Oracle
    ZZ wZZ = GetKey(conv<ZZ>(grmN), AES_KEY_SIZE * 8);
    // just make the seed a little differnt so that the IV is different
    ZZ wivZZ = GetKey(conv<ZZ>(grmN + 1), AES_IV_SIZE * 8);

    unsigned char w[AES_KEY_SIZE];
    unsigned char wiv[AES_IV_SIZE];
    BytesFromZZ(w, wZZ, AES_KEY_SIZE);
    BytesFromZZ(wiv, wivZZ, AES_IV_SIZE);
    AES128KEY256EncryptFile("plaintext", w, wiv);
  };
}
TEST_CASE("SimulateBaseProtocol2048bits") {
  // SETUP
  //  we will use this value to generate a key
  // 0xABCDEF in decimal
  const std::string CLIENTHASH = "ABCDEF";

  // Pi{b}
  std::string testBlockList[] = {"ABC", "DEF", "ABCDEF"};

  // set seed for NTL
  SetSeed(ZZ(12345));

  // have to make a mini block list
  ZZ p, q, N;
  ZZ pprime, qprime;
  ZZ QRorder, Norder;
  ZZ_p g;

  // choosing small primes for testing purposes
  const int NUMBITS = 2048;
  SetUpInputs(NUMBITS, p, q, N, pprime, qprime, QRorder, Norder, g);

  SECTION("Verify Orders") {
    // Verify that QRorder = Norder/4
    ZZ testQRorder = QRorder * 4;
    ZZ testNorder = (p - 1) * (q - 1);
    REQUIRE(testNorder == Norder);
    REQUIRE(testQRorder == Norder);
  }

  // create a test signature
  ZZ_p::init(QRorder);
  ZZ_p inverse;
  ZZ bprod = ZZ(1);
  ZZ bi;

  // sanity check that we did not change g by mistake
  //  generate a block list
  for (auto item : testBlockList) {
    ZZ seed = GetZZfromHexString(item);
    ZZ b = GetPrimeLessThanN(seed, NUM_OF_PRIME_ORACLE_BITS);
    bprod *= b;

    // this is for sanity checking purposes
    if (item == CLIENTHASH) {
      bi = ZZ(b);
    }
  }

  inv(inverse, conv<ZZ_p>(bprod));

  // going to mod N
  ZZ_p::init(N);
  ZZ exp = conv<ZZ>(inverse);
  ZZ_p sig = power(g, exp);

  // alternate way to calculate the signature
  // for sanity checking purposes
  ZZ_p altsig = ZZ_p(g);
  for (auto item : testBlockList) {
    ZZ seed = GetZZfromHexString(item);
    ZZ b = GetPrimeLessThanN(seed, NUM_OF_PRIME_ORACLE_BITS);
    ZZ_p::init(QRorder);
    inv(inverse, conv<ZZ_p>(b));
    ZZ_p::init(N);
    altsig = power(altsig, conv<ZZ>(inverse));
  }

  SECTION("Verify signature") {
    ZZ_p sigtest = power(sig, bprod);
    REQUIRE(sigtest == g);
    REQUIRE(altsig == sig);
  }

  // FINISH SETUP

  // now we have a signature, we can actually start doing the protocol
  // we will use this value to generate a key
  std::string clientval = "ENCRYPT THIS FILE!!!";
  std::ofstream outFile("plaintext");
  outFile << clientval;
  outFile.close();

  ZZ seed = GetZZfromHexString(CLIENTHASH);
  ZZ hp = GetPrimeLessThanN(seed, NUM_OF_PRIME_ORACLE_BITS);
  REQUIRE(hp == bi);

  // C.2 Randomize
  ZZ r = RandomBnd(power(N, 2));
  // wait, this line ain't right
  ZZ_p v;
  power(v, sig, (r * hp));
  ZZ_p grmN = power(g, r);

  // use our H_G Oracle
  ZZ wZZ = GetKey(conv<ZZ>(grmN), AES_KEY_SIZE * 8);
  // just make the seed a little differnt so that the IV is different
  ZZ wivZZ = GetKey(conv<ZZ>(grmN + 1), AES_IV_SIZE * 8);

  unsigned char w[AES_KEY_SIZE];
  unsigned char wiv[AES_IV_SIZE];
  BytesFromZZ(w, wZZ, AES_KEY_SIZE);
  BytesFromZZ(wiv, wivZZ, AES_IV_SIZE);
  // v is our c
  // the out outputfile is our c'

  AES128KEY256EncryptFile("plaintext", w, wiv);

  SECTION("Match") {
    // pretend that that our c and c' have been transmitted over grpc

    // recalcualte blocklist, but we don't have have bi
    // this is the same as the signature, but we are now working with mod N
    // instead
    ZZ_p::init(N);
    ZZ bprodWithoutbi = ZZ(1);

    // sanity check that we did not change g by mistake
    //  generate a block list
    for (auto item : testBlockList) {
      if (item != CLIENTHASH) {
        ZZ seed = GetZZfromHexString(item);
        ZZ b = GetPrimeLessThanN(seed, NUM_OF_PRIME_ORACLE_BITS);
        bprodWithoutbi *= b;
      }
    }

    SECTION("Verify that bprodWithoutbi was correctly calculated") {
      ZZ siginv = hp * bprodWithoutbi;
      ZZ_p gtest = power(sig, siginv);
      REQUIRE(gtest == g);
    }

    // S.1
    ZZ_p vb = power(v, bprodWithoutbi);
    ZZ rkeyZZ = GetKey(conv<ZZ>(vb), AES_KEY_SIZE * 8);
    ZZ rivZZ = GetKey(conv<ZZ>(vb + 1), AES_IV_SIZE * 8);

    unsigned char rkey[AES_KEY_SIZE];
    unsigned char riv[AES_IV_SIZE];
    BytesFromZZ(rkey, rkeyZZ, AES_KEY_SIZE);
    BytesFromZZ(riv, rivZZ, AES_IV_SIZE);
    REQUIRE(rkeyZZ == wZZ);
    REQUIRE(rivZZ == wivZZ);

    // S.2
    AES128KEY256DecryptFile("plaintext-encrypted", rkey, riv);

    // Check the values
    std::ifstream inFile("plaintext-encrypted-decrypted");
    std::string test;
    std::getline(inFile, test);
    inFile.close();
    REQUIRE(test == clientval);
  }

  std::remove("plaintext");
  std::remove("plaintext-encrypted");
  std::remove("plaintext-encrypted-decrypted");
}
