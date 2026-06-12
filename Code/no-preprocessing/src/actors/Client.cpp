#include "actors/Client.hpp"
#include "Projections.hpp"
#include "DpsiUtils.hpp"
#include "DetectableHashFunction.hpp"
#include "baseprotocol.grpc.pb.h"
#include "grpcpp/security/server_credentials.h"
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/ZZ_pX.h>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <memory>

#include <grpc/grpc.h>
#include <grpcpp/channel.h>
#include <grpcpp/client_context.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/security/credentials.h>
#include <sstream>

namespace actors {

DpsiClient::DpsiClient(const NTL::ZZ_p &sig, const NTL::ZZ_p &g,
                       const NTL::ZZ &N)
    : m_sig(sig), m_g(g), m_N(N) {}

BasicDpsiClient::BasicDpsiClient(const NTL::ZZ_p &sig, const NTL::ZZ_p &g,
                                 const NTL::ZZ &N)
    : DpsiClient(sig, g, N) {}

FullDpsiClient::FullDpsiClient(const long l, const NTL::ZZ &N, const NTL::ZZ_p &g, const std::vector<NTL::ZZ_p> &sigs, const std::vector<NTL::ZZ> &projs) : 
  m_l(l), m_g(g), m_N(N), m_projections(projs)  {
        //make [j][k] sigs so its easier to reference
    for(int j=0; j < m_projections.size(); j++) {
      std::vector<NTL::ZZ_p> sigjk;
      for(int k = 0; k < m_l; k++) {
        int idx = (j * m_l) + k;
        sigjk.push_back(sigs[idx]);
      }
      m_sigs.push_back(sigjk);
    }
  }


void BasicDpsiClient::computeAndEncrypt(std::string &embedding,
                                        std::string &plaintext) {
  NTL::ZZ_p::init(this->m_N);
  // Debug: fixing the r value
  // SetSeed(ZZ(20));
  NTL::ZZ r = NTL::RandomBnd(power(this->m_N, 2));
  NTL::ZZ seed = GetZZfromHexString(embedding);
  NTL::ZZ hp = GetPrimeLessThanN(seed, NUM_OF_PRIME_ORACLE_BITS);
  // std::cout << "This is the server hp: " << hp << std::endl;
  this->m_c = NTL::power(this->m_sig, (r * hp));
  NTL::ZZ_p grmN = power(this->m_g, r);

  unsigned char w[AES_KEY_SIZE];
  unsigned char wiv[AES_IV_SIZE];

  NTL::ZZ wZZ = GetKey(conv<NTL::ZZ>(grmN), AES_KEY_SIZE * 8);
  NTL::RandomBits(this->m_wivZZ, AES_IV_SIZE * 8);
  BytesFromZZ(w, wZZ, AES_KEY_SIZE);
  BytesFromZZ(wiv, this->m_wivZZ, AES_IV_SIZE);

  // DEBUG
  // std::cout << "Encryption key: " << wZZ << std::endl;
  this->debug_grmN = grmN;
  this->debug_r = r;
  // std::cout << "Client m_N: " << m_N << std::endl;

  AES128KEY256EncryptStrings(this->m_cprime, plaintext, w, wiv);
}


std::chrono::milliseconds FullDpsiClient::getDHFtime() {
  return m_dhf_ms;
}

void FullDpsiClient::computeAndEncrypt(std::string &embedding,
                                        std::string &plaintext) {

  std::chrono::high_resolution_clock::time_point start;
  std::chrono::high_resolution_clock::time_point end;
  //std::vector<NTL::ZZ_pX> DHFkey = getDHFKey();
  //this is just a tad more clear to me
  std::vector<NTL::ZZ_pX> DHFkey = DHF::DHFGenKey(DHF_POLYS, DHF_THRESHOLD-1);
  std::vector<std::vector<NTL::ZZ_p>> v;
  NTL::ZZ input = GetZZfromHexString(embedding);
  NTL::ZZ_p::init(this->m_N);

  for(long j = 0; j < m_sigs.size(); j++) {
    std::vector<NTL::ZZ_p> v_j; 
    std::vector<NTL::ZZ> w_j; 
    NTL::ZZ proj = psi_proj::evalProjectionFunc(m_projections[j], input);

    for(long k = 0; k < m_l; k++) {
      NTL::ZZ_p::init(this->m_N);
      NTL::ZZ x_jk = fuzzyConcatInputs(m_projections[j], NTL::bit(proj,k), k, proj);  
      NTL::ZZ hash = GetPrimeLessThanN(x_jk, NUM_OF_PRIME_ORACLE_BITS);


      NTL::ZZ r_jk = NTL::RandomBnd(power(this->m_N, 2));
      //NTL::ZZ r_jk = NTL::ZZ(1);
      
      //use a different signature for each bit
      NTL::ZZ_p v_jk = NTL::power(m_sigs[j][k], (hash * r_jk));
      NTL::ZZ_p preimg = NTL::power(m_g, r_jk); 

      NTL::ZZ w_jk = GetKey(conv<NTL::ZZ>(preimg), AES_KEY_SIZE * 8);
      v_j.push_back(v_jk);
      w_j.push_back(w_jk);

      //if(k == 200) {
      //  std::cout << "client wjk: " << w_jk << std::endl;
      //  std::cout << "bits " << NTL::NumBits(w_jk) << std::endl;
      //}
    }


    unsigned char key_bytes[AES_KEY_SIZE];

    //WARNING: this is for testing purposes, the IV is all zeros
    unsigned char iv_bytes[AES_IV_SIZE] = {};

    //generate key with a random polynomial
    start = std::chrono::high_resolution_clock::now();
    NTL::ZZ_pPush(DHF::GetField());
    NTL::ZZ_pX poly = getRandPoly(DHF_THRESHOLD-1);
    NTL::ZZ key_ZZ = getKeyFromPoly(poly);
    //this is for testing and debugging
    m_keyZZ = key_ZZ;
    NTL::BytesFromZZ(key_bytes, key_ZZ, AES_KEY_SIZE);
   
    //perform ecryption
    std::string ciphertext;
    AES128KEY256EncryptStrings(ciphertext, plaintext, key_bytes, iv_bytes);

    this->m_cprime.push_back(ciphertext);
  
    // split key into secret shares
    std::vector<NTL::ZZ> ss_j =  PolySecretShare(m_l, poly);
    std::vector<NTL::ZZ> cprime_ss_j; 
    std::vector<std::vector<NTL::ZZ>> cprime_dhf_j; 

    for(long k = 0; k < m_l; k++) {
      // ijust need any old input there, so long as I create an appropirate DHF
      NTL::ZZ_p rprime_jk  = random_ZZ_p();     
      // every jk has a vector associated with it
      NTL::vec_ZZ_p detectableHash = DHF::DHFk_xi(DHFkey, rprime_jk);
      
      //have to blind each element of the vec_ZZ_p with w_j[k]
      NTL::ZZ cprime_ss_k;

      //DEBUG: just get this to work without the blinding
      NTL::bit_xor(cprime_ss_k, ss_j[k], w_j[k]);
      cprime_ss_j.push_back(cprime_ss_k);
      //cprime_ss_j.push_back(ss_j[k]);

      std::vector<NTL::ZZ> cprime_dhf_k;
      NTL::ZZ cprime_dhf_i;

      //every element of the detectable hash is blinded

      for(long i = 0; i < detectableHash.length(); i++) {
        //if(k == 200) {
        ////  std::cout << "client hash: " << detectableHash[i] << std::endl;
        ////std::cout << "bits " << NTL::NumBits(NTL::conv<NTL::ZZ>(detectableHash[i])) << std::endl;
        //}
        NTL::bit_xor(cprime_dhf_i, NTL::conv<NTL::ZZ>(detectableHash[i]), NTL::conv<NTL::ZZ>(w_j[k]));
        cprime_dhf_k.push_back(cprime_dhf_i);
      }

      cprime_dhf_j.push_back(cprime_dhf_k);
    }

    end = std::chrono::high_resolution_clock::now();
    m_dhf_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    this->m_w.push_back(w_j);
    this->m_c.push_back(v_j);
    this->m_cprime_dhf.push_back(cprime_dhf_j);
    this->m_cprime_ss.push_back(cprime_ss_j);
    
    //for(auto element : cprime_dhf_j[200]) {
    //    std::cout << "this is what the client should match" << std::endl;
    //    NTL::ZZ test;
    //    NTL::bit_xor(test, element, w_j[200]);
    //    std::cout << test << std::endl;
    //}
  }

}

NTL::ZZ FullDpsiClient::getKey() {
  return m_keyZZ;
}

JSONBasicClientFactory::JSONBasicClientFactory(const std::filesystem::path &p) {
  namespace pt = boost::property_tree;
  pt::ptree proptree;
  pt::read_json(p.c_str(), proptree);

  // Read in the entries as strings
  std::string NString = proptree.get<std::string>("N");
  std::string gString = proptree.get<std::string>("g");
  std::string sigString = proptree.get<std::string>("sig");
  std::string numbitsString = proptree.get<std::string>("numbits");

  this->m_N = conv<ZZ>(NString.c_str());
  NTL::ZZ_p::init(this->m_N);
  this->m_sig = conv<ZZ_p>(sigString.c_str());
  this->m_g = conv<ZZ_p>(gString.c_str());
  this->m_numbits = stoi(numbitsString);
}

std::unique_ptr<BasicDpsiClient> JSONBasicClientFactory::CreateClient() {
  return std::make_unique<BasicDpsiClient>(this->m_sig, this->m_g, this->m_N);
}

NTL::ZZ BasicDpsiClient::getr() { return this->debug_r; }
NTL::ZZ_p BasicDpsiClient::getsig() { return this->m_sig; }
NTL::ZZ BasicDpsiClient::getN() { return this->m_N; }

NTL::ZZ_p BasicDpsiClient::getgrmN() { return this->debug_grmN; }
NTL::ZZ_p BasicDpsiClient::getg() { return this->m_g; }

NTL::ZZ_p BasicDpsiClient::getC() { return this->m_c; }
std::string BasicDpsiClient::getCprime() { return this->m_cprime; }
NTL::ZZ BasicDpsiClient::getIV() { return this->m_wivZZ; }

NTL::ZZ_p FullDpsiClient::getG() {return this->m_g;}
std::vector<std::vector<NTL::ZZ_p>> FullDpsiClient::getC(){ return this->m_c;}
std::vector<std::vector<NTL::ZZ>> FullDpsiClient::getW(){return this->m_w;}
std::vector<std::string> FullDpsiClient::getCprime(){return this->m_cprime;}
std::vector<std::vector<std::vector<NTL::ZZ>>> FullDpsiClient::getCprime_dhf(){return this->m_cprime_dhf;}
std::vector<std::vector<NTL::ZZ>> FullDpsiClient::getCprime_ss(){return this->m_cprime_ss;}

BasicgRPCClientChannel::BasicgRPCClientChannel(std::string serverAddr) {
  this->serverAddr = serverAddr;
  this->basicClient = nullptr;
}

void BasicgRPCClientChannel::setClient(
    std::unique_ptr<BasicDpsiClient> basicClient) {
  this->basicClient = std::move(basicClient);
}

bool BasicgRPCClientChannel::sendMessage(std::string embedding,
                                         std::string plaintext) {
  this->basicClient->computeAndEncrypt(embedding, plaintext);
  auto chan =
      grpc::CreateChannel(this->serverAddr, grpc::InsecureChannelCredentials());
  BasicProtocolClient client(chan);

  auto payload = genCiphertext();
  baseprotocol::RecievedCipherText resp;
  client.sendMessage(payload, &resp);

  return true;
}

bool BasicgRPCClientChannel::sendMessage(std::string plaintext) {
  // get the SHA-256 hash of the string with the SHA-2 digest from the CryptoPP
  // library
  std::string digest;
  std::string encodedDigest;
  CryptoPP::SHA256 hash;
  hash.Update((const CryptoPP::byte *)plaintext.data(), plaintext.size());
  digest.resize(hash.DigestSize());
  hash.Final((CryptoPP::byte *)&digest[0]);

  // Convert digest to hex string
  CryptoPP::StringSource(
      digest, true,
      new CryptoPP::HexEncoder(new CryptoPP::StringSink(encodedDigest)));

  this->basicClient->computeAndEncrypt(digest, plaintext);
  // do the rest here

  auto chan =
      grpc::CreateChannel(this->serverAddr, grpc::InsecureChannelCredentials());
  BasicProtocolClient client(chan);

  auto payload = genCiphertext();
  baseprotocol::RecievedCipherText resp;
  client.sendMessage(payload, &resp);

  return true;
}

baseprotocol::Ciphertext BasicgRPCClientChannel::genCiphertext() {
  baseprotocol::Ciphertext payload;

  // everything must be turned into a strinog
  std::ostringstream css;
  std::ostringstream ivss;

  ivss << this->basicClient->getIV();
  css << this->basicClient->getC();

  std::cout << "CLIENT" << std::endl;
  std::cout << "g as ZZ: " << this->basicClient->getg() << std::endl;
  std::cout << "IV as a ZZ: " << this->basicClient->getIV() << std::endl;
  std::cout << "C as a ZZ: " << this->basicClient->getC() << std::endl;
  // std::cout << "Cprime: " << this->basicClient->getCprime() << std::endl;
  std::cout << "Cprime length: " << this->basicClient->getCprime().length()
            << std::endl;
  std::cout << "grmN value:" << this->basicClient->getgrmN() << std::endl;
  std::cout << "N: " << this->basicClient->getN() << std::endl;
  std::cout << "sig: " << this->basicClient->getsig() << std::endl;

  // std::cout << "this is the IV in hex: " << ivss.str() << std::endl; // Debug
  // std::cout << "this is the c  in hex: " << css.str() << std::endl;  // Debug
  payload.set_c(css.str());
  payload.set_iv(ivss.str());
  // WARNING: we have no guarantee if Cprime will happens to have a null pointer
  // chracter, so we use the set_foo(char *, int) invocation
  // https://protobuf.dev/reference/cpp/cpp-generated/#proto3_string
  payload.set_cprime(this->basicClient->getCprime().data(),
                     this->basicClient->getCprime().length());
  payload.set_cprimelength(this->basicClient->getCprime().length());
  // std::cout << "this is the crpime: " << this->basicClient->getCprime()
  //           << std::endl; // Debug
  // std::cout << "this is the cprime length:"
  //           << this->basicClient->getCprime().length() << std::endl; // Debug

  return payload;
}

BasicProtocolClient::BasicProtocolClient(std::shared_ptr<grpc::Channel> channel)
    : m_stub(baseprotocol::BasicStringServer::NewStub(channel)) {}

bool BasicProtocolClient::sendMessage(const baseprotocol::Ciphertext &c,
                                      baseprotocol::RecievedCipherText *resp) {
  grpc::ClientContext context;
  this->m_stub->HandleUploadString(&context, c, resp);
  return true;
}

} // namespace actors
