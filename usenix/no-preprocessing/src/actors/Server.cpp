#include "actors/Server.hpp"
#include "DpsiUtils.hpp"
#include "DynamicBlockList.hpp"
#include "DetectableHashFunction.hpp"
#include "Projections.hpp"
#include "baseprotocol.pb.h"
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/vec_ZZ_p.h>
#include <boost/program_options.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <chrono>
#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include <fstream>
#include <grpc/grpc.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>
#include <grpcpp/support/status.h>
#include <memory>
#include <vector>

namespace actors {
BasicSearchServer::BasicSearchServer(NTL::ZZ &N, NTL::ZZ_p &sig)
    : m_N(N), m_sig(sig){
      };

FullSearchServer::FullSearchServer(const long l, const NTL::ZZ &N, const std::vector<NTL::ZZ_p> &sigs, const std::vector<NTL::ZZ> &projs)
  : m_l(l), m_N(N), m_projections(projs)  {
        //make [j][k] sigs so its easier to reference
    for(int j=0; j < m_projections.size(); j++) {
      std::vector<NTL::ZZ_p> sigjk;
      for(int k = 0; k < m_l; k++) {
        int idx = (j * m_l) + k;
        sigjk.push_back(sigs[idx]);
      }
      m_sigs.push_back(sigjk);
    }
  };


//TODO: change the way the blocklists are made
void FullSearchServer::fullInitBlockList(std::vector<NTL::ZZ> embeddings) {
  //make a blocklist but have a signature for each full embedding
  NTL::ZZ_p::init(m_N);
  //for each projection
  for(int j = 0; j < m_projections.size(); j++) {
    std::vector<std::vector<NTL::ZZ>> blocklist_j;
    NTL::ZZ proj = m_projections[j]; 
    for(long k = 0; k < m_l; k++) {
      std::vector<NTL::ZZ> blocklist_jk;
      for(int i = 0; i < embeddings.size(); i++) {
        NTL::ZZ z = psi_proj::evalProjectionFunc(proj, embeddings[i]);
        long zk = NTL::bit(z, k); 
        NTL::ZZ hashPreImg = fuzzyConcatInputs(proj, zk, k, z);       
        blocklist_jk.push_back(GetPrimeLessThanN(hashPreImg, NUM_OF_PRIME_ORACLE_BITS));
      }
      blocklist_j.push_back(blocklist_jk);
    }
    m_blocklist.push_back(blocklist_j);
  }
}


void BasicSearchServer::basicInitBlockList(std::vector<NTL::ZZ> embeddings) {
  // Debug
  // std::cout << "Server side ZZs that are added to the blocklist!" <<
  // std::endl;
  for (auto hash : embeddings) {
    ZZ blocklistZZ = GetPrimeLessThanN(hash, NUM_OF_PRIME_ORACLE_BITS);
    this->m_blocklist.push_back(blocklistZZ);
    // std::cout << blocklistZZ << std::endl; // Debug
  }
}

NTL::ZZ FullSearchServer::getKey() {
  return m_keyZZ;
}

std::chrono::milliseconds FullSearchServer::getDHFtime() {
  return m_dhf_ms;
} 

std::chrono::milliseconds FullSearchServer::getExptime() {
  return m_exp_ms;
} 

bool FullSearchServer::checkMatches(const std::vector<std::vector<NTL::ZZ>> &cprime_ss,
    const std::vector<std::vector<std::vector<NTL::ZZ>>> &cprime_dhf,
    const std::vector<std::string> &ciphertexts,
    const std::vector<std::vector<NTL::ZZ_p>> &c) {

  std::chrono::high_resolution_clock::time_point start;
  std::chrono::high_resolution_clock::time_point end;

  for(long j = 0; j < m_projections.size(); j++) {
    NTL::ZZ_p::init(m_N);
    
    start = std::chrono::high_resolution_clock::now();
    std::vector<std::vector<NTL::ZZ>> w_k;
    for(long k = 0; k < m_l; k++){
      NTL::ZZ_p::init(m_N);
      NTL::ZZ_p cjk = c[j][k];

      //WARNING: the order of items might be shuffled, but everything is shuffled the same way so it should be okay
      std::vector<NTL::ZZ_p> vals = dynamicblocklist::MakeBlockListforClientInput(m_blocklist[j][k], cjk, m_N);
      //
      //std::vector<NTL::ZZ_p> vals;
      //for(auto n : m_blocklist[j][k]) {
      //  NTL::ZZ_p element = cjk;
      //  for(auto m : m_blocklist[j][k]) {
      //    if (n != m) {
      //      element = NTL::power(element, m);
      //    }
      //  }
      //  vals.push_back(element);
      //} 

      std::vector<NTL::ZZ> w_ki;
      for(auto val : vals) {
        //store each one potential time pad
        NTL::ZZ item  = GetKey(conv<ZZ>(val), AES_KEY_SIZE*8);
        w_ki.push_back(item);
      }         
      w_k.push_back(w_ki);
    }
    end = std::chrono::high_resolution_clock::now();
    m_exp_ms += std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    //std::cout << "server w_[0][i]: " << std::endl;
    //for(auto val : w_k[0]) {
    //  std::cout << val << std::endl;
    //}
    //std::cout << "server w_[1][i]: " << std::endl;
    //for(auto val : w_k[1]) {
    //  std::cout << val << std::endl;
    //}
    //std::cout << "server w_[2][i]: " << std::endl;
    //for(auto val : w_k[2]) {
    //  std::cout << val << std::endl;
    //}

    //std::cout << "server c[200]: " << std::endl;
    //std::cout << c[0][200] << std::endl;
    // looks like one the values is correctly recovered

    //now we do the DHF detection with each projection 
    //doing DHF calculations so we need to make sure the modulus is correctly set;
    NTL::ZZ_p::init(DHF::GetField());

    start = std::chrono::high_resolution_clock::now();
    for(int i = 0; i < w_k[0].size() ; i++) {
      std::vector<NTL::vec_ZZ_p> unblinded_dhf;
      std::vector<NTL::ZZ> unblinded_ss;

      for(int k = 0; k < m_l; k++) {
        NTL::ZZ ssk;
        NTL::bit_xor(ssk, cprime_ss[j][k], w_k[k][i]);
        unblinded_ss.push_back(ssk);

        std::vector<NTL::ZZ> dhf = cprime_dhf[j][k];
        NTL::vec_ZZ_p unblinded_vector; 
        unblinded_vector.SetLength(dhf.size());

        for(long e = 0; e < dhf.size(); e++) {
          NTL::ZZ out;
          NTL::bit_xor(out, dhf[e], w_k[k][i]);
          unblinded_vector[e] = NTL::conv<ZZ_p>(out);
        }
        unblinded_dhf.push_back(unblinded_vector);
      }

      std::vector<int> detect_idx = DHF::DHFdetect(unblinded_dhf, DHF_THRESHOLD-1);
      if(detect_idx.size() > 0) {

        unsigned char key[AES_KEY_SIZE];
        unsigned char iv[AES_IV_SIZE] = {};
       
        std::vector<NTL::ZZ> ycoords;
        std::vector<NTL::ZZ> xcoords;

        for(long e = 0; e < detect_idx.size(); e++) {
          xcoords.push_back(NTL::ZZ(detect_idx[e]+1));
          ycoords.push_back(NTL::ZZ(unblinded_ss[detect_idx[e]]));
        }

        NTL::ZZ keyZZ = PolyShareInterpolate(xcoords,ycoords);
        m_keyZZ = keyZZ;

        NTL::BytesFromZZ(key, keyZZ, AES_KEY_SIZE);

        try {
          std::string recoveredtext;
          std::string ciphertext = ciphertexts[j];
          AES128KEY256DecryptStrings(recoveredtext, ciphertext, key, iv);
          end = std::chrono::high_resolution_clock::now();
          m_dhf_ms += std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
          return true;
        } catch (CryptoPP::HashVerificationFilter::HashVerificationFailed &e) {}
      }

    }
    end = std::chrono::high_resolution_clock::now();
    m_dhf_ms += std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
  }
  return false;
}

std::vector<NTL::ZZ> BasicSearchServer::getBlocklist() {
  return this->m_blocklist;
}

void BasicSearchServer::basicInitSig(NTL::ZZ_p &sig) { this->m_sig = sig; };

std::vector<NTL::ZZ_p> BasicSearchServer::calculateMatches(NTL::ZZ_p &v) {
  NTL::ZZ_p::init(this->m_N);
  std::vector<NTL::ZZ_p> valuesToCheck =
      dynamicblocklist::MakeBlockListforClientInput(this->m_blocklist, v,
                                                    this->m_N);

  // std::vector<NTL::ZZ_p> valuesToCheck;
  //// brute force n^2 way of doing the calculations

  // for (int i = 0; i < this->m_blocklist.size(); i++) {
  //   NTL::ZZ_p entry(v);
  //   for (int j = 0; j < this->m_blocklist.size(); j++) {
  //     if (j != i) {
  //       entry = NTL::power(entry, m_blocklist[j]);
  //     }
  //  }
  //   valuesToCheck.push_back(entry);
  // }
  //
  //  the vlaues seem to be the same as the dynamicblocklist

  return valuesToCheck;
}

std::chrono::milliseconds BasicSearchServer::gettime() {
  return this->m_time_ms;
}

void BasicSearchServer::enable_benchmarking(bool enable) {
  this->m_benchmarking = enable;
}

NTL::ZZ BasicSearchServer::getN() { return this->m_N; }

bool BasicSearchServer::checkMatches(std::string &ciphertext,
                                     std::string &recoveredtext, NTL::ZZ_p &v,
                                     unsigned char *iv) {
  std::chrono::high_resolution_clock::time_point start;
  std::chrono::high_resolution_clock::time_point end;
  if (m_benchmarking) {
    start = std::chrono::high_resolution_clock::now();
    std::atomic_thread_fence(std::memory_order_seq_cst);
  }
  NTL::ZZ_p::init(this->m_N);
  std::vector<NTL::ZZ_p> vals = calculateMatches(v);

  // Debug
  unsigned char key[AES_KEY_SIZE];
  //  the vlaues seem to be the same as the dynamicblocklist
  //  debug
  // std::cout << "SERVER VLAUES TO COMPARE TO GRMN:" << std::endl;
  // for (auto val : vals) {
  //  std::cout << val << std::endl;
  //}
  std::cout << "SERVER SIG: " << this->m_sig << std::endl;

  for (auto val : vals) {
    NTL::ZZ trykey = GetKey(conv<ZZ>(val), AES_KEY_SIZE * 8);
    NTL::BytesFromZZ(key, trykey, AES_KEY_SIZE);
    try {

      std::string teststring;
      AES128KEY256DecryptStrings(teststring, ciphertext, key, iv);
      if (this->m_benchmarking) {
        end = std::chrono::high_resolution_clock::now();
        this->m_time_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        std::atomic_thread_fence(std::memory_order_seq_cst);
      }
      recoveredtext = teststring;
      return true;
    } catch (CryptoPP::HashVerificationFilter::HashVerificationFailed &e) {
      // std::cout << "this should fail a lot" << std::endl;
      //  ignore the exception because we expect this to fail often
    }
  }

  if (this->m_benchmarking) {
    end = std::chrono::high_resolution_clock::now();
    this->m_time_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    std::atomic_thread_fence(std::memory_order_seq_cst);
  }
  return false;
}

BasicSearchServer::BasicSearchServer(const BasicSearchServer &other)
    : m_blocklist(other.m_blocklist), m_N(other.m_N), m_sig(other.m_sig) {}

JSONBasicSearchServerFactory::JSONBasicSearchServerFactory(
    const std::filesystem::path &config,
    const std::filesystem::path &blocklist) {
  // read the config
  namespace pt = boost::property_tree;
  pt::ptree proptree;
  pt::read_json(config, proptree);

  // Read in the entries as strings
  std::string NString = proptree.get<std::string>("N");
  std::string sigString = proptree.get<std::string>("sig");

  this->m_N = conv<ZZ>(NString.c_str());
  NTL::ZZ_p::init(this->m_N);
  this->m_sig = conv<ZZ_p>(sigString.c_str());

  // turn the hash list to ZZs
  std::ifstream blocklistfile(blocklist);
  std::string item;
  std::vector<NTL::ZZ> embeddings;

  // std::cout << "INPUTS TO MATCH:" << std::endl;
  while (getline(blocklistfile, item)) {
    ZZ element = GetZZfromHexString(item);
    embeddings.push_back(element);
    // std::cout << element << std::endl;
  }

  this->m_embeddings = embeddings;
  // Debug
  // for (auto embed : embeddings) {
  //  std::cout << embed << std::endl;
  //}
}

void JSONBasicSearchServerFactory::setBlockList(
    std::filesystem::path &blocklist, NTL::ZZ_p &sig) {
  NTL::ZZ_p::init(this->m_N);
  std::ifstream blocklistfile(blocklist);
  std::string item;
  std::vector<NTL::ZZ> embeddings;

  // std::cout << "INPUTS TO MATCH:" << std::endl;
  while (getline(blocklistfile, item)) {
    ZZ element = GetZZfromHexString(item);
    embeddings.push_back(element);
    // std::cout << element << std::endl;
  }

  this->m_embeddings = embeddings;
  this->m_sig = sig;
}

std::unique_ptr<BasicSearchServer>
JSONBasicSearchServerFactory::CreateBasicSearchServer() {
  BasicSearchServer ret(this->m_N, this->m_sig);
  // DEBUG
  // std::cout << "EMBEDDINGS:" << std::endl;
  for (auto embed : this->m_embeddings) {
    // std::cout << embed << std::endl;
  }
  ret.basicInitBlockList(this->m_embeddings);
  // enable benchmarking by deafult
  ret.enable_benchmarking(true);
  return std::make_unique<BasicSearchServer>(ret);
}

// you DO NOT need to map the embeddings to prime numbers through
// basicInitBlockList.
// This is still an offline step, but should save you some compute time
// for larger lists
std::unique_ptr<BasicSearchServer>
JSONBasicSearchServerFactory::CreateBasicSearchServer(
    const BasicSearchServer &other) {
  return std::make_unique<BasicSearchServer>(other);
}

GrpcBasicServer::GrpcBasicServer(std::string address) : m_address(address) {}
void GrpcBasicServer::setSearchServer(
    std::unique_ptr<BasicSearchServer> server) {
  this->m_searchServer = std::move(server);
}

NTL::ZZ_p BasicSearchServer::getSig() { return this->m_sig; }

grpc::Status
GrpcBasicServer::HandleUploadString(grpc::ServerContext *context,
                                    const baseprotocol::Ciphertext *req,
                                    baseprotocol::RecievedCipherText *resp) {
  NTL::ZZ_p::init(this->m_searchServer->getN());
  std::string cprime = req->cprime();
  std::string iv = req->iv();
  std::string c = req->c();
  unsigned char ivbuff[AES_IV_SIZE];

  std::cout << "SERVERSIDE:" << std::endl; // Debug
  // std::cout << "this is the IV: " << iv << std::endl;          // Debug
  // std::cout << "this is the c: " << c << std::endl;            // Debug
  // std::cout << "this is the cprime:" << cprime << std::endl;   // Debug
  // std::cout << "this is the cprime length:" << cprime.length() // Debug
  //<< std::endl; // Debug
  std::string recoveredtext;
  NTL::ZZ ivZZ = NTL::conv<ZZ>(iv.c_str());
  NTL::ZZ_p cZZ = NTL::conv<ZZ_p>(c.c_str());
  BytesFromZZ(ivbuff, ivZZ, AES_IV_SIZE);

  std::cout << "this is the IV: " << ivZZ << std::endl; // Debug
  std::cout << "this is the c: " << cZZ << std::endl;   // Debug
  // std::cout << "this is the cprime: " << cprime << std::endl;  // Debug
  std::cout << "this is the cprime length:" << cprime.length() // Debug
            << std::endl;                                      // Debug
  std::cout << "this is the N: " << this->m_searchServer->getN() << std::endl;
  std::cout << "this is the sig: " << this->m_searchServer->getSig()
            << std::endl;

  // list out the blocklist

  // std::cout << "BlockList Items:" << std::endl;
  // for (auto item : this->m_searchServer->getBlocklist()) {
  //   std::cout << item << std::endl;
  // }

  bool match =
      this->m_searchServer->checkMatches(cprime, recoveredtext, cZZ, ivbuff);

  if (match) {
    std::cout << "Match found in: " << this->m_searchServer->gettime().count()
              << "ms" << std::endl;
    std::cout << "recoveredtext: " << recoveredtext << std::endl;
  } else {
    std::cout << "No Match found in: "
              << this->m_searchServer->gettime().count() << "ms" << std::endl;
  }

  return grpc::Status::OK;
}

std::string GrpcBasicServer::getAddr() { return this->m_address; }

void RunServer(GrpcBasicServer &service) {
  std::string server_address(service.getAddr());

  grpc::ServerBuilder builder;
  builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
  builder.RegisterService(&service);
  std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
  server->Wait();
}

} // namespace actors
