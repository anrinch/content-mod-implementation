#include "actors/Auditor.hpp"
#include "DpsiUtils.hpp"
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <fstream>
#include <sstream>
#include <vector>
#include <set>
#include "Projections.hpp"

// handles all the math that that the Auditor needs to handle
namespace actors {

Auditor::Auditor(int numbits) : m_numbits(numbits) {};
FuzzyAuditor::FuzzyAuditor(int numbits) : m_numbits(numbits) {};

void Auditor::AuditorInit() {
  SetUpInputs(m_numbits, m_p, m_q, m_N, m_pprime, m_qprime, m_QRorder, m_Norder,
              m_g);
}

void Auditor::SignBlockList(std::vector<NTL::ZZ> &blocklist) {
  NTL::ZZ_p::init(this->m_QRorder);
  NTL::ZZ_p bprod = NTL::ZZ_p(1);
  // std::cout << "SEEDS:" << std::endl;
  for (auto seed : blocklist) {
    // std::cout << seed << std::endl;
    NTL::ZZ b = GetPrimeLessThanN(seed, NUM_OF_PRIME_ORACLE_BITS);
    bprod *= conv<NTL::ZZ_p>(b);
  }
  NTL::ZZ_p inverse = inv(bprod);
  NTL::ZZ_p::init(this->m_N);
  NTL::ZZ exp = conv<NTL::ZZ>(inverse);
  this->m_sig = NTL::power(this->m_g, exp);
}

void Auditor::AddToBlockList(std::vector<NTL::ZZ> &append) {
  NTL::ZZ_p::init(this->m_QRorder);
  NTL::ZZ_p aprod = NTL::ZZ_p(1);

  for(auto element : append) {
    NTL::ZZ a = GetPrimeLessThanN(element, NUM_OF_PRIME_ORACLE_BITS);
    aprod *= conv<NTL::ZZ_p>(a);
  }

  NTL::ZZ_p invsig = NTL::inv(aprod);
  NTL::ZZ_p::init(this->m_N);
  NTL::ZZ exp = conv<NTL::ZZ>(invsig);
  this->m_sig = NTL::power(this->m_sig, exp);
}

NTL::ZZ_p Auditor::getG() { return this->m_g; }
NTL::ZZ_p Auditor::getSig() { return this->m_sig; }
NTL::ZZ Auditor::getN() { return this->m_N; }


NTL::ZZ_p FuzzyAuditor::getG() { return this->m_g; }
std::vector<NTL::ZZ_p> FuzzyAuditor::getSigs() { return this->m_sigs; }
NTL::ZZ FuzzyAuditor::getN() { return this->m_N; }
std::vector<NTL::ZZ> FuzzyAuditor::getProjections(){return this->m_projections;}
int FuzzyAuditor::getNumBits() {return this->m_numbits;}

IOAuditorJSON::IOAuditorJSON(int numbits)
    : Auditor(numbits), m_config("config.json") {
  // std::cout << "Setting up Inputs" << std::endl;
  this->AuditorInit();
}

IOFuzzyAuditorJSON::IOFuzzyAuditorJSON(int numbits, long lambda, long l, long i)
    : FuzzyAuditor(numbits), m_config("config.json") {
  this->AuditorInit(lambda, l, i);
}

void FuzzyAuditor::AuditorInit(long lambda, long l ,long i) {
  SetUpInputs(m_numbits, m_p, m_q, m_N, m_pprime, m_qprime, m_QRorder, m_Norder,
              m_g);
  m_projections = psi_proj::getProjections(lambda, l, i);
  m_i = i;
  m_l = l;
  m_lambda = lambda;
}

void FuzzyAuditor::SignBlockList(std::vector<NTL::ZZ> &blocklist) {
  // TODO: want to make sure everything has at least one projection
  // for now, we're going to set lambda to 1

  //this may not be the most efficient but its simple to follow
  //get the projection of each element
  for(auto proj: m_projections) {
    std::vector<NTL::ZZ> projset;
    for(auto item : blocklist) {
      projset.push_back(psi_proj::evalProjectionFunc(proj, item));
    }

    m_evalprojections.push_back(projset);
  }


  //calculate the hash of each projection
  std::vector<std::vector<std::vector<NTL::ZZ>>> listsToSign;
  for(long j = 0; j < m_projections.size(); j++) {
    NTL::ZZ proj = m_projections.at(j);
    std::vector<std::vector<NTL::ZZ>> Bjprime;
    for (long k = 0; k < m_l; k++) {
    std::vector<NTL::ZZ> Bjkprime;
      // go through each bit of the element
      for(long i = 0; i < m_evalprojections[j].size(); i++) {
        NTL::ZZ z = m_evalprojections.at(j).at(i);
        //get the bit at k 
        long zk = NTL::bit(z, k); 
        NTL::ZZ hashPreImg = fuzzyConcatInputs(proj, zk, k, z);       
        Bjkprime.push_back(GetPrimeLessThanN(hashPreImg, NUM_OF_PRIME_ORACLE_BITS));
      }
      Bjprime.push_back(Bjkprime);
    }
    listsToSign.push_back(Bjprime);
  }

  // generate the exponenets 
  NTL::ZZ_p::init(this->m_QRorder);
  std::vector<std::vector<NTL::ZZ_p>> expsj;
  for (auto projSet : listsToSign) {
    std::vector<NTL::ZZ_p> expsjk;
    for (long k = 0; k < m_l; k++) {
      NTL::ZZ_p bprod = NTL::ZZ_p(1);
      for(auto item : projSet[k]) {
        bprod *= NTL::conv<ZZ_p>(item);
      }
      expsjk.push_back(NTL::inv(bprod));
    }
    expsj.push_back(expsjk);
  }

  // exponentiate
  // 256 sigs * projections
  NTL::ZZ_p::init(this->m_N);
  for (auto expjk : expsj) {
    for(auto exp : expjk) {
      m_sigs.push_back(NTL::power(m_g, NTL::conv<ZZ>(exp)));
    }
  }
}

std::string IOAuditorJSON::toString() {
  std::stringstream ss;
  ss << "{\n";
  ss << "  \"p\": \"" << this->m_p << "\",\n";
  ss << "  \"q\": \"" << this->m_q << "\",\n";
  ss << "  \"N\": \"" << this->m_N << "\",\n";
  ss << "  \"pprime\": \"" << this->m_pprime << "\",\n";
  ss << "  \"qprime\": \"" << this->m_qprime << "\",\n";
  ss << "  \"QRorder\": \"" << this->m_QRorder << "\",\n";
  ss << "  \"Norder\": \"" << this->m_Norder << "\",\n";
  ss << "  \"g\": \"" << this->m_g << "\",\n";
  ss << "  \"numbits\": \"" << this->m_numbits << "\",\n";
  ss << "  \"sig\": \"" << this->m_sig << "\"\n";
  ss << "}\n";
  return ss.str();
}

std::string IOFuzzyAuditorJSON::toString() {
  std::stringstream ss;
  ss << "{\n";
  ss << "  \"p\": \"" << this->m_p << "\",\n";
  ss << "  \"q\": \"" << this->m_q << "\",\n";
  ss << "  \"N\": \"" << this->m_N << "\",\n";
  ss << "  \"pprime\": \"" << this->m_pprime << "\",\n";
  ss << "  \"qprime\": \"" << this->m_qprime << "\",\n";
  ss << "  \"QRorder\": \"" << this->m_QRorder << "\",\n";
  ss << "  \"Norder\": \"" << this->m_Norder << "\",\n";
  ss << "  \"g\": \"" << this->m_g << "\",\n";
  ss << "  \"numbits\": \"" << this->m_numbits << "\",\n";
  ss << "  \"length\": \"" << this->m_l << "\",\n";
  ss << "  \"sigs\": [";
  for (size_t i = 0; i < m_sigs.size(); ++i) {
      ss << "\"" << m_sigs[i] << "\"";
      if (i < m_sigs.size() - 1) {
          ss << ", ";
      }
  }
  ss << "],\n";
  ss << "  \"projs\": [";
  for (size_t i = 0; i < m_projections.size(); ++i) {
      ss << "\"" << m_projections[i] << "\"";
      if (i < m_projections.size() - 1) {
          ss << ", ";
      }
  }
  ss << "]\n";
  ss << "}\n";
  return ss.str();
}

void IOAuditorJSON::parseHashFile(std::filesystem::path &filename) {
  std::vector<NTL::ZZ> blocklist;
  std::ifstream hashFile(filename);
  std::string item;

  while (std::getline(hashFile, item)) {
    try {
      blocklist.push_back(GetZZfromHexString(item));
    } catch (std::exception &e) {
      std::cerr << "something went wrong: " << e.what() << std::endl;
    }
  }
  this->SignBlockList(blocklist);
}

void IOFuzzyAuditorJSON::parseHashFile(std::filesystem::path &filename) {
  std::vector<NTL::ZZ> blocklist;
  std::ifstream hashFile(filename);
  std::string item;

  while (std::getline(hashFile, item)) {
    try {
      blocklist.push_back(GetZZfromHexString(item));
    } catch (std::exception &e) {
      std::cerr << "something went wrong: " << e.what() << std::endl;
    }
  }
  this->m_blocklistsize = blocklist.size();
  this->SignBlockList(blocklist);
}

int IOFuzzyAuditorJSON::GetBlockListSize() {
  return m_blocklistsize;
}

int Auditor::getNumBits() { return this->m_numbits; }

void IOAuditorJSON::generateConfigJSON(std::string filename) {
  std::ofstream outputfile(filename);
  outputfile << this->toString();
  outputfile.close();
  std::filesystem::path config(filename);
  this->m_config = config;
}

std::filesystem::path IOAuditorJSON::GetJSONConfigFile() {
  return this->m_config;
}

void IOFuzzyAuditorJSON::generateConfigJSON(std::string filename) {
  std::ofstream outputfile(filename);
  outputfile << this->toString();
  outputfile.close();
  std::filesystem::path config(filename);
  this->m_config = config;
}

std::filesystem::path IOFuzzyAuditorJSON::GetJSONConfigFile() {
  return this->m_config;
}

} // namespace actors
