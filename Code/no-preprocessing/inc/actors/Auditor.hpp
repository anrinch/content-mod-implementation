#ifndef DPSI_AUDITOR
#define DPSI_AUDITOR
#include <NTL/ZZ_p.h>
#include <filesystem>
#include <vector>
#include <set>

namespace actors {
class Auditor {

public:
  Auditor(int numbits);
  void AuditorInit();
  // maps and signs blocklist given vector of values
  void SignBlockList(std::vector<NTL::ZZ> &blocklist);
  void AddToBlockList(std::vector<NTL::ZZ> &append);
  int getNumBits();
  NTL::ZZ getN();
  NTL::ZZ_p getSig();
  NTL::ZZ_p getG();

protected:
  int m_numbits;
  NTL::ZZ m_p;
  NTL::ZZ m_q;
  NTL::ZZ m_N;
  NTL::ZZ m_pprime;
  NTL::ZZ m_qprime;
  NTL::ZZ m_QRorder;
  NTL::ZZ m_Norder;
  NTL::ZZ_p m_g;
  NTL::ZZ_p m_sig;
};

class IOAuditorJSON : public Auditor {
public:
  IOAuditorJSON(int numbits = 1024);
  std::string toString();
  // prases and signs the blocklist, this will parse the file and call
  // Auditor::SignBlockList
  void parseHashFile(std::filesystem::path &filename);
  void generateConfigJSON(std::string filename = "config.json");
  std::filesystem::path GetJSONConfigFile();

protected:
  std::filesystem::path m_config;
};

class FuzzyAuditor {

public:
  FuzzyAuditor(int numbits);
  void AuditorInit(long lambda, long l, long i);
  void SignBlockList(std::vector<NTL::ZZ> &blocklist);
  //void AddToBlockList(std::vector<NTL::ZZ> &append);
  int getNumBits();
  NTL::ZZ getN();
  std::vector<NTL::ZZ> getProjections();
  std::vector<NTL::ZZ_p> getSigs();
  NTL::ZZ_p getG();

protected:
  std::vector<NTL::ZZ> m_projections;
  std::vector<std::vector<NTL::ZZ>> m_evalprojections;
  int m_numbits;
  long m_lambda;
  long m_l;
  long m_i;
  std::vector<NTL::ZZ_p> m_sigs;
  NTL::ZZ m_p;
  NTL::ZZ m_q;
  NTL::ZZ m_N;
  NTL::ZZ m_pprime;
  NTL::ZZ m_qprime;
  NTL::ZZ m_QRorder;
  NTL::ZZ m_Norder;
  NTL::ZZ_p m_g;

};

class IOFuzzyAuditorJSON : public FuzzyAuditor {
public:
  IOFuzzyAuditorJSON(int numbits, long lambda, long l, long i);
  std::string toString();
  void parseHashFile(std::filesystem::path &filename);
  void generateConfigJSON(std::string filename = "config.json");
  std::filesystem::path GetJSONConfigFile();
  int GetBlockListSize();

protected:
  std::filesystem::path m_config;
  int m_blocklistsize;
};

} // namespace actors

#endif
