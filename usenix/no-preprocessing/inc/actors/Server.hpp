#include "baseprotocol.grpc.pb.h"
#include "baseprotocol.pb.h"
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <chrono>
#include <filesystem>
#include <memory>
#include <vector>

namespace actors {
const int GRPC_SEARCH_SERVER_BYTE_BUFFER_SIZE = 512;


class FullSearchServer{
public:
  FullSearchServer(const long l, const NTL::ZZ &N, const std::vector<NTL::ZZ_p> &sigs, const std::vector<NTL::ZZ> &projs);
  void fullInitBlockList(std::vector<NTL::ZZ> embeddings);
  NTL::ZZ getKey();
  std::chrono::milliseconds getDHFtime();
  std::chrono::milliseconds getExptime();
  bool checkMatches(const std::vector<std::vector<NTL::ZZ>> &cprime_ss,
    const std::vector<std::vector<std::vector<NTL::ZZ>>> &cprime_dhf,
    const std::vector<std::string> &ciphertexts,
    const std::vector<std::vector<NTL::ZZ_p>> &c);

protected:
  std::vector<std::vector<std::vector<NTL::ZZ>>> m_blocklist;
  std::chrono::milliseconds m_time_ms;
  std::vector<std::vector<NTL::ZZ_p>> m_sigs;
  std::vector<NTL::ZZ> m_projections;
  std::string m_plaintext;
  NTL::ZZ m_keyZZ;
  long m_l; 
  NTL::ZZ m_N;
  std::chrono::milliseconds m_dhf_ms;
  std::chrono::milliseconds m_exp_ms;
};

// this does no IO. This only handles the Math
class BasicSearchServer {
public:
  BasicSearchServer(NTL::ZZ &N, NTL::ZZ_p &sig);

  // copy constructor might makes sense if you want to have multiple searches
// going at the same time
  BasicSearchServer(const BasicSearchServer &other);
  void basicInitBlockList(std::vector<NTL::ZZ> m_embeddings);
  void basicInitSig(NTL::ZZ_p &sig);
  // generate the values to check against for decryption
  std::vector<NTL::ZZ_p> calculateMatches(NTL::ZZ_p &v);

  // return true if the cipher text was decrpyted
  bool checkMatches(std::string &ciphertext, std::string &recoveredtext,
                    NTL::ZZ_p &v, unsigned char *iv);

  // times the checkMatches method if benchmarking is enabled
  std::chrono::milliseconds gettime();
  std::vector<NTL::ZZ> getBlocklist();

  //
  void enable_benchmarking(bool enable);
  NTL::ZZ getN();
  NTL::ZZ_p getSig();

protected:
  std::vector<NTL::ZZ> m_blocklist;
  NTL::ZZ m_N;
  NTL::ZZ_p m_sig;
  bool m_benchmarking;
  // std::chrono::milliseconds m_time_ms;
  std::chrono::milliseconds m_time_ms;
};

// set up the server by allocating and configuring a search server
class GrpcBasicServer final : public baseprotocol::BasicStringServer::Service {
public:
  GrpcBasicServer(std::string address);
  void setSearchServer(std::unique_ptr<BasicSearchServer> server);
  std::string getAddr();

  grpc::Status
  HandleUploadString(grpc::ServerContext *context,
                     const baseprotocol::Ciphertext *req,
                     baseprotocol::RecievedCipherText *resp) override;

protected:
  std::string m_address;
  // this can be changed to a vector if you need multiple servers
  std::unique_ptr<BasicSearchServer> m_searchServer;
};

// While you can crate a BasicSearchServer Directly, its may be easier to
// create one through the JSONBasicSearchServerFactory.
// This class is supposed to intilize BasicSearchServer instances using the
// config.json created by the IOAuditorJSON. You can create duplicates or you
// can modify the signature and blocklist
class JSONBasicSearchServerFactory {
public:
  // take in a JSON file crated by the IOAuditorJSON
  // expects a file with list of hexstrings as the blocklist
  // This will also Init the blocklist
  JSONBasicSearchServerFactory(const std::filesystem::path &config,
                               const std::filesystem::path &blocklist);

  // Craetes and initlizes the BasicSearchServer
  // benchmarking is enabled by default
  std::unique_ptr<BasicSearchServer> CreateBasicSearchServer();

  // this should just wrap the copy constructor, its here for conveniance
  // This way you don't have to the computation of re-mapping the embeddings to
  // prime numbers
  std::unique_ptr<BasicSearchServer>
  CreateBasicSearchServer(const BasicSearchServer &other);

  // in case you want to change the blocklist and signature of the Server.
  // This might not be compleletly implemented yet, but we can start here if we
  // want to support multiple blocklists and signatures
  // if we also change the N, we may as well create a whole new factory
  void setBlockList(std::filesystem::path &blocklist, NTL::ZZ_p &sig);

protected:
  std::vector<NTL::ZZ> m_embeddings;
  NTL::ZZ m_N;
  NTL::ZZ_p m_sig;
};

void RunServer(GrpcBasicServer &server);
} // namespace actors
