#ifndef DPSI_CLIENT
#define DPSI_CLIENT
#include "baseprotocol.grpc.pb.h"
#include <NTL/ZZ_p.h>
#include <filesystem>
#include <memory>

namespace actors {

// This is the abstract client. Its up to the derived class to
// decide how to compute the ciphertext
class DpsiClient {
public:
  DpsiClient(const NTL::ZZ_p &sig, const NTL::ZZ_p &g, const NTL::ZZ &N);
  virtual ~DpsiClient() = default;

  // takes in a embedding as a hexstring
  // take in plaintext string to encrypt
  virtual void computeAndEncrypt(std::string &embedding,
                                 std::string &plaintext) = 0;

protected:
  NTL::ZZ_p m_g;
  NTL::ZZ_p m_sig;
  NTL::ZZ m_N;
};

// This is the client for the basic protocol
// This will encrypt a string when given a std::string
// The DpsiClient Object must be initalized with the g, sig, and N
// you can use an Client initlizer
class BasicDpsiClient : public DpsiClient {
public:
  BasicDpsiClient(const NTL::ZZ_p &sig, const NTL::ZZ_p &g, const NTL::ZZ &N);
  void computeAndEncrypt(std::string &embedding,
                         std::string &plaintext) override;
  NTL::ZZ_p getC();
  NTL::ZZ getN();
  std::string getCprime();
  NTL::ZZ getIV();

  // theses are for dubgging
  NTL::ZZ_p getgrmN();
  NTL::ZZ getr();
  NTL::ZZ_p getsig();
  NTL::ZZ_p getg();
protected:
  NTL::ZZ_p m_c;
  std::string m_cprime;
  NTL::ZZ m_wivZZ;

  // These are for debugging
  NTL::ZZ_p debug_grmN;
  NTL::ZZ debug_r;
};

//this won't inherit
class FullDpsiClient {
public:
  FullDpsiClient(const long l, const NTL::ZZ &N, const NTL::ZZ_p &g, const std::vector<NTL::ZZ_p> &sigs, const std::vector<NTL::ZZ> &projs);
  void computeAndEncrypt(std::string &embedding, std::string &plaintext);

  // theses are for dubgging
  NTL::ZZ_p getG();
  std::chrono::milliseconds getDHFtime();

  std::vector<std::vector<NTL::ZZ_p>> getC();
  std::vector<std::vector<NTL::ZZ>> getW();
  std::vector<std::string> getCprime();
  std::vector<std::vector<std::vector<NTL::ZZ>>> getCprime_dhf();
  std::vector<std::vector<NTL::ZZ>> getCprime_ss();
  NTL::ZZ getKey();


protected:
  std::vector<std::vector<NTL::ZZ_p>> m_c;
  std::vector<std::vector<NTL::ZZ>> m_w;
  NTL::ZZ_p m_g;
  NTL::ZZ m_N;
  NTL::ZZ m_keyZZ;
  long m_l;
  std::vector<std::string> m_cprime;
  std::vector<std::vector<NTL::ZZ_p>> m_sigs;
  std::vector<NTL::ZZ> m_projections;
  std::vector<std::vector<std::vector<NTL::ZZ>>> m_cprime_dhf;
  std::vector<std::vector<NTL::ZZ>> m_cprime_ss;
  std::chrono::milliseconds m_dhf_ms;
};


// this class will cosntruct the DpsiClients based off of a JSON input file
// You can create multiple clients from the same config this way
// Takes in a JSON config file in the constructor. Use a relative path for now.
class JSONBasicClientFactory {
public:
  std::unique_ptr<BasicDpsiClient> CreateClient();
  JSONBasicClientFactory(const std::filesystem::path &p);

protected:
  int m_numbits;
  NTL::ZZ m_N;
  NTL::ZZ_p m_g;
  NTL::ZZ_p m_sig;
};

// This class takes in a client instance
// It takes in address for communicating with a server
// It has a pointer to client instance
// This class the gRPC stub for sending the client data
// Is best to use the Factory to set the client of this class
// This uses SHA-2 by default
//
// This isn't the actually grpC client, but it craetes the channel
// and provides the input to the grpc client
class BasicgRPCClientChannel {
public:
  BasicgRPCClientChannel(std::string serverAddr);
  void setClient(std::unique_ptr<BasicDpsiClient> basicClient);

  // you have a hash function for the input for the plaintext
  // this allows you to use a different embedding if you don't
  // want to use SHA-2 for plaintext strings
  bool sendMessage(std::string embedding, std::string plaintext);

  // this uses the SHA-2 digest of the plaintext input
  bool sendMessage(std::string plaintext);

protected:
  std::unique_ptr<BasicDpsiClient> basicClient;
  std::string serverAddr;

private:
  baseprotocol::Ciphertext genCiphertext();
};

// this the actual gRPC client with the stub
// this makes the call to the server and should be constructed
// and used through the BasicgRPCClientChannel object
class BasicProtocolClient {
public:
  BasicProtocolClient(std::shared_ptr<grpc::Channel> channel);
  bool sendMessage(const baseprotocol::Ciphertext &c,
                   baseprotocol::RecievedCipherText *resp);

protected:
  std::unique_ptr<baseprotocol::BasicStringServer::Stub> m_stub;
};

} // namespace actors
#endif
