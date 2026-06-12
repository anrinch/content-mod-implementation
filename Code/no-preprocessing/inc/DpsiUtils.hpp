#ifndef DPSI_UTILS_HPP
#define DPSI_UTILS_HPP
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <filesystem>
#include <vector>

const int TAG_SIZE = 16;
const size_t AES_KEY_SIZE = 32;
const size_t AES_IV_SIZE = 16;
const int PHASH_SIZE = 8;
const int UPLOAD_BUFFER_SZ = 4096;
const int NUM_OF_PRIME_ORACLE_BITS = 232;
const int MAX_N_BYTES = 4096 / 8;
const int ZZ_BUFFER_SZ = MAX_N_BYTES;
const size_t LONGSZ = sizeof(long);


//detection happens at the max of (t+1,m-s)
//m is 256 in this implementation
const long DHF_THRESHOLD  = 236;
const long DHF_POLYS = 21;
const long DHF_SEED = 1234;

// encrypted file is stored as file is [IV || RAWENCRYPTEDFILE]

using namespace NTL;
// using std::string;
// using std::tuple;

// tuple<ZZ, secure_string> CreatePayLoad(string xkey, string xval, ZZ &N, ZZ
// &g,
//                                        ZZ_p &sig);

// these are not secure
// this is just for feasibility and timing
void AES128KEY256EncryptFile(std::string filepath, unsigned char *key,
                             unsigned char *iv);

void AES128KEY256DecryptFile(std::string filepath, unsigned char *key,
                             unsigned char *iv);

void AES128KEY256EncryptStrings(std::string &ciphertext, std::string &plaintext,
                                unsigned char *key, unsigned char *iv);

void AES128KEY256DecryptStrings(std::string &recoveredtext,
                                std::string &ciphertext, unsigned char *key,
                                unsigned char *iv);

std::string CalculateHash(std::string filepath);

//This is here to make sure that both the client and Server use the same DHF KEY
std::vector<NTL::ZZ_pX> getDHFKey();

ZZ GetKey(ZZ groupElm, int keylength);

ZZ_p ChooseQRGenerator(ZZ &N, ZZ &QRorder, ZZ &pprime, ZZ &qprime);

void SetSignature(std::string signaturefile, ZZ_p &sig);

void SetFromConfig(std::string config, ZZ &p, ZZ &q, ZZ &N, ZZ &pprime,
                   ZZ &qprime, ZZ &QRorder, ZZ &Norder, ZZ &g);
ZZ GetPrimeLessThanN(ZZ &seed, long numbits);

ZZ GetZZfromHexString(std::string hexstr);

std::vector<NTL::ZZ> PolySecretShare(long shares, NTL::ZZ_pX& f);
NTL::ZZ getKeyFromPoly(NTL::ZZ_pX& f);
NTL::ZZ_pX getRandPoly(long degree);
NTL::ZZ PolyShareInterpolate(std::vector<NTL::ZZ>& xcoords,std::vector<NTL::ZZ>& ycoords);

void SetUpInputs(int numbits, ZZ &p, ZZ &q, ZZ &N, ZZ &pprime, ZZ &qprime,
                 ZZ &QRorder, ZZ &Norder, ZZ_p &g);

// this creates a small file of hashes for testing purposes
void GenTestHashFile(std::filesystem::path &p);

//concat inputs into a bit string and return as a NTL::ZZ
NTL::ZZ fuzzyConcatInputs(NTL::ZZ j, long zk, long k, NTL::ZZ z);

#endif
