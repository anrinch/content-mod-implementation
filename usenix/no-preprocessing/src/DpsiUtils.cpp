#include "DpsiUtils.hpp"
#include "DetectableHashFunction.hpp"
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/ZZ_pX.h>
#include <boost/program_options.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <cryptopp/cryptlib.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/gcm.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rijndael.h>
#include <fstream>

namespace pt = boost::property_tree;
using namespace NTL;
const NTL::ZZ POLYSHARE_FIELD = NTL::power2_ZZ(256) - 357;

void AES128KEY256EncryptFile(std::string filepath, unsigned char *key,
                             unsigned char *iv) {
  // using some boiler platecode fromthe cyptopp wiki
  using namespace CryptoPP;
  std::string sinkfile;
  size_t pos = filepath.find_last_of("/");
  if (pos != std::string::npos) {
    sinkfile = filepath.substr(pos + 1) + "-encrypted";
  } else {
    sinkfile = filepath + "-encrypted";
  }

  // SecByteBlock key(AES::DEFAULT_KEYLENGTH);
  // SecByteBlock iv(AES::BLOCKSIZE);

  try {
    GCM<AES>::Encryption e;
    e.SetKeyWithIV((byte *)key, AES_KEY_SIZE, (byte *)iv, AES_IV_SIZE);

    AuthenticatedEncryptionFilter *ef = new AuthenticatedEncryptionFilter(
        e, new FileSink(sinkfile.c_str()), false, TAG_SIZE);

    FileSource(filepath.c_str(), true, ef);

  } catch (CryptoPP::AuthenticatedSymmetricCipher::BadState &e) {
    std::cerr << "Caught BadState..." << std::endl;
    std::cerr << e.what() << std::endl;
    std::cerr << std::endl;
  } catch (CryptoPP::InvalidArgument &e) {
    std::cerr << "Caught InvalidArgument..." << std::endl;
    std::cerr << e.what() << std::endl;
    std::cerr << std::endl;
  }
}

//This is here to make sure that both the client and Server use the same DHF KEY
std::vector<NTL::ZZ_pX> getDHFKey() {
  return DHF::DHFGenKey(DHF_POLYS, DHF_THRESHOLD-1, DHF_SEED);
}

void AES128KEY256DecryptFile(std::string filepath, unsigned char *key,
                             unsigned char *iv) {
  using namespace CryptoPP;

  try {
    GCM<AES>::Decryption d;
    d.SetKeyWithIV((byte *)key, AES_KEY_SIZE, (byte *)iv, AES_IV_SIZE);

    std::string outfile;
    size_t pos = filepath.find_last_of("/");
    if (pos != std::string::npos) {
      outfile = filepath.substr(pos + 1) + "-decrypted";
    } else {
      outfile = filepath + "-decrypted";
    }

    AuthenticatedDecryptionFilter *df = new AuthenticatedDecryptionFilter(
        d, new FileSink(outfile.c_str()),
        AuthenticatedDecryptionFilter::MAC_AT_END |
            AuthenticatedDecryptionFilter::THROW_EXCEPTION,
        TAG_SIZE);

    FileSource(filepath.c_str(), true, df);

  } catch (CryptoPP::AuthenticatedSymmetricCipher::BadState &e) {
    std::cerr << "Caught BadState..." << std::endl;
    std::cerr << e.what() << std::endl;
    std::cerr << std::endl;
  } catch (CryptoPP::HashVerificationFilter::HashVerificationFailed &e) {
    std::cerr << "Caught HashVerificationFailed..." << std::endl;
    std::cerr << e.what() << std::endl;
    std::cerr << std::endl;
  }
}

// encrypt and decrypt strings with CryptoPP
void AES128KEY256EncryptStrings(std::string &ciphertext, std::string &plaintext,
                                unsigned char *key, unsigned char *iv) {
  using namespace CryptoPP;

  try {
    GCM<AES>::Encryption e;
    e.SetKeyWithIV((byte *)key, AES_KEY_SIZE, (byte *)iv, AES_IV_SIZE);

    AuthenticatedEncryptionFilter *ef = new AuthenticatedEncryptionFilter(
        e, new StringSink(ciphertext), false, TAG_SIZE);

    StringSource(plaintext.c_str(), true, ef);
  } catch (CryptoPP::AuthenticatedSymmetricCipher::BadState &e) {
    std::cerr << "Caught BadState..." << std::endl;
    std::cerr << e.what() << std::endl;
    std::cerr << std::endl;
  } catch (CryptoPP::InvalidArgument &e) {
    std::cerr << "Caught InvalidArgument..." << std::endl;
    std::cerr << e.what() << std::endl;
    std::cerr << std::endl;
  }
}

void AES128KEY256DecryptStrings(std::string &recovertext,
                                std::string &ciphertext, unsigned char *key,
                                unsigned char *iv) {

  using namespace CryptoPP;

  try {
    GCM<AES>::Decryption d;
    d.SetKeyWithIV((byte *)key, AES_KEY_SIZE, (byte *)iv, AES_IV_SIZE);

    AuthenticatedDecryptionFilter *df = new AuthenticatedDecryptionFilter(
        d, new StringSink(recovertext),
        AuthenticatedDecryptionFilter::MAC_AT_END |
            AuthenticatedDecryptionFilter::THROW_EXCEPTION,
        TAG_SIZE);

    StringSource(ciphertext, true, df);

  } catch (CryptoPP::AuthenticatedSymmetricCipher::BadState &e) {
    std::cerr << "Caught BadState..." << std::endl;
    std::cerr << e.what() << std::endl;
    std::cerr << std::endl;
  } catch (CryptoPP::HashVerificationFilter::HashVerificationFailed &e) {
    // std::cerr << "Caught HashVerificationFailed..." << std::endl;
    // std::cerr << e.what() << std::endl;
    // std::cerr << std::endl;
    throw e;
  }
}

// figure out a generator:
// https://cacr.uwaterloo.ca/hac/about/chap4.pdf pg 163
// find a generator mod N, and then square it.
// a number is a generator if it is co
// Phi(N)/2 = p' * q' * 2 so we have the prime factorization
ZZ_p ChooseQRGenerator(ZZ &N, ZZ &QRorder, ZZ &pprime, ZZ &qprime) {
  // ZZ_p::init(N);
  ZZ_p::init(QRorder);
  ZZ_p a, b;

  int testcount = 1;
  while (testcount > 0) {
    testcount = 0;
    a = random_ZZ_p();

    ZZ test1 = QRorder / pprime;
    ZZ test2 = QRorder / qprime;
    ZZ test3 = QRorder / 2;

    power(b, a, test1);
    if (b == ZZ_p(1)) {
      testcount++;
    }
    power(b, a, test2);
    if (b == ZZ_p(1)) {
      testcount++;
    }
    power(b, a, test3);
    if (b == ZZ_p(1)) {
      testcount++;
    }
  }

  return a;
}

// H_G: G -> K
ZZ GetKey(ZZ groupElm, int keylength) {
  SetSeed(groupElm);
  ZZ key = RandomBits_ZZ(keylength);
  return key;
}

//std::vector<NTL::ZZ> XorSecretShare(long shares, NTL::ZZ &secret, long bitLength) {
//  std::vector<NTL:ZZ> shares;
//  NTL::ZZ input(secret);
//  NTL::ZZ result(0);
//
//  for(long i = 0; i < shares-1; i++) {
//    NTL::ZZ randinput = NTL::RandomBits_ZZ(bitLength);
//    NTL::bit_xor(result, input, randinput);
//    shares.push_back(randinput); 
//    input = result;
//  }
//  
//  shares.push_back(input);
//  return shares;
//}


//these operations ar done like this becuase these operations require a different modulus/field
NTL::ZZ_pX getRandPoly(long degree) {
  NTL::ZZ_pPush push(POLYSHARE_FIELD);
  NTL::ZZ_pX randpoly = NTL::random_ZZ_pX(degree);
  return randpoly;
}

NTL::ZZ getKeyFromPoly(NTL::ZZ_pX& f) {
  // change the POLYSHARE_FIELD to be thes second largest prime
  // less than 2^256
  // no need to truncate becuase the key should be in the field
  NTL::ZZ_pPush push(POLYSHARE_FIELD);
  NTL::ZZ zero(0);
  NTL::ZZ key = NTL::conv<ZZ>(NTL::eval(f, NTL::conv<ZZ_p>(zero)));
  return key;
}

NTL::ZZ PolyShareInterpolate(std::vector<NTL::ZZ>& xcoords,std::vector<NTL::ZZ>& ycoords) {
  NTL::ZZ_pPush push(POLYSHARE_FIELD);
  NTL::vec_ZZ_p y;
  NTL::vec_ZZ_p x;
  NTL::ZZ_pX poly;

  y.SetLength(ycoords.size());
  x.SetLength(xcoords.size());

  for(long i = 0; i < xcoords.size(); i++) {
    x[i] = NTL::conv<ZZ_p>(xcoords[i]);
    y[i] = NTL::conv<ZZ_p>(ycoords[i]);
  }

  NTL::interpolate(poly, x, y);
  NTL::ZZ zero(0);
  NTL::ZZ secret = NTL::conv<ZZ>(NTL::eval(poly, NTL::conv<ZZ_p>(zero)));
  
  return secret;
}

// just want to return the 
std::vector<NTL::ZZ> PolySecretShare(long shares, NTL::ZZ_pX& f) {
  NTL::ZZ_pPush push(POLYSHARE_FIELD);
  NTL::vec_ZZ_p x;
  NTL::vec_ZZ_p y;
  
  x.SetLength(shares);
  for(long i = 0; i < shares; i++) {
    x[i] = NTL::ZZ_p(i+1);
  }

  NTL::eval(y, f, x);
  std::vector<NTL::ZZ> ret;

  for(long i = 0; i < shares; i++) {
    ret.push_back(NTL::conv<ZZ>(y[i]));
  }

  return ret;
}


// assumes that you have set ZZ_p::init(N)
void SetSignature(std::string signaturefile, ZZ_p &sig) {
  pt::ptree proptree;
  pt::read_json(signaturefile, proptree);
  std::string sigstring = proptree.get<std::string>("signature");
  sig = conv<ZZ_p>(sigstring.c_str());
}

void SetFromConfig(std::string config, ZZ &p, ZZ &q, ZZ &N, ZZ &pprime,
                   ZZ &qprime, ZZ &QRorder, ZZ &Norder, ZZ &g) {

  pt::ptree proptree;
  pt::read_json(config, proptree);

  // Read in the entries as strings
  std::string pstring = proptree.get<std::string>("p");
  std::string qstring = proptree.get<std::string>("q");
  std::string Nstring = proptree.get<std::string>("N");
  std::string pprimestring = proptree.get<std::string>("pprime");
  std::string qprimestring = proptree.get<std::string>("qprime");
  std::string QRorderstring = proptree.get<std::string>("QRorder");
  std::string Norderstring = proptree.get<std::string>("Norder");
  std::string gstring = proptree.get<std::string>("g");

  p = conv<ZZ>(pstring.c_str());
  q = conv<ZZ>(qstring.c_str());
  N = conv<ZZ>(Nstring.c_str());
  pprime = conv<ZZ>(pprimestring.c_str());
  qprime = conv<ZZ>(qprimestring.c_str());
  QRorder = conv<ZZ>(QRorderstring.c_str());
  Norder = conv<ZZ>(Norderstring.c_str());
  g = conv<ZZ>(gstring.c_str());
}

// TODO: error checking here to make sure that we are getting a proper prime
//  assumes that you have set ZZ_p::init(N)
//  H_p: G -> P
ZZ GetPrimeLessThanN(ZZ &seed, long numbits) {
  SetSeed((seed));

  // the -1 makes sure that the primes are less than N
  return GenPrime_ZZ((numbits - 1), 80);
}

// convert a string rpresentation of a hexnumber to a NTL::ZZ
// if its a human readable hash, the MSB is probably shown first
ZZ GetZZfromHexString(std::string hexstr) {

  // lmabda to get rid of whitespcae
  hexstr.erase(std::remove_if(hexstr.begin(), hexstr.end(),
                              [](unsigned char c) { return !std::isalnum(c); }),
               hexstr.end());
  if (hexstr.length() % 2 != 0) {

    // pad with a zero so we can read each value one byte at a time
    hexstr = "0" + hexstr;
  }

  std::vector<unsigned char> char2bytes;
  for (int i = hexstr.length(); i > 0; i -= 2) {
    // assuming the hexstr is big endian MSB->LSB
    // byte  = nibble0  | nibble1 (MSB)
    // ZZfromBytes is little endian
    //
    // ZZ ZZFromBytes(const unsigned char *p, long n)
    // x = sum(p[i]*256^i, i=0..n-1)
    //
    // example hexstr = DEADBEEF, decstr: 3735928559
    // p[0] = EF
    unsigned char v = std::stoi(hexstr.substr(i - 2, 2), nullptr, 16);
    char2bytes.push_back(v);
  }

  return ZZFromBytes(char2bytes.data(), (hexstr.length() / 2));
}

// this is what geneartes the config file,
void SetUpInputs(int numbits, ZZ &p, ZZ &q, ZZ &N, ZZ &pprime, ZZ &qprime,
                 ZZ &QRorder, ZZ &Norder, ZZ_p &g) {

  // seed the input so I always create the same result when testing
  // SetSeed(ZZ(0));

  GenGermainPrime(p, numbits, 80);
  GenGermainPrime(q, numbits, 80);

  N = p * q;
  Norder = (p - 1) * (q - 1);

  p -= 1;
  q -= 1;
  RightShift(pprime, p, 1);
  RightShift(qprime, q, 1);
  p += 1;
  q += 1;

  QRorder = qprime * pprime;

  ZZ_p::init(N);
  g = ChooseQRGenerator(N, QRorder, pprime, qprime);
}

void GenTestHashFile(std::filesystem::path &p) {
  std::ofstream testFile(p);
  testFile << "083bf3fec698dad766a50436605b7a9f6a8a51b66f5717dedf3eb0ca01b22f0c"
           << "\n";
  testFile << "8009c4ade6f9da066b786896d13d1b144ca40d1c16bfc983f765db7e2f4d7552"
           << "\n";
  testFile << "01f5cd852f2100fcaf4a0abbbaf438dc790fc2fe7a255d8d15b328b598f75a51"
           << "\n";
}


NTL::ZZ fuzzyConcatInputs(NTL::ZZ j, long zk, long k, NTL::ZZ z) {
  NTL::ZZ ret(j);     
  //ret << LONGSZ; changing this to be more explicit/consistent
 // ret << 64;
 // ret |= zk;
 // //ret << LONGSZ;
 // ret << 64;
 // ret |= k;
 // ret << NTL::NumBits(z);
 // ret |= z;NTL::ZZ ret = j;

  ret <<= 1;
  ret |= NTL::ZZ(zk & 1); // ensure only 1 bit
  ret <<= 16;
  ret |= NTL::ZZ(k & 0xFFFF); // 16-bit mask
  long zbits = NTL::NumBits(z); // this is dynamic
  ret <<= zbits;
  ret |= z;
  return ret;
}

