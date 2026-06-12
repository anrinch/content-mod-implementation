#ifndef APPLE_DHF
#define APPLE_DHF
#include <NTL/ZZ_p.h>
#include <NTL/ZZ_pX.h>
#include <NTL/mat_ZZ_p.h>
#include <NTL/vec_ZZ_p.h>
#include <cstdint>
#include <vector>

typedef unsigned long ulong;

namespace DHF {

// make an (s,t)  detectable hash detectablehashfunction

// constructing a DHF
//
// t+1 is the number of matches needed
// s is the upper bound on the set size
//
// K: F_{l}^{s /cross t}
// X: F_{l}
// R: F_{l}^{s+1}
//
// we have s polynomails p_1,...p_s \in F_{l}[X]
// each of degree t-1

// let x_0 \in X be an element
// DHF(k x_0) := (x_0, p_1(x_0),..,p_s(x_0)) \in F^{s+1}_{l}

// get a vector ZZ_p DHF()

// each column of the output matrix is the output of
// DHF(k,x_0)

// outputs vector of s polynomials of degree t-1
NTL::ZZ GetField();
std::vector<NTL::ZZ_pX> DHFGenKey(long s, long t);

// adding this function and setting a hardcoded seed
std::vector<NTL::ZZ_pX> DHFGenKey(long s, long t, long seed);
NTL::mat_ZZ_p ExpandNTLVecsIntoNTLMatrix(std::vector<NTL::vec_ZZ_p> dhf_vectors,
                                         long t);
NTL::vec_ZZ_p DHFk_xi(std::vector<NTL::ZZ_pX> key, NTL::ZZ_p x);
std::vector<int> DHFdetect(std::vector<NTL::vec_ZZ_p> dhf_vectors, long t);
bool IsInLinearSpan(NTL::mat_ZZ_p &m, long rank);
bool DHFdetect(NTL::mat_ZZ_p hash);
NTL::vec_ZZ_p DHFk_xi(std::vector<NTL::ZZ_pX> key);

// this is the prime field over which the DHF will be computed
NTL::ZZ GetPrimel();
} // namespace DHF

std::vector<ulong> pyconvVecZZp(const NTL::vec_ZZ_p v);

unsigned long getTest();
std::vector<uint8_t> vecZZp_to_bytes(const NTL::vec_ZZ_p &v);

NTL::vec_ZZ_p bytes_to_vecZZp(const uint8_t *bytes, size_t length);

std::vector<uint8_t> pyDHFvect(std::vector<NTL::ZZ_pX> key);
// std::vector<NTL::vec_ZZ_p>
// to_vecZZp(const std::vector<std::vector<long>> &data);

std::vector<NTL::vec_ZZ_p>
list_of_bytes_to_vecZZp(const std::vector<std::vector<uint8_t>> &list_of_bytes);

std::vector<int>
pyDHFDetect(const std::vector<std::vector<uint8_t>> &list_of_bytes, long t);

std::vector<int> pySimDHF(long s, long t);
#endif
