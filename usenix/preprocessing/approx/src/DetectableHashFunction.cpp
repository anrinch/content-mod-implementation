#include "DetectableHashFunction.hpp"
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/ZZ_pX.h>
#include <NTL/mat_ZZ_p.h>
#include <NTL/matrix.h>
#include <NTL/vec_ZZ_p.h>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <sys/types.h>
#include <vector>

typedef unsigned long ulong;

namespace DHF {

NTL::ZZ GetField() { return NTL::power2_ZZ(64) - 59; }

std::vector<NTL::ZZ_pX> DHFGenKey(long s_size, long t_degree) {
  NTL::ZZ dhf_field = GetField();
  NTL::ZZ_pPush dhfmod(dhf_field);
  std::vector<NTL::ZZ_pX> dhf_polys;
  for (int i = 0; i < s_size; i++) {
    dhf_polys.push_back(NTL::random_ZZ_pX(t_degree));
  }
  return dhf_polys;
}

std::vector<NTL::ZZ_pX> DHFGenKey(long s_size, long t_degree, long seed) {
  NTL::SetSeed(NTL::ZZ(seed));
  NTL::ZZ dhf_field = GetField();
  NTL::ZZ_pPush dhfmod(dhf_field);
  std::vector<NTL::ZZ_pX> dhf_polys;
  for (int i = 0; i < s_size; i++) {
    dhf_polys.push_back(NTL::random_ZZ_pX(t_degree));
  }
  return dhf_polys;
}

std::vector<int> DHFdetect(std::vector<NTL::vec_ZZ_p> dhf_vectors, long t) {
  NTL::ZZ dhf_field = GetField();
  NTL::ZZ_pPush dhfmod(dhf_field);
  NTL::mat_ZZ_p expanded = ExpandNTLVecsIntoNTLMatrix(dhf_vectors, t);
  long s = expanded.NumRows() - t;

  NTL::mat_ZZ_p expandedtranspose = NTL::transpose(expanded);
  NTL::mat_ZZ_p ker;
  NTL::kernel(ker, expandedtranspose);

  if (NTL::IsZero(ker) == 1) {
    return {};
  }

  std::vector<int> subidxs;
  for (int i = 0; i < ker[0].length(); i++) {
    if (ker[0][i] != 0) {
      subidxs.push_back(i);
    }
  }

  NTL::mat_ZZ_p submatrix;
  submatrix.SetDims(subidxs.size(), (s + t));
  for (int i = 0; i < subidxs.size(); i++) {
    submatrix[i] = expandedtranspose[subidxs.at(i)];
  }

  long submatrix_rank = NTL::gauss(submatrix);
  std::vector<int> outidx;
  for (int i = 0; i < expandedtranspose.NumRows(); i++) {
    NTL::mat_ZZ_p augmentedtranspose;
    augmentedtranspose.SetDims(submatrix.NumRows() + 1, (s + t));

    for (int j = 0; j < submatrix.NumRows(); j++) {
      augmentedtranspose[j] = submatrix[j];
    }
    augmentedtranspose[submatrix.NumRows()] = expandedtranspose[i];

    NTL::mat_ZZ_p augmented = NTL::transpose(augmentedtranspose);
    long rank = NTL::gauss(augmented);

    if (rank == submatrix_rank) {
      outidx.push_back(i);
    }
  }

  return outidx;
}

bool IsInLinearSpan(NTL::mat_ZZ_p &m, long rank) {
  NTL::ZZ dhf_field = GetField();
  NTL::ZZ_pPush dhfmod(dhf_field);
  long numberOfZeroRows = m.NumRows() - rank;
  if (numberOfZeroRows == 0) {
    return true;
  }

  long rowCheck = 0;
  for (int i = 0; i < m.NumRows(); i++) {
    if (NTL::IsZero(m[i])) {
      rowCheck++;
    }
  }

  return (rowCheck == numberOfZeroRows);
}

NTL::vec_ZZ_p DHFk_xi(std::vector<NTL::ZZ_pX> key, NTL::ZZ_p x) {
  NTL::ZZ dhf_field = GetField();
  NTL::ZZ_pPush dhfmod(dhf_field);

  NTL::vec_ZZ_p v;
  v.SetLength(key.size() + 1);
  NTL::SetSeed(NTL::conv<NTL::ZZ>(x));
  NTL::ZZ_p xx = NTL::random_ZZ_p();
  v[0] = xx;

  for (int i = 1; i < v.length(); i++) {
    v[i] = NTL::eval(key.at(i - 1), xx);
  }
  return v;
}

NTL::vec_ZZ_p DHFk_xi(std::vector<NTL::ZZ_pX> key) {
  NTL::ZZ dhf_field = GetField();
  NTL::ZZ_pPush dhfmod(dhf_field);

  NTL::vec_ZZ_p v;
  v.SetLength(key.size() + 1);
  NTL::ZZ_p x = NTL::random_ZZ_p();
  v[0] = x;

  for (int i = 1; i < v.length(); i++) {
    v[i] = NTL::eval(key.at(i - 1), x);
  }
  return v;
}

NTL::mat_ZZ_p ExpandNTLVecsIntoNTLMatrix(std::vector<NTL::vec_ZZ_p> dhf_vectors,
                                         long t) {
  NTL::ZZ dhf_field = GetField();
  NTL::ZZ_pPush dhfmod(dhf_field);
  NTL::mat_ZZ_p expansion;

  long s = dhf_vectors.at(0).length() - 1;
  long m = dhf_vectors.size();
  expansion.SetDims(m, s + t);

  for (long i = 0; i < m; i++) {
    NTL::vec_ZZ_p temp;
    temp.SetLength(s + t);
    NTL::ZZ_p x0 = dhf_vectors.at(i)[0];

    int idx = 1;
    for (long j = 0; j < (s + t); j++) {
      if (j == 0) {
        temp[j] = 1;
      } else if (j < t) {
        temp[j] = NTL::power(x0, j);
      } else {
        temp[j] = dhf_vectors.at(i)[idx];
        idx++;
      }
    }
    expansion[i] = temp;
  }

  return NTL::transpose(expansion);
}
} // namespace DHF

// std::vector<NTL::vec_ZZ_p>
// to_vecZZp(const std::vector<std::vector<ulong>> &data) {
//   NTL::ZZ f = DHF::GetField();
//   NTL::ZZ_p::init(f);
//   std::vector<NTL::vec_ZZ_p> result;
//   result.reserve(data.size());
//
//   for (const auto row : data) {
//     NTL::vec_ZZ_p v;
//     v.SetLength(row.size());
//     for (ulong i = 0; i < (ulong)row.size(); i++) {
//       v[i] = NTL::conv<NTL::ZZ_p>(NTL::ZZ(row[i]));
//     }
//     result.push_back(v);
//   }
//
//   return result;
// }
NTL::vec_ZZ_p bytes_to_vecZZp(const uint8_t *bytes, size_t length) {
  NTL::ZZ f = DHF::GetField();
  NTL::ZZ_p::init(f);
  size_t n = length / 8; // 8 bytes per element
  NTL::vec_ZZ_p v;
  v.SetLength(n);

  for (size_t i = 0; i < n; i++) {
    uint64_t val = 0;
    for (int b = 0; b < 8; b++) {
      val |= static_cast<uint64_t>(bytes[i * 8 + b])
             << (8 * b); // little-endian
    }
    NTL::ZZ foo(val);
    NTL::ZZ_p bar = NTL::conv<NTL::ZZ_p>(foo); // ✅ correct conversion
    v[i] = bar;
  }

  return v;
}

std::vector<NTL::vec_ZZ_p> list_of_bytes_to_vecZZp(
    const std::vector<std::vector<uint8_t>> &list_of_bytes) {
  NTL::ZZ f = DHF::GetField();
  NTL::ZZ_p::init(f);
  std::vector<NTL::vec_ZZ_p> result;
  result.reserve(list_of_bytes.size());

  for (const auto &bytes : list_of_bytes) {
    result.push_back(bytes_to_vecZZp(bytes.data(), bytes.size()));
  }

  return result;
}

ulong getTest() {
  NTL::ZZ f = DHF::GetField();
  NTL::ZZ_p::init(f);
  NTL::ZZ seed(42);
  NTL::SetSeed(seed);
  NTL::ZZ_p r = NTL::random_ZZ_p();
  return NTL::conv<ulong>(r);
}

std::vector<ulong> pyconvVecZZp(const NTL::vec_ZZ_p v) {
  std::vector<ulong> res;
  for (long i = 0; i < v.length(); i++) {
    res.push_back(NTL::conv<ulong>(v[i]));
  }
  return res;
}

std::vector<uint8_t> vecZZp_to_bytes(const NTL::vec_ZZ_p &v) {
  NTL::ZZ f = DHF::GetField();
  NTL::ZZ_p::init(f);
  std::vector<uint8_t> out;
  out.reserve(v.length() * 8); // each element → 8 bytes

  for (long i = 0; i < v.length(); i++) {
    // get integer value from field element
    unsigned long num = NTL::conv<unsigned long>(NTL::rep(v[i]));

    // write as 8 bytes (little endian)
    for (int j = 0; j < 8; j++) {
      out.push_back(static_cast<uint8_t>((num >> (8 * j)) & 0xFF));
    }
  }

  return out;
}

std::vector<uint8_t> pyDHFvect(std::vector<NTL::ZZ_pX> key) {
  NTL::ZZ f = DHF::GetField();
  NTL::ZZ_p::init(f);
  NTL::vec_ZZ_p v = DHF::DHFk_xi(key);
  return vecZZp_to_bytes(v);
}

std::vector<int>
pyDHFDetect(const std::vector<std::vector<uint8_t>> &list_of_bytes, long t) {
  NTL::ZZ f = DHF::GetField();
  NTL::ZZ_p::init(f);

  std::vector<NTL::vec_ZZ_p> inputvectors =
      list_of_bytes_to_vecZZp(list_of_bytes);

  // just generate some random inputs instead
  return DHF::DHFdetect(inputvectors, t);
}

std::vector<int> pySimDHF(long s, long t) {
  NTL::SetSeed(NTL::ZZ(0));
  NTL::ZZ l = DHF::GetField();
  NTL::ZZ_p::init(l);

  std::vector<NTL::vec_ZZ_p> inputvectors;
  std::vector<NTL::ZZ_pX> key = DHF::DHFGenKey(s, t - 1, 42);

  for (int i = 0; i < t; i++) {
    NTL::vec_ZZ_p invec;
    invec = DHF::DHFk_xi(key);
    inputvectors.push_back(invec);
  }

  for (int i = 5; i < (s + t); i++) {
    NTL::vec_ZZ_p fake;
    fake = NTL::random_vec_ZZ_p(key.size() + 1);
    inputvectors.push_back(fake);
  }

  return DHF::DHFdetect(inputvectors, t - 1);
}
