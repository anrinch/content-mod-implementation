#include "DetectableHashFunction.hpp"
// needed for the random polynomial generation
#include <NTL/ZZ.h>
#include <NTL/ZZ_pX.h>
#include <NTL/mat_ZZ_p.h>
#include <NTL/matrix.h>
#include <NTL/vec_ZZ_p.h>
#include <vector>
namespace DHF {


//use the same field as the polynomial share field
//this is for 256 bit keys/secre shares that are blinded with a OTP
NTL::ZZ GetField() { 
  return NTL::power2_ZZ(256) - 357;
}

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
  //std::cout << "Num of cols: " << expanded.NumRows() << std::endl;
  long s = expanded.NumRows() - t;

  // have to use the RIGHT kernel, but NTL only gives us the left 
  // Therefore we have to use the transpose!
  NTL::mat_ZZ_p expandedtranspose = NTL::transpose(expanded);
  NTL::mat_ZZ_p ker;
  NTL::kernel(ker, expandedtranspose);

  if(NTL::IsZero(ker) == 1) {
    std::vector<int> empty;
    return empty;
  }

  // find the non-zero entries in a vector of the right kernel
  std::vector<int> subidxs;
  //DEBUG:
  //std::cout << ker[0] << std::endl;
  for(int i = 0; i < ker[0].length(); i++) {
    if(ker[0][i] != 0) {
      subidxs.push_back(i);
    }
  }

  //DEBUG
  //for(auto i : subidxs) {
  //  std::cout << i << std::endl;
  //}

  //get the sumbmatrix
  NTL::mat_ZZ_p submatrix;
  submatrix.SetDims(subidxs.size(), (s+t));
  for(int i = 0; i < subidxs.size(); i++) {
    submatrix[i] = expandedtranspose[subidxs.at(i)];
  }

  NTL::mat_ZZ_p submatrix_cpy(submatrix);
  long submatrix_rank = NTL::gauss(submatrix);
  //check the linear span using the augmented matrix
  std::vector<int> outidx;
  for(int i = 0; i < expandedtranspose.NumRows(); i++) {
    NTL::mat_ZZ_p augmentedtranspose;
    augmentedtranspose.SetDims(submatrix.NumRows() + 1, (s+t));

    for(int j = 0; j < submatrix.NumRows(); j++) {
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

  // check for an inconsistency
  // there are either multiple solutions or no solutions
  long rowCheck = 0;
  for (int i = 0; i < m.NumRows(); i++) {
    if (NTL::IsZero(m[i])) {
      rowCheck++;
    }
  }

  if (rowCheck != numberOfZeroRows) {
    return false;
  }

  return true;
}

// we also need to know the max degree of the polynomials
NTL::vec_ZZ_p DHFk_xi(std::vector<NTL::ZZ_pX> key, NTL::ZZ_p x) {
  NTL::ZZ dhf_field = GetField();
  NTL::ZZ_pPush dhfmod(dhf_field);
  // create a one vector of DHF(x_i)
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

NTL::mat_ZZ_p ExpandNTLVecsIntoNTLMatrix(std::vector<NTL::vec_ZZ_p> dhf_vectors,
                                         long t) {
  NTL::ZZ dhf_field = GetField();
  NTL::ZZ_pPush dhfmod(dhf_field);
  NTL::mat_ZZ_p expansion;
  // each col will be a vector of length s+t (number of polynomails + max degree
  // there are m columns
  //
  // for ease, we will columns as rows and then return the transpose

  // the dhf_vectors are of length s+1
  long s = dhf_vectors.at(0).length() - 1;
  long m = dhf_vectors.size();
  expansion.SetDims(m, s + t);

  for (long i = 0; i < m; i++) {
    NTL::vec_ZZ_p temp;
    temp.SetLength(s + t);
    NTL::ZZ_p x0 = dhf_vectors.at(i)[0];

    int idx = 1;
    for(long j = 0; j < (s+t); j++) {
      if(j == 0) {
        temp[j] = 1;
      } else if(j < t) {
        // debug: a problem can come up
        if(NTL::conv<NTL::ZZ>(x0) > dhf_field || NTL::conv<NTL::ZZ>(x0) < 0) {
          std::cout << x0 << std::endl;
        }
        temp[j] = NTL::power(x0,j);
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
