// start writing code for the projections
#include <vector>
#include <set>
#include <NTL/ZZ.h>
#include <Projections.hpp>

namespace psi_proj{


  std::vector<NTL::ZZ> getProjections(int gamma, long l, long i) {
    std::vector<NTL::ZZ> projections;
    for(int j = 0; j < gamma; j++) {
      projections.push_back(projectionMask(l,i,NTL::RandomBnd(SEEDBOUND)));
    }
    return projections;
  }

  NTL::ZZ projectionMask(long l, long i,NTL::ZZ seed) {
    NTL::SetSeed(seed);
    NTL::ZZ mask;
    std::set<long> positions;
    
    while(positions.size() < i) {
      long pos = NTL::RandomBnd(l);
      NTL::SetBit(mask, pos);
      positions.insert(pos);
    }

    return mask;
  }

  //I can always change this code. The projection will technically be the same number
  //of bits, but since the projection is a mask, the number of "free" bits will be correct
  NTL::ZZ evalProjectionFunc(NTL::ZZ mask, NTL::ZZ element) {
    return mask & element;
  }

}





