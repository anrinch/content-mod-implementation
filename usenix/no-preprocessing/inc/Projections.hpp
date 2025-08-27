#ifndef PSI_PROJECTIONS_HPP 
#define PSI_PROJECTIONS_HPP 
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <vector>


namespace psi_proj {
  //TODO: make the SEEDBOUND something sensible
  const NTL::ZZ SEEDBOUND = NTL::ZZ(123456789);
  std::vector<NTL::ZZ> getProjections(int gamma, long l, long i);
  NTL::ZZ projectionMask(long l, long i,NTL::ZZ seed);
  NTL::ZZ evalProjectionFunc(NTL::ZZ mask, NTL::ZZ element);
}

#endif

