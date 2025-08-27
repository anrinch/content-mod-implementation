
#include "Projections.hpp"
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/mat_ZZ_p.h>
#include <NTL/vec_ZZ_p.h>
#include <chrono>
#include <vector>

void projTest(int gamma, long l, long i) {
  std::chrono::high_resolution_clock::time_point start;
  std::chrono::high_resolution_clock::time_point end;
  
  NTL::ZZ rand = NTL::RandomBits_ZZ(l);
  std::vector<NTL::ZZ> projs = psi_proj::getProjections(gamma, l, i);
  start = std::chrono::high_resolution_clock::now();
  std::atomic_thread_fence(std::memory_order_seq_cst);
 
  psi_proj::evalProjectionFunc(projs[0], rand);

  end = std::chrono::high_resolution_clock::now();
  std::atomic_thread_fence(std::memory_order_seq_cst);
  std::chrono::nanoseconds mask_time_us = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);

  std::cout << "=================" << std::endl;
  std::cout << "Projection mask time for " << l << " bits: " << mask_time_us.count()<< "ns" << std::endl; 
  std::cout << "=================" << std::endl;
}

int main(int args, char* argv[]) {
  NTL::SetSeed(NTL::ZZ(0));
  projTest(1, 256, 200);
}
