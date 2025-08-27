#include "DetectableHashFunction.hpp"
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/mat_ZZ_p.h>
#include <NTL/vec_ZZ_p.h>
#include <chrono>

void runTestSuccess(long s, long t) {
  NTL::ZZ l = DHF::GetField();
  NTL::ZZ_p::init(l);

  std::vector<NTL::ZZ_pX> key = DHF::DHFGenKey(s, t);
  std::vector<NTL::vec_ZZ_p> inputvectors;

  std::chrono::high_resolution_clock::time_point start;
  std::chrono::high_resolution_clock::time_point end;

  start = std::chrono::high_resolution_clock::now();
  std::atomic_thread_fence(std::memory_order_seq_cst);

  for (int i = 0; i < (s+t); i++) {
    NTL::vec_ZZ_p invec;
    invec = DHF::DHFk_xi(key, NTL::random_ZZ_p());
    inputvectors.push_back(invec);
  }

  end = std::chrono::high_resolution_clock::now();
  std::atomic_thread_fence(std::memory_order_seq_cst);
  std::chrono::milliseconds gen_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

  start = std::chrono::high_resolution_clock::now();
  std::atomic_thread_fence(std::memory_order_seq_cst);
  std::vector<int> outputidx = DHF::DHFdetect(inputvectors, t);

  end = std::chrono::high_resolution_clock::now();
  std::atomic_thread_fence(std::memory_order_seq_cst);

  std::chrono::milliseconds detect_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
  
  bool pass = false;
  if (outputidx.size() == (s+t)) pass = true;
  std::cout << "=================" << std::endl;
  std::cout << "Field: " << l << std::endl;
  std::cout << "Time to generate hash for (s+t) columns:" << gen_time_ms.count() << std::endl;
  std::cout << "s value (number of polynomials): " << s << std::endl; 
  std::cout << "t value (degree of polynomials): " << t << std::endl; 
  std::cout << "All columns detected? " << pass << std::endl; 
  std::cout << "Time taken to detect (s+t) columns:" << detect_time_ms.count() << std::endl; 
  std::cout << "=================" << std::endl;
}

int main(int args, char* argv[]) {
  NTL::SetSeed(NTL::ZZ(0));

//  for(int i = 3; i < 100; i++) {
//    for(int j = 3; j < 100; j++) {
//      runTestSuccess(i,j);
//    }
//  }


  runTestSuccess(236 ,20);


  return 0;
}
