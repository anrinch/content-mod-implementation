#include "DetectableHashFunction.hpp"
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/mat_ZZ_p.h>
#include <NTL/vec_ZZ_p.h>
#include <chrono>

//test how long it takes to output a failed detection
void runTest(long s, long t, int count){
  NTL::ZZ l = DHF::GetField();
  NTL::ZZ_p::init(l);
  std::chrono::high_resolution_clock::time_point start;
  std::chrono::high_resolution_clock::time_point end;

  std::vector<std::vector<NTL::vec_ZZ_p>> inputs;

  //create count random inputs
  for(int i = 0; i < count; i++) {
    std::vector<NTL::vec_ZZ_p> dhash;
    for(int j = 0; j < (s+t); j++) {
      dhash.push_back(NTL::random_vec_ZZ_p(s+1));
    }
    inputs.push_back(dhash);
  }
 
  start = std::chrono::high_resolution_clock::now();
  std::atomic_thread_fence(std::memory_order_seq_cst);

  for(int i = 0; i < count; i++) {
    std::vector<int> outputidx = DHF::DHFdetect(inputs[i], t);
  }
  end = std::chrono::high_resolution_clock::now();
  std::atomic_thread_fence(std::memory_order_seq_cst);

  std::chrono::milliseconds time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

  std::cout << "=================" << std::endl;
  std::cout << "Count: " << count << std::endl;
  std::cout << "Time taken :" << time_ms.count() << std::endl; 
  std::cout << "=================" << std::endl;
}


void clientsideDHF(long s, long t) {
  std::chrono::high_resolution_clock::time_point start;
  std::chrono::high_resolution_clock::time_point end;
  std::vector<NTL::vec_ZZ_p> inputvectors;
  
  std::vector<NTL::ZZ_pX> key = DHF::DHFGenKey(s, t);

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

  std::cout << "=================" << std::endl;
  std::cout << "Client DHF time: " << gen_time_ms.count() << std::endl; 
  std::cout << "=================" << std::endl;
}

int main(int args, char* argv[]) {
  NTL::SetSeed(NTL::ZZ(0));
  long s,t;
  s = 20;
  t = 236;

  runTest(s,t, 10);
  runTest(s,t, 20);
  runTest(s,t, 30);
  runTest(s,t, 40);
  runTest(s,t, 50);
  runTest(s,t, 60);
  runTest(s,t, 70);
  runTest(s,t, 80);
  runTest(s,t, 90);
  runTest(s,t, 100);
  clientsideDHF(s,t);
}
