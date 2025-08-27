// NOTE: WE ASSUME YOU ARE USING A 64-bit ABI
// NTL and GMP should be compiled and installed with a 64-bit ABI
#include <DetectableHashFunction.hpp>
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/ZZ_pX.h>
#include <NTL/mat_ZZ_p.h>
#include <NTL/vec_ZZ_p.h>
#include <cstdio>

int main() {
  NTL::SetSeed(NTL::ZZ(0));
  NTL::ZZ l = DHF::GetField();
  NTL::ZZ_p::init(l);

  long s, t, real;
  t = 5;
  s = 50;

  std::vector<NTL::ZZ_pX> key = DHF::DHFGenKey(s, t - 1, 42);
  std::vector<NTL::vec_ZZ_p> inputvectors;
  std::vector<NTL::vec_ZZ_p> inputvectors2;
  std::vector<NTL::vec_ZZ_p> fakevec;

  // need a certain amount of inputs for detection
  for (int i = 0; i < 5; i++) {
    NTL::vec_ZZ_p invec;
    invec = DHF::DHFk_xi(key);
    inputvectors.push_back(invec);
  }

  for (int i = 0; i < 4; i++) {
    NTL::vec_ZZ_p invec;
    invec = DHF::DHFk_xi(key);
    inputvectors2.push_back(invec);
  }

  for (int i = real; i < 8; i++) {
    NTL::vec_ZZ_p fake;
    fake = NTL::random_vec_ZZ_p(key.size() + 1);
    fakevec.push_back(fake);
  }

  std::vector<int> outputidx = DHF::DHFdetect(inputvectors, t - 1);
  std::cout << outputidx.size() << std::endl;
  for (auto idx : outputidx) {
    std::cout << idx << std::endl;
    std::cout << inputvectors[idx][1] << std::endl;
  }

  // std::vector<int> outputidx2 = DHF::DHFdetect(inputvectors2, t - 1);
  // std::cout << outputidx2.size() << std::endl;

  // std::vector<int> outputidx3 = DHF::DHFdetect(fakevec, t - 1);
  // std::cout << outputidx3.size() << std::endl;

  // inputvectors.insert(inputvectors.end(), fakevec.begin(), fakevec.end());
  // std::vector<int> outputidx4 = DHF::DHFdetect(inputvectors, t - 1);
  // std::cout << outputidx4.size() << std::endl;
  // for (auto idx : outputidx4) {
  //   std::cout << idx << std::endl;
  // }

  std::cout << getTest() << std::endl;

  return 0;
}
