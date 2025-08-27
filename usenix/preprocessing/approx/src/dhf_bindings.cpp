#include "DetectableHashFunction.hpp"
#include <NTL/ZZ.h>
#include <NTL/ZZ_pX.h>
#include <NTL/vec_ZZ_p.h>
#include <cstdint>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <sstream>
#include <sys/types.h>
#include <vector>

namespace py = pybind11;

PYBIND11_MODULE(dhf, m) {
  py::class_<NTL::vec_ZZ_p>(m, "vec_ZZ_p");
  py::class_<NTL::ZZ>(m, "ZZ");
  py::class_<NTL::ZZ_pX>(m, "ZZ_pX");
  m.doc() = "Detectable Hash Function bindings (C++/NTL via pybind11)";

  m.def("gen_key", py::overload_cast<long, long>(&DHF::DHFGenKey),
        "Generate DHF key polynomials (random seed)");
  m.def("gen_key", py::overload_cast<long, long, long>(&DHF::DHFGenKey),
        "Generate DHF key polynomials with seed");

  m.def("genDHFvector", [](std::vector<NTL::ZZ_pX> key) {
    NTL::vec_ZZ_p dhfv = DHF::DHFk_xi(key);
    std::vector<ulong> res;
    res.reserve(dhfv.length());
    for (int i = 0; i < dhfv.length(); i++) {
      res.push_back(NTL::conv<ulong>(dhfv[i]));
    }
    return res;
  });

  m.def("simDHF", &pySimDHF, "simulate DHF with projections and threshhold");
  m.def("performDHFdetect", &pyDHFDetect, "detect the dhf");

  m.def("py42test", &getTest, "This is a test function");
  m.def("pyconvVecZZp", &pyconvVecZZp, "this is for debugging");
  m.def("pyDHFvect", &pyDHFvect,
        "Convert vec_ZZ_p into flat list of raw bytes (little-endian, 8 bytes "
        "per element)");

  m.def("bytes_to_vecZZp_list", &list_of_bytes_to_vecZZp,
        "Convert list of raw byte arrays to std::vector<vec_ZZ_p>");
  m.def(
      "gen_key_str",
      [](long s_size, long t_degree) {
        auto polys = DHF::DHFGenKey(s_size, t_degree);
        std::vector<std::string> out;
        for (auto &p : polys) {
          std::ostringstream oss;
          oss << p;
          out.push_back(oss.str());
        }
        return out;
      },
      "generates a key and outputs it as a list of strings", py::arg("s_size"),
      py::arg("t_degree"));
}
