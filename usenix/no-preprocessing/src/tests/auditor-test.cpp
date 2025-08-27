#include "actors/Auditor.hpp"
#include <filesystem>

// sanity check to make sure this can actually be called
int main() {
  actors::IOAuditorJSON test(2048);
  std::filesystem::path file("TestBlockList");
  test.parseHashFile(file);
  test.generateConfigJSON();
}
