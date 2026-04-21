#include <cstdint>
#include <cstdlib>
#include <iostream>

#include "core/run_engine.hpp"
#include "core/validators.hpp"

int main(int argc, char** argv) {
  std::uint64_t iterations = 200000;
  if (argc >= 2) {
    iterations = std::strtoull(argv[1], nullptr, 10);
  }

  fuzzing::run_stage1(iterations, fuzzing::good_validator);
  std::cout << "Good validator completed budget without oracle failure.\n";
  return 0;
}
