// Mirrors host.cpp::basic_div_by_zero_guarded.
// nonzero_validator rejects zero denominators before the sink runs,
// preventing the division-by-zero. Expected behavior: no crashes.
// Calibration partner for stage2_afl_div_by_zero.

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

#include "core/run_engine.hpp"
#include "core/sink_oracle.hpp"
#include "core/validators.hpp"

#ifdef __AFL_HAVE_MANUAL_CONTROL
#include <unistd.h>
__AFL_FUZZ_INIT();
#endif

namespace {

std::vector<uint8_t> read_input_bytes(const std::string& file_path) {
  std::ifstream input(file_path, std::ios::binary);
  if (!input) {
    std::cerr << "Could not open input file: " << file_path << "\n";
    std::exit(1);
  }
  return std::vector<uint8_t>(std::istreambuf_iterator<char>(input),
                              std::istreambuf_iterator<char>());
}

}  // namespace

int main(int argc, char** argv) {
#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
  unsigned char* buf = __AFL_FUZZ_TESTCASE_BUF;

  while (__AFL_LOOP(10000)) {
    const int len = __AFL_FUZZ_TESTCASE_LEN;
    fuzzing::run_stage2_case_with_sink(buf, static_cast<std::size_t>(len),
                                       fuzzing::nonzero_validator,
                                       fuzzing::sink_divide);
  }
  return 0;
#else
  if (argc < 2) {
    std::cerr << "Usage: stage2_afl_div_by_zero_guarded <input_file>\n";
    return 1;
  }
  const std::vector<uint8_t> bytes = read_input_bytes(argv[1]);
  return fuzzing::run_stage2_case_with_sink(bytes,
                                            fuzzing::nonzero_validator,
                                            fuzzing::sink_divide);
#endif
}
