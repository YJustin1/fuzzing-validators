#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

#include "core/run_engine.hpp"

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
  std::vector<uint8_t> bytes;
  if (argc >= 2) {
    bytes = read_input_bytes(argv[1]);
  } else {
    bytes = {0x42, 0x00, 0x00, 0x00, 0x5D, 0xFC, 0xFF, 0xFF};
    std::cout << "No input file provided. Using built-in seed bytes.\n";
  }

  return fuzzing::run_stage2_four_sink_chain_one_bad(bytes);
}
