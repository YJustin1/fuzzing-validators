#pragma once

// Reference-style host examples that can be exercised dynamically without
// a full RLBox sandbox. They back the smoke-test runner (scripts/smoke_test.py),
// which encodes expected safe vs trap outcomes for each case name.
//
// These examples fall into three categories, and this
// project handles them in three *different* places. This header only
// covers categories (A) and (B); category (C) is handled by dedicated
// AFL harnesses.
//
//   (A) Smoke-test, constant-behavior cases:
//       No inputs, deterministic outcome every run. Useful only as a
//       one-shot check that the expected-safe cases stay safe and the
//       expected-crash cases still trap on this platform/toolchain.
//
//       Safe:  trivial_array_read, repeated_array_read,
//              trivial_array_read_2d, trivial_struct_read,
//              trivial_struct_read_nested
//       Crash: basic_null_read, basic_null_write, basic_div_by_zero,
//              basic_oob_read, basic_oob_write
//
//   (B) Arg-driven cases:
//       A single scalar argument controls the outcome. The smoke-test
//       runner pins a fixed value chosen to force the smoke_test.py-expected
//       behavior. These *could* be fuzzed per-argument but the payoff
//       is small since they don't exercise any RLBox boundary.
//
//       basic_oob_read_from_arg(index)   -> crash when index >= 4
//       basic_null_write2(ptr)           -> crash when ptr == nullptr
//       basic_div_by_zero2(denom)        -> crash when denom == 0
//       basic_div_by_zero_guarded(denom) -> always safe
//
//   (C) RLBox-specific cases (NOT in this header):
//       Unchecked vs clamped sandbox indexing is modeled by the dedicated
//       AFL harnesses in src/stage2_afl_*, which drive the fuzzer-controlled
//       sandbox value through our full RlSandbox + validator + sink pipeline.
//
// Sanitizer caveat for category (A) stack-array OOB reads/writes:
// those are undefined behavior that may not reliably trap on MSVC or
// optimized Linux builds. For dependable signal on those rows, build
// with ENABLE_SANITIZERS=ON.

#include <array>
#include <cstdint>

namespace host_examples {

// ===========================================================
// (A) Smoke-test, constant-behavior cases (no inputs)
// ===========================================================

// ----- Expected Ok (see smoke_test.py CASES_* tables) -----

inline int trivial_array_read() {
  volatile int32_t host_array[4] = {100, 200, 300, 400};
  volatile int32_t sink = host_array[1];
  (void)sink;
  return 0;
}

inline int repeated_array_read() {
  volatile int32_t host_array[4] = {100, 200, 300, 400};
  volatile int32_t x = host_array[1];
  volatile int32_t y = host_array[2];
  return static_cast<int>(x + y);
}

inline int trivial_array_read_2d() {
  volatile int host_array[2][3] = {{1, 4, 2}, {3, 6, 8}};
  volatile int sink = host_array[1][1];
  (void)sink;
  return 0;
}

struct SimpleStruct {
  int32_t a;
  int32_t b;
};

struct ComplexStruct {
  SimpleStruct a;
  SimpleStruct b;
};

inline int trivial_struct_read() {
  volatile SimpleStruct host_struct = {100, 200};
  return static_cast<int>(host_struct.a);
}

inline int trivial_struct_read_nested() {
  volatile ComplexStruct host_struct = {{100, 200}, {300, 400}};
  return static_cast<int>(host_struct.b.a);
}

// ----- Expected Err / trap (see smoke_test.py) -----

inline int basic_null_read() {
  volatile int32_t* host_array = nullptr;
  return *host_array;
}

inline int basic_null_write() {
  volatile int32_t* host_array = nullptr;
  *host_array = 1337;
  return 0;
}

inline int basic_div_by_zero() {
  volatile int denominator = 0;
  return 3 / denominator;
}

// Stack-OOB cases: often do NOT crash without sanitizers. The out-of-bounds
// access is the whole point, so we silence MSVC's (correct) C4789 warning
// locally.
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4789)
#endif
inline int basic_oob_read() {
  volatile int32_t host_array[4] = {100, 200, 300, 400};
  volatile int32_t sink = host_array[4];
  (void)sink;
  return 0;
}

inline int basic_oob_write() {
  volatile int32_t host_array[4] = {100, 200, 300, 400};
  host_array[5] = 1337;
  return 0;
}
#if defined(_MSC_VER)
#pragma warning(pop)
#endif


// ===========================================================
// (B) Arg-driven cases (single scalar input)
// ===========================================================

// Safe only if denominator != 0; otherwise early-returns 0.
inline int basic_div_by_zero_guarded(int denominator) {
  if (denominator == 0) {
    return 0;
  }
  volatile int sink = 3 / denominator;
  return sink;
}

// Crashes whenever ptr == nullptr.
inline int basic_null_write2(int32_t* ptr) {
  *ptr = 1337;
  return 0;
}

// Crashes whenever denominator == 0.
inline int basic_div_by_zero2(int denominator) {
  volatile int d = denominator;
  return 3 / d;
}

// Stack-OOB when index >= 4. Needs sanitizers for reliable trapping.
inline int basic_oob_read_from_arg(uint32_t index) {
  volatile int32_t host_array[4] = {100, 200, 300, 400};
  volatile int32_t sink = host_array[index];
  (void)sink;
  return 0;
}

// NOTE: Category (C) RLBox-specific cases (sandbox_array_index_*) are
// NOT ported here. Those require a live RlSandbox and are exercised by
// the AFL harnesses stage2_afl_unchecked_indexed and
// stage2_afl_clamped_indexed.

}  // namespace host_examples
