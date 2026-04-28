#pragma once

// Host-side examples runnable without a full sandbox; paired with
// scripts/smoke_test.py (expected safe vs trap per case name).
//
// (A) Constant-behavior — no inputs. Safe: trivial_* reads; crash: basic_null_*,
//     basic_div_by_zero, basic_oob_*.
// (B) Arg-driven — smoke_test pins args. basic_oob_read_from_arg crashes when
//     index >= 4; basic_null_write2 / basic_div_by_zero2 on bad inputs;
//     basic_div_by_zero_guarded always safe.
// (C) Full Candidate + RLBox pipeline — not here; use stage2_afl_unchecked_indexed
//     and stage2_afl_clamped_indexed.
//
// Stack OOB in (A) may not trap without sanitizers (ENABLE_SANITIZERS=ON).

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

}  // namespace host_examples
