cmake_minimum_required(VERSION 3.20)
project(rlbox_validator_fuzzing CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(ENABLE_SANITIZERS "Enable Address/Undefined sanitizers for Clang/GCC" OFF)

if(ENABLE_SANITIZERS)
  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    add_compile_options(-fno-omit-frame-pointer -fsanitize=address,undefined)
    add_link_options(-fsanitize=address,undefined)
  else()
    message(WARNING "Sanitizers requested but compiler does not support requested flags")
  endif()
endif()

set(RLBOX_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/third_party/rlbox/code/include")

add_library(stage1_core INTERFACE)
target_include_directories(stage1_core INTERFACE "${CMAKE_SOURCE_DIR}/src" "${RLBOX_INCLUDE_DIR}")

add_executable(stage1_bad_validator src/stage1_bad_validator.cpp)
target_link_libraries(stage1_bad_validator PRIVATE stage1_core)

add_executable(stage1_good_validator src/stage1_good_validator.cpp)
target_link_libraries(stage1_good_validator PRIVATE stage1_core)

add_executable(stage2_bad_validator src/stage2_bad_validator.cpp)
target_link_libraries(stage2_bad_validator PRIVATE stage1_core)

add_executable(stage2_good_validator src/stage2_good_validator.cpp)
target_link_libraries(stage2_good_validator PRIVATE stage1_core)

add_executable(stage2_length_only_indexed src/stage2_length_only_indexed.cpp)
target_link_libraries(stage2_length_only_indexed PRIVATE stage1_core)

add_executable(stage2_afl_bad_validator src/stage2_afl_bad_validator.cpp)
target_link_libraries(stage2_afl_bad_validator PRIVATE stage1_core)

add_executable(stage2_afl_good_validator src/stage2_afl_good_validator.cpp)
target_link_libraries(stage2_afl_good_validator PRIVATE stage1_core)

add_executable(stage2_afl_length_only_indexed src/stage2_afl_length_only_indexed.cpp)
target_link_libraries(stage2_afl_length_only_indexed PRIVATE stage1_core)

# Extra Stage 2 targets (indexed / division sinks).

add_executable(stage2_unchecked_indexed src/stage2_unchecked_indexed.cpp)
target_link_libraries(stage2_unchecked_indexed PRIVATE stage1_core)

add_executable(stage2_clamped_indexed src/stage2_clamped_indexed.cpp)
target_link_libraries(stage2_clamped_indexed PRIVATE stage1_core)

add_executable(stage2_div_by_zero src/stage2_div_by_zero.cpp)
target_link_libraries(stage2_div_by_zero PRIVATE stage1_core)

add_executable(stage2_div_by_zero_guarded src/stage2_div_by_zero_guarded.cpp)
target_link_libraries(stage2_div_by_zero_guarded PRIVATE stage1_core)

add_executable(stage2_afl_unchecked_indexed src/stage2_afl_unchecked_indexed.cpp)
target_link_libraries(stage2_afl_unchecked_indexed PRIVATE stage1_core)

add_executable(stage2_afl_clamped_indexed src/stage2_afl_clamped_indexed.cpp)
target_link_libraries(stage2_afl_clamped_indexed PRIVATE stage1_core)

add_executable(stage2_afl_div_by_zero src/stage2_afl_div_by_zero.cpp)
target_link_libraries(stage2_afl_div_by_zero PRIVATE stage1_core)

add_executable(stage2_afl_div_by_zero_guarded src/stage2_afl_div_by_zero_guarded.cpp)
target_link_libraries(stage2_afl_div_by_zero_guarded PRIVATE stage1_core)

# Smoke-test driver for host_examples.hpp (paired with scripts/smoke_test.py).
add_executable(smoke_host_examples src/smoke_host_examples.cpp)
target_link_libraries(smoke_host_examples PRIVATE stage1_core)
