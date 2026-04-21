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

add_executable(stage1_bad_validator src/stage1_harness.cpp)
target_compile_definitions(stage1_bad_validator PRIVATE USE_BAD_VALIDATOR=1)

add_executable(stage1_good_validator src/stage1_harness.cpp)
target_compile_definitions(stage1_good_validator PRIVATE USE_BAD_VALIDATOR=0)
