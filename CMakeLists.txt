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
