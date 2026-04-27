# Build Guide

This project ships three build flavors. Pick the one that matches what you're doing.

| Flavor | Compiler | Purpose |
| --- | --- | --- |
| Local (Windows, MSVC) | Visual Studio 2022 via CMake | Stage 1 runs, Stage 2 file-input reproducers, crash-replay, day-to-day dev |
| AFL++ (Linux, Docker) | `afl-clang-fast++` inside `aflplusplus/aflplusplus` | Stage 2 coverage-guided fuzzing campaigns |
| Sanitizers (Clang/GCC) | Clang or GCC with ASan/UBSan | Stronger bug signals on Linux/WSL/Clang-on-Windows |

## Prerequisites

- Git (with submodule support — RLBox is a submodule at `third_party/rlbox/`)
- CMake ≥ 3.20
- Python 3 (for `scripts/gen_seeds.py`)
- One of:
  - Visual Studio 2022 with the C++ workload (local flavor)
  - Docker Desktop (AFL++ flavor)
  - Clang or GCC with sanitizer support (sanitizer flavor)

Clone the submodule if you haven't:

```powershell
git submodule update --init --recursive
```

## Local Flavor (Windows, MSVC)

Used by every file-input binary (Stage 1 targets, Stage 2 byte-driven targets, the crash-replay reproducers).

```powershell
cmake -S . -B build-vs -G "Visual Studio 17 2022"
cmake --build build-vs --config Debug
```

Output lives in `build-vs\Debug\`. Built targets:

- `stage1_bad_validator.exe`, `stage1_good_validator.exe`
- `stage2_bad_validator.exe`, `stage2_good_validator.exe`, `stage2_length_only_indexed.exe`
- `stage2_afl_bad_validator.exe`, `stage2_afl_good_validator.exe`, `stage2_afl_length_only_indexed.exe`
  - Under MSVC the `__AFL_HAVE_MANUAL_CONTROL` macro is never defined, so these fall back to file-input mode — they behave identically to the non-AFL Stage 2 targets.

## AFL++ Flavor (Docker)

Builds AFL-instrumented Stage 2 binaries for use with `afl-fuzz`. The easiest path is to let `scripts/run_afl.sh` drive the build:

```powershell
.\scripts\fuzz.ps1 stage2_afl_bad_validator
```

On first run, `run_afl.sh` will:

1. Create `build-afl/` inside the container.
2. Configure with `CC=afl-clang-fast CXX=afl-clang-fast++` and the Ninja generator.
3. Build the requested AFL target **plus the three non-AFL file-input reproducers** (`stage2_bad_validator`, `stage2_good_validator`, `stage2_length_only_indexed`). The reproducers are required by `scripts/report.py` for crash replay.
4. Run `afl-fuzz`.

If you want to build manually inside the container without running a campaign:

```bash
docker run --rm -it \
  -v "C:\Users\justi\Documents\Projects\fuzzing-validators:/src" \
  -w /src aflplusplus/aflplusplus \
  bash -c "mkdir -p build-afl && cd build-afl \
    && CC=afl-clang-fast CXX=afl-clang-fast++ cmake -G Ninja .. \
    && cmake --build ."
```

### Cache safety

`run_afl.sh` inspects `build-afl/CMakeCache.txt`. If the directory exists but was not configured with AFL's compilers (e.g. a leftover gcc-built tree), it wipes and reconfigures. This protects against silently running uninstrumented binaries under `afl-fuzz`, which would make AFL think coverage never changes.

## Sanitizer Flavor (optional)

For stronger bug signals on platforms where Clang or GCC is available:

```powershell
cmake -S . -B build-asan -G "Ninja" -DCMAKE_BUILD_TYPE=Debug -DENABLE_SANITIZERS=ON
cmake --build build-asan
```

The `ENABLE_SANITIZERS` option adds `-fsanitize=address,undefined` and `-fno-omit-frame-pointer` for Clang/GCC; it's a no-op under MSVC.

## Clean Rebuilds

Just delete the build directory:

```powershell
Remove-Item -Recurse -Force build-vs
Remove-Item -Recurse -Force build-afl
```

`run_afl.sh` will notice the missing `build-afl/` and reconfigure from scratch.

## Troubleshooting

- **"Does not match the generator used previously"** — you asked for a different CMake generator than the cache has. Delete the build directory and reconfigure.
- **`__AFL_FUZZ_TESTCASE_LEN` references undeclared `read`** — the AFL-mode entrypoints include `<unistd.h>` under the `__AFL_HAVE_MANUAL_CONTROL` guard specifically to avoid this. If you see it, your AFL source file is missing that include.
- **AFL binary appears to run but finds nothing** — check that the binary was built with `afl-clang-fast++`, not the default compiler. Look for `afl-clang-fast` strings in `build-afl/CMakeCache.txt`, or just delete `build-afl/` and let `run_afl.sh` rebuild.
- **`cmake` not found in Cursor's terminal on Windows** — it works in an external PowerShell but Cursor's terminal hasn't picked up the PATH. Either reload the IDE window or invoke it by absolute path: `"C:\Program Files\CMake\bin\cmake.exe"`.
