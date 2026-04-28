#!/usr/bin/env bash
# Run an AFL++ campaign on one Stage 2 target with a time budget.
#
# Meant to be run inside the aflplusplus/aflplusplus container, with
# the project root mounted at /src. Example (from the Windows host):
#
#   docker run --rm -it \
#     -v "/path/to/fuzzing-validators:/src" \
#     -w /src aflplusplus/aflplusplus \
#     bash scripts/run_afl.sh stage2_afl_bad_validator out_bad 600
#   (On Windows Docker Desktop, use e.g. -v "C:\path\to\fuzzing-validators:/src".)
#
# Or use scripts/fuzz.ps1 for a one-line Windows wrapper.
#
# Positional args:
#   $1 = target name (e.g. stage2_afl_bad_validator)
#   $2 = output dir   (e.g. out_bad)
#   $3 = budget secs  (e.g. 600 for a 10-minute run)

set -euo pipefail

TARGET="${1:?target name required}"
OUT_DIR="${2:?output dir required}"
BUDGET_SEC="${3:-600}"

BUILD_DIR="build-afl"
SEED_DIR="seeds"

# Generate the seed corpus if the user hasn't done it already.
if [[ ! -d "${SEED_DIR}" || -z "$(ls -A "${SEED_DIR}" 2>/dev/null)" ]]; then
  echo "[seeds] ${SEED_DIR}/ empty, running scripts/gen_seeds.py"
  python3 scripts/gen_seeds.py
fi

# Detect whether build-afl was configured with AFL's compilers. If not
# (or if it doesn't exist yet) wipe the cache and reconfigure so the
# target is AFL-instrumented.
needs_configure=0
if [[ ! -f "${BUILD_DIR}/CMakeCache.txt" ]]; then
  needs_configure=1
elif ! grep -q "afl-clang-fast" "${BUILD_DIR}/CMakeCache.txt" 2>/dev/null; then
  echo "[build] ${BUILD_DIR}/ exists but was not built with afl-clang-fast++; resetting"
  rm -rf "${BUILD_DIR}"
  needs_configure=1
fi

if [[ "${needs_configure}" -eq 1 ]]; then
  mkdir -p "${BUILD_DIR}"
  ( cd "${BUILD_DIR}" \
    && CC=afl-clang-fast CXX=afl-clang-fast++ cmake -G Ninja .. )
fi

echo "[build] building ${TARGET} + file-input reproducers"
# Build the AFL target plus the non-AFL reproducers used by scripts/report.py
# to replay crashes. Reproducers are quick to build and live in the same
# build tree so report.py can find them.
cmake --build "${BUILD_DIR}" --target "${TARGET}"
for repro in stage2_bad_validator stage2_good_validator stage2_length_only_indexed \
             stage2_unchecked_indexed stage2_clamped_indexed \
             stage2_div_by_zero stage2_div_by_zero_guarded; do
  cmake --build "${BUILD_DIR}" --target "${repro}" 2>/dev/null || true
done

mkdir -p "${OUT_DIR}"

export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1

echo "[afl] running ${TARGET} for ${BUDGET_SEC}s -> ${OUT_DIR}"
timeout "${BUDGET_SEC}" afl-fuzz \
    -i "${SEED_DIR}" \
    -o "${OUT_DIR}" \
    -- "./${BUILD_DIR}/${TARGET}" @@ \
  || true

echo
echo "[afl] campaign complete. summary:"
afl-whatsup -s "${OUT_DIR}" || true
