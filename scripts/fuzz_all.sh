#!/usr/bin/env bash
# Batch runner: fuzz every Stage 2 AFL++ target sequentially with a
# shared per-target budget. Meant to run inside aflplusplus/aflplusplus
# with the project root mounted at /src.
#
# Usage (inside container):
#   bash scripts/fuzz_all.sh [BUDGET_SEC]
#
# Default budget is 300s per target. Outputs land in out_<name>/ at the
# project root; each target's per-campaign log is tee'd to
# results/logs/<target>.log.

set -euo pipefail

BUDGET_SEC="${1:-300}"

BUILD_DIR="build-afl"
SEED_DIR="seeds"
LOG_DIR="results/logs"

TARGETS=(
  stage2_afl_bad_validator
  stage2_afl_good_validator
  stage2_afl_length_only_indexed
  stage2_afl_unchecked_indexed
  stage2_afl_clamped_indexed
  stage2_afl_div_by_zero
  stage2_afl_div_by_zero_guarded
)

REPROS=(
  stage2_bad_validator
  stage2_good_validator
  stage2_length_only_indexed
  stage2_unchecked_indexed
  stage2_clamped_indexed
  stage2_div_by_zero
  stage2_div_by_zero_guarded
)

# Seed corpus: generated if missing.
if [[ ! -d "${SEED_DIR}" || -z "$(ls -A "${SEED_DIR}" 2>/dev/null)" ]]; then
  echo "[seeds] ${SEED_DIR}/ empty, running scripts/gen_seeds.py"
  python3 scripts/gen_seeds.py
fi

# Detect whether build-afl was configured with AFL's compilers; reset
# if not.
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

# Build every AFL target + every reproducer once up front. This avoids
# re-running cmake N times (run_afl.sh rebuilds one-at-a-time).
echo "[build] building all AFL targets + file-input reproducers"
for t in "${TARGETS[@]}"; do
  cmake --build "${BUILD_DIR}" --target "${t}"
done
for r in "${REPROS[@]}"; do
  cmake --build "${BUILD_DIR}" --target "${r}" 2>/dev/null || true
done

mkdir -p "${LOG_DIR}"

export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_NO_UI=1
# NOTE: do NOT set AFL_BENCH_UNTIL_CRASH here. AFL++ treats ANY value of
# that env var (including "0") as truthy, which would make crashing
# targets exit after the first crash and ruin time-to-crash / coverage
# measurements.
unset AFL_BENCH_UNTIL_CRASH || true

run_one () {
  local target="$1"
  local out_dir="out_${target#stage2_afl_}"
  local log="${LOG_DIR}/${target}.log"
  echo
  echo "============================================================"
  echo "[afl-all] target : ${target}"
  echo "[afl-all] out    : ${out_dir}"
  echo "[afl-all] budget : ${BUDGET_SEC}s"
  echo "[afl-all] log    : ${log}"
  echo "============================================================"
  mkdir -p "${out_dir}"
  timeout "${BUDGET_SEC}" afl-fuzz \
      -i "${SEED_DIR}" \
      -o "${out_dir}" \
      -- "./${BUILD_DIR}/${target}" @@ \
    > "${log}" 2>&1 \
    || true
  echo "[afl-all] finished ${target}; afl-whatsup summary:"
  afl-whatsup -s "${out_dir}" 2>/dev/null || true
}

for t in "${TARGETS[@]}"; do
  run_one "$t"
done

echo
echo "[afl-all] all campaigns complete."
