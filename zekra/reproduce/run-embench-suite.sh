#!/usr/bin/env bash
#
# ZEKRA's own circuit over every application it ships, not just crc32.
#
# `run-crc32-paper22.sh` reproduces one application end to end. This runs the same pipeline over
# all twenty-one, at a per-application capacity, which is what a cross-prover suite needs. The
# extractor is not re-run: every application directory already carries the `numified_*` artifacts
# its formatter consumes, so this reproduces from the pinned checkout alone.
#
# Two images: the pinned linux/amd64 image formats inputs and compiles
# the xJsnark circuit, and the arm64 image runs Groth16, since `.arith`/`.in` are architecture
# independent and proving under emulation would not be a property of Groth16.
#
#   APPS="crc32 st"   restrict to named applications (default: all 21)
#   CONTROL=0         skip the crc32 500/500 control row
#   OUT=<file>        results CSV (default: results/embench-suite/summary.csv)
#   KEEP_ARTIFACTS=1  retain the arithmetic circuit and witness for each case
#
# THE CONTROL IS NOT OPTIONAL IN SPIRIT. crc32 at 500/500 must print 336,230 constraints -- ZEKRA's
# published figure. If it does not, the lane is mis-parameterised and no other row means anything.
#
# Nine of the twenty-one are expected to compile and then fail circuit evaluation. That is not a
# configuration error on our side: see `EMBENCH_SUITE.md` for the 32-bit truncation in the
# in-circuit adjacency memory, which this script's `--truncation-check` output evidences.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
root="$(cd "$here/.." && pwd -P)"
zekra="$root/ZEKRA"
work="$here/results/embench-suite"
logs="$work/logs"
out="${OUT:-$work/summary.csv}"
amd="${ZEKRA_PAPER22_IMAGE:-zkcfa-zekra:paper-ubuntu22.04}"
arm="${ZEKRA_NATIVE_IMAGE:-zekra-native:local}"
levels=15
stack=15

# The campaign wrapper archives upstream sources before invoking this worker.
# Check resolved paths before creating outputs or backing up the parameter file.
python3 - "$root" "$zekra" <<'PY' || exit 1
from pathlib import Path
import sys

snapshot, source = (Path(value).resolve() for value in sys.argv[1:])
marker = snapshot / ".zekra-campaign-snapshot"

def refuse(reason):
    raise SystemExit(
        "Refusing to run the ZEKRA suite: " + reason + ". "
        "Use python3 zekra/reproduce/scripts/run_zekra_campaign.py "
        "--output /absolute/new/zekra21 --prepare-only from the repository root, "
        "then rerun without --prepare-only. See zekra/reproduce/APPLICATIONS.md."
    )

git_entry = source / ".git"
if git_entry.exists() or git_entry.is_symlink():
    refuse("the source is a Git checkout")
if source != snapshot / "ZEKRA" or not source.is_dir():
    refuse("the source must stay inside the campaign snapshot")
if marker.is_symlink() or not marker.is_file():
    refuse("the campaign snapshot marker is missing or is a symbolic link")
if marker.read_text() != "isolated ZEKRA source archive\n":
    refuse("the campaign snapshot marker is invalid")
PY

mkdir -p "$work" "$logs"
printf 'app,adjlist_len,path_len,levels,stack_depth,label_bw,bucket_bw,addr_bw,r1cs_constraints,qap_degree,qap_variables,keygen_s,prove_s,verify_s,satisfied,outcome\n' > "$out"

# compile_circuit.py patches this file in place; restore whatever state it was in.
guarded="zekra_java/zekra/zekra.java"
backup="$work/.zekra.java.orig"
cp -p "$zekra/$guarded" "$backup"
restore() { cp -p "$backup" "$zekra/$guarded"; }
trap restore EXIT INT TERM

# Capacity: the next powers of two above the node and step counts -- the same rule the Binius
# lanes' `ZKCFA_PARAMS=fit` applies, so both suites are measured at matched capacities.
capacity_of() {
  python3 - "$1" <<'PY'
import sys, os
d = sys.argv[1]
SCOPE = 0xFFFF0000
def addr(s):
    s = s.strip()
    return SCOPE if s == "SCOPE_RETURN" else int(s[2:] if s.startswith("0x") else s, 16)
labels, steps = set(), 1
for line in open(os.path.join(d, "translator")):
    if line.strip(): labels.add(addr(line))
for line in open(os.path.join(d, "recorded_path")):
    f = line.split()
    if not f: continue
    if f[0].startswith("initial_node"):
        labels.add(addr(f[0].split("=", 1)[1])); continue
    labels.add(addr(f[1])); steps += 1
    if f[0] == "call": labels.add(addr(f[2]) if len(f) > 2 else SCOPE)
for line in open(os.path.join(d, "adjlist")):
    for t in line.split(): labels.add(addr(t))
def p2(x, floor):
    n = 1
    while n < x: n <<= 1
    return max(n, floor)
print(p2(len(labels), 8), p2(steps, 16))
PY
}

# ZEKRA sizes the label field for "max label is <padded length>", i.e. bit_length(len), and the
# bucket field for bit_length(len/8). The floors are its own published crc32 choice, so small
# applications are measured in exactly the configuration its paper reports.
widths_of() {
  python3 -c "
n=int('$1')
print(max(10, n.bit_length()), max(7, (n//8).bit_length()))"
}

run_one() {
  local app="$1" nlen="$2" plen="$3" tag="${4:-$1}"
  local d="$work/$tag" log="$logs/$tag"
  local lbw bbw
  read -r lbw bbw <<< "$(widths_of "$nlen")"
  [ "$tag" = "crc32-control-500" ] && { lbw=10; bbw=7; }
  mkdir -p "$d"

  for f in adjlist numified_adjlist translator recorded_path numified_path; do
    if ! cp -p "$zekra/embench-iot-applications/$app/$f" "$d/"; then
      echo "$tag,$nlen,$plen,$levels,$stack,$lbw,$bbw,24,,,,,,,,missing-$f" >> "$out"; return
    fi
  done

  echo "[$tag] format (adjlist->$nlen path->$plen, label=$lbw bucket=$bbw)"
  docker run --rm --platform linux/amd64 \
    -v "$zekra:/workspace/ZEKRA" -v "$work:/scratch" -w /workspace/ZEKRA "$amd" \
    python3 scripts/circuit_input_formatter.py -a "/scratch/$tag/" \
      --pad-adjlist-to "$nlen" --pad-path-to "$plen" --adjlist-levels "$levels" \
      --nonce-verifier 12353 --nonce-path 123 --nonce-translator 123 --nonce-adjlist 123 \
      --label-bitwidth "$lbw" --bucket-bitwidth "$bbw" --address-bitwidth 24 \
    > "$log-01-format.log" 2>&1
  if [ ! -s "$d/in_encoded_adjlist" ]; then
    echo "$tag,$nlen,$plen,$levels,$stack,$lbw,$bbw,24,,,,,,,,format-failed" >> "$out"
    echo "[$tag] FORMAT FAILED -- see $log-01-format.log" >&2; return
  fi

  echo "[$tag] compile"
  docker run --rm --platform linux/amd64 \
    -v "$zekra:/workspace/ZEKRA" -v "$work:/scratch" -w /workspace/ZEKRA "$amd" \
    python3 scripts/compile_circuit.py --zekra-dir zekra_java/zekra \
      --adjlist-len "$nlen" --adjlist-levels "$levels" --path-len "$plen" --stack-depth "$stack" \
      --label-bitwidth "$lbw" --bucket-bitwidth "$bbw" --address-bitwidth 24 \
      --input-dir "/scratch/$tag" --output-dir "/scratch/$tag" \
      --components-dir zekra_java/components \
    > "$log-02-compile.log" 2>&1
  local cons sat
  cons="$(grep -oE 'Total constraints: [0-9]+' "$log-02-compile.log" | tail -1 | grep -oE '[0-9]+')"
  if grep -q 'Circuit was not satisfied' "$log-02-compile.log"; then sat=NO; else sat=YES; fi
  if [ -z "${cons:-}" ] || [ ! -s "$d/zekra.arith" ]; then
    echo "$tag,$nlen,$plen,$levels,$stack,$lbw,$bbw,24,,,,,,,$sat,compile-failed" >> "$out"
    echo "[$tag] COMPILE FAILED -- see $log-02-compile.log" >&2; return
  fi

  if [ "$sat" = NO ]; then
    # Evidence, not a shrug: the assertion prints both operands, and the witness value reduced
    # mod 2^32 is exactly what the in-circuit adjacency memory returned.
    grep -oE '^[0-9]+\*1!=[0-9]+' "$log-02-compile.log" | head -1 | python3 -c "
import sys
line = sys.stdin.read().strip()
if line:
    w, m = (int(x) for x in line.replace('*1', '').split('!='))
    print('[truncation-check] witness=%d memory=%d witness mod 2^32=%d -> %s'
          % (w, m, w % 2**32, 'MATCH' if w % 2**32 == m else 'no match'))
" | tee -a "$log-02-compile.log"
    echo "$tag,$nlen,$plen,$levels,$stack,$lbw,$bbw,24,$cons,,,,,,NO,unsatisfiable" >> "$out"
    echo "[$tag] circuit unsatisfiable at $cons constraints (see EMBENCH_SUITE.md)"
    if [ "${KEEP_ARTIFACTS:-0}" != 1 ]; then
      rm -f "$d/zekra.arith" "$d/zekra_Sample_Run1.in"
    fi
    return
  fi

  echo "[$tag] groth16 ($cons constraints)"
  docker run --rm -v "$d:/w" -w /w "$arm" \
    /opt/jsnark/libsnark/build/libsnark/jsnark_interface/run_ppzksnark \
      gg zekra.arith zekra_Sample_Run1.in > "$log-03-groth16.log" 2>&1
  local rc=$?
  local deg vars kg pv vf res
  deg="$(grep -oE 'QAP degree: [0-9]+' "$log-03-groth16.log" | tail -1 | grep -oE '[0-9]+')"
  vars="$(grep -oE 'QAP number of variables: [0-9]+' "$log-03-groth16.log" | tail -1 | grep -oE '[0-9]+')"
  phase() { grep -E "\(leave\) Call to r1cs_gg_ppzksnark_$1" "$log-03-groth16.log" \
              | grep -oE '\[[0-9]+\.[0-9]+s' | tr -d '[s' | tail -1; }
  kg="$(phase generator)"; pv="$(phase prover)"; vf="$(phase verifier_strong_IC)"
  res="$(grep -oE 'The verification result is: [A-Z]+' "$log-03-groth16.log" | tail -1 | awk '{print $NF}')"
  if [ -z "${res:-}" ]; then
    # 137 is SIGKILL: the container hit the Docker VM's memory ceiling. That is a limit of the
    # host, not of the circuit, and must not be recorded as a circuit failure.
    [ "$rc" = 137 ] && res="host-memory" || res="no-result-rc$rc"
  else
    res="$(tr '[:upper:]' '[:lower:]' <<< "$res")"
    [ "$res" = pass ] && res=proved
  fi

  printf '%s,%s,%s,%s,%s,%s,%s,24,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$tag" "$nlen" "$plen" "$levels" "$stack" "$lbw" "$bbw" \
    "$cons" "${deg:-}" "${vars:-}" "${kg:-}" "${pv:-}" "${vf:-}" "$sat" "$res" >> "$out"
  echo "[$tag] $res"
  if [ "${KEEP_ARTIFACTS:-0}" != 1 ]; then
    rm -f "$d/zekra.arith" "$d/zekra_Sample_Run1.in"   # tens of MB each
  fi
}

if [ "${CONTROL:-1}" = 1 ]; then
  run_one crc32 500 500 crc32-control-500
  if ! grep -Eq '^crc32-control-500,500,500,15,15,10,7,24,336230,.*YES,proved$' "$out"; then
    echo "CONTROL FAILED: crc32 at 500/500 did not prove and verify at 336230 constraints." >&2
    echo "The lane is mis-parameterised; no other row is meaningful. Refusing to continue." >&2
    exit 1
  fi
  echo "[control] crc32 500/500 reproduced ZEKRA's published 336230 constraints"
fi

if [ -n "${APPS:-}" ]; then
  read -r -a apps <<< "$APPS"
else
  apps=()
  for d in "$zekra"/embench-iot-applications/*/; do apps+=("$(basename "$d")"); done
fi

for app in "${apps[@]}"; do
  read -r nlen plen <<< "$(capacity_of "$zekra/embench-iot-applications/$app")"
  run_one "$app" "$nlen" "$plen"
done

echo
echo "EMBENCH SUITE COMPLETE -> $out"
python3 - "$out" <<'PY'
import csv, sys
rows = [r for r in csv.DictReader(open(sys.argv[1])) if r['app'] != 'crc32-control-500']
from collections import Counter
c = Counter(r['outcome'] for r in rows)
print("  %d applications: %s" % (len(rows), ", ".join("%s %s" % (v, k) for k, v in sorted(c.items()))))
PY
