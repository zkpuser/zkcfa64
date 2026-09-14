#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
EXPECTED_BINIUS="c56e2027591df056cee5bd741085e110d491f28e"
EXPECTED_PLONK="4fc762ac433a942939ad43a3b29050a26ce52533"
EXPECTED_ZEKRA="01a0152bfd9812a0569dce19965e7e92df30015d"
PROVIDER_IMAGE="zkcfa64-provider-pipeline:local"
BINIUS_IMAGE="zkcfa64-binius-pipeline:local"
PLONK_IMAGE="zkcfa64-plonk-pipeline:local"

OUTPUT=""
STAGES="provider,binius,plonk,zekra"
QUICK=0
DRY_RUN=0

usage() {
    cat <<'EOF'
Usage: scripts/run-crc32-pipeline.sh [options]

Reproduce the CRC32 pipeline from a fresh maintained trace through Binius64
and PLONK proof verification, plus the isolated ZEKRA comparison baseline.

Options:
  --output DIR       New output directory (default: private temporary directory)
  --stages LIST      Comma-separated stages: provider,binius,plonk,zekra
                     (default: all four; binius/plonk require provider)
  --quick            Smoke run: omit provider negatives/tests, use PLONK
                     preflight instead of a proof, and omit ZEKRA
  --dry-run          Print commands without executing them
  -h, --help         Show this help

The output directory must not be inside the repository. It contains disposable
private signing keys and confidential proof inputs; keep or delete it explicitly.
EOF
}

die() {
    echo "error: $*" >&2
    exit 1
}

print_command() {
    printf '+'
    printf ' %q' "$@"
    printf '\n'
}

run() {
    print_command "$@"
    if [ "${DRY_RUN}" -eq 0 ]; then
        "$@"
    fi
}

run_logged() {
    local logfile="$1"
    shift
    print_command "$@"
    if [ "${DRY_RUN}" -eq 0 ]; then
        "$@" 2>&1 | tee "${logfile}"
    fi
}

require_log_text() {
    local logfile="$1"
    local text="$2"
    if [ "${DRY_RUN}" -eq 0 ] && ! grep -Fq "${text}" "${logfile}"; then
        die "expected result '${text}' is absent from ${logfile}"
    fi
}

has_stage() {
    case ",${STAGES}," in
        *",$1,"*) return 0 ;;
        *) return 1 ;;
    esac
}

validate_stages() {
    local old_ifs item
    [ -n "${STAGES}" ] || die "--stages must not be empty"
    case "${STAGES}" in
        ,*|*,|*,,*) die "--stages contains an empty stage" ;;
    esac
    old_ifs="${IFS}"
    IFS=','
    for item in ${STAGES}; do
        case "${item}" in
            provider|binius|plonk|zekra) ;;
            *) die "unknown stage '${item}'" ;;
        esac
    done
    IFS="${old_ifs}"
    if { has_stage binius || has_stage plonk; } && ! has_stage provider; then
        die "the binius and plonk stages require provider in --stages"
    fi
}

require_submodule_pin() {
    local path="$1"
    local expected="$2"
    local label="$3"
    local actual
    [ -e "${path}/.git" ] || die "${label} is not initialized; run git submodule update --init --recursive"
    actual="$(git -C "${path}" rev-parse HEAD)"
    [ "${actual}" = "${expected}" ] || die "${label} is at ${actual}; expected ${expected}"
    [ -z "$(git -C "${path}" status --porcelain)" ] || die "${label} has local changes; the pipeline requires the recorded clean pin"
}

json_value() {
    python3 -c 'import json,sys
value=json.load(open(sys.argv[1], encoding="utf-8"))
for key in sys.argv[2].split("."):
    value=value[key]
print(value)' "$1" "$2"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --output)
            [ "$#" -ge 2 ] || die "--output requires a directory"
            OUTPUT="$2"
            shift 2
            ;;
        --stages)
            [ "$#" -ge 2 ] || die "--stages requires a comma-separated list"
            STAGES="$2"
            shift 2
            ;;
        --quick)
            QUICK=1
            shift
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown option '$1' (try --help)"
            ;;
    esac
done

validate_stages
if [ "${QUICK}" -eq 1 ]; then
    case "${STAGES}" in
        zekra) STAGES="" ;;
        zekra,*) STAGES="${STAGES#zekra,}" ;;
        *,zekra) STAGES="${STAGES%,zekra}" ;;
        *,zekra,*) STAGES="$(printf '%s' "${STAGES}" | sed 's/,zekra,/,/')" ;;
    esac
    [ -n "${STAGES}" ] || die "--quick omits ZEKRA; select another stage or remove --quick"
fi

command -v docker >/dev/null 2>&1 || die "docker is required"
command -v git >/dev/null 2>&1 || die "git is required"
command -v python3 >/dev/null 2>&1 || die "python3 is required"

if has_stage binius; then
    require_submodule_pin "${ROOT}/zkcfa-binius64/binius64" "${EXPECTED_BINIUS}" "Binius64 submodule"
fi
if has_stage plonk; then
    require_submodule_pin "${ROOT}/zkcfa-plonk/plonk" "${EXPECTED_PLONK}" "PLONK submodule"
fi
if has_stage zekra; then
    require_submodule_pin "${ROOT}/zekra/ZEKRA" "${EXPECTED_ZEKRA}" "ZEKRA submodule"
fi

if [ -z "${OUTPUT}" ]; then
    if [ "${DRY_RUN}" -eq 1 ]; then
        OUTPUT="/tmp/zkcfa64-crc32.XXXXXX"
    else
        OUTPUT="$(mktemp -d /tmp/zkcfa64-crc32.XXXXXX)"
    fi
else
    OUTPUT="$(python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve())' "${OUTPUT}")"
    case "${OUTPUT}/" in
        "${ROOT}/"*) die "--output must be outside ${ROOT}" ;;
    esac
    [ ! -e "${OUTPUT}" ] || die "refusing to overwrite existing output: ${OUTPUT}"
    if [ "${DRY_RUN}" -eq 0 ]; then
        umask 077
        mkdir -p "${OUTPUT}"
    fi
fi

LOGS="${OUTPUT}/logs"
if [ "${DRY_RUN}" -eq 0 ]; then
    umask 077
    mkdir -p "${LOGS}"
fi

echo "CRC32 pipeline output: ${OUTPUT}"

if has_stage provider; then
    run_logged "${LOGS}/00-provider-image.log" \
        docker build --tag "${PROVIDER_IMAGE}" "${ROOT}/zkcfa-tracer/provider"
    if [ "${QUICK}" -eq 1 ]; then
        provider_target="static"
    else
        provider_target="container-demo"
    fi
    run_logged "${LOGS}/01-provider.log" \
        docker run --rm --init \
        --volume "${OUTPUT}:/run" \
        "${PROVIDER_IMAGE}" \
        make -C /provider "STATIC_OUT=/run/provider/static" "${provider_target}"
    run_logged "${LOGS}/02-binius-issuance.log" \
        docker run --rm --init \
        --volume "${ROOT}/zkcfa-tracer:/workspace/zkcfa-tracer:ro" \
        --volume "${OUTPUT}:/run" \
        --env PYTHONPATH=/provider \
        "${PROVIDER_IMAGE}" \
        python3 /workspace/zkcfa-tracer/research/provider-integration/bundle.py \
        --run-dir /run/provider/signed-binius \
        --artifacts /run/provider/static/registry \
        --policy-artifacts /run/provider/static/registry \
        --binary /run/provider/static/crc32-aarch64 \
        --trace /run/provider/static/trace.log \
        --path-mode complete
fi

if has_stage binius || has_stage plonk; then
    if [ "${DRY_RUN}" -eq 1 ]; then
        BINIUS_AUTHORITY_HASH="<binius-authority-sha256>"
        BINIUS_CHALLENGE="<binius-challenge-id>"
        BINIUS_NONCE="<binius-nonce>"
    else
        BINIUS_RESULT="${OUTPUT}/provider/signed-binius/protocol-result.json"
        [ -f "${BINIUS_RESULT}" ] || die "provider result is missing: ${BINIUS_RESULT}"
        BINIUS_AUTHORITY_HASH="$(json_value "${BINIUS_RESULT}" authority_sha256)"
        BINIUS_CHALLENGE="$(json_value "${BINIUS_RESULT}" challenge.challenge_id)"
        BINIUS_NONCE="$(json_value "${BINIUS_RESULT}" challenge.nonce)"
    fi
fi

if has_stage binius; then
    run_logged "${LOGS}/03-binius-image.log" \
        docker build --tag "${BINIUS_IMAGE}" "${ROOT}/zkcfa-binius64"
    run_logged "${LOGS}/04-binius-proof.log" \
        docker run --rm --init \
        --volume "${ROOT}:/workspace:ro" \
        --volume "${OUTPUT}:/run" \
        --volume zkcfa64-cargo-registry:/usr/local/cargo/registry \
        --volume zkcfa64-cargo-git:/usr/local/cargo/git \
        --workdir /workspace/zkcfa-binius64 \
        --env CARGO_TARGET_DIR=/run/cargo-target/binius \
        --env 'RUSTFLAGS=-C target-cpu=native' \
        --env ZKCFA_PROVIDER_BUNDLE=/run/provider/signed-binius/bundle \
        --env ZKCFA_AUTHORITY_PUBLIC=/run/provider/signed-binius/keys/public/authority.pem \
        --env "ZKCFA_AUTHORITY_SHA256=${BINIUS_AUTHORITY_HASH}" \
        --env "ZKCFA_EXPECTED_CHALLENGE_ID=${BINIUS_CHALLENGE}" \
        --env "ZKCFA_EXPECTED_NONCE=${BINIUS_NONCE}" \
        --env ZKCFA_JSON=1 \
        "${BINIUS_IMAGE}" \
        cargo run --release --locked --manifest-path zkcfa64/Cargo.toml
    require_log_text "${LOGS}/04-binius-proof.log" '"verified":true'
fi

if has_stage plonk; then
    REISSUER="${ROOT}/zkcfa-plonk/zkcfa/src/bin/zkcfa-reissue.rs"
    [ -f "${REISSUER}" ] || die "PLONK authenticated reissuer is missing: ${REISSUER}"
    run_logged "${LOGS}/05-plonk-image.log" \
        docker build --tag "${PLONK_IMAGE}" "${ROOT}/zkcfa-plonk"
    if [ "${DRY_RUN}" -eq 1 ]; then
        TARGET_CHALLENGE="<fresh-plonk-challenge-id>"
        TARGET_NONCE="<fresh-plonk-nonce>"
    else
        TARGET_CHALLENGE="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
        TARGET_NONCE="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
    fi
    # The reissuer deliberately requires an existing, non-symlink parent so
    # it never creates path components before authenticating the source.
    run mkdir -p "${OUTPUT}/plonk"
    run_logged "${LOGS}/06-plonk-reissuance.log" \
        docker run --rm --init \
        --volume "${ROOT}:/workspace:ro" \
        --volume "${OUTPUT}:/run" \
        --volume zkcfa64-cargo-registry:/usr/local/cargo/registry \
        --volume zkcfa64-cargo-git:/usr/local/cargo/git \
        --workdir /workspace \
        --env CARGO_TARGET_DIR=/run/cargo-target/plonk \
        "${PLONK_IMAGE}" \
        cargo run --release --locked --manifest-path zkcfa-plonk/zkcfa/Cargo.toml \
        --bin zkcfa-reissue -- \
        --source-bundle /run/provider/signed-binius/bundle \
        --source-authority-public /run/provider/signed-binius/keys/public/authority.pem \
        --source-authority-sha256 "${BINIUS_AUTHORITY_HASH}" \
        --source-challenge-id "${BINIUS_CHALLENGE}" \
        --source-nonce "${BINIUS_NONCE}" \
        --source-enrollment /run/provider/signed-binius/staging-private/enrollment.json \
        --target-challenge-id "${TARGET_CHALLENGE}" \
        --target-nonce "${TARGET_NONCE}" \
        --run-dir /run/plonk/reissued

    if [ "${DRY_RUN}" -eq 1 ]; then
        PLONK_AUTHORITY_HASH="<plonk-authority-sha256>"
        PLONK_CHALLENGE="<plonk-challenge-id>"
        PLONK_NONCE="<plonk-nonce>"
    else
        PLONK_RESULT="${OUTPUT}/plonk/reissued/protocol-result.json"
        [ -f "${PLONK_RESULT}" ] || die "PLONK reissuance result is missing: ${PLONK_RESULT}"
        PLONK_AUTHORITY_HASH="$(json_value "${PLONK_RESULT}" authority_sha256)"
        PLONK_CHALLENGE="$(json_value "${PLONK_RESULT}" challenge_id)"
        PLONK_NONCE="$(json_value "${PLONK_RESULT}" nonce)"
    fi

    # Keep the array non-empty: macOS ships Bash 3.2, where expanding an empty
    # array under `set -u` raises "unbound variable". A lone `--` is Cargo's
    # normal argument separator and passes no arguments to the proof binary.
    PLONK_ARGS=(--)
    if [ "${QUICK}" -eq 1 ]; then
        PLONK_ARGS=(-- --preflight)
    fi
    run_logged "${LOGS}/07-plonk-proof.log" \
        docker run --rm --init \
        --volume "${ROOT}:/workspace:ro" \
        --volume "${OUTPUT}:/run" \
        --volume zkcfa64-cargo-registry:/usr/local/cargo/registry \
        --volume zkcfa64-cargo-git:/usr/local/cargo/git \
        --workdir /workspace/zkcfa-plonk \
        --env CARGO_TARGET_DIR=/run/cargo-target/plonk \
        --env ZKCFA_PROVIDER_BUNDLE=/run/plonk/reissued/bundle \
        --env ZKCFA_AUTHORITY_PUBLIC=/run/plonk/reissued/keys/public/authority.pem \
        --env "ZKCFA_AUTHORITY_SHA256=${PLONK_AUTHORITY_HASH}" \
        --env "ZKCFA_EXPECTED_CHALLENGE_ID=${PLONK_CHALLENGE}" \
        --env "ZKCFA_EXPECTED_NONCE=${PLONK_NONCE}" \
        --env ZKCFA_JSON=1 \
        "${PLONK_IMAGE}" \
        cargo run --release --locked --manifest-path zkcfa/Cargo.toml \
        --bin zkcfa "${PLONK_ARGS[@]}"
    if [ "${QUICK}" -eq 1 ]; then
        require_log_text "${LOGS}/07-plonk-proof.log" '"satisfied":true'
    else
        require_log_text "${LOGS}/07-plonk-proof.log" '"verified":true'
    fi
fi

if has_stage zekra; then
    run_logged "${LOGS}/08-zekra-compiler-build.log" \
        docker build --platform linux/amd64 --file "${ROOT}/zekra/Dockerfile.zekra-paper22" \
        --tag zkcfa-zekra:paper-ubuntu22.04 "${ROOT}/zekra"
    run_logged "${LOGS}/08-zekra-prover-build.log" \
        docker build --file "${ROOT}/zekra/Dockerfile.zekra-native" \
        --tag zekra-native:local "${ROOT}/zekra"
    run_logged "${LOGS}/08-zekra.log" \
        bash "${ROOT}/zekra/reproduce/run-crc32-paper22.sh" --output "${OUTPUT}/zekra"
fi

if [ "${DRY_RUN}" -eq 1 ]; then
    echo "CRC32 pipeline dry run complete; no commands were executed."
else
    echo "CRC32 pipeline passed. Private run directory: ${OUTPUT}"
fi
