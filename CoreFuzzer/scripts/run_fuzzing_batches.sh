#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FUZZER="${SCRIPT_DIR}/../core_fuzzer.py"

if [[ ! -f "${FUZZER}" ]]; then
    echo "Unable to locate core_fuzzer.py at ${FUZZER}" >&2
    exit 1
fi

# Default NAS message groupings. Override by exporting FUZZ_SYMBOL_GROUPS
# as a semicolon-separated list (e.g. "registrationRequest,authenticationResponse;serviceRequest").
DEFAULT_GROUPS=(
    "registrationRequest"
    "registrationComplete"
    "authenticationResponse"
    "securityModeComplete"
    "serviceRequest"
    "deregistrationRequest"
    "identityResponse"
    "configurationUpdateComplete"
    "deregistrationAccept"
    "authenticationFailure"
    "securityModeReject"
    "ulNasTransport"
    "PDUSessionEstablishmentRequest"
    "PDUSessionAuthenticationComplete"
    "PDUSessionModificationRequest"
    "PDUSessionModificationComplete"
    "PDUSessionModificationCommandReject"
    "PDUSessionReleaseRequest"
    "PDUSessionReleaseComplete"
    "gsmStatus"
    "gmmStatus"
)

if [[ -n "${FUZZ_SYMBOL_GROUPS:-}" ]]; then
    IFS=';' read -r -a SYMBOL_GROUPS <<< "${FUZZ_SYMBOL_GROUPS}"
else
    SYMBOL_GROUPS=("${DEFAULT_GROUPS[@]}")
fi

ITERATIONS="${FUZZ_ITERATIONS:-1}"
BASE_LOG_ROOT="${FUZZ_LOG_ROOT:-${SCRIPT_DIR}/../logs}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BATCH_DIR="${BASE_LOG_ROOT}/batch_${TIMESTAMP}"
mkdir -p "${BATCH_DIR}"

EXTRA_ARGS=("$@")
for arg in "${EXTRA_ARGS[@]}"; do
    case "${arg}" in
        --symbols|--symbols=*|--output-log-dir|--output-log-dir=*)
            echo "Please configure symbols and log directories via the wrapper (see README)." >&2
            exit 1
            ;;
    esac
done

for symbols in "${SYMBOL_GROUPS[@]}"; do
    trimmed="${symbols// /}"
    if [[ -z "${trimmed}" ]]; then
        continue
    fi
    slug="$(echo "${trimmed}" | tr '[:upper:]' '[:lower:]' | tr ',/' '__' | tr -cs 'a-z0-9_.-' '_')"
    RUN_DIR="${BATCH_DIR}/${slug}"
    mkdir -p "${RUN_DIR}"
    echo "Starting fuzzing for NAS symbols: ${symbols} (logs -> ${RUN_DIR})"
    python3 "${FUZZER}" --iterations "${ITERATIONS}" --symbols "${symbols}" --output-log-dir "${RUN_DIR}" "${EXTRA_ARGS[@]}"
    echo "Completed fuzzing for ${symbols}"
    echo "---"
    sleep 2
done

echo "All fuzzing runs stored under ${BATCH_DIR}"
