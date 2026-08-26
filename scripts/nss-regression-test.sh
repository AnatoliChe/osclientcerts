#!/bin/bash
set -Eeuo pipefail

#
# NSS regression harness: loads this crate's real, unmodified PKCS #11 object/attribute code
# (via backend_other.rs's `nss-regression` feature) into a real, from-source NSS build, across
# several generated certificate chains (varying signature algorithms) and trust-grant shapes, and
# checks that NSS resolves S/MIME email trust the way we expect.
#
# This exists because the two real bugs that blocked S/MIME signing in this project (a missing
# CKA_NSS_CERT_SHA1_HASH silently discarding a CKO_NSS_TRUST grant, and C_GetAttributeValue not
# updating ulValueLen) both live in how a real NSS build interprets our PKCS #11 objects -- neither
# was visible to the crate's own unit tests, which only exercise our code's own state machines
# against a fixed stub. See tests/nss-regression/generate_chains.py for the generated cases.
#
# This is slow (builds a real NSS from source the first time, ~2-10 minutes depending on cores)
# and is meant to be run manually/before a release, not on every push -- see
# .github/workflows/nss-regression.yml for the CI (workflow_dispatch-only) equivalent.
#
# Usage:
#   ./scripts/nss-regression-test.sh
#
# Environment:
#   NSS_SECURITY_DIR   Directory containing an NSS checkout (nss/) and its build output (dist/),
#                       i.e. Mozilla's `security/` layout. Reused (and built only if dist/Release
#                       isn't already there) rather than re-cloned. Defaults to
#                       ../firefox/security relative to this repo if present, otherwise
#                       ROOT/.nss-regression-cache/security (cloned from
#                       https://github.com/mozilla/nss on first run).
#   NSS_CORES           Parallelism for the NSS build (default: nproc).
#   DOCKER_IMAGE         Docker image to run in (default: mozilla-win-cross-builder, the same
#                       image build-fork-osclientcerts.sh uses).
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ROOT="$(cd "${REPO_DIR}/.." && pwd)"

DOCKER_IMAGE="${DOCKER_IMAGE:-mozilla-win-cross-builder}"
NSS_CORES="${NSS_CORES:-$(nproc)}"

DEFAULT_LOCAL_SECURITY_DIR="${ROOT}/firefox/security"
CACHE_SECURITY_DIR="${REPO_DIR}/.nss-regression-cache/security"

if [[ -n "${NSS_SECURITY_DIR:-}" ]]; then
    : # explicit override, use as-is
elif [[ -d "${DEFAULT_LOCAL_SECURITY_DIR}/nss" ]]; then
    NSS_SECURITY_DIR="${DEFAULT_LOCAL_SECURITY_DIR}"
else
    NSS_SECURITY_DIR="${CACHE_SECURITY_DIR}"
fi

echo "============================================================"
echo " NSS regression harness"
echo "============================================================"
echo "REPO_DIR:         ${REPO_DIR}"
echo "NSS_SECURITY_DIR: ${NSS_SECURITY_DIR}"
echo "DOCKER_IMAGE:     ${DOCKER_IMAGE}"
echo "NSS_CORES:        ${NSS_CORES}"
echo

if ! docker image inspect "${DOCKER_IMAGE}" >/dev/null 2>&1; then
    echo "ERROR: Docker image '${DOCKER_IMAGE}' not found. Build it first (see build-fork-osclientcerts.sh)."
    exit 1
fi

mkdir -p "${NSS_SECURITY_DIR}"

TMP_CONTEXT="$(mktemp -d)"
INNER_SCRIPT="${TMP_CONTEXT}/run.sh"
cleanup() { rm -rf "${TMP_CONTEXT}"; }
trap cleanup EXIT

cat > "${INNER_SCRIPT}" <<'INNER_SCRIPT'
#!/bin/bash
set -Eeuo pipefail

export PATH="/home/builder/.cargo/bin:${PATH}"
NSS_CORES="${NSS_CORES:?}"

SEC="/work/security"
SRC="/work/fork-osclientcerts"
DIST="${SEC}/dist/Release"

echo "=== [1/5] NSS source ==="
if [[ ! -d "${SEC}/nss" ]]; then
    echo "No NSS checkout at ${SEC}/nss -- cloning https://github.com/mozilla/nss (shallow, master)..."
    apt-get update -qq && apt-get install -y -qq git >/dev/null
    git clone --depth 1 https://github.com/mozilla/nss "${SEC}/nss"
else
    echo "Reusing existing NSS checkout at ${SEC}/nss"
    git -C "${SEC}/nss" rev-parse HEAD 2>/dev/null || echo "(not a standalone git checkout; skipping revision)"
fi

echo
echo "=== [2/5] NSS build (Release, --system-nspr) ==="
if [[ -x "${DIST}/bin/certutil" && -x "${DIST}/bin/modutil" && -x "${DIST}/bin/vfychain" ]]; then
    echo "Reusing existing build at ${DIST}"
else
    echo "Building NSS from source (this takes a few minutes)..."
    apt-get update -qq
    apt-get install -y -qq gyp ninja-build libnspr4-dev python3 pkg-config >/dev/null
    (cd "${SEC}/nss" && ./build.sh -o --system-nspr -j "${NSS_CORES}")
fi
export LD_LIBRARY_PATH="${DIST}/lib"
echo "NSS tools OK: ${DIST}/bin/{certutil,modutil,vfychain}"

echo
echo "=== [3/5] Generate certificate chains ==="
python3 -m venv /tmp/venv >/dev/null
/tmp/venv/bin/pip install --quiet cryptography
(cd "${SRC}/tests/nss-regression" && /tmp/venv/bin/python3 generate_chains.py)

echo
echo "=== [4/5] Build osclientcerts.so (host target, --features nss-regression) ==="
export CARGO_HOME="/tmp/fork-cargo-home-regression"
export CARGO_TARGET_DIR="/tmp/fork-target-regression"
mkdir -p "${CARGO_HOME}" "${CARGO_TARGET_DIR}"
(cd "${SRC}" && cargo build --release --features nss-regression)
MODULE="${CARGO_TARGET_DIR}/release/libosclientcerts.so"
[[ -f "${MODULE}" ]] || { echo "ERROR: ${MODULE} not built"; exit 1; }

echo
echo "=== [5/5] Run cases against real NSS ==="
NSS_DIST="${DIST}" MODULE="${MODULE}" CASES_DIR="${SRC}/tests/nss-regression/cases" \
    "${SRC}/tests/nss-regression/run_cases.sh"
INNER_SCRIPT

chmod +x "${INNER_SCRIPT}"

docker run --rm \
    --name "${DOCKER_IMAGE}-nss-regression" \
    --user "$(id -u):$(id -g)" \
    -e HOME=/home/builder \
    -e NSS_CORES="${NSS_CORES}" \
    -v "${REPO_DIR}:/work/fork-osclientcerts" \
    -v "${NSS_SECURITY_DIR}:/work/security" \
    -v "${INNER_SCRIPT}:/tmp/run.sh:ro" \
    "${DOCKER_IMAGE}" \
    /bin/bash /tmp/run.sh
