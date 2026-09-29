#!/usr/bin/env bash
# Builds the live demo into a static folder (default: _site) for GitHub Pages:
# the page itself, the Aegis source it runs, and the Python wheels it installs.
#   demo/build.sh [out-dir]
# Serve the result with any static server, e.g. python -m http.server -d _site
set -euo pipefail
cd "$(dirname "$0")/.."
out="${1:-_site}"

rm -rf "$out"
mkdir -p "$out/py" "$out/wheels"
cp demo/index.html demo/demo.css demo/demo.js demo/bridge.py "$out/"
cp -r app policies seed_data.py "$out/py/"
rm -rf "$out/py/app/static"  # the server's dashboard; the demo has its own page
find "$out/py" -name '__pycache__' -type d -prune -exec rm -rf {} +

# The page fetches these lists to know what to load: the Python, plus the Cedar policy files
# the evaluator reads at startup.
(cd "$out/py" && find . \( -name '*.py' -o -path './policies/*' \) -type f | sed 's|^\./||' | sort) \
  | python3 -c 'import json,sys; print(json.dumps([l.strip() for l in sys.stdin]))' > "$out/py/manifest.json"

python3 -m pip download --quiet --no-deps --only-binary=:all: -d "$out/wheels" -r demo/requirements.txt
(cd "$out/wheels" && ls *.whl) \
  | python3 -c 'import json,sys; print(json.dumps([l.strip() for l in sys.stdin]))' > "$out/wheels/manifest.json"

# Cedar's official WebAssembly build: the same policy engine cedarpy wraps on the server.
# Pinned by version and verified against the npm registry's published integrity hash.
CEDAR_VERSION=4.12.0
CEDAR_SHA512=tCSj92hh4fnmas4ojO4tjx8wAAW3mKVgQ7M388NsSpXp64FVeYY6xwhKtJRaaYGK0qLiN2jnq8/SNIU2r5fdPw==
tgz="$(mktemp)"
curl -fsSL "https://registry.npmjs.org/@cedar-policy/cedar-wasm/-/cedar-wasm-${CEDAR_VERSION}.tgz" -o "$tgz"
actual="$(openssl dgst -sha512 -binary "$tgz" | openssl base64 -A)"
if [ "$actual" != "$CEDAR_SHA512" ]; then
  echo "cedar-wasm integrity mismatch: got $actual" >&2
  exit 1
fi
mkdir -p "$out/cedar"
tar -xzf "$tgz" -C "$out/cedar" --strip-components=2 package/web/cedar_wasm.js package/web/cedar_wasm_bg.wasm
rm -f "$tgz"

touch "$out/.nojekyll"
echo "Built $out: $(python3 -c "import json;print(len(json.load(open('$out/py/manifest.json'))))") source files, $(ls "$out/wheels"/*.whl | wc -l) wheels"
