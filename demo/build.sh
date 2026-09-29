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
cp -r app seed_data.py "$out/py/"
find "$out/py" -name '__pycache__' -type d -prune -exec rm -rf {} +

# The page fetches these lists to know what to load.
(cd "$out/py" && find . -name '*.py' | sed 's|^\./||' | sort) \
  | python3 -c 'import json,sys; print(json.dumps([l.strip() for l in sys.stdin]))' > "$out/py/manifest.json"

python3 -m pip download --quiet --no-deps --only-binary=:all: -d "$out/wheels" -r demo/requirements.txt
(cd "$out/wheels" && ls *.whl) \
  | python3 -c 'import json,sys; print(json.dumps([l.strip() for l in sys.stdin]))' > "$out/wheels/manifest.json"

touch "$out/.nojekyll"
echo "Built $out: $(python3 -c "import json;print(len(json.load(open('$out/py/manifest.json'))))") Python files, $(ls "$out/wheels"/*.whl | wc -l) wheels"
