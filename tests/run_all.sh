#!/usr/bin/env bash
# Full acceptance run: build every fixture, then check server + browser layers.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
export GVH_PHP_MODE=wasm
SITES=${SITES:-/tmp/gvh-sites}
OUT=${OUT:-/tmp/gvh-out}
FAIL=0

python3 tests/fixtures_gen.py "$SITES" > /tmp/gvh-sites.json || exit 1

echo
echo "================ SOFT CRYPTO ================"
node tests/softcrypto_test.mjs || FAIL=1

echo "================ VAULT ================"
node tests/vault_suite.mjs || FAIL=1

for name in simple rich media big unicode; do
  echo
  echo "================ BUILD $name ================"
  python3 src/gvh.py build "$SITES/$name/index.html" -o "$OUT/$name" --force --quiet \
      --allow-non-native || { echo "BUILD FAILED: $name"; FAIL=1; continue; }
  echo "================ API $name ================"
  node tests/api_suite.mjs "$OUT/$name" "$SITES/$name/index.html" || FAIL=1
  echo "================ BROWSER $name ================"
  node tests/browser_suite.mjs "$OUT/$name" "$SITES/$name/index.html" || FAIL=1
done

echo
echo "================ DEMO ================"
python3 src/gvh.py build examples/demo/index.html -o "$OUT/demo" --force --quiet --allow-non-native || FAIL=1
node tests/api_suite.mjs "$OUT/demo" examples/demo/index.html || FAIL=1
node tests/browser_suite.mjs "$OUT/demo" examples/demo/index.html || FAIL=1

echo
if [ "$FAIL" = 0 ]; then echo "ALL SUITES PASSED"; else echo "SOME SUITES FAILED"; fi
exit "$FAIL"
