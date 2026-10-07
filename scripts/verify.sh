#!/bin/sh
# One-shot verification entry point used by the `verify` compose service.
# Aggregates: build check (byte-compile) + unit tests + admission smoke.
set -u

cd "$(dirname "$0")/.."

rc=0

echo "==> [1/3] build check: byte-compiling app, scripts, tests"
if python3 -m compileall -q app scripts tests; then
    echo "    OK"
else
    echo "    FAILED"
    rc=1
fi

echo "==> [2/3] unit tests"
if python3 -m unittest discover -v -s tests; then
    echo "    OK"
else
    echo "    FAILED"
    rc=1
fi

echo "==> [3/3] signature-admission smoke"
if python3 scripts/smoke.py; then
    echo "    OK"
else
    echo "    FAILED"
    rc=1
fi

if [ "$rc" -eq 0 ]; then
    echo "verify: ALL CHECKS PASSED"
else
    echo "verify: CHECKS FAILED (exit $rc)"
fi
exit "$rc"
