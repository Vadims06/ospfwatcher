#!/bin/sh
# Needs docker; the container is privileged to load the program and run BPF_PROG_TEST_RUN.
set -e
cd "$(dirname "$0")/.."
docker build -q -t ospf-filter-test test >/dev/null
docker run --rm --privileged -v "$PWD":/work -w /work ospf-filter-test python3 -W ignore test/run_tests.py "$@"
