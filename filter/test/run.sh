#!/bin/sh
# Needs docker; privileged to load the program and run BPF_PROG_TEST_RUN.
# The filter is attached by the production entrypoint, with the production tc.
set -e
cd "$(dirname "$0")/.."
docker build -q -t vadims06/ospf-filter:latest . >/dev/null
docker build -q -t ospf-filter-test -f test/Dockerfile . >/dev/null
docker run --rm --privileged ${1:+-v "$PWD/$1":/announcement_filter.c} ospf-filter-test
