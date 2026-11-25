#!/usr/bin/env bash
# Contract v1 entry point: bash run.sh <sample file> <sample role>
exec python3 "$(dirname "$0")/run.py" "$@"
