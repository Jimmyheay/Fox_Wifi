#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
build_dir=$(mktemp -d /tmp/fox-tests.XXXXXX)
trap 'rm -rf "$build_dir"' EXIT
flags=(-std=c++11 -Wall -Wextra -Werror -pthread -g -IESP32-WiFi-Hash-Monster)
if [[ "${SANITIZE:-0}" == 1 ]]; then
  flags+=(-fsanitize=address,undefined -fno-omit-frame-pointer)
fi
"${CXX:-g++}" "${flags[@]}" ESP32-WiFi-Hash-Monster/SecurityAnalyzer.cpp tests/security_analyzer_test.cpp -o "$build_dir/parser"
"$build_dir/parser"
"${CXX:-g++}" "${flags[@]}" -Itests/host ESP32-WiFi-Hash-Monster/Buffer.cpp ESP32-WiFi-Hash-Monster/SecurityAnalyzer.cpp tests/buffer_test.cpp -o "$build_dir/buffer"
"$build_dir/buffer"
