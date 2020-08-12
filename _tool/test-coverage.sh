#!/bin/bash

# WARNING:
# This is way too slow. Probably because of cryptography with coverage colleciton.
# https://github.com/dart-lang/coverage/issues/261

set -xeu

cd "${0%/*}"/..


pub get
pub global activate test_coverage

fail=false
pub global run test_coverage || fail=true
echo "fail=$fail"
bash <(curl -s https://codecov.io/bash) -f coverage/lcov.info

test "$fail" == "true" && exit 1

echo "Success 🎉️"

exit 0
