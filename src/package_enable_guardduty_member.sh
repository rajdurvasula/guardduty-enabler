#!/bin/bash
SCRIPT_DIRECTORY="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

pushd $SCRIPT_DIRECTORY > /dev/null

rm -rf .package enable_guardduty_member.zip

zip enable_guardduty_member.zip enable_guardduty_member.py

popd > /dev/null
