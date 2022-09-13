#!/bin/bash
SCRIPT_DIRECTORY="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

pushd $SCRIPT_DIRECTORY > /dev/null

rm -rf .package enable_guardduty_admin.zip

zip enable_guardduty_admin.zip enable_guardduty_admin.py

popd > /dev/null
