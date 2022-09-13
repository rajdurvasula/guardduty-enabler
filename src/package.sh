#!/bin/bash
SCRIPT_DIRECTORY="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

pushd $SCRIPT_DIRECTORY > /dev/null

rm -rf .package guardduty_enabler.zip

zip guardduty_enabler.zip guardduty_enabler.py

popd > /dev/null
