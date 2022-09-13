#!/bin/bash
CURR_DIR=`pwd`
for i in "setup-guardduty-sf.yaml" "gd_enabler_sm.json"
do
	aws s3 cp $i s3://org-sh-ops/
done
cd src
for i in "enable_guardduty_admin.zip" "enable_guardduty_member.zip" "ou_accounts.zip";
do
	aws s3 cp $i s3://org-sh-ops/
done
cd $CURR_DIR
