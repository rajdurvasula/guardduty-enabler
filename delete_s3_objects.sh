#!/bin/bash
for i in "setup-guardduty-sf.yaml" "gd_enabler_sm.json" "enable_guardduty_admin.zip" "enable_guardduty_member.zip" "ou_accounts.zip";
do
	aws s3 rm s3://org-sh-ops/$i
done
