# Setup Guard Duty in Control Tower Landing Zone
- This automation code enables GuardDuty Master/Admin on Audit/Security Account and GuardDuty Member/Child on Member accounts

## Instructions

1. Upload files:
  - src/enable_guardduty_admin.zip to S3 Bucket. Note down the S3 Key
  - src/enable_guardduty_member.zip to S3 Bucket. Note down the S3 Key
  - src/ou_accounts.zip to S3 Bucket. Note down the S3 Key
  - gd_enabler_sm.json to S3 Bucket. Note down the S3 Key
    - *This is referred as* **GuardDutyEnablerSM** *statemachine*
  - setup-guardduty-sf.yaml  to S3 Bucket

## Launch sequence
1. Launch CloudFormation stack using setup-guardduty-sf.yaml
2. Execute StateMachine **GuardDutyEnablerSM**
3. Input JSON to StateMachine:
  - **org_unit_id** parameter value is the Organizational Unit comprising of member accounts where GuardDuty should be enabled
```
{
  "org_id": "o-a4tlobvmc0",
  "org_unit_id": "ou-6ulx-jlonwpfj",
  "ct_home_region": "us-east-1",
  "s3_bucket": "org-sh-ops",
  "s3_key": "gd_enabler_sm.json",
  "gd_admin_account": "413157014023",
  "assume_role": "AWSControlTowerExecution"
}
```

## State Machine
- State Machine attempts to enable GuardDuty Organizational Admin on Audit/Security account
- State Machine attempts to enable GuardDuty Child on member accounts that belong to provided Organizational Unit
  - In cases where member account is already enabled, exception is reported and no further action needed

![gd_enabler_sm.png](./gd_enabler_sm.png?raw=true)

## Limitations
- GuardDuty cannot be targeted to a Single Member Account
- All Member Accounts in provided Organizational Unit are effected