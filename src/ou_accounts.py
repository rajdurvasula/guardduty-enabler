import sys
import boto3
import json
import urllib3
import os
import logging
from datetime import date, datetime
from botocore.exceptions import ClientError

LOGGER = logging.getLogger()
if 'log_level' in os.environ:
    LOGGER.setLevel(os.environ['log_level'])
    LOGGER.info('Log level set to %s' % LOGGER.getEffectiveLevel())
else:
    LOGGER.setLevel(logging.ERROR)

session = boto3.Session()

def json_serial(obj):
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    raise TypeError('Type %s not serializable' % type(obj))

def assume_role(org_id, aws_account_number, role_name):
    sts_client = boto3.client('sts')
    partition = sts_client.get_caller_identity()['Arn'].split(":")[1]
    response = sts_client.assume_role(
        RoleArn='arn:%s:iam::%s:role/%s' % (
            partition, aws_account_number, role_name
        ),
        RoleSessionName=str(aws_account_number+'-'+role_name),
        ExternalId=org_id
    )
    sts_session = boto3.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken']
    )
    LOGGER.info(f"Assumed region_session for Account {aws_account_number}")
    return sts_session

def get_ou_accounts(ou_id, region):
    aws_accounts = []
    try:
        org_client = session.client('organizations', region_name=region)
        paginator = org_client.get_paginator('list_children')
        iterator = paginator.paginate(ParentId=ou_id, ChildType='ACCOUNT')
        for page in iterator:
            for account in page['Children']:
                response = org_client.describe_account(AccountId=account['Id'])
                if response['Account'] and response['Account']['Status'] == 'ACTIVE':
                    aws_accounts.append({ 'Id': account['Id'], 'Email': response['Account']['Email']})
        LOGGER.info(f"Active Accounts Count: %s of Org Unit: %s" %  (len(aws_accounts), ou_id))
    except Exception as e:
        LOGGER.error(f"failed in Organizations calls")
        LOGGER.error(str(e))
    return aws_accounts

def lambda_handler(event, context):
    LOGGER.info(f"REQUEST RECEIVED: {json.dumps(event, default=str)}")
    accounts_params = []
    org_id = event['org_id']
    ou_id = event['org_unit_id']
    ct_home_region = event['ct_home_region']
    s3bucket = event['s3_bucket']
    s3key = event['s3_key']
    gd_admin_account = event['gd_admin_account']
    assume_role_name = event['assume_role']
    member_region = event['region']
    aws_accounts = get_ou_accounts(ou_id, ct_home_region)
    for account in aws_accounts:
        accounts_params.append({
            'org_id': org_id,
            'org_unit_id': ou_id,
            's3_bucket': s3bucket,
            's3_key': s3key,
            'ct_home_region': ct_home_region,
            'gd_admin_account': gd_admin_account,
            'assume_role': assume_role_name,
            'member_account': account['Id'],
            'member_account_email': account['Email'],
            'member_region': member_region
        })
    return {
        'statusCode': 200,
        'accounts': accounts_params
    }
    
