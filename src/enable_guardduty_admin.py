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

# globals
GD_FINDING_PUBLISH_INTERVAL = 'ONE_HOUR'

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

def get_ct_regions(account_id):
    # use CT session
    cf_client = session.client('cloudformation')
    region_set = set()
    try:
        # stack instances are outdated
        paginator = cf_client.get_paginator('list_stack_instances')
        iterator = paginator.paginate(StackSetName='AWSControlTowerBP-BASELINE-CONFIG',
            StackInstanceAccount=account_id)
        for page in iterator:
            for summary in page['Summaries']:
                region_set.add(summary['Region'])
    except Exception as ex:
        LOGGER.warning("Control Tower StackSet not found in this Region")
        LOGGER.warning(str(ex))
    LOGGER.info(f"Control Tower Regions: {list(region_set)}")
    return list(region_set)

def enable_admin(gd_admin_session, gd_admin_account, gd_regions):
    for region in gd_regions:
        try:
            gd_admin_client = gd_admin_session.client('guardduty', 
            endpoint_url=f"https://guardduty.{region}.amazonaws.com", 
            region_name=region)
            # check detectors
            response = gd_admin_client.list_detectors()
            if len(response['DetectorIds']) > 0:
                detectorId = response['DetectorIds'][0]
                LOGGER.info(f"GuardDuty Detector {detectorId} found in {region}")
            else:
                LOGGER.info(f"GuardDuty Detector NOT found in {region}. Create it.")
                response = gd_admin_client.create_detector(Enable=True, FindingPublishingFrequency=GD_FINDING_PUBLISH_INTERVAL)
                if response['DetectorId']:
                    detectorId = response['DetectorId']
                    LOGGER.info(f"GuardDuty Detector {detectorId} CREATED in {region}.")
                else:
                    LOGGER.warning(f"GuardDuty Detector creation DID NOT return DetectorId in {region} !")
        except Exception as e:
            LOGGER.error(f"GuardDuty not currently enabled on Admin Account {gd_admin_account} in {region}. Enabling it now..")
            LOGGER.error(str(e))
            try:
                gd_admin_client.enable_organization_admin_account(AdminAccountId=gd_admin_account)
            except Exception as ex:
                LOGGER.error(f"Failed to enable GuardDuty in region {region} for {gd_admin_account}")
                LOGGER.error(str(ex))

def lambda_handler(event, context):
    LOGGER.info(f"REQUEST RECEIVED: {json.dumps(event, default=str)}")
    region_params = []
    org_id = event['org_id']
    ou_id = event['org_unit_id']
    ct_home_region = event['ct_home_region']
    s3bucket = event['s3_bucket']
    s3key = event['s3_key']
    gd_admin_account = event['gd_admin_account']
    assume_role_name = event['assume_role']
    gd_admin_session = assume_role(org_id, gd_admin_account, assume_role_name)
    guardduty_regions = get_ct_regions(gd_admin_account)
    enable_admin(gd_admin_session, gd_admin_account, guardduty_regions)
    for region in guardduty_regions:
        region_params.append({
            'org_id': org_id,
            'org_unit_id': ou_id,
            's3_bucket': s3bucket,
            's3_key': s3key,
            'ct_home_region': ct_home_region,
            'gd_admin_account': gd_admin_account,
            'assume_role': assume_role_name,
            'region': region
        })
    return {
        'statusCode': 200,
        'ct_regions': region_params
    }
