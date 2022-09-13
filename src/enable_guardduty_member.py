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

def get_admin_detector(gd_admin_session, member_region):
    members_to_enable = []
    try:
        gd_admin_client = gd_admin_session.client('guardduty', 
        endpoint_url=f"https://guardduty.{member_region}.amazonaws.com", 
        region_name=member_region)
        detectors_response = gd_admin_client.list_detectors()
        if detectors_response['DetectorIds']:
            # get 1st and only detector
            detector_id = detectors_response['DetectorIds'][0]
            LOGGER.info('Admin Detector: {} found im Region: {}'.format(detector_id, member_region))
            return detector_id
    except Exception as e:
        LOGGER.error("failed in guardduty calls")
        LOGGER.error(str(e))

def associate_member(member_session, member_account, member_account_email, gd_admin_session, admin_detector, member_region):
    gd_member_dict = {}
    try:
        gd_client = member_session.client('guardduty', 
        endpoint_url=f"https://guardduty.{member_region}.amazonaws.com", 
        region_name=member_region)
        gd_admin_client = gd_admin_session.client('guardduty', 
        endpoint_url=f"https://guardduty.{member_region}.amazonaws.com", 
        region_name=member_region)
        dataSource = {
            "S3Logs": {
                "Enable": True
            }
        }
        response = gd_client.create_detector(Enable=True, FindingPublishingFrequency=GD_FINDING_PUBLISH_INTERVAL, DataSources=dataSource)
        member_detector = response['DetectorId']
        LOGGER.info("Detector: {} created for Member: {}".format(member_detector, member_account))
        gd_admin_client.create_members(DetectorId=admin_detector,
        AccountDetails=[{ 'AccountId': member_account, 'Email': member_account_email}])
        LOGGER.info("Member: {} added to Master with Master Detector Id: {}".format(member_account, admin_detector))
        gd_admin_client.invite_members(DetectorId=admin_detector, AccountIds=[ member_account ], DisableEmailNotification=False)
        LOGGER.info("Member: {} invited by Master with Master Detector Id: {}".format(member_account, admin_detector))
        gd_member_dict.update({'AccountId': member_account, 'DetectorId': member_detector})        
    except Exception as e:
        LOGGER.error(f"failed in guardduty calls")
        LOGGER.error(str(e))
    return gd_member_dict

def accept_invitations(member_session, gd_admin_account, gd_member_dict, member_region):
    try:
        gd_client = member_session.client('guardduty', 
        endpoint_url=f"https://guardduty.{member_region}.amazonaws.com", 
        region_name=member_region)
        member_invitations = gd_client.list_invitations()
        # get latest invitation
        invite_id = member_invitations['Invitations'][-1]['InvitationId']
        gd_client.accept_invitation(DetectorId=gd_member_dict['DetectorId'], MasterId=gd_admin_account, InvitationId=invite_id)
        LOGGER.info("Member: {} ACCEPTED Invite from Admin: {} in Region: {}".format(gd_member_dict['AccountId'], gd_admin_account, member_region))
    except Exception as e:
        LOGGER.error(f"failed in guardduty accept_invitation(..)")
        LOGGER.error(str(e))

def lambda_handler(event, context):
    LOGGER.info(f"REQUEST RECEIVED: {json.dumps(event, default=str)}")
    org_id = event['org_id']
    ou_id = event['org_unit_id']
    ct_home_region = event['ct_home_region']
    s3bucket = event['s3_bucket']
    s3key = event['s3_key']
    gd_admin_account = event['gd_admin_account']
    member_account = event['member_account']
    member_account_email = event['member_account_email']
    member_region = event['member_region']
    assume_role_name = event['assume_role']
    member_session = assume_role(org_id, member_account, assume_role_name)
    gd_admin_session = assume_role(org_id, gd_admin_account, assume_role_name)
    admin_detector = get_admin_detector(gd_admin_session, member_region)
    gd_member_dict = associate_member(member_session, member_account, member_account_email, gd_admin_session, admin_detector, member_region)
    accept_invitations(member_session, gd_admin_account, gd_member_dict, member_region)
    return {
        'statusCode': 200,
        'guardduty_member_status': {
            'org_id': org_id,
            'org_unit_id': ou_id,
            'ct_home_region': ct_home_region,
            's3_bucket': s3bucket,
            's3_key': s3key,
            'gd_admin_account': gd_admin_account,
            'member_account': member_account,
            'member_account_email': member_account_email,
            'member_region': member_region,
            'assume_role': assume_role_name
        }
    }