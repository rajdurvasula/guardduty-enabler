import sys
import boto3
import json
import urllib3
import os
import logging
from datetime import datetime
from botocore.exceptions import ClientError

LOGGER = logging.getLogger()
if 'log_level' in os.environ:
    LOGGER.setLevel(os.environ['log_level'])
    LOGGER.info('Log level set to %s' % LOGGER.getEffectiveLevel())
else:
    LOGGER.setLevel(logging.ERROR)

session = boto3.Session()

class GDMember:

    def __init__(self, accountId, detectorId, masterId, status):
        self.accountId = accountId
        self.detectorId = detectorId
        self.masterId = masterId
        self.status = status
    
    def set_detectorId(self, detectorId):
        self.detectorId = detectorId
    
    def to_dict(self):
        return {
            'AccountId': self.accountId,
            'DetectorId': self.detectorId,
            'MasterId': self.masterId,
            'Status': self.status
        }

def send(event, context, response_status, response_data, physical_resource_id=None, no_echo=False):
    response_url = event['ResponseURL']
    print(response_url)
    logstream = context.log_stream_name
    response_body = {}
    response_body['Status'] = response_status
    response_body['Reason'] = 'Check details in log stream: '+logstream
    response_body['PhysicalResourceId'] = physical_resource_id or logstream
    response_body['StackId'] = event['StackId']
    response_body['RequestId'] = event['RequestId']
    response_body['LogicalResourceId'] = event['LogicalResourceId']
    response_body['NoEcho'] = no_echo
    response_body['Data'] = response_data

    json_response_body = json.dumps(response_body)
    print('Response Body:\n'+json_response_body)
    headers = {
        'content-type': '',
        'content-length': str(len(json_response_body))
    }
    http = urllib3.PoolManager()
    try:
        response = http.request('PUT', response_url, body=json_response_body, headers=headers)
        print('HTTP Status: '+response.reason)
    except Exception as ex:
        print("send(..) failed executing requests.put(..): "+str(ex))

def get_enabled_regions(region_session, regions):
    enabled_regions = []
    for region in regions:
        sts_client = region_session.client('sts', endpoint=f"https://sts.{region}.amazonaws.com", region_name=region)
    try:
        sts_client.get_caller_identity()
        enabled_regions.append(region)
    except ClientError as ce:
        if ce.response['Error']['Code'] == 'InvalidClientTokenId':
            LOGGER.info(f"{region} region is disabld")
        else:
            err = ce.response['Error']
            LOGGER.error(f"Error {err} occurred testing region {region}")
    LOGGER.info(f"Enabled Regions: {enabled_regions}")
    return enabled_regions

def is_ou_account(ou_name, account_id, org_client):
    list_parents_response = org_client.list_parents(ChildId=account_id)
    parent_id = list_parents_response['Parents'][0]['Id']
    parent_type = list_parents_response['Parents'][0]['Type']
    if parent_type != 'ROOT':
        ou_response = org_client.describe_organizational_unit(OrganizationalUnitId=parent_id)
        if ou_response['OrganizationalUnit']['Name'] == ou_name:
            return True
    return False

def get_account_list():
    aws_accounts_dict = dict()
    org_client = session.client('organizations', region_name='us-east-1')
    accounts = org_client.list_accounts()
    LOGGER.info(f"AWS Organizations Accounts: {accounts}")
    while 'NextToken' in accounts:
        more_accounts = org_client.list_accounts(NextToken=accounts['NextToken'])
        for acct in accounts['Accounts']:
            more_accounts['Accounts'].append(acct)
        accounts = more_accounts
        LOGGER.debug(f"Accounts: {accounts}")
        LOGGER.info('Total accounts: {}'.format(len(accounts['Accounts'])))
        for account in accounts['Accounts']:
            ou_account = is_ou_account(os.environ['ou_filter'], account['Id'], org_client=org_client)
            if ou_account and account['Status'] == 'ACTIVE':
                account_id = account['Id']
                email = account['Email']
                aws_accounts_dict.update({account_id: email})
        LOGGER.info('Active accounts count: %s, Active accounts: %s' % (
            len(aws_accounts_dict.keys()), json.dumps(aws_accounts_dict)))
        return aws_accounts_dict

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

def assume_role(aws_account_number, role_name):
    sts_client = boto3.client('sts', region_name=os.environ['AWS_REGION'],
        endpoint_url=f"https://sts.{os.environ['AWS_REGION']}.amazonaws.com")
    partition = sts_client.get_caller_identity()['Arn'].split(":")[1]
    current_account = sts_client.get_caller_identity()['Arn'].split(":")[4]
    if aws_account_number == current_account:
        LOGGER.info(f"Using existing region_session for Account {aws_account_number}")
        return session
    else:
        response = sts_client.assume_role(
            RoleArn='arn:%s:iam::%s:role/%s' % (
                partition, aws_account_number, role_name),
                RoleSessionName='EnableSecurityHub')
        sts_session = boto3.Session(
            aws_access_key_id=response['Credentials']['AccessKeyId'],
            aws_secret_access_key=response['Credentials']['SecretAccessKey'],
            aws_session_token=response['Credentials']['SessionToken'])
        LOGGER.info(f"Assumed region_session for Account {aws_account_number}")
        return sts_session

def get_admin_members(admin_session, aws_region):
    """
    Returns a list current members of GuardDuty admin account
    """
    member_list = []
    gd_client = admin_session.client('guardduty', endpoint_url=f"https://guardduty.{aws_region}.amazonaws.com", region_name=aws_region)
    detectors_response = gd_client.list_detectors()
    if len(detectors_response['DetectorIds']) > 0:
        # get first detector id
        detectorId = detectors_response['DetectorIds'][0]
        # paginate list_members
        paginator = gd_client.get_paginator('list_members')
        page_iterator = paginator.paginate(DetectorId=detectorId, OnlyAssociated='False')
        for page in page_iterator:
            if page['Members']:
                for member in page['Members']:
                    if member['RelationshipStatus'] == 'Removed':
                        member_list.append(GDMember(member['AccountId'], None, member['MasterId'], member['RelationshipStatus']))
                    elif member['RelationshipStatus'] == 'Removed':
                        member_list.append(GDMember(member['AccountId'], member['DetectorId'], member['MasterId'], member['RelationshipStatus']))
        LOGGER.info(f"Region: {aws_region}, Members of GuardDuty Admin Account: {member_list}")
    return member_list

def find_admin_member(admin_session, aws_region, account):
    member_list = get_admin_members(admin_session, aws_region)
    for member in member_list:
        member_dict = member.to_dict()
        if member_dict['AccountId'] == account:
            break
    else:
        member = None
    return member

def update_admin_member(admin_session, aws_region, account, detectorId):
    member_list = get_admin_members(admin_session, aws_region)
    for member in member_list:
        member_dict = member.to_dict()
        if member_dict['AccountId'] == account:
            member.set_detectorId(detectorId)
            break

def enable_admin(admin_session, guardduty_regions, partition):
    admin_account = os.environ['gd_admin_account']
    for region in guardduty_regions:
        gd_admin_client = admin_session.client('guardduty', endpoint_url=f"https://guardduty.{region}.amazonaws.com", region_name=region)
        try:
            #findings_response = gd_admin_client.get_findings()
            list_response = gd_admin_client.list_detectors()
            if len(list_response['DetectorIds']) > 0:
                detectorId = list_response['DetectorIds'][0]
                LOGGER.info(f"GuardDuty Detector {detectorId} found in {region}")
            else:
                LOGGER.info(f"GuardDuty Detector {detectorId} NOT found in {region}. Effectively NOT ENABLED.")
                # Q: should we enable guardduty in regions where it is not enabled
                # Q: create a detector
        except Exception as ex:
            LOGGER.info(f"GuardDuty not currently enabled on Admin Account {admin_account} in {region}. Enabling it now..")
            try:
                gd_admin_client.enable_organization_admin_account(AdminAccountId=admin_account)
            except:
                LOGGER.error(f"Failed to enable GuardDuty in region {region} for {admin_account}")

def disable_admin(admin_session, role, guardduty_regions):
    for region in guardduty_regions:
        gd_admin_client = admin_session.client('guardduty', endpoint_url=f"https://guardduty.{region}.amazonaws.com", region_name=region)
        admin_members = get_admin_members(admin_session, region)
        member_accountIds = []
        for member in admin_members:
            member_dict = member.to_dict()
            member_accountIds.append(member_dict['AccountId'])
            member_session = assume_role(member_dict['AccountId'], role)
            member_client = member_session.client('guardduty', endpoint_url=f"https://guardduty.{region}.amazonaws.com", region_name=region)
            try:
                member_client.disassociate_from_master_account(member_dict['DetectorId'])
            except Exception as ex:
                LOGGER.warning(f"Dissassociating member {member} from GuardDuty Admin in {region} failed")
            accountId = member_dict['AccountId']
            detectorId = member_dict['DetectorId']
            try:
                member_client.delete_detector(DetectorId=detectorId)
            except Exception as ex:
                LOGGER.warning(f"Error deleting DetectorId {detectorId} of member Account {accountId}")
        detectors_response = gd_admin_client.list_detectors()
        # get first detector id
        detectorId = detectors_response['DetectorIds'][0]
        # convert to set for unique member ids
        members_set = set(member_accountIds)
        # disassociate members
        gd_admin_client.disassociate_members(DetectorId=detectorId, AccountIds=list(members_set))
        # delete members
        gd_admin_client.delete_members(AccountIds=list(members_set))

# push custom event on successful completion
def successful_completion(admin_session, guadduty_regions):
    for region in guadduty_regions:
        event_admin_client = admin_session.client('events')
        entries = []
        message = {
            "Message": "Member added to Admin"
        }
        entry = {
            'Time': datetime.now(),
            'Detail': json.dumps(message),
            'DetailType': 'Message from GuardDutyAdminEnablerLambda',
            'EventBusName': 'default',
            'Source': 'GuardDutyAdminEnablerLambda'
        }
        entries.append(entry)
        event_admin_client.put_events(Entries=entries)

def lambda_handler(event, context):
    LOGGER.info(f"REQUEST RECEIVED: {json.dumps(event, default=str)}")
    partition = context.invoked_function_arn.split(":")[1]
    admin_account_id = os.environ['gd_admin_account']
    admin_session = assume_role(admin_account_id, os.environ['assume_role'])
    # Regions to deploy
    if os.environ['region_filter'] == 'ControlTower':
        guardduty_regions = get_ct_regions(admin_account_id)
    if 'RequestType' in event and (event['RequestType'] == "Create" or event['RequestType'] == "Delete" or event['RequestType'] == "Update"):
        action = event['RequestType']
        if action == 'Create':
            enable_admin(admin_session, guardduty_regions, partition)
        if action == "Delete":
            disable_admin(admin_session, os.environ['assume_role'], guardduty_regions, partition)
        LOGGER.info(f"Sending Custom Resource Response")
        response_data = {}
        send(event, context, "SUCCESS", response_data)
        if action == "Delete":
            raise SystemExit()
    else:
        action = 'Create'
    LOGGER.info(f"Enabling GuardDuty in Regions: {guardduty_regions}")
    # Iterates through list of accounts and calls the function by SNS.
    # SNS is used to Fan-Out requests to avoid function timeout if too many accounts
    #aws_account_dict = get_account_list()
    aws_account_dict = dict()
    # Check if function called by SNS subscription
    if 'Records' in event:
        message = event['Records'][0]['Sns']['Message']
        json_message = json.loads(message)
        LOGGER.info(f"SNS message: {json.dumps(json_message, default=str)}")
        accountId = json_message['AccountId']
        email = json_message['Email']
        aws_account_dict.update({accountId: email})
        action = json_message['Action']
    else:
        # If NOT called by SNS
        aws_account_dict = get_account_list()
        sns_client = session.client('sns', region_name=os.environ['AWS_REGION'])
        for accountId, email in aws_account_dict.items():
            sns_message = {
                'AccountId': accountId,
                'Email': email,
                'Action': action
            }
            LOGGER.info(f"Publishing to configure Account {accountId}")
            sns_client.publish(TopicArn=os.environ['topic'], Message=json.dumps(sns_message))
    # Ensure GuardDuty Admin is still enabled
    # TODO: Is this needed ?
    enable_admin(admin_session, guardduty_regions, partition)
    # Processing Accounts asynchronously over SNS
    for account in aws_account_dict.keys():
        email_address = aws_account_dict[account]
        if account == admin_account_id:
            LOGGER.info(f"Account {account} cannot become a member of itself")
            continue
        LOGGER.debug(f"Working on SecurityHub on Account {account} in regions %{guardduty_regions}")
        member_session = assume_role(account, os.environ['assume_role'])
        # Process Regions
        for aws_region in guardduty_regions:
            gd_member_client = member_session.client('guardduty', endpoint_url=f"https://guardduty.{aws_region}.amazonaws.com", region_name=aws_region)
            gd_admin_client = admin_session.client('guardduty', endpoint_url=f"https://guardduty.{aws_region}.amazonaws.com", region_name=aws_region)
            admin_members = get_admin_members(admin_session, aws_region)
            LOGGER.info(f"Beginning {aws_region} in Account {account}")
            for gdMember in admin_members:
                gdMember_dict = gdMember.to_dict()
                # If admin member matches org account
                if gdMember_dict['AccountId'] == account:
                    if gdMember_dict['Status'] == 'Enabled':
                        LOGGER.info(f"Account {account} is already associated "
                                    f"with Admin Account {admin_account_id} in "
                                    f"{aws_region} and Enabled")
                        # Handle 'Delete' action
                        if action == 'Delete':
                            try:
                                gd_admin_client.disassociate_members(AccountIds = [ account ])
                            except Exception as ex:
                                continue
                            try:
                                gd_admin_client.delete_members(AccountIds = [ account ])
                            except Exception as ex:
                                continue
                    else:
                        # Members not Associated / Removed
                        LOGGER.info(f"Deleting Member Account {account} from "
                                    f"Admin Account {admin_account_id} in "
                                    f"{aws_region}")
                        try:
                            gd_admin_client.delete_members(AccountIds = [ account ])
                        except Exception as ex:
                            continue
        
            # If admin member does not match org account
            # This means org account is NOT a member of GuardDuty admin
            try:
                if action != 'Delete':
                    admin_detectors_response = gd_admin_client.list_detectors()
                    member_detectors_response = gd_member_client.list_detectors()
                    memberDetectorId = None
                    if len(member_detectors_response['DetectorIds']) > 0:
                        memberDetectorId = member_detectors_response['DetectorIds'][0]
                        LOGGER.info(f"GuardDuty Detector {memberDetectorId} found in {aws_region} for Account: {account}")
                    adminDetectorId = None
                    if (len(admin_detectors_response['DetectorIds'])) > 0:
                        adminDetectorId = admin_detectors_response['DetectorIds'][0]
                    if not (adminDetectorId is None):
                        if not (memberDetectorId is None):
                            admin_members.append(GDMember(account, memberDetectorId, admin_account_id, 'Enabled'))
                        else:
                            dataSource = {
                                "S3Logs": {
                                    "Enable": True
                                }
                            }
                            detector_response = gd_member_client.create_detector(Enable=True, FindingPublishingFrequency='ONE_HOUR',
                                DataSources=dataSource)
                            admin_members.append(GDMember(account, detector_response['DetectorId'], admin_account_id, 'Enabled'))
                        LOGGER.info(f"Create Member for Account: {account} with Email: {email_address} in Region {aws_region}")
                        gd_admin_client.create_members(DetectorId=adminDetectorId, AccountDetails=[{ 'AccountId': account, 'Email': email_address }])
                    else:
                        LOGGER.info(f"No Detector found for Admin Account in {aws_region}")
            except Exception as ex:
                LOGGER.error(f"Error calling create_members(..) for Account {account} in Region {aws_region}")
                LOGGER.error(str(ex))
            # No exception on getting detectors from admin account and member account
            else:
                # GuardDuty already enabled
                # Action is NOT 'Delete'
                if action != 'Delete':
                    LOGGER.info(f"GuardDuty already Enabled in Account "
                            f"{account} in {aws_region}")
                # Action is 'Delete'
                else:
                    LOGGER.info(f"GuardDuty will be disabled in Account "
                            f"{account} in {aws_region}")
                    for gdMember in admin_members:
                        gdMember_dict = gdMember.to_dict()
                        if gdMember_dict['AccountId'] == account:
                            detectorId = gdMember_dict['DetectorId']
                            if detectorId != None:
                                try:
                                    # delete detector in member
                                    gd_member_client.delete_detector(DetectorId=detectorId)
                                    LOGGER.info(f"Deleted DetectorId {detectorId} for Account {account}")
                                except Exception as ex:
                                    LOGGER.info(f"Delete DetectorId {detectorId} for Account {account} Failed !")
                                    LOGGER.error(str(ex))
            # go over each invitation
            try:
                paginator = gd_member_client.get_paginator('list_invitations')
                response_iterator = paginator.paginate()
                for invite in response_iterator:
                    admin_invite = next(item for item in invite['Invitations'] if item['AccountId'] == admin_account_id)
                    LOGGER.info(f"Accepting invitation on Account {account} "
                            f"from Admin Account {admin_account_id} in "
                            f"{aws_region}")
                    gd_member = find_admin_member(admin_session, aws_region, account)
                    gd_member_dict = gd_member.to_dict()
                    gd_member_client.accept_invitation(DetectorId=gd_member_dict['DetectorId'], MasterId=admin_account_id, InvitationId=admin_invite['InvitationId'])
            except Exception as ex:
                LOGGER.warning(f"Account {account} could not accept "
                                f"invitation from Admin Account "
                                f"{admin_account_id} in {aws_region}")
                LOGGER.warning(ex)
            # send successful completion event
            #successful_completion(admin_session, guardduty_regions, partition)