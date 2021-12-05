# -*- coding: utf-8 -*-
import boto3 
import sys
import json
import copy
import ServiceAction as sa
import Convert as cvt
from Scan import AWSIAMInfo, ScanInfo

# reqeust target 구하기
def get_reqeust_target(requestParameters):
    for key, value in requestParameters.items():
        if 'policy' not in key:
            return value

# targets(list or string)에 * 존재 여부 확인
def check_exist_asterisk(targets):
    asterisk_flag = False
    if isinstance(targets, list):
        for action in targets:
            if '*' in action:
                asterisk_flag = True
                break
    else:
        if '*' in targets:
            asterisk_flag = True
    return asterisk_flag

# 정책 document 분석
def check_policy(document, related):
    actionAsterisk_flag = False # * 사용(False == secure)
    resourceAsterisk_flag = False # * 사용(False == secure)
    no_condition_flag = True # 조건 사용 안함(False == secure)
    no_deny_flag = True # Deny 명시 안함(False == secure)
    allowNotAction_flag = False # Effect:Allow NotAction 조합 사용(False == secure)

    if isinstance(document, list):
        statementList = document
    else:
        statementList = document['Statement']
    for statement in statementList:
        effect = statement['Effect']
        if effect == 'Allow':
            if 'Action' in statement.keys():
                actions = statement['Action']
                actionAsterisk_flag = check_exist_asterisk(actions)
                if 'Resource' in statement.keys():
                    resources = statement['Resource']
                    resourceAsterisk_flag = check_exist_asterisk(resources)          
            if 'NotAction' in statement.keys():
                allowNotAction_flag = True
        elif effect == 'Deny':
            no_deny_flag = False
        if 'Condition' in statement.keys():
            no_condition_flag = False
    flagList = [actionAsterisk_flag, resourceAsterisk_flag, no_condition_flag, no_deny_flag, allowNotAction_flag]
    for idx in range(len(flagList)):
        if flagList[idx] == True:
            itemNo = '3.2.'+str(idx+1)
            cvt.update_dict_key_value(related, itemNo, '-')
    return related

def is_entity_extends_permission(policies, addedPolicy, scan):
    perDict = {'Allow':{'Action':[], 'NotAction':[]}, 'Deny':{'Action':[], 'NotAction':[]}}
    for policyKey, policy in policies.items():
        perDict = sa.merge_permission(perDict, policy['Permission'])
    diffPerDict = sa.get_diff_permission(addedPolicy['Permission'], perDict)
    if not sa.is_permission_empty(diffPerDict):
        return True     # 권한 확대 발생
    return False 

def is_user_extends_permission(userArn, policyKey, aws, scan):
    if userArn not in aws.users.keys():
        userName = userArn.split('/')[-1]
        aws.users[userArn] = {'UserName': userName}
        aws.get_user_info(userArn, userName)
    policies = scan.get_user_policies_info(aws, userArn)
    for groupArn in aws.users[userArn]['RelationUG']:
        if groupArn not in aws.groups.keys():
            groupName = groupArn.split('/')[-1]
            aws.groups[groupArn] = {'GroupName': groupName}
            aws.get_group_info(groupArn, groupName)
        policies.update(scan.get_group_policies_info(aws, groupArn))
    addedPolicy = policies.pop(policyKey)
    return is_entity_extends_permission(policies, addedPolicy, scan)

def is_group_extends_permission(groupArn, policyKey, aws, scan):
    if groupArn not in aws.groups.keys():
        groupName = groupArn.split('/')[-1]
        aws.groups[groupArn] = {'GroupName': groupName}
        aws.get_group_info(groupArn, groupName)
    policies = scan.get_group_policies_info(aws, groupArn)
    addedPolicy = policies.pop(policyKey)
    return is_entity_extends_permission(policies, addedPolicy, scan)

def is_role_extends_permission(roleArn, policyKey, aws, scan):
    if roleArn not in aws.roles.keys():
        roleName = roleArn.split('/')[-1]
        aws.roles[roleArn] = {'RoleName': roleName}
        aws.get_role_info(roleArn, roleName)
    policies = scan.get_role_policies_info(aws, roleArn)
    addedPolicy = policies.pop(policyKey)
    return is_entity_extends_permission(policies, addedPolicy, scan)

# check_excessive_organization_permission 변형(Scan.py)
def is_user_excessive_organization_permission(userArn, policyKey, aws, scan):
    # 같은 조직원 파악
    orgList = []
    partners = []
    for org, users in aws.orgTable.items():
        if userArn in users:
            orgList.append(org)
            partners.extend(users)
    partners = list(set(partners) - set([userArn]))
    if len(partners) == 0:
        return False
    # 조직원들의 policies, 통합 permission 정보
    targetPerDict = aws.permissions[policyKey]['Permission']
    orgUserPerDict = {}
    for partnerArn in partners:
        perDict = {'Allow':{'Action':[], 'NotAction':[]}, 'Deny':{'Action':[], 'NotAction':[]}}
        if partnerArn not in aws.users.keys():
            userName = partnerArn.split('/')[-1]
            aws.users[partnerArn] = {'UserName': userName}
            aws.get_user_info(partnerArn, userName)
        # 동일한 IAM Group에 속하는 경우
        if len(set(aws.users[userArn]['RelationUG']) & set(aws.users[partnerArn]['RelationUG'])) == 0:
            return False
        policies = scan.get_user_policies_info(aws, partnerArn)
        # user가 속하는 group의 관리형, 인라인 정책
        for groupArn in aws.users[partnerArn]['RelationUG']:
            policies.update(scan.get_group_policies_info(aws, groupArn))
        for policyKey, policy in policies.items():
            perDict = sa.merge_permission(perDict, policy['Permission'])
        orgUserPerDict[partnerArn] = {'Permission': perDict, 'Policies': policies}
        # 같은 조직원과 비교하여 과도하게(추가로) 가진 권한 파악
        partnerPerDict = orgUserPerDict[partnerArn]['Permission']
        targetPerDict = sa.get_diff_permission(targetPerDict, partnerPerDict)
        if sa.is_permission_empty(targetPerDict):
            break 
    if sa.is_permission_empty(targetPerDict):
        return False    # 과도한 권한 없는 경우
    else:
        return True    # 과도한 권한 발생

def list_entities_arn_for_policy(aws, policyKey, cloudId):
    userBaseArn = 'arn:aws:iam::' + cloudId + ':user/'
    groupBaseArn = 'arn:aws:iam::' + cloudId + ':group/'
    roleBaseArn = 'arn:aws:iam::' + cloudId + ':role/'
    policyUsers = []
    policyGroups = []
    policyRoles = []
    response = aws.iam.list_entities_for_policy(PolicyArn=policyKey)
    while(True):
        for user in response['PolicyUsers']:
            policyUsers.append(userBaseArn + user['UserName'])
        for group in response['PolicyGroups']:
            policyGroups.append(groupBaseArn + group['GroupName'])
        for user in response['PolicyRoles']:
            policyRoles.append(roleBaseArn + user['RoleName'])
        if response['IsTruncated'] == False:
            break
        else:
            response = aws.iam.list_entities_for_policy(PolicyArn=policyKey, Marker=response['Marker'])
    return policyUsers, policyGroups, policyRoles

# IAM USER 권한 확대, 조직도 기반 과도한 권한
def check_user_permission(userArn, policyKey, aws, scan, related):
    if is_user_extends_permission(userArn, policyKey, aws, scan):
        cvt.update_dict_key_value(related, '3.1.1', userArn) 
        if is_user_excessive_organization_permission(userArn, policyKey, aws, scan):
            cvt.update_dict_key_value(related, '3.1.2', userArn) 
    return related

# IAM GROUP 권한 확대
def check_group_permission(groupArn, policyKey, aws, scan, related):
    if is_group_extends_permission(groupArn, policyKey, aws, scan):
        cvt.update_dict_key_value(related, '3.1.1', groupArn)
    return related

# IAM ROLE 권한 확대
def check_role_permission(roleArn, policyKey, aws, scan, related):
    if is_role_extends_permission(roleArn, policyKey, aws, scan):
        cvt.update_dict_key_value(related, '3.1.1', entityName)
    return related

# 특정 AWS 관리형 정책
def check_aws_managed_policy(policyKey, entityArn, related):
    if policyKey == 'arn:aws:iam::aws:policy/AdministratorAccess':
        cvt.update_dict_key_value(related, '3.1.4', entityArn)
    elif policyKey == 'arn:aws:iam::aws:policy/AWSCloudTrail_FullAccess':
        cvt.update_dict_key_value(related, '3.1.5', entityArn)
    return related

# managed policy 수정에 따른 전체 entity 권한 검증
def check_policy_by_version(policyKey, pastVersionId, lastVersionId, aws, scan, related):
    if policyKey not in aws.permissions.keys():
        aws.policies[policyKey] = {}
        aws.permissions[policyKey] = {}
    aws.get_managed_policy_statement(policyKey, pastVersionId)
    pastPerDict = copy.deepcopy(aws.permissions[policyKey]['Permission'])
    aws.get_managed_policy_statement(policyKey, lastVersionId)
    lastPerDict = copy.deepcopy(aws.permissions[policyKey]['Permission'])
    extendedPerDict = sa.get_diff_permission(lastPerDict, pastPerDict)
    if not sa.is_permission_empty(extendedPerDict):
        cvt.update_dict_key_value(related, '3.1.1', policyKey)
        # 확대된 권한만 policyKey의 permission으로 세팅
        aws.permissions[policyKey]['Permission'] = extendedPerDict
        # 해당 policy에 연결된 entity 파악
        policyUsers, policyGroups, policyRoles = list_entities_arn_for_policy(aws, policyKey, cloudId)
        groupsUsers = []
        # 연결된 Entity 마다 권한 확대, 조직도 기반 과도한 권한 확인
        for groupArn in policyGroups:
            # 연결된 group 권한 검증
            related = check_group_permission(groupArn, policyKey, aws, scan, related)
            groupsUsers.extend(aws.groups[groupArn]['RelationGU'])
            for userArn in aws.groups[groupArn]['RelationGU']:
                # 연결된 group에 속한 user 권한 검증
                related = check_user_permission(userArn, policyKey, aws, scan, related)
        for userArn in policyUsers:
            if userArn in groupsUsers:
                continue
            # 연결된 user 권한 검증
            related = check_user_permission(userArn, policyKey, aws, scan, related)
        for roleArn in policyRoles:
            # 연결된 role 권한 검증
            related = check_role_permission(roleArn, policyKey, aws, scan, related)
    return related

if __name__ == '__main__':
    if len(sys.argv) >= 6:
        sys.stderr.write("인자가 충분하지 않음\n")
        exit(0)
    
    scan = ScanInfo()
    aws = AWSIAMInfo()
    aws.create_iam_client(sys.argv[1], sys.argv[2], sys.argv[3])
    event = json.loads(sys.argv[4])
    aws.orgTable = json.loads(sys.argv[5])
    
    eventSource = event['detail']['eventSource']
    if eventSource != "iam.amazonaws.com":
        sys.stderr.write("no iam event!")
        exit(0)
    
    identityArn = event['detail']['userIdentity']['arn']
    eventName = event['detail']['eventName']
    cloudId = event['detail']['recipientAccountId']
    requestParameters = event['detail']['requestParameters']
    responseElements = event['detail']['responseElements']
    
    log = {}
    log['creation'] = event['detail']['eventTime']
    if '/' in identityArn:
        log['identity_name'] = identityArn.split('/')[-1]
    else:
        log['identity_name'] = 'Root'
    log['identiy_arn'] = identityArn
    log['access_ip'] = event['detail']['sourceIPAddress']
    log['region'] = event['detail']['awsRegion']
    log['service'] = 'iam'
    log['api_name'] = eventName
    log['result'] = 1   # SUCCESS
    # log['raw_data'] = event

    log['resource_name'] = []
    log['resource_arn'] = []
    log['reason_category'] = [] 
    log['reason_detail'] = []
    for key, value in requestParameters.items():
        log['resource_name'].append(value)
    

    related = {}

    try:
        if 'CreatePolicy' == eventName:     # CreatePolicy
            policyKey = responseElements['policy']['arn']
            policyName = responseElements['policy']['policyName']
            log['resource_name'] = [policyName]
            log['resource_arn'] = [policyKey]
            # IAM POLICY 검증
            policyDoc = requestParameters['policyDocument']
            if not isinstance(policyDoc, dict):
                policyDoc = json.loads(policyDoc)
            related = check_policy(policyDoc, related)
        elif 'CreatePolicyVersion' == eventName:     # CreatePolicyVersion
            policyKey = requestParameters['policyArn']
            policyName = policyKey.split('/')[-1]
            log['resource_name'] = [policyName]
            log['resource_arn'] = [policyKey]
            # IAM POLICY 검증
            lastPolicyDoc = requestParameters['policyDocument']
            if not isinstance(lastPolicyDoc, dict):
                lastPolicyDoc = json.loads(lastPolicyDoc)
            related = check_policy(lastPolicyDoc, related)
            if responseElements['policyVersion']['isDefaultVersion'] == True:
                # 이전 버전과 비교하여 권한 검증
                pastVersionId = sys.argv[6]
                lastVersionId = responseElements['policyVersion']['versionId']
                related = check_policy_by_version(policyKey, pastVersionId, lastVersionId, aws, scan, related)
        elif 'SetDefaultPolicyVersion' == eventName:    # SetDefaultPolicyVersion
            policyKey = requestParameters['policyArn']
            policyName = policyKey.split('/')[-1]
            log['resource_name'] = [policyName]
            log['resource_arn'] = [policyKey]
            lastVersionId = requestParameters['versionId']
            # IAM POLICY 검증
            if policyKey not in aws.policies.keys():
                aws.policies[policyKey] = {}
                aws.permissions[policyKey] = {}
            aws.get_managed_policy_statement(policyKey)
            related = check_policy(aws.permissions[policyKey]['Document'], related)
            # 이전 버전과 비교하여 권한 검증
            pastVersionId = sys.argv[6]
            related = check_policy_by_version(policyKey, pastVersionId, lastVersionId, aws, scan, related)
        elif 'Put' in eventName and 'Policy' in eventName:  # PutUserPolicy, PutGroupPolicy, PutRolePolicy
            policyName = requestParameters['policyName']
            entityName = get_reqeust_target(requestParameters)
            # IAM POLICY 검증
            policyDoc = requestParameters['policyDocument']
            if not isinstance(policyDoc, dict):
                policyDoc = json.loads(policyDoc)
            related = check_policy(policyDoc, related)
            if 'PutUserPolicy' == eventName:
                # Inline 정책 사용
                cvt.update_dict_key_value(related, '3.1.3', 'USER')
                policyKey = 'USER//' + entityName + '//' + policyName
                userArn = 'arn:aws:iam::' + cloudId + ':user/' + entityName
                log['resource_name'] = [policyName, entityName]
                log['resource_arn'] = [policyName, userArn]
                # user 권한 검증
                related = check_user_permission(userArn, policyKey, aws, scan, related)
            elif 'PutGroupPolicy' == eventName:
                # Inline 정책 사용
                cvt.update_dict_key_value(related, '3.1.3', 'GROUP')
                policyKey = 'GROUP//' + entityName + '//' + policyName
                groupArn = 'arn:aws:iam::' + cloudId + ':group/' + entityName
                log['resource_name'] = [policyName, entityName]
                log['resource_arn'] = [policyName, groupArn]
                # group 권한 검증
                related = check_group_permission(groupArn, policyKey, aws, scan, related)
                # group에 속하는 user 권한 검증
                for userArn in aws.groups[groupArn]['RelationGU']:
                    related = check_user_permission(userArn, policyKey, aws, scan, related)
            elif 'PutRolePolicy' == eventName:
                # Inline 정책 사용
                cvt.update_dict_key_value(related, '3.1.3', 'ROLE')
                policyKey = 'ROLE//' + entityName + '//' + policyName
                roleArn = 'arn:aws:iam::' + cloudId + ':role/' + entityName
                log['resource_name'] = [policyName, entityName]
                log['resource_arn'] = [policyName, roleArn]
                # role 권한 검증
                related = check_role_permission(roleArn, policyKey, aws, scan, related)
        elif 'Attach' in eventName and 'Policy' in eventName:  # AttachUserPolicy, AttachGroupPolicy, AttachRolePolicy
            entityName = get_reqeust_target(requestParameters)
            policyKey = requestParameters['policyArn']
            policyName = policyKey.split('/')[-1]
            # IAM POLICY 검증
            if policyKey not in aws.policies.keys():
                aws.policies[policyKey] = {}
                aws.permissions[policyKey] = {}
            aws.get_managed_policy_statement(policyKey)
            related = check_policy(aws.permissions[policyKey]['Document'], related)
            if 'AttachUserPolicy' == eventName:
                userArn = 'arn:aws:iam::' + cloudId + ':user/' + entityName
                log['resource_name'] = [policyName, entityName]
                log['resource_arn'] = [policyKey, userArn]
                # 특정 AWS 관리형 정책 검증
                related = check_aws_managed_policy(policyKey, userArn, related)
                # user 권한 검증
                related = check_user_permission(userArn, policyKey, aws, scan, related)  
            elif 'AttachGroupPolicy' == eventName:
                groupArn = 'arn:aws:iam::' + cloudId + ':group/' + entityName
                log['resource_name'] = [policyName, entityName]
                log['resource_arn'] = [policyKey, groupArn]
                # 특정 AWS 관리형 정책 검증
                related = check_aws_managed_policy(policyKey, groupArn, related)
                # group 권한 검증
                related = check_group_permission(groupArn, policyKey, aws, scan, related)
                # group에 속한 user 권한 검증
                for userArn in aws.groups[groupArn]['RelationGU']:
                    related = check_user_permission(userArn, policyKey, aws, scan, related)
            elif 'AttachRolePolicy' == eventName:
                roleArn = 'arn:aws:iam::' + cloudId + ':role/' + entityName
                log['resource_name'] = [policyName, entityName]
                log['resource_arn'] = [policyKey, roleArn]
                # 특정 AWS 관리형 정책 검증
                related = check_aws_managed_policy(policyKey, roleArn, related)
                related = check_role_permission(roleArn, policyKey, aws, scan, related)
        elif 'AddUserToGroup' == eventName:
            groupName = requestParameters['groupName']
            userName = requestParameters['userName']
            groupArn = 'arn:aws:iam::' + cloudId + ':group/' + groupName
            userArn = 'arn:aws:iam::' + cloudId + ':user/' + userName
            log['resource_name'] = [userName, groupName]
            log['resource_arn'] = [userArn, groupArn]
            if userArn not in aws.users.keys():
                aws.users[userArn] = {'UserName': userName}
                aws.get_user_info(userArn, userName)
            policies = scan.get_user_policies_info(aws, userArn)
            # 추가된 그룹 제외한 사용자의 permission(perDict)
            addedGroupArn = groupArn
            for groupArn in aws.users[userArn]['RelationUG']:
                if groupArn == addedGroupArn:
                    continue
                if groupArn not in aws.groups.keys():
                    groupName = groupArn.split('/')[-1]
                    aws.groups[groupArn] = {'GroupName': groupName}
                    aws.get_group_info(groupArn, groupName)
                policies.update(scan.get_group_policies_info(aws, groupArn))
            perDict = {'Allow':{'Action':[], 'NotAction':[]}, 'Deny':{'Action':[], 'NotAction':[]}}
            for policyKey, policy in policies.items():
                perDict = sa.merge_permission(perDict, policy['Permission'])
            # 추가된 그룹의 permission(addedPerDict)
            if addedGroupArn not in aws.groups.keys():
                groupName = addedGroupArn.split('/')[-1]
                aws.groups[addedGroupArn] = {'GroupName': groupName}
                aws.get_group_info(addedGroupArn, groupName)
            policies = scan.get_group_policies_info(aws, addedGroupArn)
            addedPerDict = {'Allow':{'Action':[], 'NotAction':[]}, 'Deny':{'Action':[], 'NotAction':[]}}
            for policyKey, policy in policies.items():
                addedPerDict = sa.merge_permission(addedPerDict, policy['Permission'])
            diffPerDict = sa.get_diff_permission(addedPerDict, perDict)
            if not sa.is_permission_empty(diffPerDict):
                cvt.update_dict_key_value(related, '3.1.1', userArn)
                policyKey = 'diff'
                aws.permissions[policyKey] = {}
                aws.permissions[policyKey]['Permission'] = diffPerDict
                if is_user_excessive_organization_permission(userArn, policyKey, aws, scan):
                    cvt.update_dict_key_value(related, '3.1.2', userArn)
    except:
        pass
    finally:
        result = cvt.convert_monitor_log(log, related)
        jsonResult = json.dumps(result)
        print(jsonResult, end="")
