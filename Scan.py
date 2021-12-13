# -*- coding: utf-8 -*-
import boto3
import botocore
import datetime
import json
import sys
import copy
import Convert as cvt
import ServiceAction as sa

class AWSIAMInfo:
    def __init__(self):
        self.iam = None
        self.users = {}
        self.groups = {}
        self.roles = {}
        self.policies = {}
        self.permissions = {}

    def create_iam_client(self, accessKey, secretKey, region, fileName):
        try:  
            session = boto3.Session(
                aws_access_key_id=accessKey, 
                aws_secret_access_key=secretKey, 
                region_name=region)
            self.iam = session.client('iam')
            # connection 확인
            response = self.iam.list_account_aliases()
        except:
            sys.stderr.write("부적절한 access key, secret key 또는 IAM 서비스 연결 실패 오류\n")
            f = open('./src/scripts/' + sys.argv[6] + '.json', 'w')
            f.write('error')
            f.close()
            exit(0)
    
    def get_iam_resource(self):
        # IAM Users
        response = self.iam.list_users()
        while(True):
            for user in response['Users']:
                self.users[user['Arn']] = user
                self.get_user_info(user['Arn'], user['UserName'])
            if response['IsTruncated'] == False:
                break
            else:
                response = self.iam.list_users(Marker=response['Marker'])
        # IAM Groups
        response = self.iam.list_groups()
        while(True):
            for group in response['Groups']:
                self.groups[group['Arn']] = group
                self.get_group_info(group['Arn'], group['GroupName'])
            if response['IsTruncated'] == False:
                break
            else:
                response = self.iam.list_groups(Marker=response['Marker'])
        # IAM Roles
        response = self.iam.list_roles()
        while(True):
            for role in response['Roles']:
                self.roles[role['Arn']] = role
                self.get_role_info(role['Arn'], role['RoleName'])
            if response['IsTruncated'] == False:
                break
            else:
                response = self.iam.list_roles(Marker=response['Marker'])
        # IAM Policies
        response = self.iam.list_policies(Scope='Local', OnlyAttached=False)
        while(True):
            for policy in response['Policies']:
                self.policies[policy['Arn']] = policy
            if response['IsTruncated'] == False:
                break
            else:
                response = self.iam.list_policies(Scope='Local', OnlyAttached=False, Marker=response['Marker'])

    def get_user_info(self, userArn, userName):
        # user-group relation
        relationUG = []
        response2 = self.iam.list_groups_for_user(UserName=userName)
        while(True):
            for group in response2['Groups']:
                relationUG.append(group['Arn'])
            if response2['IsTruncated'] == False:
                break
            else:
                response2 = self.iam.list_groups_for_user(UserName=userName, Marker=response2['Marker'])
        self.users[userArn]['RelationUG'] = relationUG
        # user-managed_policy relation
        relationUMP = []
        response3 = self.iam.list_attached_user_policies(UserName=userName)
        while(True):
            for policy in response3['AttachedPolicies']:
                relationUMP.append(policy['PolicyArn'])
            if response3['IsTruncated'] == False:
                break
            else:
                response3 = self.iam.list_attached_user_policies(UserName=userName, Marker=response3['Marker'])
        self.users[userArn]['RelationUMP'] = relationUMP
        # user-inline_policy relation
        relationUIP = []
        response4 = self.iam.list_user_policies(UserName=userName)
        while(True):
            for policy in response4['PolicyNames']:
                relationUIP.append(policy)
            if response4['IsTruncated'] == False:
                break
            else:
                response4 = self.iam.list_user_policies(UserName=userName, Marker=response4['Marker'])
        self.users[userArn]['RelationUIP'] = relationUIP
    
    def get_group_info(self, groupArn, groupName):
        # group-managed_policy relation
        relationGMP = []
        response2 = self.iam.list_attached_group_policies(GroupName=groupName)
        while(True):
            for policy in response2['AttachedPolicies']:
                relationGMP.append(policy['PolicyArn'])
            if response2['IsTruncated'] == False:
                break
            else:
                response2 = self.iam.list_attached_group_policies(GroupName=groupName, Marker=response2['Marker'])
        self.groups[groupArn]['RelationGMP'] = relationGMP
        # group-inline_policy relation
        relationGIP = []
        response3 = self.iam.list_group_policies(GroupName=groupName)
        while(True):
            for policy in response3['PolicyNames']:
                relationGIP.append(policy)
            if response3['IsTruncated'] == False:
                break
            else:
                response3 = self.iam.list_group_policies(GroupName=groupName, Marker=response3['Marker'])
        self.groups[groupArn]['RelationGIP'] = relationGIP
        # group-user relation
        relationGU = []
        response4 = self.iam.get_group(GroupName=groupName)
        while(True):
            for user in response4['Users']:
                relationGU.append(user['Arn'])
            if response4['IsTruncated'] == False:
                break
            else:
                response4 = self.iam.get_group(GroupName=groupName, Marker=response4['Marker'])
        self.groups[groupArn]['RelationGU'] = relationGU
    
    def get_role_info(self, roleArn, roleName):
        # role-managed_policy relation
        relationRMP = []
        response2 = self.iam.list_attached_role_policies(RoleName=roleName)
        while(True):
            for policy in response2['AttachedPolicies']:
                relationRMP.append(policy['PolicyArn'])
            if response2['IsTruncated'] == False:
                break
            else:
                response2 = self.iam.list_attached_role_policies(RoleName=roleName, Marker=response2['Marker'])
        self.roles[roleArn]['RelationRMP'] = relationRMP
        # role-inline_policy relation
        relationRIP = []
        response3 = self.iam.list_role_policies(RoleName=roleName)
        while(True):
            for policy in response3['PolicyNames']:
                relationRIP.append(policy)
            if response3['IsTruncated'] == False:
                break
            else:
                response3 = self.iam.list_role_policies(RoleName=roleName, Marker=response3['Marker'])
        self.roles[roleArn]['RelationRIP'] = relationRIP
    
    def get_policies_permission(self):
        for policyArn in self.policies.keys():
            self.permissions[policyArn] = {}
            self.get_managed_policy_statement(policyArn)
        for userArn, info in self.users.items():
            entityType = 'USER'
            entityName = info['UserName']
            for inlinePolicyName in info['RelationUIP']:
                key = entityType + '//' + entityName + '//' + inlinePolicyName
                self.permissions[key] = {}
                self.get_inline_policy_statement(key)
        for groupArn, info in self.groups.items():
            entityType = 'GROUP'
            entityName = info['GroupName']
            for inlinePolicyName in info['RelationGIP']:
                key = entityType + '//' + entityName + '//' + inlinePolicyName
                self.permissions[key] = {}
                self.get_inline_policy_statement(key)
        for roleArn, info in self.roles.items():
            entityType = 'ROLE'
            entityName = info['RoleName']
            for inlinePolicyName in info['RelationRIP']:
                key = entityType + '//' + entityName + '//' + inlinePolicyName
                self.permissions[key] = {}
                self.get_inline_policy_statement(key)

    def get_managed_policy_statement(self, policyArn, policyVersion=None):
        if policyVersion == None:
            response = self.iam.get_policy(PolicyArn=policyArn)
            policyVersion = response['Policy']['DefaultVersionId']
        policy = self.iam.get_policy_version(PolicyArn=policyArn, VersionId=policyVersion)
        self.permissions[policyArn]['Document'] = policy['PolicyVersion']['Document']
        self.permissions[policyArn]['Permission'] = sa.get_permission_from_policy_statements(self.permissions[policyArn]['Document']['Statement'])
          
    def get_inline_policy_statement(self, key):
        argv = key.split('//')
        entityType = argv[0]
        entityName = argv[1]
        policyName = argv[2]
        if entityType == 'USER':
            policy = self.iam.get_user_policy(UserName=entityName, PolicyName=policyName)
        elif entityType == 'GROUP':
            policy = self.iam.get_group_policy(GroupName=entityName, PolicyName=policyName)
        elif entityType == 'ROLE':
            policy = self.iam.get_role_policy(RoleName=entityName, PolicyName=policyName)
        self.permissions[key]['Document'] = policy['PolicyDocument']
        self.permissions[key]['Permission'] = sa.get_permission_from_policy_statements(self.permissions[key]['Document']['Statement'])

    def get_account_password_policy(self):
        try:
            self.pwPolicy = self.iam.get_account_password_policy()['PasswordPolicy']
        except self.iam.exceptions.NoSuchEntityException:
            self.pwPolicy = None
    
    def get_credential_report(self):
        self.credentailReport = {}
        while(True):
            response = self.iam.generate_credential_report()
            if response['State'] == 'COMPLETE':
                break
        response = self.iam.get_credential_report()
        contents = str(response['Content'], 'utf-8')
        contents = contents.split('\n')
        keys = contents[0].split(',')
        for idx in range(1, len(contents)):
            values = contents[idx].split(',')
            report = dict(zip(keys, values))
            self.credentailReport[report['arn']] = report
    
    def list_server_certificates(self):
        self.serverCerts = []
        response = self.iam.list_server_certificates()
        while(True):
            self.serverCerts.extend(response['ServerCertificateMetadataList'])
            if response['IsTruncated'] == False:
                break
            else:
                response = self.iam.list_server_certificates(Marker=response['Marker'])
    
    def get_service_last_accessed_details(self, arn):
        serviceLastAccessList = []
        jobResponse = self.iam.generate_service_last_accessed_details(Arn=arn)
        while(True):
            response = self.iam.get_service_last_accessed_details(JobId=jobResponse['JobId'])
            if response['JobStatus'] == 'COMPLETED':
                break
        while(True):
            serviceLastAccessList.extend(response['ServicesLastAccessed'])
            if response['IsTruncated'] == False:
                break
            else:
                response = self.iam.get_service_last_accessed_details(JobId=jobResponse['JobId'], Marker=response['Marker'])
        return serviceLastAccessList
    
    # 조직을 가진 userArn 리스트
    def get_organization_users(self):
        orgUsers = []
        for org, userList in self.orgTable.items():
            orgUsers.extend(userList)
        self.orgUsers = list(set(orgUsers))

class ScanInfo:
    def __init__(self):
        self.infoDict = {}
        self.criteria30Day = cvt.set_criteria_time(30)
        self.criteria7Day = cvt.set_criteria_time(7, 'after')
        self.criteria90Day = cvt.set_criteria_time(90)

    def check_root_used_30Days(self, report):
        reason = []
        lastUsed_list = [report['password_last_used'], report['access_key_1_last_used_date'], report['access_key_2_last_used_date']]
        for i in range(len(lastUsed_list)):
            lastUsed = lastUsed_list[i]
            if(lastUsed != 'N/A' and lastUsed >= self.criteria30Day):
                if i == 0:
                    key = "password"
                else:
                    key = 'access_key_'+str(i)
                timeGap = cvt.cal_time_gap(lastUsed)
                content = {key : timeGap.days}
                reason.append(content)
        cvt.add_dict_key_value(self.infoDict, '1.1.1', reason, report['arn'])
    
    # 1.1.2(Root 계정은 1개 이상 active면 안됨), 1.1.5(일반 계정은 2개 이상 active면 안됨)
    def check_access_key_active(self, report):
        reason = []
        for i in range(1, 3):
            key = 'access_key_'+str(i)+'_active'
            if report[key] == 'true':
                key = 'access_key_'+str(i)
                content = {key : "활성화"}  
                reason.append(content)
        if report['user'] != '<root_account>': 
            if len(reason) < 2:
                reason = []
            cvt.add_dict_key_value(self.infoDict, '1.1.5', reason, report['arn'])
        else:
            cvt.add_dict_key_value(self.infoDict, '1.1.2', reason, report['arn'])

    # 1.1.3(Root 계정은 30일 이내에 교체 필요), 1.1.4(일반 계정은 90일 이내 교체 필요)
    def check_active_access_key_rotate(self, report):
        reason = []
        if report['user'] != '<root_account>':
            criteriaTime = self.criteria90Day
        else:
            criteriaTime = self.criteria30Day
        for i in range(1, 3):
            key = 'access_key_'+str(i)+'_last_rotated'
            lastRotated = report[key]
            if (lastRotated != 'N/A' and lastRotated < criteriaTime):
                key = 'access_key_'+str(i)
                timeGap = cvt.cal_time_gap(lastRotated)
                content = {key : timeGap.days}
                reason.append(content)
        if report['user'] != '<root_account>':
            cvt.add_dict_key_value(self.infoDict, '1.1.4', reason, report['arn'])
        else:
            cvt.add_dict_key_value(self.infoDict, '1.1.3', reason, report['arn'])
    
    def check_2_ssh_pub_active(self, sshPubKeys, userArn):
        reason = []
        if len(sshPubKeys) >= 2:
            for i in range(len(sshPubKeys)):
                if sshPubKeys[i]['Status'] == 'Active':
                    key = sshPubKeys[i]['SSHPublicKeyId']
                    content = {key : "활성화"}  
                    reason.append(content)
            if len(reason) < 2:
                reason = []
        cvt.add_dict_key_value(self.infoDict, '1.1.6', reason, userArn)
    
    def check_ssh_pub_upload_90Days(self, sshPubKeys, userArn):
        reason = []
        if len(sshPubKeys) != 0:
            for i in range(len(sshPubKeys)):
                uploadDay = sshPubKeys[i]['UploadDate'].isoformat()
                if uploadDay <= self.criteria90Day:
                    key = sshPubKeys[i]['SSHPublicKeyId']
                    timeGap = cvt.cal_time_gap(uploadDay)
                    content = {key : timeGap.days}
                    reason.append(content)
        cvt.add_dict_key_value(self.infoDict, '1.1.7', reason, userArn)

    def check_mfa_active(self, report):
        reason = []
        if report['mfa_active'] == 'false':
            content = {"MFA" : "비활성화"}  
            reason.append(content)
        if report['user'] != '<root_account>':
            cvt.add_dict_key_value(self.infoDict, '1.2.3', reason, report['arn'])
        else:
            cvt.add_dict_key_value(self.infoDict, '1.2.1', reason, report['arn'])

    def check_pwPolicy_usage(self, pwPolicy):
        if pwPolicy == None:
            cvt.add_dict_key_value(self.infoDict, '1.3.1', [{'pwPolicyUse': 0}])

    def check_strong_pwPolicy_used(self, pwPolicy):
        if pwPolicy != None:
            reason = []
            requires = {'특수문자':'RequireSymbols', '숫자':'RequireNumbers', '대문자':'RequireUppercaseCharacters', '소문자':'RequireLowercaseCharacters'}
            i = 0
            for k,v in requires.items():
                if pwPolicy[v] != True:
                    content = {i: k}
                    reason.append(content)
                    i += 1 
        else:
            reason = [{0:'특수문자', 1:'숫자', 2:'대문자', 3:'소문자'}]
        cvt.add_dict_key_value(self.infoDict, '1.3.2', reason)

    def check_long_pw(self, pwPolicy):
        if pwPolicy != None:
            reason = []
            if pwPolicy['MinimumPasswordLength'] < 14:
                content = {"minPWLen": pwPolicy['MinimumPasswordLength']}
                reason.append(content)
        else:
            reason = [{"minPWLen": 8}]
        cvt.add_dict_key_value(self.infoDict, '1.3.3', reason)

    def check_pw_reused(self, pwPolicy):
        if pwPolicy != None:
            reason = []
            key = 'PasswordReusePrevention'
            if key in pwPolicy.keys():
                if pwPolicy[key] < 5:
                    content = {"있습니다": str(pwPolicy[key])+'개로 '}
                    reason.append(content)
            else:
                content = {"있지 않습니다": ' '}
                reason.append(content)
        else:
            reason = [{"있지 않습니다": ' '}]
        cvt.add_dict_key_value(self.infoDict, '1.3.4', reason)

    def check_pw_expiration_period_90Days(self, pwPolicy):
        if pwPolicy != None:
            reason = []
            key = 'MaxPasswordAge'
            if key in pwPolicy.keys():
                if pwPolicy[key] > 90:
                    content = {"있습니다": str(pwPolicy[key])+'일로 '}
                    reason.append(content)
            else:
                content = {"있지 않습니다": ' '}
                reason.append(content)
        else:
            reason = [{"있지 않습니다": ' '}]
        cvt.add_dict_key_value(self.infoDict, '1.3.5', reason)

    def check_pw_expriy_7Days(self, report):
        reason = []
        nextRotate = report['password_next_rotation']
        if (nextRotate != 'N/A' and nextRotate <= self.criteria7Day):  
            timeGap = cvt.cal_time_gap(nextRotate, 'after')
            if timeGap.days >= 0:
                content = {"남았습니다": timeGap.days}
            else:
                content = {"지났습니다": -(timeGap.days+1)}
            reason.append(content)
        cvt.add_dict_key_value(self.infoDict, '1.3.6', reason, report['arn'])
    
    def check_cert_expriy_7Days(self, cert):
        reason = []
        expiryTime = cert['Expiration'].isoformat()
        if expiryTime < self.criteria7Day:
            timeGap = cvt.cal_time_gap(expiryTime, 'after')
            if timeGap.days >= 0:
                content = {"남았습니다": timeGap.days}
            else:
                content = {"지났습니다": -(timeGap.days+1)}
            reason.append(content)
        cvt.add_dict_key_value(self.infoDict, '1.4.1', reason, cert['Arn'])
    
    def check_cert_heartbleed(self, cert):
        reason = []
        criteriaTime = datetime.datetime(2014, 4, 1, 0, 0, 0, 0).isoformat()
        UploadTime = cert['UploadDate'].isoformat()
        if UploadTime < criteriaTime:
            content = {"uploadTime": cvt.set_KST_timezone(UploadTime)}
            reason.append(content)
        cvt.add_dict_key_value(self.infoDict, '1.4.2', reason, cert['Arn'])

    def get_accessed_history_90Days(self, history):
        accessedHistory90Days = []
        # service, action 90일 이내 접근한 것만 추출
        for service in history:
            # 90일 이내 service 접근
            content = {'ServiceNamespace':service['ServiceNamespace'], 'ActionName':[]}
            if 'TrackedActionsLastAccessed' in service.keys():
                for action in service['TrackedActionsLastAccessed']:
                    if 'LastAccessedTime' in action.keys():
                        action_last_access = action['LastAccessedTime']
                        if action_last_access >= self.criteria90Day:
                            content['ActionName'].append(action['ActionName'])
            accessedHistory90Days.append(content)
        return accessedHistory90Days
    
    # 해당 IAM entity의 90일 이내 action 기록을 기반으로 Service, Action statement 생성
    def make_action_statement(self, action, accessedHistory, support, notSupport):
        actionStatement = []
        if action == '*':
            for service in accessedHistory:
                serviceName = service['ServiceNamespace']
                if len(service['ActionName']) == len(sa.ServiceActionDict[serviceName]):
                    new = serviceName + ":*"
                    actionStatement.append(new)
                    continue
                for actionName in service['ActionName']:
                    new = serviceName+":"+actionName
                    actionStatement.append(new)
            for service in notSupport:
                new = service+":*"
                actionStatement.append(new)
            if len(actionStatement) == (len(support) + len(notSupport)):
                actionStatement = [action] 
        else:
            serviceAction = action.split(":")
            serviceName = serviceAction[0]
            actionName = serviceAction[1]
            if serviceName in notSupport:
                actionStatement.append(action)
            else:
                for service in accessedHistory:
                    if serviceName == service['ServiceNamespace']:
                        perList = sa.convert_service_action(action)
                        if actionName == "*":
                            for historyActionName in service['ActionName']:
                                new = serviceName+":"+historyActionName
                                actionStatement.append(new)
                        else:
                            for per in perList:
                                perAction = per.split(":")[-1]
                                for historyActionName in service['ActionName']:
                                    if perAction == historyActionName:
                                        new = serviceName+":"+historyActionName
                                        actionStatement.append(new)
                        if set(actionStatement) == set(perList):
                            actionStatement = [action]
                        break
        return actionStatement

    # 해당 IAM entity의 90일 이내 사용 기록을 기반으로 최소 권한 document 생성
    def make_new_document_with_accessed_history(self, document, accessedHistory):
        supportAWSService = ['s3', 'ec2', 'lambda', 'sns', 'cloudfront', 'ebs', 'iam', 'sqs', 'elasticbeanstalk', 'rds']
        notSupportAWSService = list(sa.ServiceActionDict.keys())
        for service in supportAWSService:
            notSupportAWSService.remove(service)
        newDocument = {}
        statementList = document['Document']['Statement']
        content = []
        for statement in statementList:
            newStatement = copy.deepcopy(statement)
            if newStatement['Effect'] != 'Deny':
                if 'Action' in newStatement.keys():
                    newAction = []
                    if isinstance(newStatement['Action'], list):
                        for action in newStatement['Action']:
                            newAction.extend(self.make_action_statement(action, accessedHistory, supportAWSService, notSupportAWSService))
                    else:
                        action = newStatement['Action']
                        newAction.extend(self.make_action_statement(action, accessedHistory, supportAWSService, notSupportAWSService))
                    newStatement['Action'] = newAction
                    if len(newAction) == 0:
                        newStatement = {}
                content.append(newStatement)
        content = list(filter(None, content))   # {}(=None) 제거
        if len(content) > 0:
            newDocument['Version'] = document['Document']['Version']
            newDocument['Statement'] = content
            return newDocument
        return None

    # group의 관리형, 인라인 정책 가져오기
    def get_group_policies_info(self, aws, arn):
        info = aws.groups[arn]
        policies = {}
        # 관리형 정책
        for policyArn in info['RelationGMP']:
            if policyArn not in aws.permissions.keys():
                aws.permissions[policyArn] = {}
                aws.get_managed_policy_statement(policyArn)
            statement = aws.permissions[policyArn]['Document']
            permission = aws.permissions[policyArn]['Permission']
            policies[policyArn] = {'Document': statement, 'Permission': permission, 'EntityType': 'GROUP', 'EntityName': info['GroupName'], 'PolicyType': '관리형'}
        # 인라인 정책
        baseKey = 'GROUP//'+ info['GroupName'] + '//'
        for policyName in info['RelationGIP']:
            key = baseKey + policyName
            if key not in aws.permissions.keys():
                aws.permissions[key] = {}
                aws.get_inline_policy_statement(key)
            statement = aws.permissions[key]['Document']
            permission = aws.permissions[key]['Permission']
            policies[key] = {'Document': statement, 'Permission': permission, 'EntityType': 'GROUP', 'EntityName': info['GroupName'], 'PolicyType': '인라인'}
        return policies

    # user의 관리형, 인라인 정책 가져오기
    def get_user_policies_info(self, aws, arn):
        info = aws.users[arn]
        policies = {}
        # 관리형 정책
        for policyArn in info['RelationUMP']:
            if policyArn not in aws.permissions.keys():
                aws.permissions[policyArn] = {}
                aws.get_managed_policy_statement(policyArn)
            statement = aws.permissions[policyArn]['Document']
            permission = aws.permissions[policyArn]['Permission']
            policies[policyArn] = {'Document': statement, 'Permission': permission, 'EntityType': 'USER', 'EntityName': info['UserName'], 'PolicyType': '관리형'}
        # 인라인 정책
        baseKey = 'USER//'+ info['UserName'] + '//'
        for policyName in info['RelationUIP']:
            key = baseKey + policyName
            if key not in aws.permissions.keys():
                aws.permissions[key] = {}
                aws.get_inline_policy_statement(key)
            statement = aws.permissions[key]['Document']
            permission = aws.permissions[key]['Permission']
            policies[key] = {'Document': statement, 'Permission': permission, 'EntityType': 'USER', 'EntityName': info['UserName'], 'PolicyType': '인라인'}
        return policies

    # role의 관리형, 인라인 정책 가져오기
    def get_role_policies_info(self, aws, arn):
        info = aws.roles[arn]
        policies = {}
        # 관리형 정책
        for policyArn in info['RelationRMP']:
            if policyArn not in aws.permissions.keys():
                aws.permissions[policyArn] = {}
                aws.get_managed_policy_statement(policyArn)
            statement = aws.permissions[policyArn]['Document']
            permission = aws.permissions[policyArn]['Permission']
            policies[policyArn] = {'Document': statement, 'Permission': permission, 'EntityType': 'ROLE', 'EntityName': info['RoleName'], 'PolicyType': '관리형'}
        # 인라인 정책
        baseKey = 'ROLE//'+ info['RoleName'] + '//'
        for policyName in info['RelationRIP']:
            key = baseKey + policyName
            if key not in aws.permissions.keys():
                aws.permissions[key] = {}
                aws.get_inline_policy_statement(key)
            statement = aws.permissions[key]['Document']
            permission = aws.permissions[key]['Permission']
            policies[key] = {'Document': statement, 'Permission': permission, 'EntityType': 'ROLE', 'EntityName': info['RoleName'], 'PolicyType': '인라인'}
        return policies

    def check_user_has_excessive_permission(self, aws, arn, accessedHistory):
        policies = self.get_user_policies_info(aws, arn)
        # user가 속하는 group의 관리형, 인라인 정책
        for groupArn in info['RelationUG']:
            policies.update(self.get_group_policies_info(aws, groupArn))
        if bool(aws.history):
            # accessed history와 비교하여 과도한 권한 추출
            for policyKey, document in policies.items():
                newDocument = self.make_new_document_with_accessed_history(document, accessedHistory)
                if newDocument != None:
                    policies[policyKey]['NewDocument'] = newDocument
            cvt.add_dict_key_value(self.infoDict, '2.1.1', policies, arn)

    def check_group_has_excessive_permission(self, aws, arn, accessedHistory):
        policies = self.get_group_policies_info(aws, arn)
        if bool(aws.history):
            # accessed history와 비교하여 과도한 권한 추출
            for policyKey, document in policies.items():
                newDocument = self.make_new_document_with_accessed_history(document, accessedHistory)
                if newDocument != None:
                    policies[policyKey]['NewDocument'] = newDocument
            cvt.add_dict_key_value(self.infoDict, '2.1.2', policies, arn)

    def check_role_has_excessive_permission(self, aws, arn, accessedHistory):
        policies = self.get_role_policies_info(aws, arn)
        if bool(aws.history):
            # accessed history와 비교하여 과도한 권한 추출
            for policyKey, document in policies.items():
                newDocument = self.make_new_document_with_accessed_history(document, accessedHistory)
                if newDocument != None:
                    policies[policyKey]['NewDocument'] = newDocument
            cvt.add_dict_key_value(self.infoDict, '2.1.3', policies, arn)

    def check_user_used_90Days(self, report):
        reason = []
        lastUsed_list = [report['password_last_used'], report['access_key_1_last_used_date'], report['access_key_2_last_used_date']]
        last = None
        for i in range(len(lastUsed_list)):
            lastUsed = lastUsed_list[i]
            if lastUsed != 'N/A' and lastUsed != 'no_information':
                if lastUsed >= self.criteria90Day:
                    return None
                if last == None or lastUsed >= last :
                    last = lastUsed
        if last == None:
            content = {cvt.set_KST_timezone(report['user_creation_time']): "활동한 기록이 없습니다"}
            reason.append(content)
        else:
            content = {cvt.set_KST_timezone(report['user_creation_time']): cvt.set_KST_timezone(last)+"에 활동했습니다"}
            reason.append(content)
        cvt.add_dict_key_value(self.infoDict, '2.2.1', reason, report['arn'])

    def check_role_used_90Days(self, report):
        reason = []
        if bool(report['Role']['RoleLastUsed']): 
            last_used = report['Role']['RoleLastUsed']['LastUsedDate'].isoformat(timespec="seconds")
            if last_used < self.criteria90Day:
                content = {cvt.set_KST_timezone(report['Role']['CreateDate'].isoformat(timespec="seconds")): cvt.set_KST_timezone(last_used)+"에 활동했습니다"}
                reason.append(content)
        else:
            content = {cvt.set_KST_timezone(report['Role']['CreateDate'].isoformat(timespec="seconds")): "활동한 기록이 없습니다"}
            reason.append(content)
        cvt.add_dict_key_value(self.infoDict, '2.2.3', reason, report['Role']['Arn'])

    def check_entity_used_90Days(self, serviceLastAccessList, info, entityType):
        arn = info['Arn']
        reason = []
        last = None
        for service in serviceLastAccessList:
            if 'LastAuthenticated' in service.keys():
                service_last_auth = service['LastAuthenticated'].isoformat()
                if service_last_auth >= self.criteria90Day: # 90일 이내 service 접근
                    return None
                if last == None or service_last_auth >= last :
                    last = service_last_auth
        if last == None:
            content = {cvt.set_KST_timezone(info['CreateDate'].isoformat(timespec="seconds")): "활동한 기록이 없습니다"}
            reason.append(content)
        else:
            content = {cvt.set_KST_timezone(info['CreateDate'].isoformat(timespec="seconds")): cvt.set_KST_timezone(last)+"에 활동했습니다"}
            reason.append(content)
        if entityType == 'GROUP':
            cvt.add_dict_key_value(self.infoDict, '2.2.2', reason, arn)
        elif entityType == 'POLICY':
            cvt.add_dict_key_value(self.infoDict, '2.2.4', reason, arn)

    # entity에 직접적으로 연결된 관리형, 인라인 정책 존재 유무
    def entity_has_policy_directly(self, info):
        for key, value in info.items():
            if 'MP' in key or 'IP' in key:
                if len(value) != 0:
                    return True # policy exists
        return False    # no policy
    
    def check_user_has_policy(self, info, groups):
        reason = []
        if self.entity_has_policy_directly(info):
            return
        for groupArn in info['RelationUG']:
            if self.entity_has_policy_directly(groups[groupArn]):
                return
        content = {"create": cvt.set_KST_timezone(info['CreateDate'].isoformat(timespec="seconds"))}
        reason.append(content)
        cvt.add_dict_key_value(self.infoDict, '2.3.1', reason, info['Arn'])

    def check_group_has_user(self, info):
        reason = []
        if len(info['RelationGU']) == 0:
            content = {"create": cvt.set_KST_timezone(info['CreateDate'].isoformat(timespec="seconds"))}
            reason.append(content)
            cvt.add_dict_key_value(self.infoDict, '2.3.2', reason, info['Arn'])

    def check_role_has_policy(self, info):
        reason = []
        if self.entity_has_policy_directly(info):
            return
        content = {"create": cvt.set_KST_timezone(info['CreateDate'].isoformat(timespec="seconds"))}
        reason.append(content)
        cvt.add_dict_key_value(self.infoDict, '2.3.3', reason, info['Arn'])

    def check_policy_attached(self, info):
        reason = []
        if info['AttachmentCount'] == 0:
            content = {'create': cvt.set_KST_timezone(info['CreateDate'].isoformat(timespec="seconds"))}
            reason.append(content)
            cvt.add_dict_key_value(self.infoDict, '2.3.4', reason, info['Arn'])

    def check_excessive_organization_permission(self, aws):
        # 조직원 정보 구성
        orgUserPerDict = {} # 조직원들의 policies, 통합 permission 정보
        for userArn in aws.orgUsers:
            info = aws.users[userArn]
            perDict = {'Allow':{'Action':[], 'NotAction':[]}, 'Deny':{'Action':[], 'NotAction':[]}}
            policies = self.get_user_policies_info(aws, userArn)
            # user가 속하는 group의 관리형, 인라인 정책
            for groupArn in info['RelationUG']:
                policies.update(self.get_group_policies_info(aws, groupArn))
            for policyKey, policy in policies.items():
                perDict = sa.merge_permission(perDict, policy['Permission'])
            orgUserPerDict[userArn] = {'Permission': perDict, 'Policies': policies}
        # 조직원 권한 비교
        for targetUser in aws.orgUsers:
            orgList = []    # target 조직
            partners = []   # target과 같은 조직원
            for org, users in aws.orgTable.items():
                if targetUser in users:
                    orgList.append(org)
                    partners.extend(users)
            partners = list(set(partners) - set([targetUser]))
            # 같은 조직원과 비교하여 과도하게(추가로) 가진 권한 파악
            if len(partners) > 0:
                targetInfo = aws.users[targetUser]
                targetPerDict = copy.deepcopy(orgUserPerDict[targetUser]['Permission'])
                for partner in partners:
                    partnerPerDict = orgUserPerDict[partner]['Permission']
                    targetPerDict = sa.get_diff_permission(targetPerDict, partnerPerDict)
                    if sa.is_permission_empty(targetPerDict):
                        break
            # 과도한 권한 없는 경우
            if sa.is_permission_empty(targetPerDict):
                continue
            # 과도한 권한이 있는 경우
            changedPolicy = {}
            for policyKey, policy in orgUserPerDict[targetUser]['Policies'].items():
                interPerDict = sa.get_intersection_permission(targetPerDict, policy['Permission'])
                if not sa.is_permission_empty(interPerDict):
                    newStatement = copy.deepcopy(policy['Document'])
                    for idx in range(len(policy['Document']['Statement'])):
                        statement = policy['Document']['Statement'][idx]
                        statementPerDict = sa.get_permission_from_policy_statements([statement])
                        duplicatedPer = sa.get_intersection_permission(interPerDict, statementPerDict)
                        if not sa.is_permission_empty(duplicatedPer):
                            if 'Allow' in statement.keys():
                                effect = 'Allow'
                            else:
                                effect = 'Deny'
                            if 'Action' in statement.keys():
                                key = 'Action'
                            else:
                                key = 'NotAction'
                            new = list(set(statementPerDict[effect][key]) - set(duplicatedPer[effect][key]))
                            if len(new) == 0:
                                newStatement['Statement'][idx] = None
                            else:
                                newStatement['Statement'][idx][key] = new
                    newStatement['Statement'] = list(filter(None, newStatement['Statement'])) # None 제거
                    changedPolicy[policyKey] = newStatement
            reason = {}
            reason['organization'] = orgList
            for policyKey, newStatement in changedPolicy.items():
                content = orgUserPerDict[targetUser]['Policies'][policyKey]
                if len(newStatement['Statement']) != 0:
                    content['NewStatement'] = newStatement
                reason[policyKey] = content
            cvt.add_dict_key_value(self.infoDict, '2.4.1', reason, targetUser)

    def check_same_policy(self, permissions, policies):
        policyStatementInfo = {}
        policyKeyList = list(policies.keys())   # 고객 관리형 정책 대상 검증
        totalPolicy = len(policyKeyList)
        for idx in range(totalPolicy-1):
            targetKey = policyKeyList[idx]
            targetInfo = permissions[targetKey]
            for i in range(idx+1, totalPolicy):
                partnerKey = policyKeyList[i]
                partnerInfo = permissions[partnerKey]
                # 갖고 있는 권한 종류가 다름
                if not sa.is_permission_same(targetInfo['Permission'], partnerInfo['Permission']):
                    continue
                # 갖고 있는 리소스 종류가 다름
                if targetKey not in policyStatementInfo.keys():
                    policyStatementInfo.update(sa.get_policy_statement_info(targetKey, targetInfo['Document']['Statement']))
                targetStatementInfo = policyStatementInfo[targetKey]
                if partnerKey not in policyStatementInfo.keys():
                    policyStatementInfo.update(sa.get_policy_statement_info(partnerKey, partnerInfo['Document']['Statement']))
                partnerStatementInfo = policyStatementInfo[partnerKey]
                if set(targetStatementInfo['Resource']) != set(partnerStatementInfo['Resource']):
                    continue
                # 동일한 resource의 permission 비교
                sameFlag = True
                for targetIdx in range(len(targetStatementInfo['Resource'])):
                    if sameFlag == False:
                        break
                    targetRes = targetStatementInfo['Resource'][targetIdx]
                    partnerIdx = partnerStatementInfo['Resource'].index(targetRes)
                    targetPerDict = targetStatementInfo['Permission'][targetIdx]
                    partnerPerDict = partnerStatementInfo['Permission'][partnerIdx]
                    if not sa.is_permission_same(targetPerDict, partnerPerDict):
                        sameFlag = False
                # 동일한 정책인 경우
                if sameFlag:
                    perCount = 0
                    serviceCount = 0    
                    for effect, element in targetInfo['Permission'].items():
                        for key, perList in element.items():
                            if len(perList) != 0:
                                perCount += len(perList)
                                perDict = sa.permission_to_service_action(perList)
                                serviceCount += len(perDict)
                    if targetKey not in policies.keys():
                        if '//' in targetKey:
                            entityType = target
                    targetCreate = policies[targetKey]['CreateDate'].isoformat(timespec="seconds")
                    partnerCreate = policies[partnerKey]['CreateDate'].isoformat(timespec="seconds")
                    if targetCreate >= partnerCreate:
                        pastKey = partnerKey
                        recentKey = targetKey
                    else:
                        pastKey = targetKey
                        recentKey = partnerKey  
                    reason = [{"create": cvt.set_KST_timezone(policies[recentKey]['CreateDate'].isoformat(timespec="seconds")), "serviceCount": serviceCount, "permissionCount": perCount, "pastPolicyArn": pastKey, "pastPolicyCreate": cvt.set_KST_timezone(policies[pastKey]['CreateDate'].isoformat(timespec="seconds"))}]
                    cvt.add_dict_key_value(self.infoDict, '2.5.1', reason, recentKey)


if __name__ == '__main__':
    if len(sys.argv) <= 6:
        sys.stderr.write("인자가 충분하지 않음\n")
        exit(0)

    aws = AWSIAMInfo()
    aws.create_iam_client(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[6])
    aws.history = json.loads(sys.argv[4])
    aws.orgTable = json.loads(sys.argv[5])
    
    aws.get_iam_resource()
    aws.get_policies_permission()
    aws.get_credential_report()
    aws.get_account_password_policy()
    aws.list_server_certificates()
    aws.get_organization_users()

    scan = ScanInfo()

    # PW 검증
    scan.check_pwPolicy_usage(aws.pwPolicy)
    scan.check_strong_pwPolicy_used(aws.pwPolicy)
    scan.check_long_pw(aws.pwPolicy)
    scan.check_pw_reused(aws.pwPolicy)
    scan.check_pw_expiration_period_90Days(aws.pwPolicy)
    
    # Server Cert 검증
    for cert in aws.serverCerts:
        scan.check_cert_expriy_7Days(cert)
        scan.check_cert_heartbleed(cert)

    # Root 계정 검증
    for userArn, report in aws.credentailReport.items():
        if report['user'] == '<root_account>':
            scan.check_root_used_30Days(report)
            scan.check_access_key_active(report)
            if '1.1.2' in scan.infoDict.keys():
                scan.check_active_access_key_rotate(report)
            scan.check_mfa_active(report)
            break # 삭제x
    
    # IAM GROUP
    for groupArn, info in aws.groups.items():
        # 미사용 IAM Group
        serviceLastAccessList = aws.get_service_last_accessed_details(groupArn)
        scan.check_entity_used_90Days(serviceLastAccessList, info, 'GROUP')
        # 미연결 IAM Group
        scan.check_group_has_user(info)
        # 과도한 권한 IAM Group
        if groupArn not in aws.history.keys():
            aws.history[groupArn] = []
        accessedHistory = scan.get_accessed_history_90Days(aws.history[groupArn])
        scan.check_group_has_excessive_permission(aws, groupArn, accessedHistory)

    # IAM ROLE
    for roleArn, info in aws.roles.items():
        # 미사용 IAM Role
        report = aws.iam.get_role(RoleName=info['RoleName'])
        scan.check_role_used_90Days(report)
        # 미연결 IAM Role
        scan.check_role_has_policy(info)
        # 과도한 권한 IAM Role
        if roleArn not in aws.history.keys():
            aws.history[roleArn] = []
        accessedHistory = scan.get_accessed_history_90Days(aws.history[roleArn])
        scan.check_role_has_excessive_permission(aws, roleArn, accessedHistory)

    # IAM POLICY
    for policyArn, info in aws.policies.items():
        # 미사용 IAM Policy
        serviceLastAccessList = aws.get_service_last_accessed_details(policyArn)
        scan.check_entity_used_90Days(serviceLastAccessList, info, 'POLICY')
        # 미연결 IAM Policy
        scan.check_policy_attached(info)

    # IAM USER
    for userArn, info in aws.users.items():
        if userArn in aws.credentailReport.keys():
            # 일반 계정 검증
            report = aws.credentailReport[userArn]
            scan.check_pw_expriy_7Days(report)
            scan.check_active_access_key_rotate(report)
            scan.check_access_key_active(report)
            scan.check_mfa_active(report)
            # 미사용 IAM User
            scan.check_user_used_90Days(report)
        # 미연결 IAM User
        scan.check_user_has_policy(info, aws.groups)
        # 과도한 권한 IAM User
        if userArn not in aws.history.keys():
            aws.history[userArn] = []
        accessedHistory = scan.get_accessed_history_90Days(aws.history[userArn])
        scan.check_user_has_excessive_permission(aws, userArn, accessedHistory)

        # SSH PubKey 검증
        sshPubKeys = []
        sshResponse = aws.iam.list_ssh_public_keys(UserName=info['UserName'])
        while(True):
            sshPubKeys.extend(sshResponse['SSHPublicKeys'])
            if sshResponse['IsTruncated'] == False:
                break
            else:
                sshResponse = aws.iam.list_ssh_public_keys(UserName=info['UserName'], Marker=response['Marker'])
        scan.check_2_ssh_pub_active(sshPubKeys, userArn)
        scan.check_ssh_pub_upload_90Days(sshPubKeys, userArn)
    
    # 조직도 기반 과도한 권한
    scan.check_excessive_organization_permission(aws)
    # 중복된 정책
    scan.check_same_policy(aws.permissions, aws.policies)

    scanData = cvt.convert_scan_info(scan.infoDict)
    iamResource = cvt.convert_iam_resource(aws)
    result = {'scanData': scanData, 'IAMResource': iamResource}
    jsonResult = json.dumps(result)
    f = open('./src/scripts/' + sys.argv[6] + '.json', 'w')
    f.write(jsonResult)
    f.close()
 