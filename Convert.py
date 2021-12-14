import copy
import datetime
from pytz import timezone
import ItemRef as ref
import ServiceAction as sa

# Set criteria time base on ISO 8601+00:00 
def set_criteria_time(criteria, point='previous'): 
    now = datetime.datetime.utcnow()
    criteriaDays = datetime.timedelta(days=criteria)
    if point == 'previous':
        criteriaTime = (now - criteriaDays).isoformat(timespec="seconds")
    else: 
        criteriaTime = (now + criteriaDays).isoformat(timespec="seconds")
    return criteriaTime

# Calculate the time gap
def cal_time_gap(criteriaTime, point='previous'):
    now = datetime.datetime.now(datetime.timezone.utc)
    criteriaTime = datetime.datetime.fromisoformat(criteriaTime)
    if point == 'previous':
        time_gap = now - criteriaTime
    else:
        time_gap = criteriaTime - now
    return time_gap

# isoFormat time UTC+09:00(한국)으로 설정
def set_KST_timezone(isoTime):
    KST = timezone('Asia/Seoul')
    time = datetime.datetime.fromisoformat(isoTime)
    time = time.astimezone(KST)
    time = time.isoformat(timespec="seconds")
    return time

# 데이터 포멧 맞추기
def make_format(value, arn=None):
    if len(value) > 0:
        if arn == None:
            return {"detail" : value}
        else: 
            if "/" in arn:
                name = arn.split("/")
                name = name[-1] 
            else:
                name = "Root"
            return {"targetName": name, "targetArn": arn, "detail" : value}
    return None

# Dictionary에 key와 value 추가, 이때 key가 이미 존재하면 하나의 key에 여러 value 가능
def update_dict_key_value(resultDict, key, value):
    if value != None:
        if key in resultDict:
            if isinstance(value, list):
                resultDict[key] = resultDict[key] + value
            else:
                resultDict[key].append(value)
        else:
            if isinstance(value, list):
                resultDict[key] = value
            else:
                resultDict[key] = [value]
    return resultDict

# value 포멧 맞춘 이후 dictionary에 추가
def add_dict_key_value(resultDict, key, value, arn=None):
    value = make_format(value, arn)
    resultDict = update_dict_key_value(resultDict, key, value)
    return resultDict

# Dictionary 형태의 스캔 결과를 scan info로 변환
def convert_scan_info(targetDict):
    infoList = []
    for itemNo, item in targetDict.items():
        if itemNo.startswith('2.1.'):
            infoList = convert_unused_permission_scan_info(itemNo, item, infoList)
        elif itemNo == '2.4.1':
            infoList = convert_excessive_org_scan_info(itemNo, item, infoList)
        elif itemNo == '2.5.1':
            infoList = convert_same_policy_scan_info(itemNo, item, infoList)
        else:
            infoList = convert_basic_scan_info(itemNo, item, infoList)
    return infoList

def convert_basic_scan_info(itemNo, item, infoList):
    baseInfo = {}
    baseInfo['reason_category'] = itemNo
    baseInfo['recommand'] = ref.recommand[itemNo]  
    
    if itemNo[0] == '1':
        baseInfo['type'] = 0    # config
    elif itemNo[0] == '2':
        baseInfo['type'] = 1    # permission
    else:
        # print("error")
        exit(0)

    for content in item:
        info = copy.deepcopy(baseInfo)
        name = ''
        if 'targetName' in content.keys():
            name = content['targetName']
            info['resource_name'] = name
        if 'targetArn' in content.keys():
            info['resource_arn'] = content['targetArn']
        if 'detail' in content.keys():
            details =''
            for detail in content['detail']:
                for key, value in detail.items():
                    base = ref.detail[itemNo]
                    base = base.replace("$NAME", name).replace("$KEY", str(key)).replace("$VALUE", str(value))                 
                    details = details + base
            info['reason_detail'] = [details]
        
        new_info = copy.deepcopy(info)
        infoList.append(new_info)
    return infoList

# 미사용 서비스/권한/리소스에 관한 Dictionary 형태의 스캔 결과를 scan info로 변환
def convert_unused_permission_scan_info(itemNo, item, infoList):
    baseInfo = {}
    baseInfo['reason_category'] = itemNo
    baseInfo['recommand'] = {} 
    baseInfo['reason_detail'] = []
    
    if itemNo[0] == '1':
        baseInfo['type'] = 0    # config
    elif itemNo[0] == '2':
        baseInfo['type'] = 1    # permission
    else:
        # print("error")
        exit(0)

    for content in item:
        info = copy.deepcopy(baseInfo)
        name = ''
        if 'targetName' in content.keys():
            name = content['targetName']
            info['resource_name'] = name
        if 'targetArn' in content.keys():
            info['resource_arn'] = content['targetArn']
        if 'detail' in content.keys():
            for policyName in content['detail'].keys():
                policy = content['detail'][policyName]
                policyName = policyName.split('/')[-1]
                # origin vs new => same, modified, removed
                if 'NewDocument' in policy.keys():
                    origin = policy['Document']['Statement']
                    new = policy['NewDocument']['Statement']
                    originPer = sa.get_permission_from_policy_statements(origin)
                    newPer = sa.get_permission_from_policy_statements(new)
                    if not sa.is_permission_same(originPer, newPer):    # modified   
                        relation = ref.recommand[itemNo][0]
                        relation = relation.replace("$NAME1", name).replace("$TYPE1", policy['EntityType']).replace("$NAME2", policy['EntityName'])
                        relation = relation.replace("$TYPE2", policy['PolicyType']).replace("$NAME3", policyName)
                        recommand = {policyName: {'relation': relation, 'origin': policy['Document'], 'new': policy['NewDocument']}}
                        info['recommand'].update(recommand)

                        details = ref.detail[itemNo][0]
                        details = details.replace("$NAME", name).replace("$POLICY", policyName)
                        info['reason_detail'].append(details)
                    # else:
                        # print(policyName + " same")
                else:   # removed
                    relation = ref.recommand[itemNo][0]
                    relation = relation.replace("$NAME1", name).replace("$TYPE1", policy['EntityType']).replace("$NAME2", policy['EntityName'])
                    relation = relation.replace("$TYPE2", policy['PolicyType']).replace("$NAME3", policyName)
                    recommand = {'relation': relation}
                    recommand.update(ref.recommand[itemNo][1])
                    recommand = {policyName: recommand}
                    info['recommand'].update(recommand)

                    details = ref.detail[itemNo][1]
                    details = details.replace("$NAME", name).replace("$POLICY", policyName)
                    info['reason_detail'].append(details)
        if len(info['reason_detail']) > 0:
            new_info = copy.deepcopy(info)
            infoList.append(new_info)
    return infoList
    
# 조직도 기반 과도한 권한에 관한 Dictionary 형태의 스캔 결과를 scan info로 변환
def convert_excessive_org_scan_info(itemNo, item, infoList):
    org_info = {}
    for content in item:
        if 'targetArn' in content.keys():
            resource_arn = content['targetArn']
        if 'detail' in content.keys():
            if 'organization' in content['detail']:
                org = content['detail'].pop('organization')
                org_info[resource_arn] = org
    
    infoList = convert_unused_permission_scan_info(itemNo, item, infoList)

    infoListLen = len(infoList)
    for num in range(len(item)):
        info = infoList[infoListLen-1-num]
        resource_arn = info['resource_arn']
        org = org_info[resource_arn]
        for idx in range(len(info['reason_detail'])):
            info['reason_detail'][idx] = info['reason_detail'][idx].replace("$ORG", str(org))
    return infoList

# 동일한 정책에 관한 Dictionary 형태의 스캔 결과를 scan info로 변환
def convert_same_policy_scan_info(itemNo, item, infoList):
    baseInfo = {}
    baseInfo['reason_category'] = itemNo
    baseInfo['recommand'] = ref.recommand[itemNo]  
    
    if itemNo[0] == '1':
        baseInfo['type'] = 0    # config
    elif itemNo[0] == '2':
        baseInfo['type'] = 1    # permission
    else:
        # print("error")
        exit(0)

    for content in item:
        info = copy.deepcopy(baseInfo)
        name = ''
        if 'targetName' in content.keys():
            name = content['targetName']
            info['resource_name'] = name
        if 'targetArn' in content.keys():
            info['resource_arn'] = content['targetArn']
        if 'detail' in content.keys():
            details = ref.detail[itemNo]
            details = details.replace("$NAME", name)
            for detail in content['detail']:
                details = details.replace("$CREATE_RECENT", detail['create'])
                details = details.replace("$SERVICE", str(detail['serviceCount'])).replace("$PERMISSION", str(detail['permissionCount']))
                details = details.replace("$CREATE_PAST", detail['pastPolicyCreate']).replace("$PAST", detail['pastPolicyArn'])
            info['reason_detail'] = [details]
        
        new_info = copy.deepcopy(info)
        infoList.append(new_info)
    return infoList

# for convert_iam_resource()
def make_user_format(user, iam):
    infoDict = {}
    info = {'resource_name': user['UserName'], "resource_type": 1, "creation": set_KST_timezone(user['CreateDate'].isoformat())}
    # access key
    accessKeyResponse = iam.list_access_keys(UserName=user['UserName'])
    accessKeyData = accessKeyResponse['AccessKeyMetadata']
    for idx in range(0, 2):
        infoKey = 'accessKey'+str(idx+1)
        try:
            accessKey = accessKeyData[idx]['AccessKeyId']
        except:
            accessKey = None
        info[infoKey] = accessKey
    # defaultPolicyVersion
    info['defaultPolicyVersion'] = None
    # relation
    relation = []
    relation.extend(user['RelationUMP'])
    relation.extend(user['RelationUIP'])
    info['relation'] = relation
    infoDict[user['Arn']] = info
    return infoDict

# for convert_iam_resource()
def make_group_format(group):
    infoDict = {}
    info = {'resource_name': group['GroupName'], "resource_type": 2, "creation": set_KST_timezone(group['CreateDate'].isoformat())}
    # access key
    for idx in range(0, 2):
        infoKey = 'accessKey'+str(idx+1)
        accessKey = None
        info[infoKey] = accessKey
    # defaultPolicyVersion
    info['defaultPolicyVersion'] = None
    # relation
    relation = []
    relation.extend(group['RelationGU'])
    relation.extend(group['RelationGMP'])
    relation.extend(group['RelationGIP'])
    info['relation'] = relation
    infoDict[group['Arn']] = info
    return infoDict

# for convert_iam_resource()
def make_role_format(role):
    infoDict = {}
    info = {'resource_name': role['RoleName'], "resource_type": 3, "creation": set_KST_timezone(role['CreateDate'].isoformat())}
    # access key
    for idx in range(0, 2):
        infoKey = 'accessKey'+str(idx+1)
        accessKey = None
        info[infoKey] = accessKey
    # defaultPolicyVersion
    info['defaultPolicyVersion'] = None
    # relation
    relation = None
    infoDict[role['Arn']] = info
    return infoDict

# for convert_iam_resource()
def make_policy_format(policy):
    infoDict = {}
    info = {'resource_name': policy['PolicyName'], "resource_type": 4, "creation": set_KST_timezone(policy['CreateDate'].isoformat())}
    # access key
    for idx in range(0, 2):
        infoKey = 'accessKey'+str(idx+1)
        accessKey = None
        info[infoKey] = accessKey
    # defaultPolicyVersion
    info['defaultPolicyVersion'] = policy['DefaultVersionId']
    # relation
    relation = None
    infoDict[policy['Arn']] = info
    return infoDict

def convert_iam_resource(aws):
    resourceList = []
    for user in aws.users.values():
        resourceList.append(make_user_format(user, aws.iam))
    for group in aws.groups.values():
        resourceList.append(make_group_format(group))
    for role in aws.roles.values():
        resourceList.append(make_role_format(role))
    for policy in aws.policies.values():
        resourceList.append(make_policy_format(policy))
    return resourceList

def convert_monitor_log(log, related):
    for itemNo, item in related.items():
        log['reason_category'].append(itemNo)
        details = ref.detail[itemNo]
        keywordDict = {'$RELATED': str(item), '$POLICY_NAME': log['resource_name'][0], '$POLICY_ARN': log['resource_arn'][0]}
        if len(log['resource_arn']) == 2:
            keywordDict['$ENTITY_ARN'] = log['resource_arn'][1]
        for keyword, substitution in keywordDict.items():
            if keyword in details:
                details = details.replace(keyword, keywordDict[keyword])
        log['reason_detail'].append(details)
    return log
