import ItemRef as ref
import datetime
import copy

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
def covert_scan_info(targetDict):
    infoDict = {}
    i = 0
    for itemNo, item in targetDict.items():
        if itemNo.startswith('2.1.'):
            infoDict, i = convert_unused_permission_scan_info(itemNo, item, infoDict, i)
        elif itemNo == '2.4.1':
            infoDict, i = convert_excessive_org_scan_info(itemNo, item, infoDict, i)
        elif itemNo == '2.5.1':
            infoDict, i = convert_same_policy_scan_info(itemNo, item, infoDict, i)
        else:
            infoDict, i = convert_basic_scan_info(itemNo, item, infoDict, i)
    return infoDict

def convert_basic_scan_info(itemNo, item, infoDict, i):
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
            info['reason_detail'] = details
        
        new_info = copy.deepcopy(info)
        infoDict[i] = new_info
        i = i + 1
    return infoDict, i

# 미사용 서비스/권한/리소스에 관한 Dictionary 형태의 스캔 결과를 scan info로 변환
def convert_unused_permission_scan_info(itemNo, item, infoDict, i):
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
            for policyName in content['detail']:
                policy = content['detail'][policyName]
                policyName = policyName.split('/')[-1]
                # origin vs new => same, modified, removed
                if 'NewStatement' in policy.keys():
                    modify_flag = False
                    origin = policy['Document']['Statement']
                    new = policy['NewStatement']['Statement']
                    if len(origin) == len(new):
                        for idx in range(len(new)):  
                            if(modify_flag): 
                                break
                            if new[idx]['Effect'] != 'Deny' and 'Action' in new[idx].keys():
                                if isinstance(origin[idx]['Action'], list):
                                    if len(origin[idx]['Action']) != len(new[idx]['Action']):
                                        modify_flag = True
                                else:
                                    if origin[idx]['Action'] != new[idx]['Action'][0]:
                                        modify_flag = True
                    else:
                        modify_flag = True
                    
                    if(modify_flag):    # modified
                        relation = ref.recommand[itemNo][0]
                        relation = relation.replace("$NAME1", name).replace("$TYPE1", policy['EntityType']).replace("$NAME2", policy['EntityName'])
                        relation = relation.replace("$TYPE2", policy['PolicyType']).replace("$NAME3", policyName)
                        recommand = {policyName: {'relation': relation, 'origin': policy['Document'], 'new': policy['NewStatement']}}
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

        new_info = copy.deepcopy(info)
        infoDict[i] = new_info
        i += 1
    return infoDict, i
    
# 조직도 기반 과도한 권한에 관한 Dictionary 형태의 스캔 결과를 scan info로 변환
def convert_excessive_org_scan_info(itemNo, item, infoDict, i):
    org_info = {}
    for content in item:
        if 'targetArn' in content.keys():
            resource_arn = content['targetArn']
        if 'detail' in content.keys():
            if 'organization' in content['detail']:
                org = content['detail'].pop('organization')
                org_info[resource_arn] = org
    
    infoDict, i = convert_unused_permission_scan_info(itemNo, item, infoDict, i)

    for num in range(len(item)):
        info = infoDict[i-1-num]
        resource_arn = info['resource_arn']
        org = org_info[resource_arn]
        for idx in range(len(info['reason_detail'])):
            info['reason_detail'][idx] = info['reason_detail'][idx].replace("$ORG", str(org))
    return infoDict, i

# 동일한 정책에 관한 Dictionary 형태의 스캔 결과를 scan info로 변환
def convert_same_policy_scan_info(itemNo, item, infoDict, i):
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
            info['reason_detail'] = details
        
        new_info = copy.deepcopy(info)
        infoDict[i] = new_info
        i = i + 1
    return infoDict, i

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
