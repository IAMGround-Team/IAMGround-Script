# -*- coding: utf-8 -*-
detail = {
    "1.1.1": "$NAME 사용자의 $KEY이(가) $VALUE일 이내에 사용되었습니다. ",
    "1.1.2": "$NAME 사용자의 $KEY이(가) $VALUE 되어있습니다. ",
    "1.1.3": "$NAME 사용자의 $KEY이(가) 마지막으로 교체된 이후 $VALUE일 지났습니다. ",
    "1.1.4": "$NAME 사용자의 $KEY이(가) 마지막으로 교체된 이후 $VALUE일 지났습니다. ",
    "1.1.5": "$NAME 사용자의 $KEY이(가) $VALUE 되어있습니다. ",
    "1.1.6": "$NAME 사용자의 SSH Public Key(ID=$KEY)가 $VALUE 되어있습니다. ",
    "1.1.7": "$NAME 사용자의 SSH Public Key(ID=$KEY)가 마지막으로 교체된 이후 $VALUE일 지났습니다. ",
    "1.2.1": "$NAME 사용자의 $KEY가 $VALUE 되어있습니다. ",
    "1.2.2": "$NAME 사용자의 $KEY가 $VALUE 되어있습니다. ",
    "1.2.3": "$NAME 사용자의 $KEY가 $VALUE 되어있습니다. ",
    "1.3.1": "IAM 암호 정책을 사용하지 않습니다. ",
    "1.3.2": "1개 이상의 $VALUE를 IAM 암호 정책의 필수 요구 사항으로 설정하지 않았습니다. ",
    "1.3.3": "IAM 암호 정책의 필수 요구 사항 중 최소 암호 길이가 $VALUE(으)로 설정되어 있습니다. ",
    "1.3.4": "IAM 암호 정책의 필수 요구 사항 중 암호 재사용 제한이 $VALUE설정되어 $KEY. ",
    "1.3.5": "IAM 암호 정책의 필수 요구 사항 중 암호 만료 기간이 $VALUE설정되어 $KEY. ",
    "1.3.6": "$NAME 사용자의 password 만료일이 $VALUE일 $KEY. ",
    "1.4.1": "$NAME 서버 인증서 만료일이 $VALUE일 $KEY. ",
    "1.4.2": "$NAME 서버 인증서는 $VALUE에 업로드 되었습니다. ",
    
    "2.1.1": ["$NAME 사용자에 연결된 $POLICY 정책에서 90일간 사용하지 않은 서비스/권한/리소스가 존재합니다. ", "$NAME 사용자에 연결된 $POLICY 정책에서 정의된 권한을 90일간 사용하지 않습니다. "],
    "2.1.2": ["$NAME 그룹에 연결된 $POLICY 정책에서 90일간 사용하지 않은 서비스/권한/리소스가 존재합니다. ", "$NAME 그룹에 연결된 $POLICY 정책에서 정의된 권한을 90일간 사용하지 않습니다. "],
    "2.1.3": ["$NAME 역할에 연결된 $POLICY 정책에서 90일간 사용하지 않은 서비스/권한/리소스가 존재합니다. ", "$NAME 역할에 연결된 $POLICY 정책에서 정의된 권한을 90일간 사용하지 않습니다. "],

    "2.2.1": "$NAME 사용자는 $KEY에 생성되었으며, 마지막으로 $VALUE. ",
    "2.2.2": "$NAME 그룹은 $KEY에 생성되었으며, 마지막으로 $VALUE. ",
    "2.2.3": "$NAME 역할은 $KEY에 생성되었으며, 마지막으로 $VALUE. ",
    "2.2.4": "$NAME 정책은 $KEY에 생성되었으며, 마지막으로 $VALUE. ",
    "2.3.1": "$NAME 사용자는 $VALUE에 생성되었으며, 0개의 정책이 연결되어 있습니다. ",
    "2.3.2": "$NAME 그룹은 $VALUE에 생성되었으며, 0개의 사용자가 연결되어 있습니다. ",
    "2.3.3": "$NAME 역할은 $VALUE에 생성되었으며, 0개의 정책이 연결되어 있습니다. ",
    "2.3.4": "$NAME 정책은 $VALUE에 생성되었으며, 0개의 IAM 엔티티가 연결되어 있습니다. ",

    "2.4.1": ["$NAME 사용자에 연결된 $POLICY 정책에서 $ORG 조직원은 부여받지 않은 서비스/권한/리소스가 존재합니다. ", "$NAME 사용자에 연결된 $POLICY 정책에서 정의된 권한을 $ORG 조직원은 부여받지 않습니다. "],

    "2.5.1": "$NAME 정책은 $SERVICE개 서비스에 대해 $PERMISSION개의 권한을 가지고 있습니다. 해당 정책은 $CREATE_RECENT에 생성되었습니다. 이는 $CREATE_PAST에 생성된 $PAST 정책과 완전히 동일합니다. ",

    "3.1.1": "$RELATED 의 권한이 확대되었습니다. ",
    "3.1.2": "$RELATED 사용자는 조직원들은 부여받지 않은 권한을 가지게 되었습니다.",
    "3.1.3": "$ENTITY_ARN에 $POLICY_NAME 인라인 정책이 연결되었습니다. ",
    "3.1.4": "$ENTITY_ARN에 $POLICY_NAME AWS 관리형 정책이 연결되었습니다. ",
    "3.1.5": "$ENTITY_ARN에 $POLICY_NAME AWS 관리형 정책이 연결되었습니다. ",
    "3.2.1": "$POLICY_ARN 정책에서 정의된 권한에 '*'가 사용되었습니다. ",
    "3.2.2": "$POLICY_ARN 정책에서 정의된 리소스에 '*'가 사용되었습니다. ",
    "3.2.3": "$POLICY_ARN 정책 정의 시, 조건(Condition)을 사용하지 않았습니다. ",
    "3.2.4": "$POLICY_ARN 정책에서 'Deny'를 명시적으로 작성하지 않았습니다. ",
    "3.2.5": "$POLICY_ARN 정책에 'Effect:Allow'와 'NotAction' 조합이 존재합니다. "
}

recommand = {
    "1.1.1": {
        "verification_method": "- AWS Console\n1) AWS 콘솔에 접속한다.\n2) ‘서비스’를 클릭한다.\n3) ‘IAM’을 클릭한다.\n4) ‘자격 증명 보고서’를 클릭한다.\n5) ‘보고서 다운로드’를 클릭하여, .xls 파일형식의 보고서를 확인하다. 해당 보고서는 root 계정과 모든 IAM 유저들의 자격증명을 포함하고 있다.\n - 보고서의 <root_account> 계정의 password_last_used가 30일 이내의 날짜인지 확인한다.\n - 보고서의 <root_account> 계정의 access_key_1_active가 TRUE라면, access_key_1_last_used_date가 30일보다 오래됐는지 확인한다.\n - 보고서의 <root_account> 계정의 access_key_2_active가 TRUE라면, access_key_2_last_used_date가 30일보다 오래됐는지 확인한다.",
        "action_method": "- AWS Console\n1) IAM 전체 사용자를 볼 수 있는 IAM 계정을 이용하여 콘솔에 로그인한다.\n2) ‘서비스’를 클릭한다.\n3) ‘IAM’을 클릭한다.\n4) 좌측 ‘사용자’를 클릭한다.\n5) 사용자 세부 정보 설정란에 이름을 입력 항 후 AWS 액세스 유형을 선택합니다. 그리고 비밀번호 재설정 필요를 체크하고 다음:권한버튼을 클릭하시오.\n6) 권한 설정 페이지에서 기존 정책 직접 연결 옵션을 클릭하시오. 그 다음 EC2 인스턴스에 대한 액세스가 필요한 경우 AmazonEC2FullAccess정책을 선택하시오. 그 다음 다음:태그 버튼을 클릭하시오.\n7) 태그 값이 필요한 경우 태그를 추가하시오. 그 다음 다음:검토를 클릭하시오\n8) 마지막으료 사용자 만들기 버튼을 클릭하여 계정을 생성하시오\n9) .CVS 다운로드 버튼을 클릭하여 계정 정보를 저장하시오. 해당 파일을 다운로드 했다면, 다시 IAM 사용자 페이지로 이동합니다.\n10) 새로 생성한 해당 계정의 이름을 클릭하여 요약 페이지로 이동하시오.\n11) 해당 페이지에서 보안 자격 증명을 클릭하시오.\n12) 해당 탭에서 로그인 자격 증명의 할당된 MFA 디바이스의 할당되지 않음 옆 관리 버튼을 클릭하시오.\n13) MFA 디바이스 관리 창에서 추가할 MFA 디바이스를 체크 하시고 계속 버튼을 클릭하시오.(현재 문서에서는 가상 MFA Google Authenticator를 이용하겠습니다.)\n14) 호환 되는 모바일 디바이스에 Google Authenticator를 설치한 후 해당 앱에서 QR 코드를 스캔하시오. 그 다음 MFA 코드 1,2를 채우시오.\n15) MFA할당을 클릭하시오.",
        "reference": [
            {
                "url": "https: //docs.aws.amazon.com/ko_kr/general/latest/gr/aws-security-audit-guide.html#aws-security-audit-review-account",
                "item": "일상적인 작업에는 루트 액세스 키를 사용하지 않는 것이 좋습니다. AWS에 로그인하고 대신 IAM 사용자를 생성해야 합니다."
            },
            {
                "url": "https://d1.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf",
                "item": "CIS Bench mark 1.1 Avoid the use of the 'root' account"
            }
        ]
    },
    "1.1.2": {
        "verification_method": "- AWS Console\n1) AWS 콘솔에 접속한다.\n2) ‘서비스’를 클릭한다.\n3) ‘IAM’을 클릭한다.\n4) ‘자격 증명 보고서’를 클릭한다.\n5) ‘보고서 다운로드’를 클릭하여, .xls 파일형식의 보고서를 확인하다. 해당 보고서는 root 계정과 모든 IAM 유저들의 자격증명을 포함하고 있다.\n6) 보고서에 <root_account> 계정의 ‘access_key_1_active’ 그리고 ‘access_key_2_active’ 필드들의 값이 False인지 확인한다.",
        "action_method": "- AWS Console\n1) Root 계정으로 AWS 콘솔에 접속한다.\n2) AWS 계정이름이나 혹은 계정 번호를 클릭한다.\n3) 클릭 후 내 보안 자격 증명을 클릭한다.\n4) 해당 페이지에서 액세스 키를 클릭한다.\n5) 액세스 키에 활성화가 되어 있는 키를 작업열에서 삭제를 클릭한다.",
        "reference": [
            {
                "url": "https: //docs.aws.amazon.com/ko_kr/IAM/latest/UserGuide/best-practices.html#lock-away-credentials",
                "item": "AWS 계정 루트 사용자에 대한 액세스 키가 있다면 삭제"
            },
            {
                "url": "https://docs.aws.amazon.com/ko_kr/general/latest/gr/aws-access-keys-best-practices.html",
                "item": "AWS 계정 루트 사용자는 의 모든 리소스에 무제한 액세스할 수 있는 권한이 있습니다, 루트 사용자 액세스 키 보호 또는 생성 안 함"
            },
            {
                "url": "https://d1.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf",
                "item": "CIS Bench mark 1.12 Ensure no root account access key exists"
            }
        ]
    },
    "1.1.3": {
        "verification_method": "- AWS Console\n1) AWS 콘솔에 접속한다.\n2) ‘서비스’를 클릭한다.\n3) ‘IAM’을 클릭한다.\n4) ‘자격 증명 보고서’를 클릭한다.\n5) ‘보고서 다운로드’를 클릭하여, .xls 파일형식의 보고서를 확인하다. 해당 보고서는 root 계정과 모든 IAM 유저들의 자격증명을 포함하고 있다.\n - 보고서의 <root_account> 계정의 access_key_1_active가 TRUE라면, access_key_1_rotated가 30일보다 오래됐는지 확인한다.\n - 보고서의 <root_account> 계정의 access_key_2_active가 TRUE라면, access_key_2_rotated가 30일보다 오래됐는지 확인한다.",
        "action_method": "- AWS Console\n1) Root 계정으로 AWS 콘솔에 접속한다.\n2) AWS 계정이름이나 혹은 계정 번호를 클릭한다.\n3) 클릭 후 내 보안 자격 증명을 클릭한다.\n4) 해당 페이지에서 액세스 키를 클릭한다.\n5) 오래된 액세스 키를 키를 작업열에서 삭제를 클릭한다.",
        "reference": [
            {
                "url": "https://docs.aws.amazon.com/ko_kr/IAM/latest/UserGuide/best-practices.html#lock-away-credentials",
                "item": "AWS 계정 루트 사용자에 대한 액세스 키가 있다면 삭제하고, 계속 유지해야 할 경우 주기적으로 액세스 키를 교체(변경)하십시오."
            },
            {
                "url": "https://docs.aws.amazon.com/ko_kr/general/latest/gr/aws-security-audit-guide.html#aws-security-audit-review-account",
                "item": "계정에 대해 액세스 키를 유지해야 하는 경우 액세스 키를 정기적으로 교체합니다."
            },
            {
                "url": "https://d1.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf",
                "item": "CIS Bench mark 1.4 Ensure access keys are rotated every 90 days or less"
            }
        ]
    },
    "1.1.4": {
        "verification_method": "- AWS Console\n1) IAM 전체 사용자를 볼 수 있는 IAM 계정을 이용하여 콘솔에 로그인한다.\n2) ‘서비스’를 클릭한다.\n3) ‘IAM’을 클릭한다.\n4) 좌측 ‘사용자’를 클릭한다.\n5) 검사하고자 하는 IAM 계정을 클릭한다.\n6) 그 다음 보안 자격 증명탭을 클릭한다.\n7) 해당 탭에서 액세스 키의 생성 시간을 확인한다.\n8) 액세스 키의 생성 완료 시간이 30일 이내인지 확인하시오.",
        "action_method": "- AWS Console\n1) IAM 전체 사용자를 볼 수 있는 IAM 계정을 이용하여 콘솔에 로그인한다.\n2) ‘서비스’를 클릭한다.\n3) ‘IAM’을 클릭한다.\n4) 좌측 ‘사용자’를 클릭한다.\n5) 액세스 키를 교체하고자 하는 IAM 계정을 클릭한다.\n6) 그 다음 보안 자격 증명탭을 클릭한다.\n7) 해당 탭에서 액세스 키 만들기버튼을 클릭한다.\n8) .csv파일을 다운로드 받은 후 닫기 표시를 누르시오.\n9) 그 다음 생성된지 30일이 넘은 액세스 키의 상태를 비활성화 한 뒤 삭제하시오.",
        "reference": [
            {
                "url": "https://docs.aws.amazon.com/ko_kr/general/latest/gr/aws-access-keys-best-practices.html",
                "item": "액세스 키를 보유한 사람은 누구든지 사용자의 액세스 권한과 동일한 권한을 갖습니다.AWS리소스를 사용할 수 있습니다. 따라서 AWS는 사용자의 액세스 키를 보호하기 위해 최선을 다하며, 사용자도 AWS의 공동 책임 모델에 부합하는 노력을 해야 합니다."
            },
            {
                "url": "https://docs.aws.amazon.com/ko_kr/IAM/latest/UserGuide/id_credentials_access-keys.html#Using_RotateAccessKey",
                "item": "최상의 보안을 위해 IAM 사용자 액세스 키를 정기적으로 교체(변경)하는 것이 좋습니다."
            },
            {
                "url": "https://docs.aws.amazon.com/ko_kr/general/latest/gr/aws-security-audit-guide.html#aws-security-audit-review-users",
                "item": "사용자 보안 자격 증명을 주기적으로 교체(변경)합니다. 권한 없는 사용자와 자격 증명을 공유한 경우에는 즉시 교체합니다."
            },
            {
                "url": "https://d1.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf",
                "item": "CIS Bench mark 1.4 Ensure access keys are rotated every 90 days or less"
            }
        ]
    },
    "1.1.5": {
        "verification_method": "- AWS Console\n1) IAM 전체 사용자를 볼 수 있는 IAM 계정을 이용하여 콘솔에 로그인한다.\n2) ‘서비스’를 클릭한다.\n3) ‘IAM’을 클릭한다.\n4) 좌측 ‘사용자’를 클릭한다.\n5) 검사하고자 하는 IAM 계정을 클릭한다.\n6) 해당 창에서 보안 작겨 증명탭을 클릭한다.\n7) 해당 탭에서 액세스 키에 액세스 키가 2개 이상있는지 확인하시오.\n8) 만약 2개 이상이라면 둘 다 상태가 (활성)인지 확인하시오.",
        "action_method": "- AWS Console\n1) IAM 전체 사용자를 볼 수 있는 IAM 계정을 이용하여 콘솔에 로그인한다.\n2) ‘서비스’를 클릭한다.\n3) ‘IAM’을 클릭한다.\n4) 좌측 ‘사용자’를 클릭한다.\n5) 액세스 키를 교체하고자 하는 IAM 계정을 클릭한다.\n6) 그 다음 보안 자격 증명탭을 클릭한다.\n9) 해당 페이지에서 액세스 키에 두 개의 액세스 키 중 하나를 비활성화 하시오.",
        "reference": [
            {
                "url": "https://www.cloudconformity.com/knowledge-base/aws/IAM/unnecessary-access-keys.html"
            }
        ]
    },
    "1.1.6": {
        "verification_method": "- AWS Console\n1) IAM 전체 사용자를 볼 수 있는 IAM 계정을 이용하여 콘솔에 로그인한다.\n2) ‘서비스’를 클릭한다.\n3) ‘IAM’을 클릭한다.\n4) 좌측 ‘사용자’를 클릭한다.\n5) 검사하고자 하는 IAM 계정을 클릭한다.\n6) 해당 창에서 보안 작겨 증명탭을 클릭한다.\n7) 해당 탭에서 AWS CodeCommit에 대한 SSH키 탭을 확인하시오.\n8) 2개 이상의 SSH 퍼블릭 키가 있는지 확인하시오\n9) 만약 존재한다면, 모두 상태가 (활성)인지 확인하시오.",
        "action_method": "- AWS Console\n1) IAM 전체 사용자를 볼 수 있는 IAM 계정을 이용하여 콘솔에 로그인한다.\n2) ‘서비스’를 클릭한다.\n3) ‘IAM’을 클릭한다.\n4) 좌측 ‘사용자’를 클릭한다.\n5) 검사하고자 하는 IAM 계정을 클릭한다.\n6) 해당 창에서 보안 작겨 증명탭을 클릭한다.\n7) 해당 탭에서 AWS CodeCommit에 대한 SSH키 탭을 확인하시오.\n8) 두 개 이상의 Public Key 중 하나를 하나만 빼고 모두 비활성화 하시오.",
        "reference": [
            {
                "url": "https://docs.aws.amazon.com/ko_kr/IAM/latest/UserGuide/id_credentials_ssh-keys.html"
            }
        ]
    },
    "1.1.7": {
        "verification_method": "- AWS Console\n1) IAM 전체 사용자를 볼 수 있는 IAM 계정을 이용하여 콘솔에 로그인한다.\n2) ‘서비스’를 클릭한다.\n3) ‘IAM’을 클릭한다.\n4) 좌측 ‘사용자’를 클릭한다.\n5) 검사하고자 하는 IAM 계정을 클릭한다.\n6) 해당 창에서 보안 작겨 증명탭을 클릭한다.\n7) 해당 탭에서 AWS CodeCommit에 대한 SSH키 탭을 확인하시오.\n8) SSH 퍼블릭 키가 있는지 확인하시오\n9) 만약 존재한다면, 업로드됨 의 탭에 날짜가 90일 이내인지 확인하시오.",
        "action_method": "- AWS Console\n1) IAM 전체 사용자를 볼 수 있는 IAM 계정을 이용하여 콘솔에 로그인한다.\n2) ‘서비스’를 클릭한다.\n3) ‘IAM’을 클릭한다.\n4) 좌측 ‘사용자’를 클릭한다.\n5) 검사하고자 하는 IAM 계정을 클릭한다.\n6) 해당 창에서 보안 작겨 증명탭을 클릭한다.\n7) 해당 탭에서 AWS CodeCommit에 대한 SSH키 탭을 확인하시오.\n8) SSH 퍼블릭 키 업로드 버튼을 클릭하시오.\n9) 가지고 있는 퍼블릭 키를 해당 업로드 란에 업로드 한 뒤 SSH 퍼블릭 키 업로드 버튼을 클릭하여 업로드 하시오.\n10)  그 다음 90일 초과된 키를 비활성화 한 뒤 삭제하시오.",
        "reference": [
            {
                "url": "https://docs.aws.amazon.com/ko_kr/IAM/latest/UserGuide/id_credentials_ssh-keys.html"
            },
            {
                "url": "https://docs.aws.amazon.com/ko_kr/general/latest/gr/aws-security-audit-guide.html#aws-security-audit-review-account",
                "item": "사용자 보안 자격 증명을 주기적으로 교체(변경)합니다. 권한 없는 사용자와 자격 증명을 공유한 경우에는 즉시 교체합니다."
            }
        ]
    },
    "1.2.1": {
        "verification_method": "- AWS Console\n1) AWS 콘솔에 접속한다.\n2) ‘서비스’를 클릭한다.\n3) ‘IAM’을 클릭한다.\n4) ‘자격 증명 보고서’를 클릭한다.\n5) ‘보고서 다운로드’를 클릭하여, .xls 파일형식의 보고서를 확인하다. 해당 보고서는 root 계정과 모든 IAM 유저들의 자격증명을 포함하고 있다.\n - 보고서의 <root_account> 계정의 mfa_active가 FALSE인지 확인한다.",
        "action_method": "- AWS Console\n1) Root 계정으로 AWS 콘솔에 접속한다.\n2) AWS 계정이름이나 혹은 계정 번호를 클릭한다.\n3) 클릭 후 내 보안 자격 증명을 클릭한다.\n4) 해당 페이지에서 멀티 팩터 인증(MFA)를 클릭하시오.\n5) 해당 탭에서 MFA 활성화 버튼을 클릭하시오.\n6) MFA 디바이스 관리 창에서 추가할 MFA 디바이스를 체크 하시고 계속 버튼을 클릭하시오.(현재 문서에서는 가상 MFA Google Authenticator를 이용하겠습니다.)\n7) 호환 되는 모바일 디바이스에 Google Authenticator를 설치한 후 해당 앱에서 QR 코드를 스캔하시오. 그 다음 MFA 코드 1,2를 채우시오.",
        "reference": [
            {
                "url": "https://docs.aws.amazon.com/ko_kr/IAM/latest/UserGuide/best-practices.html#enable-mfa-for-privileged-users",
                "item": "보안 강화를 위해 계정에 속한 모든 사용자에게 Multi-Factor Authentication(MFA)을 요구하는 것이 좋습니다."
            },
            {
                "url": "https://d1.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf",
                "item": "CIS Bench mark 1.13 Ensure MFA is enabled for the 'root' account"
            }
        ]
    },
    "1.2.2": {
        "verification_method": "- AWS Console\n1) AWS 콘솔에 접속한다.\n2) ‘서비스’를 클릭한다.\n3) ‘IAM’을 클릭한다.\n4) 보안 상태(Security Status) 아래에서 MFA의 활성화 여부를 확인합니다. MFA가 활성화되지 않은 경우, 알림 기호가 Activate MFA on your 루트 사용자(루트 사용자에서 MFA 활성화) 옆에 표시됩니다.",
        "action_method": "- AWS Console\n1) Root 계정으로 AWS 콘솔에 접속한다.\n2) AWS 계정이름이나 혹은 계정 번호를 클릭한다.\n3) 클릭 후 내 보안 자격 증명을 클릭한다.\n4) 해당 페이지에서 멀티 팩터 인증(MFA)를 클릭하시오.\n5) 해당 탭에서 MFA 활성화 버튼을 클릭하시오.\n6) MFA 디바이스 관리 창에서 다른 하드웨어 MFA 디바이스를 클릭하시오\n7) 디바이스 일렬 번호, MFA 코드 1,2를 채우시오.\n8) MFA할당 버튼을 클릭하시오.",
        "reference": [
            {
                "url": "https://docs.aws.amazon.com/ko_kr/IAM/latest/UserGuide/best-practices.html#enable-mfa-for-privileged-users",
                "item": "보안 강화를 위해 계정에 속한 모든 사용자에게 Multi-Factor Authentication(MFA)을 요구하는 것이 좋습니다."
            },
            {
                "url": "https://docs.aws.amazon.com/ko_kr/IAM/latest/UserGuide/id_credentials_mfa_enable_physical.html",
                "item": "하드웨어 MFA 디바이스 활성화(콘솔)"
            },
            {
                "url": "https://d1.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf",
                "item": "CIS Bench mark 1.14 Ensure hardware MFA is enabled for the 'root' account"
            }
        ]
    },
    "1.2.3": {
        "verification_method": "- AWS Console\n1) AWS 콘솔에 접속한다.\n2) ‘서비스’를 클릭한다.\n3) ‘IAM’을 클릭한다.\n4) ‘자격 증명 보고서’를 클릭한다.\n5) ‘보고서 다운로드’를 클릭하여, .xls 파일형식의 보고서를 확인하다. 해당 보고서는 root 계정과 모든 IAM 유저들의 자격증명을 포함하고 있다.\n - 보고서의  IAM계정들의 mfa_active가 TRUE인지 확인하시오.",
        "action_method": "- AWS Console\n1) IAM 전체 사용자를 볼 수 있는 IAM 계정을 이용하여 콘솔에 로그인한다.\n2) ‘서비스’를 클릭한다.\n3) ‘IAM’을 클릭한다.\n4) 좌측 ‘사용자’를 클릭한다.\n5) 삭제하고자 하는 사용자 열에서 좌측 체크박스에 체크를 하시오.\n6) 패널 상단에 위치한 사용자 삭제 버튼을 클릭하여 해당 계정을 삭제하시오.",
        "reference": [
            {
                "url": "https://docs.aws.amazon.com/ko_kr/general/latest/gr/aws-security-audit-guide.html#aws-security-audit-review-users"
            },
            {
                "url": "https://d1.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf",
                "item": "CIS Bench mark 1.2 Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password"
            }
        ]
    },
    "1.3.1": {
        "verification_method": "- AWS Console\n1) IAM 계정 설정을 볼 수 있는 IAM 계정을 이용하여 콘솔에 로그인한다.\n2) ‘서비스’를 클릭한다.\n3) ‘IAM’을 클릭한다.\n4) 좌측 ‘액세스 관리’에 ‘계정 설정’을 클릭한다.\n5) ‘암호 정책 설정’을 확인한다.\n - ‘1개 이상의 라틴 알파벳 대문자(A-Z) 필수’ 항목에 체크가 되어있는지 확인한다.\n - ‘1개 이상의 라틴 알파벳 소문자(a-z) 필수’ 항목에 체크가 되어있는지 확인한다.\n - ‘1개 이상의 숫자 필수’ 항목에 체크가 되어있는지 확인한다.　\n - ‘영숫자를 제외한 문자 1개 이상 필수 (! @ # $ % ^ & * ( ) _ + - = [ ] { } | ')’ 항목에 체크가 되어있는지 확인한다.",
        "action_method": "- AWS Console\n1) IAM 전체 사용자를 볼 수 있는 IAM 계정을 이용하여 콘솔에 로그인한다.\n2) ‘서비스’를 클릭한다.\n3) ‘IAM’을 클릭한다.\n4) 좌측 ‘계정설정'을 클릭한다.\n5) 비밀번호 저책 탭에서 비밀번호 정책을 설정/수정 합니다.\n - ‘1개 이상의 라틴 알파벳 대문자(A-Z) 필수’ 항목에 체크가 되어있는지 확인한다.\n - ‘1개 이상의 라틴 알파벳 소문자(a-z) 필수’ 항목에 체크가 되어있는지 확인한다.\n - ‘1개 이상의 숫자 필수’ 항목에 체크가 되어있는지 확인한다.　\n - ‘영숫자를 제외한 문자 1개 이상 필수 (! @ # $ % ^ & * ( ) _ + - = [ ] { } | ')’ 항목에 체크가 되어있는지 확인한다.",
        "reference": [
            {
                "url": "https://docs.aws.amazon.com/ko_kr/IAM/latest/UserGuide/best-practices.html#configure-strong-password-policy",
                "item": "사용자에 대한 강력한 암호 정책 구성"
            },
            {
                "url": "https://docs.aws.amazon.com/ko_kr/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details",
                "item": "사용자 지정 암호 정책 옵션"
            }
        ]
    },
    "1.3.2": {
        "verification_method": "- AWS Console\n1) IAM 계정 설정을 볼 수 있는 IAM 계정을 이용하여 콘솔에 로그인한다.\n2) ‘서비스’를 클릭한다.\n3) ‘IAM’을 클릭한다.\n4) 좌측 ‘액세스 관리’에 ‘계정 설정’을 클릭한다.\n5) ‘암호 정책 설정’을 확인한다.\n - ‘1개 이상의 라틴 알파벳 대문자(A-Z) 필수’ 항목에 체크가 되어있는지 확인한다.\n - ‘1개 이상의 라틴 알파벳 소문자(a-z) 필수’ 항목에 체크가 되어있는지 확인한다.\n - ‘1개 이상의 숫자 필수’ 항목에 체크가 되어있는지 확인한다.　\n - ‘영숫자를 제외한 문자 1개 이상 필수 (! @ # $ % ^ & * ( ) _ + - = [ ] { } | ')’ 항목에 체크가 되어있는지 확인한다.",
        "action_method": "- AWS Console\n1) IAM 전체 사용자를 볼 수 있는 IAM 계정을 이용하여 콘솔에 로그인한다.\n2) ‘서비스’를 클릭한다.\n3) ‘IAM’을 클릭한다.\n4) 좌측 ‘계정설정'을 클릭한다.\n5) 비밀번호 저책 탭에서 비밀번호 정책을 설정/수정 합니다.\n - ‘1개 이상의 라틴 알파벳 대문자(A-Z) 필수’ 항목에 체크가 되어있는지 확인한다.\n - ‘1개 이상의 라틴 알파벳 소문자(a-z) 필수’ 항목에 체크가 되어있는지 확인한다.\n - ‘1개 이상의 숫자 필수’ 항목에 체크가 되어있는지 확인한다.　\n - ‘영숫자를 제외한 문자 1개 이상 필수 (! @ # $ % ^ & * ( ) _ + - = [ ] { } | ')’ 항목에 체크가 되어있는지 확인한다.",
        "reference": [
            {
                "url": "https://docs.aws.amazon.com/ko_kr/IAM/latest/UserGuide/best-practices.html#configure-strong-password-policy",
                "item": "사용자에 대한 강력한 암호 정책 구성"
            },
            {
                "url": "https://docs.aws.amazon.com/ko_kr/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details",
                "item": "사용자 지정 암호 정책 옵션"
            },
            {
                "url": "https://d1.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf",
                "item": "CIS Bench mark 1.5 Ensure IAM password policy requires at least one uppercase letter, CIS Bench mark 1.6 Ensure IAM password policy require at least one lowercase letter, CIS Bench mark 1.7 Ensure IAM password policy require at least one symbol, CIS Bench mark 1.8 Ensure IAM password policy require at least one number"
            }
        ]
    },
    "1.3.3": {
        "verification_method": "- AWS Console\n1) IAM 계정 설정을 볼 수 있는 IAM 계정을 이용하여 콘솔에 로그인한다.\n2) ‘서비스’를 클릭한다.\n3) ‘IAM’을 클릭한다.\n4) 좌측 ‘액세스 관리’에 ‘계정 설정’을 클릭한다.\n5) ‘암호 정책 설정’을 확인한다.",
        "action_method": "- AWS Console\n1) IAM 전체 사용자를 볼 수 있는 IAM 계정을 이용하여 콘솔에 로그인한다.\n2) ‘서비스’를 클릭한다.\n3) ‘IAM’을 클릭한다.\n4) 좌측 ‘계정설정'을 클릭한다.\n5) 비밀번호 저책 탭에서 비밀번호 정책을 설정/수정 합니다.\n - ‘최소 암호 길이 적용’ 항목에 ‘14자’ 이상의 길이가 필요한지 확인한다.",
        "reference": [
            {
                "url": "https://docs.aws.amazon.com/ko_kr/IAM/latest/UserGuide/best-practices.html#configure-strong-password-policy",
                "item": "사용자에 대한 강력한 암호 정책 구성"
            },
            {
                "url": "https://docs.aws.amazon.com/ko_kr/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details",
                "item": "사용자 지정 암호 정책 옵션"
            },
            {
                "url": "https://d1.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf",
                "item": "CIS Bench mark 1.9 Ensure IAM password policy requires minimum length of 14 or greater"
            }
        ]
    },
    "1.3.4": {
        "verification_method": "- AWS Console\n1) IAM 계정 설정을 볼 수 있는 IAM 계정을 이용하여 콘솔에 로그인한다.\n2) ‘서비스’를 클릭한다.\n3) ‘IAM’을 클릭한다.\n4) 좌측 ‘액세스 관리’에 ‘계정 설정’을 클릭한다.\n5) ‘암호 정책 설정’을 확인한다.\n - ‘암호 재사용 제한’ 항목에 체크가 되어있는지 확인한다.",
        "action_method": " AWS Console\n1) IAM 전체 사용자를 볼 수 있는 IAM 계정을 이용하여 콘솔에 로그인한다.\n2) ‘서비스’를 클릭한다.\n3) ‘IAM’을 클릭한다.\n4) 좌측 ‘계정설정'을 클릭한다.\n5) 비밀번호 저책 탭에서 비밀번호 정책을 설정/수정 합니다.\n - '암호 재사용 제한'항목에 체크가 되어있는지 확인한다.",
        "reference": [
            {
                "url": "https://docs.aws.amazon.com/ko_kr/IAM/latest/UserGuide/best-practices.html#configure-strong-password-policy",
                "item": "사용자에 대한 강력한 암호 정책 구성"
            },
            {
                "url": "https://docs.aws.amazon.com/ko_kr/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details",
                "item": "사용자 지정 암호 정책 옵션"
            },
            {
                "url": "https://d1.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf",
                "item": "CIS Bench mark 1.10 Ensure IAM password policy prevents password reuse"
            }
        ]
    },
    "1.3.5": {
        "verification_method": "- AWS Console\n1) IAM 계정 설정을 볼 수 있는 IAM 계정을 이용하여 콘솔에 로그인한다.\n2) ‘서비스’를 클릭한다.\n3) ‘IAM’을 클릭한다.\n4) 좌측 ‘액세스 관리’에 ‘계정 설정’을 클릭한다.\n5) ‘암호 정책 설정’을 확인한다.\n - ‘암호 만료 활성화’ 항목에 체크가 되어있는지 확인한다.\n - ‘암호 만료’일 수가 ‘90‘일인지 확인한다.",
        "action_method": "- AWS Console\n1) IAM 전체 사용자를 볼 수 있는 IAM 계정을 이용하여 콘솔에 로그인한다.\n2) ‘서비스’를 클릭한다.\n3) ‘IAM’을 클릭한다.\n4) 좌측 ‘계정설정'을 클릭한다.\n5) 비밀번호 저책 탭에서 비밀번호 정책을 설정/수정 합니다.\n - ‘암호 만료 활성화’ 항목에 체크가 되어있는지 확인한다.",
        "reference": [
            {
                "url": "https://docs.aws.amazon.com/ko_kr/IAM/latest/UserGuide/best-practices.html#configure-strong-password-policy",
                "item": "사용자에 대한 강력한 암호 정책 구성"
            },
            {
                "url": "https://docs.aws.amazon.com/ko_kr/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details",
                "item": "사용자 지정 암호 정책 옵션"
            },
            {
                "url": "https://d1.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf",
                "item": "CIS Bench mark 1.11 Ensure IAM password policy expires passwords within 90 days or less"
            }
        ]
    },
    "1.3.6": {
        "verification_method": "- AWS Console\n1) AWS 콘솔에 접속한다.\n2) ‘서비스’를 클릭한다.\n3) ‘IAM’을 클릭한다.\n4) ‘자격 증명 보고서’를 클릭한다.\n5) ‘보고서 다운로드’를 클릭하여, .xls 파일형식의 보고서를 확인하다. 해당 보고서는 모든 IAM 유저들(root계정 제외)의 자격증명을 포함하고 있다.\n - 보고서의 IAM 유저들(root계정 제외)의 password_last_changed의 값을 확인한다.\n - 보고서의 IAM 유저들(root계정 제외)의 password_next_rotation의 값을 확인한다.\n6) 두 시간의 차이가 만약 7일 이내인지 확인하시오.",
        "action_method": "조치 불가능(개인정보/비밀번호 필요)",
        "reference": [
            {
                "url": "https://www.cloudconformity.com/knowledge-base/aws/IAM/password-expiry-in-7-days.html"
            }
        ]
    },
    "1.4.1": {
        "verification_method": "- AWS Console\n1) IAM 전체 사용자를 볼 수 있는 IAM 계정을 이용하여 콘솔에 로그인한다.\n2) 서비스 탭에서 'EC2'를 클릭하시오.\n3) 좌측 네비게이션에서 로드 밸런싱에 로드 밸런서를 클릭하시오.\n4) 나와 있는 ELB(Elastic Load Balancer)의 만료 기간을 확인하여 7일 이내의 SSL/TLS 인증서가 있는지 확인하시오.",
        "action_method": "- AWS Console\n1) IAM 전체 사용자를 볼 수 있는 IAM 계정을 이용하여 콘솔에 로그인한다.\n2) 서비스 탭에서 'EC2'를 클릭하시오.\n3) 좌측 네비게이션에서 로드 밸런싱에 로드 밸런서클 릭하시오.\n4) ELB중 만료될 ELB를 클릭하시오\n5) SSL인증서의 리스터 탭을 클릭한 후 변경을 클릭하시오.\n6) 인증서 정보를 수정하시오."
    },
    "1.4.2": {
        "verification_method": "- AWS Console\n1) IAM 전체 사용자를 볼 수 있는 IAM 계정을 이용하여 콘솔에 로그인한다.\n2) 서비스 탭에서 'EC2'를 클릭하시오.\n3) 좌측 네비게이션에서 로드 밸런싱에 로드 밸런서를 클릭하시오.\n4) 나와 있는 ELB(Elastic Load Balancer)의 업로드 기간을 확인하여 2014년 4월 1일 이전에 업로드된 SSL/TLS 인증서가 있는지 확인하시오.",
        "action_method": "조치 불가능",
        "reference": [
            {
                "url": "https://ko.wikipedia.org/wiki/하트블리드",
                "item": "하트블리드(영어: Heartbleed)는 2014년 4월에 발견된 오픈 소스 암호화 라이브러리인 OpenSSL의 소프트웨어 버그이다."
            }
        ]
    },

    "2.1.1": [
        "$NAME1 사용자는 IAM $TYPE1 $NAME2 하위 $NAME3 $TYPE2 정책에 연결되어 있습니다.",
        {
            "action_method": [
                {
                    "url": "https://docs.aws.amazon.com/ko_kr/IAM/latest/UserGuide/access_policies_manage-delete.html"
                }
            ]
        }
    ],
    "2.1.2": [
        "$NAME1 그룹은 IAM $TYPE1 $NAME2 하위 $NAME3 $TYPE2 정책에 연결되어 있습니다.",
        {
            "action_method": [
                {
                    "url": "https://docs.aws.amazon.com/ko_kr/IAM/latest/UserGuide/access_policies_manage-delete.html"
                }
            ]
        }
    ],
    "2.1.3": [
        "$NAME1 역할은 IAM $TYPE1 $NAME2 하위 $NAME3 $TYPE2 정책에 연결되어 있습니다.",
        {
            "action_method": [
                {
                    "url": "https://docs.aws.amazon.com/ko_kr/IAM/latest/UserGuide/access_policies_manage-delete.html"
                }
            ]
        }
    ],

    "2.2.1": {
        "action_method": [
            {
                "url": "https://docs.aws.amazon.com/ko_kr/IAM/latest/UserGuide/id_users_manage.html#id_users_deleting",
                "item": "Delete IAM User"
            }
        ]
    },
    "2.2.2": {
        "action_method": [
            {
                "url": "https://docs.aws.amazon.com/ko_kr/IAM/latest/UserGuide/id_groups_manage_delete.html",
                "item": "Delete IAM Group"
            }
        ]
    },
    "2.2.3": {
        "action_method": [
            {
                "url": "https://docs.aws.amazon.com/ko_kr/IAM/latest/UserGuide/id_roles_manage_delete.html",
                "item": "Delete IAM Role"
            }
        ]
    },
    "2.2.4": {
        "action_method": [
            {
                "url": "https://docs.aws.amazon.com/ko_kr/IAM/latest/UserGuide/access_policies_manage-delete.html",
                "item": "Delete IAM Policy"
            }
        ]
    },
    "2.3.1": {
        "action_method": [
            {
                "url": "https://docs.aws.amazon.com/ko_kr/IAM/latest/UserGuide/id_users_manage.html#id_users_deleting",
                "item": "Delete IAM User"
            }
        ]
    },
    "2.3.2": {
        "action_method": [
            {
                "url": "https://docs.aws.amazon.com/ko_kr/IAM/latest/UserGuide/id_groups_manage_delete.html",
                "item": "Delete IAM Group"
            }
        ]
    },
    "2.3.3": {
        "action_method": [
            {
                "url": "https://docs.aws.amazon.com/ko_kr/IAM/latest/UserGuide/id_roles_manage_delete.html",
                "item": "Delete IAM Role"
            }
        ]
    },
    "2.3.4": {
        "action_method": [
            {
                "url": "https://docs.aws.amazon.com/ko_kr/IAM/latest/UserGuide/access_policies_manage-delete.html",
                "item": "Delete IAM Policy"
            }
        ]
    },

    "2.4.1": [
        "$NAME1 사용자는 IAM $TYPE1 $NAME2 하위 $NAME3 $TYPE2 정책에 연결되어 있습니다.",
        {
            "action_method": [
                {
                    "url": "https://docs.aws.amazon.com/ko_kr/IAM/latest/UserGuide/access_policies_manage-delete.html"
                }
            ]
        }
    ],

    "2.5.1": {
        "action_method": [
            {
                "url": "https://docs.aws.amazon.com/ko_kr/IAM/latest/UserGuide/access_policies_manage-delete.html",
                "item": "Delete IAM Policy"
            }
        ]
    },
}