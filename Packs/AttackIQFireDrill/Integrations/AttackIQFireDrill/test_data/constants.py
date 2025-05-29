class ResponseMock:
    def __init__(self, _json={}):
        self.status_code = 200
        self._json = _json

    def json(self):
        return self._json


# Dictionaries
DICT_1to5 = {"1": 1, "2": 2, "3": 3, "4": 4, "5": 5}
DICT_NESTED_123 = {"nested": {"1": 1, "2": 2, "3": 3}}
DICT_LST_AAB2B = {"aa_b": [{"2": 2}, {"2": 3}], "b": 4}
DICT_LST_NESTED = {"master": {"id": 1, "assets": [{"id": 1, "name": "a"}, {"id": 2, "name": "b"}]}}

TRANS_DICT_134 = {"1": "one", "3": "three", "4": "four"}
TRANS_DICT_NESTED_12 = {"nested.1": "one", "nested.2": "two"}
TRANS_DICT_NESTED_VAL_12 = {"1": "one.1", "2": "two"}
TRANS_DICT_LST_A2B = {"aa_b": {"2": "two"}, "b": "four"}
TRANS_DICT_LST_NESTED = {"master.id": "Master.ID", "master.assets": {"id": "ID", "name": "Name"}}

# Requests
ACTIVATE_ASS_RESP = {"message": "Successfully activated project c4e352ae-1506-4c74-bd90-853f02dd765a"}
GET_ASS_RESP = {
    "count": 1,
    "next": None,
    "previous": None,
    "results": [
        {
            "id": "2e53e597-0388-48bb-8eb8-00bb28874434",
            "name": "Arseny's ransomware project",
            "description": "Test of common ransomware variants",
            "start_date": None,
            "end_date": None,
            "project_state": "Inactive",
            "default_schedule": None,
            "project_template": {
                "id": "59d35f4a-2da0-4c4a-a08a-c30cb41dae6b",
                "template_name": "Ransomware Project",
                "template_description": "Variety of common ransomware variants",
                "project_name": "Ransomware Project",
                "project_description": "Test of common ransomware variants",
                "icon": "ransomware_template_icon.svg",
                "project_template_type": {
                    "id": "b1e7ac80-1417-4f7b-a387-35fb49f218c8",
                    "name": "Use Cases",
                    "description": "Showcase different use cases in which FireDrill can help",
                },
                "default_schedule": None,
                "report_types": [
                    {"id": "38f24061-a70f-415a-b378-bc9575b7ac6a", "name": "Security Assessment Differential Report"},
                    {"id": "986fce3c-89a5-47f0-843d-99ba269b576b", "name": "Security Assessment Detailed Report"},
                    {"id": "fdb6a5b9-ec10-4a5b-b387-7433ed4e78df", "name": "Ransomware Executive Summary"},
                ],
                "widgets": ["b955b352-e59f-4b8f-8c93-f88a7d5aa026", "938589ec-653c-45be-a7cc-6cd632387bb7"],
                "meta_data": {"hidden": True},
                "company": "906d5ec6-101c-4ae6-8906-b93ce0529060",
                "created": "2016-07-01T20:26:43.494459Z",
                "modified": "2019-02-19T03:31:54.393885Z",
            },
            "creator": "foo@test.com",
            "owner": "foo@test.com",
            "user": "foo@test.com",
            "created": "2019-09-02T11:51:57.507486Z",
            "modified": "2019-09-02T11:51:59.769959Z",
            "users": ["71e92cf9-5159-466c-8050-142d1ba279ea"],
            "groups": [],
            "default_asset_count": 0,
            "default_asset_group_count": 0,
            "master_job_count": 3,
            "meta_data": {"hidden": True},
        }
    ],
}
GET_ASS_EXECUTION_STATUS_RESP = {"message": False}
GET_TESTS_RESP = {
    "count": 1,
    "next": None,
    "previous": None,
    "results": [
        {
            "id": "9aed2cef-8c64-4e29-83b4-709de5963b66",
            "name": "Most Used Threat Actor Techniques",
            "description": None,
            "project": "8978fe24-607a-4815-a36a-89fb6191b318",
            "scenarios": [
                {"id": "fdef9f60-d933-4158-bfde-81c2d791b2a2", "name": "Persistence Through Startup Folder", "model_json": {}},
                {
                    "id": "04ed47b9-145c-46f6-9434-f9f5af27a2d2",
                    "name": "Execute Encoded Powershell Command",
                    "model_json": {"run_as_logged_in_user": False, "timeout": 10000},
                },
                {
                    "id": "a3098773-f2c1-4b32-8cba-2ed6d7ec0ba1",
                    "name": "Standard Application Layer Protocol",
                    "model_json": {
                        "ports_no_standard_protocols": ["443"],
                        "payload_type": ["safe", "malicious"],
                        "timeout": 30,
                        "ports_standard_protocols": ["21", "25", "53", "80"],
                    },
                },
                {"id": "59699d35-b268-41b5-bc00-ed8acc222b64", "name": "Scheduled Task Execution", "model_json": {}},
                {
                    "id": "cfbbd145-28a2-4ac3-a1e0-79abddfc9881",
                    "name": "Dump Windows Passwords with Original Mimikatz",
                    "model_json": {
                        "mimikatz_cred_types": [],
                        "show_all_cred_types": False,
                        "wce_cred_types": "lm_ntlm",
                        "use_custom_parameters": False,
                        "mimikatz_module": "sekurlsa",
                        "user_type": "all",
                        "gsecdump_cred_types": "sam_ad",
                        "pwdump7_cred_types": [],
                        "cred_types": ["all"],
                        "undetectable_mimikatz_cred_types": [],
                        "print_output": False,
                        "lazagne_cred_types": "browsers",
                        "pwd_dumping_tool": "mimikatz",
                    },
                },
                {
                    "id": "f73dd965-dc8c-4230-9745-a530b21c5333",
                    "name": "Remote File Copy Script",
                    "model_json": {
                        "scripts": [
                            {
                                "script_hash": "1ed3ee9d6aa12e67241be44f5e284de65c8ca297025cde2ee79bc4dc7f1f425a",
                                "exit_code": 0,
                                "platform": "windows",
                                "success_type": "with_exit_code",
                                "interpreter": "powershell.exe",
                                "script_files": "67211eac-1745-43c3-9fc9-9b99049b088c/remote_file_copy.ps1",
                            }
                        ]
                    },
                },
                {
                    "id": "8ca3ca07-b52b-4ede-af05-ce1eb8834454",
                    "name": "Command-Line Interface Script",
                    "model_json": {
                        "scripts": [
                            {
                                "script_hash": "4851bb8fdee02a8935a3ded79e39b6a0c2c9ab6bd5a94534a2524e50009c50e2",
                                "exit_code": 0,
                                "platform": "windows",
                                "success_type": "with_exit_code",
                                "interpreter": "cmd.exe",
                                "script_files": "8a354ed9-fc5e-4c5c-8b8b-47e5e66a3c4b/command_line_interface.bat",
                            }
                        ]
                    },
                },
                {
                    "id": "8e39c23c-aca4-4940-96bf-247723026e46",
                    "name": "File Deletion Script",
                    "model_json": {
                        "scripts": [
                            {
                                "script_hash": "6c670f90fba2fc5d6449c1948a5497ea7d0f53f1a3d4f1d26590d211b860adf6",
                                "exit_code": 0,
                                "platform": "windows",
                                "success_type": "with_exit_code",
                                "interpreter": "cmd.exe",
                                "script_files": "029d27bb-dc6d-4510-922b-9e564df1eca4/file_deletion.bat",
                            }
                        ]
                    },
                },
                {
                    "id": "5fbb5e71-6e35-4e2c-8dc6-7ee55be563dd",
                    "name": "System Information Discovery Script",
                    "model_json": {
                        "scripts": [
                            {
                                "script_hash": "d51e34a47a79465a0ef3916fe01fe667e8e4281ef3b676569e6a1a33419e51ea",
                                "exit_code": 0,
                                "platform": "windows",
                                "success_type": "with_exit_code",
                                "interpreter": "cmd.exe",
                                "script_files": "4be17c81-a0de-4a7e-acd2-b9bd9f9aeb1c/system_information_discovery.bat",
                            },
                            {
                                "script_hash": "b4e7c8a463c04cd1e45e1455af358185c09d144ef3c276ebd4a0fa4c628f153e",
                                "exit_code": 0,
                                "execute_as_user": False,
                                "platform": "linux",
                                "success_type": "with_exit_code",
                                "interpreter": "/bin/bash",
                                "script_files": "3b33ee2d-04a6-4a33-b0d5-15d0c91e5857/system_information_discovery.sh",
                            },
                        ]
                    },
                },
                {
                    "id": "1e46e621-2453-4aaa-85b7-ab67d0b37b8c",
                    "name": "Persistence Through Windows Registry",
                    "model_json": {
                        "registry": [
                            {
                                "data": "%SystemRoot%/attackiq_data.exe",
                                "value": "attackiq_value",
                                "key": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                            },
                            {
                                "data": "%SystemRoot%/attackiq_data.exe",
                                "value": "attackiq_value",
                                "key": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                            },
                            {
                                "data": "%APPDATA%/attackiq_data.dll",
                                "value": "attackiq_value",
                                "key": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects",  # noqa: E501
                            },
                            {
                                "data": "%PROGRAMFILES%/attackiq_texteditor.exe",
                                "value": "attackiq_texteditor",
                                "key": "HKEY_CLASSES_ROOT\\txtfile\\Shell\\Open\\command",
                            },
                        ]
                    },
                },
            ],
            "assets": [
                {
                    "id": "03e17460-849e-4b86-b6c6-ef0db72823ff",
                    "ipv4_address": "172.31.39.254",
                    "hostname": "ec2amaz-g4iu5no",
                    "product_name": "Windows Server 2016 Datacenter",
                    "modified": "2019-09-05T13:33:34.062040Z",
                    "status": "Active",
                }
            ],
            "asset_groups": [],
            "total_asset_count": 1,
            "cron_expression": None,
            "runnable": True,
            "last_result": "Failed",
            "scheduled_count": 10,
            "user": "foo@test.com",
            "created": "2019-09-05T08:47:38.273306Z",
            "modified": "2019-09-05T08:56:42.496002Z",
            "latest_instance_id": "0de2caab-1ec0-4907-948b-dca3dc65fe2c",
            "using_default_assets": True,
            "using_default_schedule": True,
        }
    ],
}
GET_TEST_STATUS_RESP = {"detected": 0, "failed": 9, "finished": True, "passed": 1, "errored": 0, "total": 10}
GET_TEST_RESULT_RESP = {
    "count": 1,
    "next": None,
    "previous": None,
    "results": [
        {
            "id": "5f044657-d0bc-48ab-afaf-98c6ae5a9e7f",
            "modified": "2019-09-03T14:22:46.747664Z",
            "project_name": "Arseny's ransomware project",
            "project_id": "c4e352ae-1506-4c74-bd90-853f02dd765a",
            "project_run_id": "74fc59ba-ec33-41c2-a63f-9a0188e3b4bb",
            "master_job": {
                "id": "1c350a5a-84f2-4938-93d8-cc31f0a99482",
                "name": "Ransomware Download",
                "assets": [
                    {
                        "id": "03e17460-849e-4b86-b6c6-ef0db72823ff",
                        "ipv4_address": "172.31.39.254",
                        "hostname": "ec2amaz-g4iu5no",
                        "product_name": "Windows Server 2016 Datacenter",
                        "modified": "2019-09-05T12:10:01.590138Z",
                    }
                ],
                "scenarios": [
                    {
                        "id": "ef72cfc8-796c-4a35-abea-547f0d898713",
                        "name": "Download Coverton Ransomware",
                        "description": "The Coverton ransomware has no known infection vector. After encryption, the ransomware deletes shadow volume copies and system restore points. A ransom note will then be created, explaining the the victim how to use the tor network and how to buy bitcoin. The authors demand a price of 1 bitcoin to decrypt and will threaten to double the price every week you do not pay. Unfortunately, the cryptography is solid so there is no decrypter available. This led some victims to pay the ransom. However, the decrypter they receive did not properly decrypt the files.",  # noqa: E501
                    }
                ],
            },
            "master_job_name": "Ransomware Download",
            "master_job_metadata": None,
            "instance_job": "24178034-cb69-442d-afd8-a7d87ae78eda",
            "instance_job_on_demand": True,
            "instance_job_run_all": True,
            "scenario_job_ref": 3874153,
            "scenario_scheduled_job_uuid": "6c757c3d-6e80-426e-94cb-625113845d8e",
            "scenario": {
                "id": "fc057ae4-c56d-4e9a-8c0f-9f22ec1e5576",
                "name": "Download SNSLock Ransomware",
                "description": "The SNSLock ransomware is spread through email spam campaigns. Upon infection, the ransomware will connect to it's C2 server and send user information such as system date and time, IP address, and MAC address. During infection, the ransomware will add a .RSNSlocked extension. After infection, it will drop an html file that contains all the information to pay $300 dollars using bitcoin.",  # noqa: E501
            },
            "scenario_args": {
                "check_if_executable": True,
                "sha256_hash": "597a14a76fc4d6315afa877ef87b68401de45d852e38f98c2f43986b4dca1c3a",
                "download_url": "https://malware.scenarios.aiqscenarioinfra.com/597a14a76fc4d6315afa877ef87b68401de45d852e38f98c2f43986b4dca1c3a/SNSLock",  # noqa: E501
            },
            "scenario_exe": "ai_python",
            "scenario_name": "Download SNSLock Ransomware",
            "scenario_type": 1,
            "asset": {
                "id": "03e17460-849e-4b86-b6c6-ef0db72823ff",
                "ipv4_address": "172.31.39.254",
                "hostname": "ec2amaz-g4iu5no",
                "product_name": "Windows Server 2016 Datacenter",
                "modified": "2019-09-05T12:10:01.590138Z",
            },
            "asset_hostname": "ec2amaz-g4iu5no",
            "asset_ipv4_address": "172.31.39.254",
            "asset_group": None,
            "asset_group_name": None,
            "scheduled_time": "2019-09-03T14:16:00Z",
            "sent_to_agent": True,
            "done": True,
            "canceled": False,
            "job_state_id": 7,
            "job_state_name": "Finished",
            "scenario_result_value": {
                "ai_scenario_outcome": 1,
                "ai_log_time": 1567520565441,
                "ai_python_process_id": 100,
                "ai_total_time_taken": 2.687,
                "ai_critical_phases_successful": 0,
                "ai_tracker_id": "125",
            },
            "outcome_id": 1,
            "outcome_name": "Passed",
            "sent_to_siem_connector": False,
            "result_id": "5f044657-d0bc-48ab-afaf-98c6ae5a9e7f",
            "company": "55b4e4cf-9cf9-4bef-8c21-6eb17f5bfc7d",
            "user": "efcc433f-c954-4855-b9f0-3c3beeefdbf6",
            "created": "2019-09-03T14:16:24.560022Z",
            "run_count": "",
            "scenario_scheduled_job": {
                "id": "5f044657-d0bc-48ab-afaf-98c6ae5a9e7f",
                "scenario_scheduled_job_uuid": "6c757c3d-6e80-426e-94cb-625113845d8e",
                "scenario_job": {
                    "id": "5f044657-d0bc-48ab-afaf-98c6ae5a9e7f",
                    "master_job": "1c350a5a-84f2-4938-93d8-cc31f0a99482",
                    "master_job_name": "Ransomware Download",
                    "project_name": "Arseny's ransomware project",
                    "project_id": "c4e352ae-1506-4c74-bd90-853f02dd765a",
                    "scenario": {
                        "id": "fc057ae4-c56d-4e9a-8c0f-9f22ec1e5576",
                        "name": "Download SNSLock Ransomware",
                        "description": "The SNSLock ransomware is spread through email spam campaigns. Upon infection, the ransomware will connect to it's C2 server and send user information such as system date and time, IP address, and MAC address. During infection, the ransomware will add a .RSNSlocked extension. After infection, it will drop an html file that contains all the information to pay $300 dollars using bitcoin.",  # noqa: E501
                        "scenario_type": "Attack",
                        "scenario_template": {
                            "id": "4f89d738-d253-452d-b944-99b41f8b2e07",
                            "zip_file": "https://static.attackiq.com/scenarios/4f89d738-d253-452d-b944-99b41f8b2e07/download_and_save_file-1.0.120.dev0.zip?v=1.0.8&Policy=eyJTdGF0ZW1lbnQiOlt7IlJlc291cmNlIjoiaHR0cHM6Ly9zdGF0aWMuYXR0YWNraXEuY29tL3NjZW5hcmlvcy80Zjg5ZDczOC1kMjUzLTQ1MmQtYjk0NC05OWI0MWY4YjJlMDcvZG93bmxvYWRfYW5kX3NhdmVfZmlsZS0xLjAuMTIwLmRldjAuemlwP3Y9MS4wLjgiLCJDb25kaXRpb24iOnsiRGF0ZUxlc3NUaGFuIjp7IkFXUzpFcG9jaFRpbWUiOjE1Njc2OTA5OTN9fX1dfQ__&Signature=H3KgpyE69Ysg3NzfkJIO-vYP1zpbqakKJZhnToPZ2PnzKw~x9~ihmQz1AKU6AGowwBN2l9fFHdigCZQ0wBdwt346MxUXVJpcjb6Wz4AVBieN9qmkfARA3SB7WCBF48HiOSLRqWJtpzBc~jqLrcGS4T-UPM5S~TEXX79~dTXg2ZJoor7FbqL-kaLX09N08r4o6XsKzB0HoVmleZ8x9b8AotgLYjbExYdLctgPnOcxWgGuJKRUtdYgW-loPf9V56yg1ngl59aA1Emgo74-BfUXGl5tgK4LPbvGQw7kg5rjM310vh3oze~h0oiE3IHHVNSW2pcsl4U7ELofUpFwE~-sUg__&Key-Pair-Id=APKAJY2DPWILXHPNCJTA",  # noqa: E501
                        },
                        "supported_platforms": {
                            "osx": ">=0.0",
                            "centos": ">=0.0",
                            "redhat": ">=0.0",
                            "windows": ">=0.0",
                            "linuxmint": ">=0.0",
                            "ubuntu": ">=0.0",
                            "debian": ">=0.0",
                            "fedora": ">=0.0",
                        },
                    },
                    "asset": {
                        "id": "03e17460-849e-4b86-b6c6-ef0db72823ff",
                        "ipv4_address": "172.31.39.254",
                        "hostname": "ec2amaz-g4iu5no",
                        "product_name": "Windows Server 2016 Datacenter",
                        "modified": "2019-09-05T12:10:01.590138Z",
                    },
                    "modified": "2019-09-03T14:22:46.747664Z",
                },
                "job_state": "Finished",
                "modified": "2019-09-03T14:22:46.747664Z",
            },
            "config_map_values": {},
            "cancellable": True,
        }
    ],
}
RUN_ALL_TESTS_RESP = {
    "message": "Successfully started running all tests in project: ATT&CK by the Numbers @ NOVA BSides 2019",
    "started_at": "2019-09-05T13:33:29.621693",
}

# Results
ACTIVATE_ASS_RES = ACTIVATE_ASS_RESP["message"]
GET_ASS_RESULT = {
    "Type": 1,
    "HumanReadable": "### AttackIQ Assessments Page 1/1\n|Id|Name|Description|User|Created|Modified|\n|---|---|---|---|---|---|\n| 2e53e597-0388-48bb-8eb8-00bb28874434 | Arseny's ransomware project | Test of common ransomware variants | foo@test.com | 2019-09-02T11:51:57.507486Z | 2019-09-02T11:51:59.769959Z |\n",
    "ContentsFormat": "json",
    "Contents": {
        "count": 1,
        "next": None,
        "previous": None,
        "results": [
            {
                "id": "2e53e597-0388-48bb-8eb8-00bb28874434",
                "name": "Arseny's ransomware project",
                "description": "Test of common ransomware variants",
                "start_date": None,
                "end_date": None,
                "project_state": "Inactive",
                "default_schedule": None,
                "project_template": {
                    "id": "59d35f4a-2da0-4c4a-a08a-c30cb41dae6b",
                    "template_name": "Ransomware Project",
                    "template_description": "Variety of common ransomware variants",
                    "project_name": "Ransomware Project",
                    "project_description": "Test of common ransomware variants",
                    "icon": "ransomware_template_icon.svg",
                    "project_template_type": {
                        "id": "b1e7ac80-1417-4f7b-a387-35fb49f218c8",
                        "name": "Use Cases",
                        "description": "Showcase different use cases in which FireDrill can help",
                    },
                    "default_schedule": None,
                    "report_types": [
                        {"id": "38f24061-a70f-415a-b378-bc9575b7ac6a", "name": "Security Assessment Differential Report"},
                        {"id": "986fce3c-89a5-47f0-843d-99ba269b576b", "name": "Security Assessment Detailed Report"},
                        {"id": "fdb6a5b9-ec10-4a5b-b387-7433ed4e78df", "name": "Ransomware Executive Summary"},
                    ],
                    "widgets": ["b955b352-e59f-4b8f-8c93-f88a7d5aa026", "938589ec-653c-45be-a7cc-6cd632387bb7"],
                    "meta_data": {"hidden": True},
                    "company": "906d5ec6-101c-4ae6-8906-b93ce0529060",
                    "created": "2016-07-01T20:26:43.494459Z",
                    "modified": "2019-02-19T03:31:54.393885Z",
                },
                "creator": "foo@test.com",
                "owner": "foo@test.com",
                "user": "foo@test.com",
                "created": "2019-09-02T11:51:57.507486Z",
                "modified": "2019-09-02T11:51:59.769959Z",
                "users": ["71e92cf9-5159-466c-8050-142d1ba279ea"],
                "groups": [],
                "default_asset_count": 0,
                "default_asset_group_count": 0,
                "master_job_count": 3,
                "meta_data": {"hidden": True},
            }
        ],
    },
    "EntryContext": {
        "AttackIQ.Assessment(val.Id === obj.Id)": [
            {
                "Id": "2e53e597-0388-48bb-8eb8-00bb28874434",
                "Name": "Arseny's ransomware project",
                "User": "foo@test.com",
                "Users": ["71e92cf9-5159-466c-8050-142d1ba279ea"],
                "Owner": "foo@test.com",
                "Groups": [],
                "Creator": "foo@test.com",
                "Created": "2019-09-02T11:51:57.507486Z",
                "EndDate": None,
                "Modified": "2019-09-02T11:51:59.769959Z",
                "StartDate": None,
                "Description": "Test of common ransomware variants",
                "AssessmentState": "Inactive",
                "MasterJobCount": 3,
                "DefaultSchedule": None,
                "DefaultAssetCount": 0,
                "AssessmentTemplateId": "59d35f4a-2da0-4c4a-a08a-c30cb41dae6b",
                "DefaultAssetGroupCount": 0,
                "AssessmentTemplateCompany": "906d5ec6-101c-4ae6-8906-b93ce0529060",
                "AssessmentTemplateCreated": "2016-07-01T20:26:43.494459Z",
                "AssessmentTemplateModified": "2019-02-19T03:31:54.393885Z",
                "AssessmentTemplateName": "Ransomware Project",
                "AssessmentTemplateDefaultSchedule": None,
                "AssessmentTemplateDescription": "Variety of common ransomware variants",
            }
        ],
        "AttackIQ.Assessment(val.Count).Count": 1,
        "AttackIQ.Assessment(val.RemainingPages).RemainingPages": 0,
    },
    "IgnoreAutoExtract": False,
    "IndicatorTimeline": None,
}  # noqa: E501
GET_ASS_EXECUTION_RESULT = {
    "Type": 1,
    "HumanReadable": "Assessment 1 execution is not running.",
    "ContentsFormat": "json",
    "Contents": {"message": False},
    "EntryContext": {"AttackIQ.Assessment(val.Id === obj.Id)": {"Running": False, "Id": 1}},
    "IgnoreAutoExtract": False,
    "IndicatorTimeline": None,
}
GET_TEST_RESULT = {
    "Type": 1,
    "HumanReadable": "# Assessment None tests\n## Page 1 / 1\n### Test - Most Used Threat Actor Techniques\n|Id|Name|Created|Modified|Runnable|Last Result|\n|---|---|---|---|---|---|\n| 9aed2cef-8c64-4e29-83b4-709de5963b66 | Most Used Threat Actor Techniques | 2019-09-05T08:47:38.273306Z | 2019-09-05T08:56:42.496002Z | true | Failed |\n### Assets (Most Used Threat Actor Techniques)\n|Hostname|Id|Ipv4Address|Modified|ProductName|Status|\n|---|---|---|---|---|---|\n| ec2amaz-g4iu5no | 03e17460-849e-4b86-b6c6-ef0db72823ff | 172.31.39.254 | 2019-09-05T13:33:34.062040Z | Windows Server 2016 Datacenter | Active |\n### Scenarios (Most Used Threat Actor Techniques)\n|Id|Name|\n|---|---|\n| fdef9f60-d933-4158-bfde-81c2d791b2a2 | Persistence Through Startup Folder |\n| 04ed47b9-145c-46f6-9434-f9f5af27a2d2 | Execute Encoded Powershell Command |\n| a3098773-f2c1-4b32-8cba-2ed6d7ec0ba1 | Standard Application Layer Protocol |\n| 59699d35-b268-41b5-bc00-ed8acc222b64 | Scheduled Task Execution |\n| cfbbd145-28a2-4ac3-a1e0-79abddfc9881 | Dump Windows Passwords with Original Mimikatz |\n| f73dd965-dc8c-4230-9745-a530b21c5333 | Remote File Copy Script |\n| 8ca3ca07-b52b-4ede-af05-ce1eb8834454 | Command-Line Interface Script |\n| 8e39c23c-aca4-4940-96bf-247723026e46 | File Deletion Script |\n| 5fbb5e71-6e35-4e2c-8dc6-7ee55be563dd | System Information Discovery Script |\n| 1e46e621-2453-4aaa-85b7-ab67d0b37b8c | Persistence Through Windows Registry |\n",
    "ContentsFormat": "json",
    "Contents": {
        "count": 1,
        "next": None,
        "previous": None,
        "results": [
            {
                "id": "9aed2cef-8c64-4e29-83b4-709de5963b66",
                "name": "Most Used Threat Actor Techniques",
                "description": None,
                "project": "8978fe24-607a-4815-a36a-89fb6191b318",
                "scenarios": [
                    {
                        "id": "fdef9f60-d933-4158-bfde-81c2d791b2a2",
                        "name": "Persistence Through Startup Folder",
                        "model_json": {},
                    },
                    {
                        "id": "04ed47b9-145c-46f6-9434-f9f5af27a2d2",
                        "name": "Execute Encoded Powershell Command",
                        "model_json": {"run_as_logged_in_user": False, "timeout": 10000},
                    },
                    {
                        "id": "a3098773-f2c1-4b32-8cba-2ed6d7ec0ba1",
                        "name": "Standard Application Layer Protocol",
                        "model_json": {
                            "ports_no_standard_protocols": ["443"],
                            "payload_type": ["safe", "malicious"],
                            "timeout": 30,
                            "ports_standard_protocols": ["21", "25", "53", "80"],
                        },
                    },
                    {"id": "59699d35-b268-41b5-bc00-ed8acc222b64", "name": "Scheduled Task Execution", "model_json": {}},
                    {
                        "id": "cfbbd145-28a2-4ac3-a1e0-79abddfc9881",
                        "name": "Dump Windows Passwords with Original Mimikatz",
                        "model_json": {
                            "mimikatz_cred_types": [],
                            "show_all_cred_types": False,
                            "wce_cred_types": "lm_ntlm",
                            "use_custom_parameters": False,
                            "mimikatz_module": "sekurlsa",
                            "user_type": "all",
                            "gsecdump_cred_types": "sam_ad",
                            "pwdump7_cred_types": [],
                            "cred_types": ["all"],
                            "undetectable_mimikatz_cred_types": [],
                            "print_output": False,
                            "lazagne_cred_types": "browsers",
                            "pwd_dumping_tool": "mimikatz",
                        },
                    },
                    {
                        "id": "f73dd965-dc8c-4230-9745-a530b21c5333",
                        "name": "Remote File Copy Script",
                        "model_json": {
                            "scripts": [
                                {
                                    "script_hash": "1ed3ee9d6aa12e67241be44f5e284de65c8ca297025cde2ee79bc4dc7f1f425a",
                                    "exit_code": 0,
                                    "platform": "windows",
                                    "success_type": "with_exit_code",
                                    "interpreter": "powershell.exe",
                                    "script_files": "67211eac-1745-43c3-9fc9-9b99049b088c/remote_file_copy.ps1",
                                }
                            ]
                        },
                    },
                    {
                        "id": "8ca3ca07-b52b-4ede-af05-ce1eb8834454",
                        "name": "Command-Line Interface Script",
                        "model_json": {
                            "scripts": [
                                {
                                    "script_hash": "4851bb8fdee02a8935a3ded79e39b6a0c2c9ab6bd5a94534a2524e50009c50e2",
                                    "exit_code": 0,
                                    "platform": "windows",
                                    "success_type": "with_exit_code",
                                    "interpreter": "cmd.exe",
                                    "script_files": "8a354ed9-fc5e-4c5c-8b8b-47e5e66a3c4b/command_line_interface.bat",
                                }
                            ]
                        },
                    },
                    {
                        "id": "8e39c23c-aca4-4940-96bf-247723026e46",
                        "name": "File Deletion Script",
                        "model_json": {
                            "scripts": [
                                {
                                    "script_hash": "6c670f90fba2fc5d6449c1948a5497ea7d0f53f1a3d4f1d26590d211b860adf6",
                                    "exit_code": 0,
                                    "platform": "windows",
                                    "success_type": "with_exit_code",
                                    "interpreter": "cmd.exe",
                                    "script_files": "029d27bb-dc6d-4510-922b-9e564df1eca4/file_deletion.bat",
                                }
                            ]
                        },
                    },
                    {
                        "id": "5fbb5e71-6e35-4e2c-8dc6-7ee55be563dd",
                        "name": "System Information Discovery Script",
                        "model_json": {
                            "scripts": [
                                {
                                    "script_hash": "d51e34a47a79465a0ef3916fe01fe667e8e4281ef3b676569e6a1a33419e51ea",
                                    "exit_code": 0,
                                    "platform": "windows",
                                    "success_type": "with_exit_code",
                                    "interpreter": "cmd.exe",
                                    "script_files": "4be17c81-a0de-4a7e-acd2-b9bd9f9aeb1c/system_information_discovery.bat",
                                },
                                {
                                    "script_hash": "b4e7c8a463c04cd1e45e1455af358185c09d144ef3c276ebd4a0fa4c628f153e",
                                    "exit_code": 0,
                                    "execute_as_user": False,
                                    "platform": "linux",
                                    "success_type": "with_exit_code",
                                    "interpreter": "/bin/bash",
                                    "script_files": "3b33ee2d-04a6-4a33-b0d5-15d0c91e5857/system_information_discovery.sh",
                                },
                            ]
                        },
                    },
                    {
                        "id": "1e46e621-2453-4aaa-85b7-ab67d0b37b8c",
                        "name": "Persistence Through Windows Registry",
                        "model_json": {
                            "registry": [
                                {
                                    "data": "%SystemRoot%/attackiq_data.exe",
                                    "value": "attackiq_value",
                                    "key": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                                },
                                {
                                    "data": "%SystemRoot%/attackiq_data.exe",
                                    "value": "attackiq_value",
                                    "key": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                                },
                                {
                                    "data": "%APPDATA%/attackiq_data.dll",
                                    "value": "attackiq_value",
                                    "key": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects",
                                },
                                {
                                    "data": "%PROGRAMFILES%/attackiq_texteditor.exe",
                                    "value": "attackiq_texteditor",
                                    "key": "HKEY_CLASSES_ROOT\\txtfile\\Shell\\Open\\command",
                                },
                            ]
                        },
                    },
                ],
                "assets": [
                    {
                        "id": "03e17460-849e-4b86-b6c6-ef0db72823ff",
                        "ipv4_address": "172.31.39.254",
                        "hostname": "ec2amaz-g4iu5no",
                        "product_name": "Windows Server 2016 Datacenter",
                        "modified": "2019-09-05T13:33:34.062040Z",
                        "status": "Active",
                    }
                ],
                "asset_groups": [],
                "total_asset_count": 1,
                "cron_expression": None,
                "runnable": True,
                "last_result": "Failed",
                "scheduled_count": 10,
                "user": "foo@test.com",
                "created": "2019-09-05T08:47:38.273306Z",
                "modified": "2019-09-05T08:56:42.496002Z",
                "latest_instance_id": "0de2caab-1ec0-4907-948b-dca3dc65fe2c",
                "using_default_assets": True,
                "using_default_schedule": True,
            }
        ],
    },
    "EntryContext": {
        "AttackIQTest(val.Id === obj.Id)": [
            {
                "Id": "9aed2cef-8c64-4e29-83b4-709de5963b66",
                "Name": "Most Used Threat Actor Techniques",
                "Description": None,
                "Assessment": "8978fe24-607a-4815-a36a-89fb6191b318",
                "TotalAssetCount": 1,
                "CronExpression": None,
                "Runnable": True,
                "LastResult": "Failed",
                "User": "foo@test.com",
                "Created": "2019-09-05T08:47:38.273306Z",
                "Modified": "2019-09-05T08:56:42.496002Z",
                "UsingDefaultSchedule": True,
                "UsingDefaultAssets": True,
                "LatestInstanceId": "0de2caab-1ec0-4907-948b-dca3dc65fe2c",
                "Scenarios": [
                    {"Name": "Persistence Through Startup Folder", "Id": "fdef9f60-d933-4158-bfde-81c2d791b2a2"},
                    {"Name": "Execute Encoded Powershell Command", "Id": "04ed47b9-145c-46f6-9434-f9f5af27a2d2"},
                    {"Name": "Standard Application Layer Protocol", "Id": "a3098773-f2c1-4b32-8cba-2ed6d7ec0ba1"},
                    {"Name": "Scheduled Task Execution", "Id": "59699d35-b268-41b5-bc00-ed8acc222b64"},
                    {"Name": "Dump Windows Passwords with Original Mimikatz", "Id": "cfbbd145-28a2-4ac3-a1e0-79abddfc9881"},
                    {"Name": "Remote File Copy Script", "Id": "f73dd965-dc8c-4230-9745-a530b21c5333"},
                    {"Name": "Command-Line Interface Script", "Id": "8ca3ca07-b52b-4ede-af05-ce1eb8834454"},
                    {"Name": "File Deletion Script", "Id": "8e39c23c-aca4-4940-96bf-247723026e46"},
                    {"Name": "System Information Discovery Script", "Id": "5fbb5e71-6e35-4e2c-8dc6-7ee55be563dd"},
                    {"Name": "Persistence Through Windows Registry", "Id": "1e46e621-2453-4aaa-85b7-ab67d0b37b8c"},
                ],
                "Assets": [
                    {
                        "Id": "03e17460-849e-4b86-b6c6-ef0db72823ff",
                        "Ipv4Address": "172.31.39.254",
                        "Hostname": "ec2amaz-g4iu5no",
                        "ProductName": "Windows Server 2016 Datacenter",
                        "Modified": "2019-09-05T13:33:34.062040Z",
                        "Status": "Active",
                    }
                ],
            }
        ],
        "AttackIQTest(val.Count).Count": 1,
        "AttackIQTest(val.RemainingPages).RemainingPages": 0,
    },
    "IgnoreAutoExtract": False,
    "IndicatorTimeline": None,
}  # noqa: E501
GET_TEST_STATUS_RESULT = {
    "Type": 1,
    "HumanReadable": "### Test 1 status\n|Detected|Errored|Failed|Finished|Id|Passed|Total|\n|---|---|---|---|---|---|---|\n| 0 | 0 | 9 | true | 1 | 1 | 10 |\n",
    "ContentsFormat": "json",
    "Contents": {"detected": 0, "failed": 9, "finished": True, "passed": 1, "errored": 0, "total": 10},
    "EntryContext": {
        "AttackIQTest(val.Id === obj.Id)": {
            "Detected": 0,
            "Failed": 9,
            "Finished": True,
            "Passed": 1,
            "Errored": 0,
            "Total": 10,
            "Id": 1,
        }
    },
    "IgnoreAutoExtract": False,
    "IndicatorTimeline": None,
}  # noqa: E501
GET_TEST_RESULT_RESULT = {
    "Type": 1,
    "HumanReadable": "### Test Results for None\n ### Page 1/1\n|Assessment Name|Scenario Name|Hostname|Asset IP|Job State|Modified|Outcome|\n|---|---|---|---|---|---|---|\n| Arseny's ransomware project | Download SNSLock Ransomware | ec2amaz-g4iu5no | 172.31.39.254 | Finished | 2019-09-03T14:22:46.747664Z |  |\n",
    "ContentsFormat": "json",
    "Contents": {
        "count": 1,
        "next": None,
        "previous": None,
        "results": [
            {
                "id": "5f044657-d0bc-48ab-afaf-98c6ae5a9e7f",
                "modified": "2019-09-03T14:22:46.747664Z",
                "project_name": "Arseny's ransomware project",
                "project_id": "c4e352ae-1506-4c74-bd90-853f02dd765a",
                "project_run_id": "74fc59ba-ec33-41c2-a63f-9a0188e3b4bb",
                "master_job": {
                    "id": "1c350a5a-84f2-4938-93d8-cc31f0a99482",
                    "name": "Ransomware Download",
                    "assets": [
                        {
                            "id": "03e17460-849e-4b86-b6c6-ef0db72823ff",
                            "ipv4_address": "172.31.39.254",
                            "hostname": "ec2amaz-g4iu5no",
                            "product_name": "Windows Server 2016 Datacenter",
                            "modified": "2019-09-05T12:10:01.590138Z",
                        }
                    ],
                    "scenarios": [
                        {
                            "id": "ef72cfc8-796c-4a35-abea-547f0d898713",
                            "name": "Download Coverton Ransomware",
                            "description": "The Coverton ransomware has no known infection vector. After encryption, the ransomware deletes shadow volume copies and system restore points. A ransom note will then be created, explaining the the victim how to use the tor network and how to buy bitcoin. The authors demand a price of 1 bitcoin to decrypt and will threaten to double the price every week you do not pay. Unfortunately, the cryptography is solid so there is no decrypter available. This led some victims to pay the ransom. However, the decrypter they receive did not properly decrypt the files.",
                        }
                    ],
                },
                "master_job_name": "Ransomware Download",
                "master_job_metadata": None,
                "instance_job": "24178034-cb69-442d-afd8-a7d87ae78eda",
                "instance_job_on_demand": True,
                "instance_job_run_all": True,
                "scenario_job_ref": 3874153,
                "scenario_scheduled_job_uuid": "6c757c3d-6e80-426e-94cb-625113845d8e",
                "scenario": {
                    "id": "fc057ae4-c56d-4e9a-8c0f-9f22ec1e5576",
                    "name": "Download SNSLock Ransomware",
                    "description": "The SNSLock ransomware is spread through email spam campaigns. Upon infection, the ransomware will connect to it's C2 server and send user information such as system date and time, IP address, and MAC address. During infection, the ransomware will add a .RSNSlocked extension. After infection, it will drop an html file that contains all the information to pay $300 dollars using bitcoin.",
                },
                "scenario_args": {
                    "check_if_executable": True,
                    "sha256_hash": "597a14a76fc4d6315afa877ef87b68401de45d852e38f98c2f43986b4dca1c3a",
                    "download_url": "https://malware.scenarios.aiqscenarioinfra.com/597a14a76fc4d6315afa877ef87b68401de45d852e38f98c2f43986b4dca1c3a/SNSLock",
                },
                "scenario_exe": "ai_python",
                "scenario_name": "Download SNSLock Ransomware",
                "scenario_type": 1,
                "asset": {
                    "id": "03e17460-849e-4b86-b6c6-ef0db72823ff",
                    "ipv4_address": "172.31.39.254",
                    "hostname": "ec2amaz-g4iu5no",
                    "product_name": "Windows Server 2016 Datacenter",
                    "modified": "2019-09-05T12:10:01.590138Z",
                },
                "asset_hostname": "ec2amaz-g4iu5no",
                "asset_ipv4_address": "172.31.39.254",
                "asset_group": None,
                "asset_group_name": None,
                "scheduled_time": "2019-09-03T14:16:00Z",
                "sent_to_agent": True,
                "done": True,
                "canceled": False,
                "job_state_id": 7,
                "job_state_name": "Finished",
                "scenario_result_value": {
                    "ai_scenario_outcome": 1,
                    "ai_log_time": 1567520565441,
                    "ai_python_process_id": 100,
                    "ai_total_time_taken": 2.687,
                    "ai_critical_phases_successful": 0,
                    "ai_tracker_id": "125",
                },
                "outcome_id": 1,
                "outcome_name": "Passed",
                "sent_to_siem_connector": False,
                "result_id": "5f044657-d0bc-48ab-afaf-98c6ae5a9e7f",
                "company": "55b4e4cf-9cf9-4bef-8c21-6eb17f5bfc7d",
                "user": "efcc433f-c954-4855-b9f0-3c3beeefdbf6",
                "created": "2019-09-03T14:16:24.560022Z",
                "run_count": "",
                "scenario_scheduled_job": {
                    "id": "5f044657-d0bc-48ab-afaf-98c6ae5a9e7f",
                    "scenario_scheduled_job_uuid": "6c757c3d-6e80-426e-94cb-625113845d8e",
                    "scenario_job": {
                        "id": "5f044657-d0bc-48ab-afaf-98c6ae5a9e7f",
                        "master_job": "1c350a5a-84f2-4938-93d8-cc31f0a99482",
                        "master_job_name": "Ransomware Download",
                        "project_name": "Arseny's ransomware project",
                        "project_id": "c4e352ae-1506-4c74-bd90-853f02dd765a",
                        "scenario": {
                            "id": "fc057ae4-c56d-4e9a-8c0f-9f22ec1e5576",
                            "name": "Download SNSLock Ransomware",
                            "description": "The SNSLock ransomware is spread through email spam campaigns. Upon infection, the ransomware will connect to it's C2 server and send user information such as system date and time, IP address, and MAC address. During infection, the ransomware will add a .RSNSlocked extension. After infection, it will drop an html file that contains all the information to pay $300 dollars using bitcoin.",
                            "scenario_type": "Attack",
                            "scenario_template": {
                                "id": "4f89d738-d253-452d-b944-99b41f8b2e07",
                                "zip_file": "https://static.attackiq.com/scenarios/4f89d738-d253-452d-b944-99b41f8b2e07/download_and_save_file-1.0.120.dev0.zip?v=1.0.8&Policy=eyJTdGF0ZW1lbnQiOlt7IlJlc291cmNlIjoiaHR0cHM6Ly9zdGF0aWMuYXR0YWNraXEuY29tL3NjZW5hcmlvcy80Zjg5ZDczOC1kMjUzLTQ1MmQtYjk0NC05OWI0MWY4YjJlMDcvZG93bmxvYWRfYW5kX3NhdmVfZmlsZS0xLjAuMTIwLmRldjAuemlwP3Y9MS4wLjgiLCJDb25kaXRpb24iOnsiRGF0ZUxlc3NUaGFuIjp7IkFXUzpFcG9jaFRpbWUiOjE1Njc2OTA5OTN9fX1dfQ__&Signature=H3KgpyE69Ysg3NzfkJIO-vYP1zpbqakKJZhnToPZ2PnzKw~x9~ihmQz1AKU6AGowwBN2l9fFHdigCZQ0wBdwt346MxUXVJpcjb6Wz4AVBieN9qmkfARA3SB7WCBF48HiOSLRqWJtpzBc~jqLrcGS4T-UPM5S~TEXX79~dTXg2ZJoor7FbqL-kaLX09N08r4o6XsKzB0HoVmleZ8x9b8AotgLYjbExYdLctgPnOcxWgGuJKRUtdYgW-loPf9V56yg1ngl59aA1Emgo74-BfUXGl5tgK4LPbvGQw7kg5rjM310vh3oze~h0oiE3IHHVNSW2pcsl4U7ELofUpFwE~-sUg__&Key-Pair-Id=APKAJY2DPWILXHPNCJTA",
                            },
                            "supported_platforms": {
                                "osx": ">=0.0",
                                "centos": ">=0.0",
                                "redhat": ">=0.0",
                                "windows": ">=0.0",
                                "linuxmint": ">=0.0",
                                "ubuntu": ">=0.0",
                                "debian": ">=0.0",
                                "fedora": ">=0.0",
                            },
                        },
                        "asset": {
                            "id": "03e17460-849e-4b86-b6c6-ef0db72823ff",
                            "ipv4_address": "172.31.39.254",
                            "hostname": "ec2amaz-g4iu5no",
                            "product_name": "Windows Server 2016 Datacenter",
                            "modified": "2019-09-05T12:10:01.590138Z",
                        },
                        "modified": "2019-09-03T14:22:46.747664Z",
                    },
                    "job_state": "Finished",
                    "modified": "2019-09-03T14:22:46.747664Z",
                },
                "config_map_values": {},
                "cancellable": True,
            }
        ],
    },
    "EntryContext": {
        "AttackIQTestResult(val.Id === obj.Id)": [
            {
                "Id": "5f044657-d0bc-48ab-afaf-98c6ae5a9e7f",
                "Modified": "2019-09-03T14:22:46.747664Z",
                "Assessment": {"Id": "c4e352ae-1506-4c74-bd90-853f02dd765a", "Name": "Arseny's ransomware project"},
                "Scenario": {
                    "Id": "fc057ae4-c56d-4e9a-8c0f-9f22ec1e5576",
                    "Name": "Download SNSLock Ransomware",
                    "Description": "The SNSLock ransomware is spread through email spam campaigns. Upon infection, the ransomware will connect to it's C2 server and send user information such as system date and time, IP address, and MAC address. During infection, the ransomware will add a .RSNSlocked extension. After infection, it will drop an html file that contains all the information to pay $300 dollars using bitcoin.",
                },
                "Asset": {
                    "Id": "03e17460-849e-4b86-b6c6-ef0db72823ff",
                    "Ipv4Address": "172.31.39.254",
                    "Hostname": "ec2amaz-g4iu5no",
                    "ProductName": "Windows Server 2016 Datacenter",
                    "Modified": "2019-09-05T12:10:01.590138Z",
                    "AssetGroup": None,
                },
                "JobState": "Finished",
                "Outcome": "Passed",
            }
        ],
        "AttackIQTestResult(val.Count).Count": 1,
        "AttackIQTestResult(val.RemainingPages).RemainingPages": 0,
    },
    "IgnoreAutoExtract": False,
    "IndicatorTimeline": None,
}  # noqa: E501
GET_ASS_BY_ID_RESULT = {
    "Type": 1,
    "HumanReadable": "### AttackIQ Assessment 1\n|Id|Name|Description|User|Created|Modified|\n|---|---|---|---|---|---|\n|  |  |  |  |  |  |\n",
    "ContentsFormat": "json",
    "Contents": {
        "count": 1,
        "next": None,
        "previous": None,
        "results": [
            {
                "id": "2e53e597-0388-48bb-8eb8-00bb28874434",
                "name": "Arseny's ransomware project",
                "description": "Test of common ransomware variants",
                "start_date": None,
                "end_date": None,
                "project_state": "Inactive",
                "default_schedule": None,
                "project_template": {
                    "id": "59d35f4a-2da0-4c4a-a08a-c30cb41dae6b",
                    "template_name": "Ransomware Project",
                    "template_description": "Variety of common ransomware variants",
                    "project_name": "Ransomware Project",
                    "project_description": "Test of common ransomware variants",
                    "icon": "ransomware_template_icon.svg",
                    "project_template_type": {
                        "id": "b1e7ac80-1417-4f7b-a387-35fb49f218c8",
                        "name": "Use Cases",
                        "description": "Showcase different use cases in which FireDrill can help",
                    },
                    "default_schedule": None,
                    "report_types": [
                        {"id": "38f24061-a70f-415a-b378-bc9575b7ac6a", "name": "Security Assessment Differential Report"},
                        {"id": "986fce3c-89a5-47f0-843d-99ba269b576b", "name": "Security Assessment Detailed Report"},
                        {"id": "fdb6a5b9-ec10-4a5b-b387-7433ed4e78df", "name": "Ransomware Executive Summary"},
                    ],
                    "widgets": ["b955b352-e59f-4b8f-8c93-f88a7d5aa026", "938589ec-653c-45be-a7cc-6cd632387bb7"],
                    "meta_data": {"hidden": True},
                    "company": "906d5ec6-101c-4ae6-8906-b93ce0529060",
                    "created": "2016-07-01T20:26:43.494459Z",
                    "modified": "2019-02-19T03:31:54.393885Z",
                },
                "creator": "foo@test.com",
                "owner": "foo@test.com",
                "user": "foo@test.com",
                "created": "2019-09-02T11:51:57.507486Z",
                "modified": "2019-09-02T11:51:59.769959Z",
                "users": ["71e92cf9-5159-466c-8050-142d1ba279ea"],
                "groups": [],
                "default_asset_count": 0,
                "default_asset_group_count": 0,
                "master_job_count": 3,
                "meta_data": {"hidden": True},
            }
        ],
    },
    "EntryContext": {
        "AttackIQ.Assessment(val.Id === obj.Id)": {
            "Id": None,
            "Name": None,
            "User": None,
            "Users": None,
            "Owner": None,
            "Groups": None,
            "Creator": None,
            "Created": None,
            "EndDate": None,
            "Modified": None,
            "StartDate": None,
            "Description": None,
            "AssessmentState": None,
            "MasterJobCount": None,
            "DefaultSchedule": None,
            "DefaultAssetCount": None,
            "AssessmentTemplateId": None,
            "DefaultAssetGroupCount": None,
            "AssessmentTemplateCompany": None,
            "AssessmentTemplateCreated": None,
            "AssessmentTemplateModified": None,
            "AssessmentTemplateName": None,
            "AssessmentTemplateDefaultSchedule": None,
            "AssessmentTemplateDescription": None,
        }
    },
    "IgnoreAutoExtract": False,
    "IndicatorTimeline": None,
}  # noqa: E501
RUN_ALL_TESTS_RESULT = "Successfully started running all tests in project: ATT&CK by the Numbers @ NOVA BSides 2019"
