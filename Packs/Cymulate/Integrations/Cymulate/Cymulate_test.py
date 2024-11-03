import demistomock as demisto
from Cymulate import cymulate_test, fetch_incidents, cymulate_get_incident_info, Client, CymulateModuleTypeEnum


BASE_URL = 'https://api.cymulate.com/v1/'

MOKE_TEST = {"success": True, "data": ["Phishing Awareness", "Web Application Firewall",
                                       "Lateral Movement", "Data Exfiltration",
                                       "Immediate Threats Intelligence", "Email Gateway",
                                       "Endpoint Security", "Web Gateway", "Full Kill-Chain APT"]}

FETCH_INCIDENTS_TEST = {"success": True,
                        "data": [
                            {
                                "Id": "5dbeaf53a910862fa859491e",
                                "Name": " Ursnif infection with Dridex and Powershell Empire",
                                "Timestamp": "03/11/2019 05:43:31",
                                "InProgress": False
                            },
                            {
                                "Id": "5dbea88c357ca849ac41bb2e",
                                "Name": "Pcap and malware for an ISC diary (Emotet + Trickbot)",
                                "Timestamp": "03/11/2019 05:14:36",
                                "InProgress": False
                            },
                            {
                                "Id": "5d528f78705e364e9055033c",
                                "Name": "BlackSquid Drops XMRig Miner",
                                "Timestamp": "13/08/2019 06:22:48",
                                "InProgress": False
                            },
                            {
                                "Id": "5d25dc5d86d73c22203d919f",
                                "Name": "dll2",
                                "Timestamp": "10/07/2019 08:38:53",
                                "InProgress": False
                            },
                            {
                                "Id": "5cc7109ca842693cc0f15588",
                                "Name": "hot files test 8",
                                "Timestamp": "29/04/2019 10:56:28",
                                "InProgress": False
                            },
                            {
                                "Id": "5c8e6cbf3dd9fe08186d7b64",
                                "Name": "Hancitor malspam infections from 2018-08-13 and 2018-08-14",
                                "Timestamp": "17/03/2019 11:50:23",
                                "InProgress": False
                            }
                        ]
                        }

CYMULATE_GET_INCIDENT_INFO_TEST = {"success": True,
                                   "data": [
                                       {
                                           "Module": "Immediate Threats Intelligence",
                                           "Penetration_Vector": "-",
                                           "Attack_Payload": "2019-07-08-Ursnif-binary-retrieved-by-Word-macro_"
                                                             "2b999360-a3f9-11e9-980e-633d1efd31f3.exe",
                                           "Name": " Ursnif infection with Dridex and Powershell Empire",
                                           "Timestamp": "03/11/2019 05:45:47",
                                           "Sha1": "ff57bfaed6db3379bbf69a19404a6e21668a7a52",
                                           "Sha256": "0894e82d9397d909099c98fe186354591ae86a73230700f462b72ae36c700ddf",
                                           "Md5": "ef99338df4078fab6e9a8cf6797a1d14",
                                           "Status": "Penetrated",
                                           "Attack_Vector": "Endpoint Security",
                                           "Attack_Type": "Antivirus",
                                           "Mitigation": "N/A",
                                           "Description": "N/A",
                                           "ID": "c1d33138a2101724889862152444ec7e",
                                           "Related_URLS": "N/A",
                                           "Related_Email_Addresses": "N/A"
                                       }
                                   ]
                                   }

TECHNICAL_INCIDENTS_IDS = ['5dbeaf53a910862fa859491e', '5dbea88c357ca849ac41bb2e', '5d528f78705e364e9055033c',
                           '5d25dc5d86d73c22203d919f', '5cc7109ca842693cc0f15588', '5c8e6cbf3dd9fe08186d7b64']

MOCK_TIMESTAMP = "2020-12-02T16%3A32%3A37"


ATTACK_ID = "5dbeaf53a910862fa859491e"


def local_get_last_run():
    return {}


def test_test_client(requests_mock):
    requests_mock.get(BASE_URL + 'user/modules', json=MOKE_TEST)

    client = Client(
        base_url=BASE_URL,
        headers={"x-token": 'RW#fdsfds34e343rdes'},
        verify=False)

    cymulate_test(client=client, is_fetch=False)


def test_fetch_incidents(mocker, requests_mock):
    requests_mock.get(BASE_URL + f'immediate-threats/ids?from={MOCK_TIMESTAMP}',
                      json=FETCH_INCIDENTS_TEST)

    for incident_id in TECHNICAL_INCIDENTS_IDS:
        requests_mock.get(BASE_URL + 'immediate-threats/attack/technical/' + incident_id,
                          json=CYMULATE_GET_INCIDENT_INFO_TEST)

    mocker.patch.object(demisto, 'params',
                        return_value={'fetch_time': MOCK_TIMESTAMP})
    mocker.patch.object(demisto, 'getLastRun', side_effect=local_get_last_run)

    client = Client(
        base_url=BASE_URL,
        headers={"x-token": 'RW#fdsfds34e343rdes'},
        verify=False)

    next_run, incidents, remain_incidents = fetch_incidents(client=client,
                                                            module_type=CymulateModuleTypeEnum.IMMEDIATE_THREATS,
                                                            last_run={'last_fetch': '2020-12-02T16:32:37'},
                                                            first_fetch_time={},
                                                            only_penatrated=False,
                                                            limit=20,
                                                            integration_context=None)

    assert len(incidents) == 6


def test_cymulate_get_incident_info(mocker, requests_mock):
    mocker.patch.object(demisto, 'args', return_value={"module_type": CymulateModuleTypeEnum.IMMEDIATE_THREATS.name,
                                                       "attack_id": ATTACK_ID})

    requests_mock.get(BASE_URL + 'immediate-threats/attack/technical/' + ATTACK_ID,
                      json=CYMULATE_GET_INCIDENT_INFO_TEST)

    client = Client(
        base_url=BASE_URL,
        headers={"x-token": 'RW#fdsfds34e343rdes'},
        verify=False)

    # Get incident's parent id
    attack_id = demisto.args().get('attack_id')

    technical_info = cymulate_get_incident_info(client=client, attack_id=attack_id)

    assert (technical_info[0]['ID'] == CYMULATE_GET_INCIDENT_INFO_TEST['data'][0]['ID'])
