import pytest
from Smokescreen_IllusionBLACK import Client

CLIENT = Client("", False, "", "", False)

RECON_DECOYS = {
    "items": [
        {
            "name": "experience.illusionblack.com",
            "ip": "1.2.3.4",
            "server_type": "nginx",
            "dataset": "generic"
        }
    ]
}

USERS = {
    "items": [
        {
            "user_name": "foo_bar",
            "first_name": "foo",
            "last_name": "bar",
            "ou": "ou",
            "state": "success"
        }
    ]
}

HOSTS = {
    "items": [
        {
            "name": "FOO",
            "ip": "1.2.3.4",
            "services": ["ssh", "mariadb"],
            "mac": "aa:bb:cc:dd:ee:ff"
        }
    ]
}

EVENTS = {
    "threat_parse": [
        {
            "id": "smb_file_open",
            "title": "Files accessed from network shares",
            "type": "single",
            "description": "An adversary has tried to open a file on a decoy file share. These events can occur "
                           "either when files or named pipes have been accessed. <br> Sensitive data can be collected "
                           "from remote systems via shared network shared drives that are accessible on the network. "
                           "<br> Adversaries may search network shares they have access to to discover files of "
                           "interest.\n",
            "examples": [
                "When it first starts, BADNEWS crawls the victim's mapped drives and collects documents with the "
                "following extensions like .doc, .docx, .pdf, .ppt, .pptx, and .txt.",
                "BRONZE BUTLER has exfiltrated files stolen from file shares.",
                "CosmicDuke steals user files from network shared drives with file extensions and keywords that match "
                "a predefined list.",
                "menuPass has collected data from remote systems by mounting network shares with net use and using "
                "Robocopy to transfer data.",
                "Sowbug extracted Word documents from a file server on a victim network."
            ],
            "score": 75,
            "mitigation": [
                "Validate whether the source system has any legitimate need to access file shares on the network."
            ],
            "mitre_id": [
                "T1039"
            ],
            "mitre_tactic": [
                "Collection"
            ]
        },
        {
            "id": "web_access",
            "title": "Web application access",
            "type": "single",
            "description": "An attempt was made to access a decoy web-server. Since decoy services should never be "
                           "accessed or enumerated, this should be investigated further.\n",
            "score": 25,
            "mitigation": [
                "Identify the source of this connection request and verify if the user has performed this activity.",
                "The request URI and user-agent may indicate what caused this connection.",
                "Identify the process running on the system that initiated this network connection.",
                "If it is an authorized process, either create a whitelist, or check for and correct any "
                "misconfigurations that may be causing it to connect to the decoy.",
                "If not, triage the system for indications of malicious activity by obtaining a memory dump of the "
                "machine. "
            ]
        }
    ],
    "events": [
        {
            "type": "network",
            "sub_type": "smb_files",
            "severity": "medium",
            "kill_chain_phase": "Lateral Movement",
            "timestamp": "2020-03-16T13:02:07Z",
            "network.connection_uid": "CbyMpm1ivKb8v1Poj",
            "attacker.ip": "1.2.3.4",
            "attacker.port": 51563,
            "decoy.ip": "7.8.9.10",
            "decoy.port": 445,
            "smb_files.action": "SMB::FILE_OPEN",
            "smb_files.path": "\\\\7.8.9.10\\c$",
            "smb_files.name": "<share_root>",
            "smb_files.size": "0",
            "smb_files.times.modified": "1.466496657E9",
            "smb_files.times.accessed": "1.580470607851474E9",
            "smb_files.times.created": "1.466496657E9",
            "smb_files.times.changed": "1.466496657E9",
            "decoy.id": "network:smb58",
            "decoy.name": "smb58",
            "decoy.group": "Group 1",
            "decoy.type": "network",
            "decoy.network_name": "12PC DHCP",
            "decoy.appliance.id": "1.appliance.illusionblack",
            "decoy.appliance.name": "IllusionBLACK 12PC",
            "attacker.name": "1.2.3.4",
            "attacker.id": "1.2.3.4",
            "decoy.client.id": "illusionblack",
            "decoy.client.name": "illusionblack",
            "mitre_ids": [
                "T1039",
                "T1135"
            ],
            "threat_parse_ids": [
                "smb_file_open",
                "shares_access"
            ],
            "whitelisted": False,
            "id": "2020-03-16T13:02:11.097255-network-4c61c535-5239-4fe7-bd77-f6ca7040fecf",
            "record_type": "event",
            "attacker.score": 400,
            "attacker.threat_parse_ids": [
                "network_ntlm",
                "shares_access",
                "web_access",
                "smb_file_open"
            ]
        },
        {
            "type": "network",
            "sub_type": "conn_init",
            "severity": "low",
            "kill_chain_phase": "Lateral Movement",
            "timestamp": "2020-03-16T13:02:05Z",
            "attacker.ip": "5.6.7.8",
            "attacker.port": 51563,
            "decoy.ip": "7.8.9.10",
            "decoy.port": 445,
            "network.connection_uid": "CbyMpm1ivKb8v1Poj",
            "decoy.id": "network:smb58",
            "decoy.name": "smb58",
            "decoy.group": "Group 1",
            "decoy.type": "network",
            "decoy.network_name": "12PC DHCP",
            "decoy.appliance.id": "1.appliance.smokescreen",
            "decoy.appliance.name": "Smokescreen 12PC",
            "attacker.name": "5.6.7.8",
            "attacker.id": "5.6.7.8",
            "decoy.client.id": "smokescreen",
            "decoy.client.name": "smokescreen",
            "whitelisted": False,
            "id": "2020-03-16T13:02:09.189408-network-7f63759b-4308-41ef-97c5-317043622f8c",
            "record_type": "event",
            "attacker.score": 400,
            "attacker.threat_parse_ids": [
                "network_ntlm",
                "shares_access",
                "web_access",
                "smb_file_open"
            ]
        }
    ],
    "meta": {
        "paging": {
            "total": 10,
            "offset": 0,
            "limit": 2,
            "amount": 2
        }
    }
}


def mock_http_request(client, url_suffix=None, **kwargs):
    if url_suffix == "/decoy/hosts":
        return HOSTS
    elif url_suffix == "/decoy/users":
        return USERS
    elif url_suffix == "/decoy/recon":
        return RECON_DECOYS
    elif url_suffix == "/events":
        return EVENTS
    return None


def test_get_network_decoys(mocker):
    mocker.patch("Smokescreen_IllusionBLACK.Client._http_request", mock_http_request)
    assert len(CLIENT.get_network_decoys()[2]) == 1


def test_get_ad_decoys(mocker):
    mocker.patch("Smokescreen_IllusionBLACK.Client._http_request", mock_http_request)
    assert len(CLIENT.get_ad_decoys()[2]) == 1


def test_get_ti_decoys(mocker):
    mocker.patch("Smokescreen_IllusionBLACK.Client._http_request", mock_http_request)
    assert len(CLIENT.get_ti_decoys()[2]) == 1


@pytest.mark.parametrize("host, output", [("FOO", "True"), ("random", "False")])
def test_is_host_decoy(mocker, host, output):
    mocker.patch("Smokescreen_IllusionBLACK.Client._http_request", mock_http_request)
    assert CLIENT.is_host_decoy(host)[0] is output


@pytest.mark.parametrize("user, output", [("foo_bar", "True"), ("random", "False")])
def test_is_user_decoy(mocker, user, output):
    mocker.patch("Smokescreen_IllusionBLACK.Client._http_request", mock_http_request)
    assert CLIENT.is_user_decoy(user)[0] is output


@pytest.mark.parametrize("subdomain, output", [("experience.illusionblack.com", "True"), ("random", "False")])
def test_is_subdomain_decoy(mocker, subdomain, output):
    mocker.patch("Smokescreen_IllusionBLACK.Client._http_request", mock_http_request)
    assert CLIENT.is_subdomain_decoy(subdomain)[0] is output
