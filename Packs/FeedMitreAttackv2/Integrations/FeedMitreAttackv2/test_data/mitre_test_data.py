ATTACK_PATTERN = {
    'response': {
        "id": "attack-pattern--01a5a209-b94c-450b-b7f9-946497d91055",
        "modified": "2020-05-13T22:50:51.258Z",
        "created": "2017-05-31T21:30:44.329Z",
        "description": "Adversaries may abuse Windows Management Instrumentation (WMI) to achieve execution.",
        "x_mitre_platforms": [
            "Windows"
        ],
        "external_references": [
            {
                "url": "https://attack.mitre.org/techniques/T1047",
                "source_name": "mitre-attack",
                "external_id": "T1047"
            },
            {
                "description": "Wikipedia. (2016, June 12). Server Message Block. Retrieved June 12, 2016.",
                "source_name": "Wikipedia SMB",
                "url": "https://en.wikipedia.org/wiki/Server_Message_Block"
            },
            {
                "description": "Microsoft. (2003, March 28). What Is RPC?. Retrieved June 12, 2016.",
                "source_name": "TechNet RPC",
                "url": "https://technet.microsoft.com/en-us/library/cc787851.aspx"
            },
        ],
    },
    'result': {
        'stixid': 'attack-pattern--01a5a209-b94c-450b-b7f9-946497d91055',
        'firstseenbysource': '2017-05-31T21:30:44.329Z',
        'modified': "2020-05-13T22:50:51.258Z",
        'description': "Adversaries may abuse Windows Management Instrumentation (WMI) to achieve execution.",
        'operatingsystemrefs': ['Windows'],
        'mitreid': 'T1047',
        'publications': [{'Link': "https://en.wikipedia.org/wiki/Server_Message_Block",
                          'Title': "Wikipedia. (2016, June 12). Server Message Block. Retrieved June 12, 2016."},
                         {'Link': "https://technet.microsoft.com/en-us/library/cc787851.aspx",
                          'Title': 'Microsoft. (2003, March 28). What Is RPC?. Retrieved June 12, 2016.'}]
    }
}

COURSE_OF_ACTION = {
    'response': {
        "id": "course-of-action--02f0f92a-0a51-4c94-9bda-6437b9a93f22",
        "description": "Prevent files from having a trailing space after the extension.",
        "modified": "2019-07-25T11:46:32.010Z",
        "external_references": [
            {
                "external_id": "T1151",
                "source_name": "mitre-attack",
                "url": "https://attack.mitre.org/mitigations/T1151"
            }
        ],
        "created": "2018-10-17T00:14:20.652Z"
    },
    'result': {
        'stixid': 'course-of-action--02f0f92a-0a51-4c94-9bda-6437b9a93f22',
        'firstseenbysource': '2018-10-17T00:14:20.652Z',
        'modified': "2019-07-25T11:46:32.010Z",
        'description': "Prevent files from having a trailing space after the extension.",
        'publications': [],
    }
}

INTRUSION_SET = {
    'response': {
        "external_references": [
            {
                "external_id": "G0066",
                "source_name": "mitre-attack",
                "url": "https://attack.mitre.org/groups/G0066"
            },
            {
                "description": "(Citation: Security Affairs Elderwood Sept 2012)",
                "source_name": "Elderwood"
            },
        ],
        "description": "[Elderwood](https://attack.mitre.org/groups/G0066)",
        "modified": "2021-03-02T22:40:11.097Z",
        "created": "2018-04-18T17:59:24.739Z",
        "aliases": [
            "Elderwood",
            "Elderwood Gang",
            "Beijing Group",
            "Sneaky Panda"
        ],
        "id": "intrusion-set--03506554-5f37-4f8f-9ce4-0e9f01a1b484"
    },
    'result': {
        'stixid': "intrusion-set--03506554-5f37-4f8f-9ce4-0e9f01a1b484",
        'firstseenbysource': "2018-04-18T17:59:24.739Z",
        'modified': "2021-03-02T22:40:11.097Z",
        'description': "[Elderwood](https://attack.mitre.org/groups/G0066)",
        'aliases': ["Elderwood", "Elderwood Gang", "Beijing Group", "Sneaky Panda"],
        'publications': [{'Link': None,
                          'Title': "(Citation: Security Affairs Elderwood Sept 2012)"}],
    }
}

MALWARE = {
    'response': {
        "description": "[Wiarp](https://attack.mitre.org/software/S0206)",
        "external_references": [
            {
                "description": "Zhou, R. (2012, May 15). Backdoor.Wiarp. Retrieved February 22, 2018.",
                "source_name": "Symantec Wiarp May 2012",
                "url": "https://www.symantec.com/security_response/writeup.jsp?docid=2012-051606-1005-99"
            }
        ],
        "x_mitre_platforms": [
            "Windows"
        ],
        "x_mitre_aliases": [
            "Wiarp"
        ],
        "modified": "2021-01-06T19:32:28.378Z",
        "created": "2018-04-18T17:59:24.739Z",
        "labels": [
            "malware"
        ],
        "id": "malware--039814a0-88de-46c5-a4fb-b293db21880a"
    },
    'result': {
        'stixid': "malware--039814a0-88de-46c5-a4fb-b293db21880a",
        'firstseenbysource': "2018-04-18T17:59:24.739Z",
        'modified': "2021-01-06T19:32:28.378Z",
        'description': "[Wiarp](https://attack.mitre.org/software/S0206)",
        'publications': [{'Link': "https://www.symantec.com/security_response/writeup.jsp?docid=2012-051606-1005-99",
                          'Title': "Zhou, R. (2012, May 15). Backdoor.Wiarp. Retrieved February 22, 2018."}],
        'tags': ['malware'],
        'aliases': ['Wiarp'],
        'operatingsystemrefs': ["Windows"]
    }
}

TOOL = {
    'response': {
        "description": "[PowerSploit](https://attack.mitre.org/software/S0194)",
        "external_references": [
            {
                "external_id": "S0194",
                "source_name": "mitre-attack",
                "url": "https://attack.mitre.org/software/S0194"
            }
        ],
        "x_mitre_platforms": [
            "Windows"
        ],
        "x_mitre_aliases": [
            "PowerSploit"
        ],
        "modified": "2021-02-09T14:00:16.093Z",
        "created": "2018-04-18T17:59:24.739Z",
        "labels": [
            "tool"
        ],
        "id": "tool--13cd9151-83b7-410d-9f98-25d0f0d1d80d"
    },
    'result': {
        'stixid': "tool--13cd9151-83b7-410d-9f98-25d0f0d1d80d",
        'firstseenbysource': "2018-04-18T17:59:24.739Z",
        'modified': "2021-02-09T14:00:16.093Z",
        'description': "[PowerSploit](https://attack.mitre.org/software/S0194)",
        'publications': [],
        'tags': ['tool'],
        'aliases': ['PowerSploit'],
        'operatingsystemrefs': ['Windows']
    }
}

ID_TO_NAME = {
    "attack-pattern--707399d6-ab3e-4963-9315-d9d3818cd6a0": "entity b",
    "malware--6a21e3a4-5ffe-4581-af9a-6a54c7536f44": "entity a"
}

RELATION_1 = {
    'response': {
        "description": " [Explosive](https://attack.mitre.org/software/S0569)",
        "source_ref": "malware--6a21e3a4-5ffe-4581-af9a-6a54c7536f44",
        "created": "2021-04-27T01:56:35.810Z",
        "relationship_type": "uses",
        "modified": "2021-04-27T01:56:35.810Z",
        "target_ref": "attack-pattern--707399d6-ab3e-4963-9315-d9d3818cd6a0",
    },
    'result': {

    }
}

RELATION_2 = {

}
