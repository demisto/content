IRIS is a collaborative platform aiming to help incident responders to share technical details during investigations. It's free and open-source.
This integration was integrated and tested with version v2.3.6 of IRIS DFIR

## Configure IRIS DFIR in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server IP or Host Name (e.g., https://192.168.0.1) |  | True |
| API Key for authentication |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Fetch incidents |  | False |
| Incidents Fetch Interval |  | False |
| Incident type |  | False |
| Incident Last Case ID | Fetch all the cases starting from this value, not including it. | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### iris-get-last-case-id

***
IRIS Command to get the last case information

#### Base Command

`iris-get-last-case-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IRIS.case_soc_id | string | SOC ID ticket case | 
| IRIS.case_id | number | case ID ticket number | 
| IRIS.case_description | string | case description | 
| IRIS.opened_by | unknown | case opened by | 
| IRIS.owner | unknown | case owner | 
| IRIS.classification_id | number | case classification ID | 
| IRIS.state_name | string | case state name | 
| IRIS.case_open_date | unknown | case open date | 
| IRIS.case_name | string | case name | 
| IRIS.client_name | string | case client name | 
| IRIS.classification | string | case classification | 
| IRIS.case_uuid | string | case uuid | 
| IRIS.state_id | string | case state ID | 
| IRIS.access_level | string | case access level | 

#### Command example
```!iris-get-last-case-id```
#### Context Example
```json
{
    "IRIS": {
        "access_level": 4,
        "case_close_date": "",
        "case_description": "TEST 7",
        "case_id": 32,
        "case_name": "#32 - TEST 7",
        "case_open_date": "12/18/2023",
        "case_soc_id": "",
        "case_uuid": "47ae5435-4c25-4408-bf86-98277807b2fa",
        "classification": "malicious-code:dialer",
        "classification_id": 9,
        "client_name": "CERT-EU",
        "opened_by": "nouser2",
        "opened_by_user_id": 1,
        "owner": "nouser2",
        "owner_id": 1,
        "state_id": 3,
        "state_name": "Opened"
    }
}
```

#### Human Readable Output

>### Command successfully sent to IRIS DFIR"
>|access_level|case_description|case_id|case_name|case_open_date|case_uuid|classification|classification_id|client_name|opened_by|opened_by_user_id|owner|owner_id|state_id|state_name|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 4 | TEST 7 | 32 | #32 - TEST 7 | 12/18/2023 | 47ae5435-4c25-4408-bf86-98277807b2fa | malicious-code:dialer | 9 | CERT-EU | nouser2 | 1 | nouser2 | 1 | 3 | Opened |


### iris-get-all-cases

***
Return a list of all IRIS DFIR cases

#### Base Command

`iris-get-all-cases`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IRIS.case_soc_id | unknown | SOC ID ticket case | 
| IRIS.case_id | number | case ID ticket number | 
| IRIS.case_description | unknown | case description | 
| IRIS.opened_by | unknown | case opened by | 
| IRIS.owner | unknown | case owner | 
| IRIS.classification_id | number | case classification ID | 
| IRIS.state_name | unknown | case state name | 
| IRIS.case_open_date | unknown | case open date | 
| IRIS.case_name | unknown | case name | 
| IRIS.client_name | unknown | case client name | 
| IRIS.classification | unknown | case classification | 
| IRIS.case_uuid | unknown | case uuid | 
| IRIS.state_id | unknown | case state ID | 
| IRIS.access_level | unknown | case access level | 

#### Command example
```!iris-get-all-cases```
#### Context Example
```json
{
    "IRIS": [
        {
            "access_level": 4,
            "case_close_date": "",
            "case_description": "TEST 7",
            "case_id": 32,
            "case_name": "#32 - TEST 7",
            "case_open_date": "12/18/2023",
            "case_soc_id": "",
            "case_uuid": "47ae5435-4c25-4408-bf86-98277807b2fa",
            "classification": "malicious-code:dialer",
            "classification_id": 9,
            "client_name": "CERT-EU",
            "opened_by": "nouser2",
            "opened_by_user_id": 1,
            "owner": "nouser2",
            "owner_id": 1,
            "state_id": 3,
            "state_name": "Opened"
        },
        {
            "access_level": 4,
            "case_close_date": "",
            "case_description": "TEST 5",
            "case_id": 31,
            "case_name": "#31 - TEST 5",
            "case_open_date": "12/18/2023",
            "case_soc_id": "",
            "case_uuid": "5d5e6bc6-2c83-4c77-9f87-fb12d82e1e35",
            "classification": "malicious-code:ransomware",
            "classification_id": 6,
            "client_name": "CERT-EU",
            "opened_by": "nouser2",
            "opened_by_user_id": 1,
            "owner": "nouser2",
            "owner_id": 1,
            "state_id": 3,
            "state_name": "Opened"
        },
        {
            "access_level": 4,
            "case_close_date": "",
            "case_description": "case null 0000f\n\n### dsdsdsd",
            "case_id": 29,
            "case_name": "#29 - case null 0000f",
            "case_open_date": "12/14/2023",
            "case_soc_id": "",
            "case_uuid": "e7ed6439-799a-4eaf-b16c-cde8f7a10ffc",
            "classification": "malicious-code:dialer",
            "classification_id": 9,
            "client_name": "CERT-EU",
            "opened_by": "nouser2",
            "opened_by_user_id": 1,
            "owner": "nouser2",
            "owner_id": 1,
            "state_id": 3,
            "state_name": "Opened"
        },
        {
            "access_level": 4,
            "case_close_date": "",
            "case_description": "malware byte you\n\ntest22222",
            "case_id": 28,
            "case_name": "#28 - malware byte you",
            "case_open_date": "12/14/2023",
            "case_soc_id": "test-eu-111",
            "case_uuid": "2aeb9026-7b1d-4caa-a22d-b95e7507eec8",
            "classification": "abusive-content:harmful-speech",
            "classification_id": 2,
            "client_name": "CERT-EU",
            "opened_by": "nouser2",
            "opened_by_user_id": 1,
            "owner": "nouser2",
            "owner_id": 1,
            "state_id": 4,
            "state_name": "Containment"
        },
        {
            "access_level": 4,
            "case_close_date": "",
            "case_description": "test jira fields\n\n### 12244434",
            "case_id": 27,
            "case_name": "#27 - test jira fields",
            "case_open_date": "11/30/2023",
            "case_soc_id": "",
            "case_uuid": "6b8d5e9a-e27b-4a6a-b27d-059b235f0814",
            "classification": "malicious-code:spyware-rat",
            "classification_id": 8,
            "client_name": "CERT-EU",
            "opened_by": "nouser2",
            "opened_by_user_id": 1,
            "owner": "nouser2",
            "owner_id": 1,
            "state_id": 3,
            "state_name": "Opened"
        },
        {
            "access_level": 4,
            "case_close_date": "",
            "case_description": "Evil rootkit\n## \nmachine evil\n\n",
            "case_id": 26,
            "case_name": "#26 - Evil rootkit",
            "case_open_date": "11/22/2023",
            "case_soc_id": "CERT-EU-846327",
            "case_uuid": "dec1a169-37cf-44b0-8e9d-78b51efebbc0",
            "classification": "malicious-code:rootkit",
            "classification_id": 10,
            "client_name": "CERT-EU",
            "opened_by": "nouser2",
            "opened_by_user_id": 1,
            "owner": "nouser2",
            "owner_id": 1,
            "state_id": 5,
            "state_name": "Eradication"
        },
        {
            "access_level": 4,
            "case_close_date": "",
            "case_description": "mail spam \n\nspam 1234444",
            "case_id": 25,
            "case_name": "#25 - mail spam",
            "case_open_date": "11/22/2023",
            "case_soc_id": "CERT-EU-8213423",
            "case_uuid": "83317f2e-72df-4934-a283-500fecd0e758",
            "classification": "abusive-content:spam",
            "classification_id": 1,
            "client_name": "CERT-EU",
            "opened_by": "nouser2",
            "opened_by_user_id": 1,
            "owner": "nouser2",
            "owner_id": 1,
            "state_id": 4,
            "state_name": "Containment"
        },
        {
            "access_level": 4,
            "case_close_date": "",
            "case_description": "Evil spyware\n\ndark 123 machine local",
            "case_id": 24,
            "case_name": "#24 - Evil spyware",
            "case_open_date": "11/22/2023",
            "case_soc_id": "CERT-EU-896492",
            "case_uuid": "c63dc059-b8a7-4595-bc2b-833e4798e3ac",
            "classification": "malicious-code:spyware-rat",
            "classification_id": 8,
            "client_name": "CERT-EU",
            "opened_by": "nouser2",
            "opened_by_user_id": 1,
            "owner": "nouser2",
            "owner_id": 1,
            "state_id": 3,
            "state_name": "Opened"
        },
        {
            "access_level": 4,
            "case_close_date": "",
            "case_description": "Scanning VIP\n\n\nfdsfdsfsdfsdfsdfsdf",
            "case_id": 23,
            "case_name": "#23 - Scanning VIP",
            "case_open_date": "11/22/2023",
            "case_soc_id": "CERT-EU-2316346",
            "case_uuid": "cd85ed04-fa5a-4f47-8a3f-0280297a3d53",
            "classification": "information-gathering:scanner",
            "classification_id": 11,
            "client_name": "CERT-EU",
            "opened_by": "nouser2",
            "opened_by_user_id": 1,
            "owner": "nouser2",
            "owner_id": 1,
            "state_id": 3,
            "state_name": "Opened"
        },
        {
            "access_level": 4,
            "case_close_date": "",
            "case_description": "virus id 2244\n\ntesting 123\n\nmachine 10.0.0.1",
            "case_id": 20,
            "case_name": "#20 - virus id 2244",
            "case_open_date": "11/22/2023",
            "case_soc_id": "CERT-EU-55",
            "case_uuid": "6e71ba63-ad61-4c7e-8b4e-10f16a65cb36",
            "classification": "malicious-code:virus",
            "classification_id": 4,
            "client_name": "CERT-EU",
            "opened_by": "nouser2",
            "opened_by_user_id": 1,
            "owner": "nouser2",
            "owner_id": 1,
            "state_id": 3,
            "state_name": "Opened"
        },
        {
            "access_level": 4,
            "case_close_date": "",
            "case_description": "rootkit blabla\n\nmachine.dark.local malware baisfldasnfadsf",
            "case_id": 19,
            "case_name": "#19 - rootkit blabla",
            "case_open_date": "09/29/2023",
            "case_soc_id": "CERT--EU-444",
            "case_uuid": "a48eed36-cc03-4a42-a13b-3af41a76dccb",
            "classification": "malicious-code:rootkit",
            "classification_id": 10,
            "client_name": "CERT-EU",
            "opened_by": "nouser2",
            "opened_by_user_id": 1,
            "owner": "nouser2",
            "owner_id": 1,
            "state_id": 3,
            "state_name": "Opened"
        },
        {
            "access_level": 4,
            "case_close_date": "09/28/2023",
            "case_description": "Phishing EU member\n\nblabla",
            "case_id": 18,
            "case_name": "#18 - Phishing EU member",
            "case_open_date": "09/28/2023",
            "case_soc_id": "CERT-EU-77",
            "case_uuid": "a9803459-461b-4442-a11e-b6440a91cd85",
            "classification": "fraud:phishing",
            "classification_id": 30,
            "client_name": "CERT-EU",
            "opened_by": "nouser2",
            "opened_by_user_id": 1,
            "owner": "nouser2",
            "owner_id": 1,
            "state_id": 9,
            "state_name": "Closed"
        },
        {
            "access_level": 4,
            "case_close_date": "",
            "case_description": "Phishing EU official\n\ntest ticket !!!",
            "case_id": 17,
            "case_name": "#17 - #17 case custom attrib test",
            "case_open_date": "08/09/2023",
            "case_soc_id": "soc_id_demo",
            "case_uuid": "c034f0fa-d19c-480a-8b1d-045b558915d0",
            "classification": "abusive-content:harmful-speech",
            "classification_id": 2,
            "client_name": "CERT-EU",
            "opened_by": "nouser2",
            "opened_by_user_id": 1,
            "owner": "Natasha Carl",
            "owner_id": 2,
            "state_id": 4,
            "state_name": "Containment"
        },
        {
            "access_level": 4,
            "case_close_date": "09/25/2023",
            "case_description": "spam test ticket\n\nblah",
            "case_id": 16,
            "case_name": "#16 - spam test ticket",
            "case_open_date": "07/13/2023",
            "case_soc_id": "CERT-EU-21",
            "case_uuid": "71636b85-ef58-4d45-a5bf-faa2ac00031a",
            "classification": "abusive-content:spam",
            "classification_id": 1,
            "client_name": "CERT-EU",
            "opened_by": "nouser2",
            "opened_by_user_id": 1,
            "owner": "nouser2",
            "owner_id": 1,
            "state_id": 9,
            "state_name": "Closed"
        },
        {
            "access_level": 4,
            "case_close_date": "",
            "case_description": "dark.local\n\ntesting notes",
            "case_id": 15,
            "case_name": "#15 - Virus detected on VM dark.local",
            "case_open_date": "07/13/2023",
            "case_soc_id": "CERT-EU-20",
            "case_uuid": "94e4a63a-3c8b-4a4e-ae02-b32c0c1b6386",
            "classification": "malicious-code:virus",
            "classification_id": 4,
            "client_name": "CERT-EU",
            "opened_by": "nouser2",
            "opened_by_user_id": 1,
            "owner": "nouser2",
            "owner_id": 1,
            "state_id": 2,
            "state_name": "In progress"
        },
        {
            "access_level": 4,
            "case_close_date": "",
            "case_description": "ROOTKIT TEST\n\nTHIS IS A TEST FORM",
            "case_id": 13,
            "case_name": "#13 - ROOTKIT TEST",
            "case_open_date": "06/08/2023",
            "case_soc_id": "CERT-EU-19",
            "case_uuid": "6f8a72b5-2c82-4654-b84a-e8e10e9299de",
            "classification": "malicious-code:rootkit",
            "classification_id": 10,
            "client_name": "CERT-EU",
            "opened_by": "nouser2",
            "opened_by_user_id": 1,
            "owner": "nouser2",
            "owner_id": 1,
            "state_id": 3,
            "state_name": "Opened"
        },
        {
            "access_level": 4,
            "case_close_date": "09/26/2023",
            "case_description": "Scanning ports machine X\n\n\n- 1\n- 2\n- 3\n- \n**## EDITED**",
            "case_id": 12,
            "case_name": "#12 - Scanning ports machine X",
            "case_open_date": "06/08/2023",
            "case_soc_id": "CERT-EU-18",
            "case_uuid": "3662a525-d572-495c-9d25-45920c3ad1ce",
            "classification": "information-gathering:scanner",
            "classification_id": 11,
            "client_name": "CERT-EU",
            "opened_by": "nouser2",
            "opened_by_user_id": 1,
            "owner": "nouser2",
            "owner_id": 1,
            "state_id": 9,
            "state_name": "Closed"
        },
        {
            "access_level": 4,
            "case_close_date": "",
            "case_description": "Code Dialer\n\n### TEST CODE CODE ",
            "case_id": 11,
            "case_name": "#11 - Code Dialer",
            "case_open_date": "06/08/2023",
            "case_soc_id": "CERT-EU-17",
            "case_uuid": "f0b3b128-88f3-4a37-a908-58ecb5fc7c89",
            "classification": "malicious-code:dialer",
            "classification_id": 9,
            "client_name": "CERT-EU",
            "opened_by": "nouser2",
            "opened_by_user_id": 1,
            "owner": "nouser2",
            "owner_id": 1,
            "state_id": 3,
            "state_name": "Opened"
        },
        {
            "access_level": 4,
            "case_close_date": "",
            "case_description": "spyware test 1",
            "case_id": 10,
            "case_name": "#10 - spyware test 1",
            "case_open_date": "06/08/2023",
            "case_soc_id": "CERT-EU-16",
            "case_uuid": "38ba94bf-978f-4073-99af-291f79889b0b",
            "classification": "malicious-code:spyware-rat",
            "classification_id": 8,
            "client_name": "CERT-EU",
            "opened_by": "nouser2",
            "opened_by_user_id": 1,
            "owner": "nouser2",
            "owner_id": 1,
            "state_id": 3,
            "state_name": "Opened"
        },
        {
            "access_level": 4,
            "case_close_date": "",
            "case_description": "Social Eng",
            "case_id": 9,
            "case_name": "#9 - Social Eng",
            "case_open_date": "06/07/2023",
            "case_soc_id": "CERT-EU-15",
            "case_uuid": "35070554-73c1-421a-bdbb-b840f09411b4",
            "classification": "information-gathering:social-engineering",
            "classification_id": 13,
            "client_name": "CERT-EU",
            "opened_by": "nouser2",
            "opened_by_user_id": 1,
            "owner": "nouser2",
            "owner_id": 1,
            "state_id": 3,
            "state_name": "Opened"
        },
        {
            "access_level": 4,
            "case_close_date": "",
            "case_description": "WAF invaded",
            "case_id": 8,
            "case_name": "#8 - WAF invaded",
            "case_open_date": "06/07/2023",
            "case_soc_id": "CERT-EU-15",
            "case_uuid": "9bab6e73-be89-497c-bfc1-25e213f933eb",
            "classification": null,
            "classification_id": null,
            "client_name": "CERT-EU",
            "opened_by": "nouser2",
            "opened_by_user_id": 1,
            "owner": "nouser2",
            "owner_id": 1,
            "state_id": 3,
            "state_name": "Opened"
        },
        {
            "access_level": 4,
            "case_close_date": "",
            "case_description": "A virus has been detected on machine **machine.darkside.in** \n\nDDOS\n\n|  Port  | Protocol   |Hostname|\n|--|--|--|\n| 443   | TCP   |machine.darkside.in|\n\n\n```echo Please investigate !```\n\n### HELP !",
            "case_id": 7,
            "case_name": "#7 - test command 1",
            "case_open_date": "06/07/2023",
            "case_soc_id": "CERT-EU-14",
            "case_uuid": "e88efdc4-6811-4c59-aca6-7eeefab72a81",
            "classification": "availability:ddos",
            "classification_id": 23,
            "client_name": "CERT-EU",
            "opened_by": "nouser2",
            "opened_by_user_id": 1,
            "owner": "nouser2",
            "owner_id": 1,
            "state_id": 6,
            "state_name": "Recovery"
        },
        {
            "access_level": 4,
            "case_close_date": "",
            "case_description": "A virus has been detected on machine **machine.darkside.in** \n\n|  Port  | Protocol   |Hostname|\n|--|--|--|\n| 443   | TCP   |machine.darkside.in|\n\n\n```echo Please investigate !```\n\n### HELP !",
            "case_id": 6,
            "case_name": "#6 - Malware detected on machine.darkside.in",
            "case_open_date": "06/07/2023",
            "case_soc_id": "CERT-EU-13",
            "case_uuid": "4f7d583d-7724-4be3-9137-7ca248630bc0",
            "classification": null,
            "classification_id": null,
            "client_name": "CERT-EU",
            "opened_by": "nouser2",
            "opened_by_user_id": 1,
            "owner": "nouser2",
            "owner_id": 1,
            "state_id": 3,
            "state_name": "Opened"
        },
        {
            "access_level": 4,
            "case_close_date": "",
            "case_description": "Ransomware test",
            "case_id": 3,
            "case_name": "#3 - CERT-EU Ransomware test",
            "case_open_date": "06/05/2023",
            "case_soc_id": "CERT-EU-82",
            "case_uuid": "7b9ec75f-f194-4d73-a98a-b657b40b2cc4",
            "classification": "malicious-code:ransomware",
            "classification_id": 6,
            "client_name": "CERT-EU",
            "opened_by": "nouser2",
            "opened_by_user_id": 1,
            "owner": "nouser2",
            "owner_id": 1,
            "state_id": 3,
            "state_name": "Opened"
        },
        {
            "access_level": 4,
            "case_close_date": "",
            "case_description": "A virus has been detected on machine **darkpace.evil** \n\n|  Port  | Protocol   |Hostname|\n|--|--|--|\n| 443   | TCP   |darkplace.evil|\n\n\n```echo Please investigate !```\n\n### HELP !",
            "case_id": 2,
            "case_name": "#2 - virus-windows-11",
            "case_open_date": "06/05/2023",
            "case_soc_id": "CERT-EU-12",
            "case_uuid": "1a5e6534-571f-4788-b4f5-47cc6b0c18bc",
            "classification": "malicious-code:virus",
            "classification_id": 4,
            "client_name": "CERT-EU",
            "opened_by": "nouser2",
            "opened_by_user_id": 1,
            "owner": "nouser2",
            "owner_id": 1,
            "state_id": 3,
            "state_name": "Opened"
        },
        {
            "access_level": 4,
            "case_close_date": "06/05/2023",
            "case_description": "This is a demonstration.",
            "case_id": 1,
            "case_name": "#1 - Initial Demo",
            "case_open_date": "06/05/2023",
            "case_soc_id": "soc_id_demo",
            "case_uuid": "46480e7c-5b78-42c5-8b2e-678991a8a495",
            "classification": null,
            "classification_id": null,
            "client_name": "CERT-EU",
            "opened_by": "nouser2",
            "opened_by_user_id": 1,
            "owner": "nouser2",
            "owner_id": 1,
            "state_id": 2,
            "state_name": "In progress"
        }
    ]
}
```

#### Human Readable Output

>### Command successfully sent to IRIS DFIR"
>|access_level|case_close_date|case_description|case_id|case_name|case_open_date|case_soc_id|case_uuid|classification|classification_id|client_name|opened_by|opened_by_user_id|owner|owner_id|state_id|state_name|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 4 |  | TEST 7 | 32 | #32 - TEST 7 | 12/18/2023 |  | 47ae5435-4c25-4408-bf86-98277807b2fa | malicious-code:dialer | 9 | CERT-EU | nouser2 | 1 | nouser2 | 1 | 3 | Opened |
>| 4 |  | TEST 5 | 31 | #31 - TEST 5 | 12/18/2023 |  | 5d5e6bc6-2c83-4c77-9f87-fb12d82e1e35 | malicious-code:ransomware | 6 | CERT-EU | nouser2 | 1 | nouser2 | 1 | 3 | Opened |
>| 4 |  | case null 0000f<br/><br/>### dsdsdsd | 29 | #29 - case null 0000f | 12/14/2023 |  | e7ed6439-799a-4eaf-b16c-cde8f7a10ffc | malicious-code:dialer | 9 | CERT-EU | nouser2 | 1 | nouser2 | 1 | 3 | Opened |
>| 4 |  | malware byte you<br/><br/>test22222 | 28 | #28 - malware byte you | 12/14/2023 | test-eu-111 | 2aeb9026-7b1d-4caa-a22d-b95e7507eec8 | abusive-content:harmful-speech | 2 | CERT-EU | nouser2 | 1 | nouser2 | 1 | 4 | Containment |
>| 4 |  | test jira fields<br/><br/>### 12244434 | 27 | #27 - test jira fields | 11/30/2023 |  | 6b8d5e9a-e27b-4a6a-b27d-059b235f0814 | malicious-code:spyware-rat | 8 | CERT-EU | nouser2 | 1 | nouser2 | 1 | 3 | Opened |
>| 4 |  | Evil rootkit<br/>## <br/>machine evil<br/><br/> | 26 | #26 - Evil rootkit | 11/22/2023 | CERT-EU-846327 | dec1a169-37cf-44b0-8e9d-78b51efebbc0 | malicious-code:rootkit | 10 | CERT-EU | nouser2 | 1 | nouser2 | 1 | 5 | Eradication |
>| 4 |  | mail spam <br/><br/>spam 1234444 | 25 | #25 - mail spam | 11/22/2023 | CERT-EU-8213423 | 83317f2e-72df-4934-a283-500fecd0e758 | abusive-content:spam | 1 | CERT-EU | nouser2 | 1 | nouser2 | 1 | 4 | Containment |
>| 4 |  | Evil spyware<br/><br/>dark 123 machine local | 24 | #24 - Evil spyware | 11/22/2023 | CERT-EU-896492 | c63dc059-b8a7-4595-bc2b-833e4798e3ac | malicious-code:spyware-rat | 8 | CERT-EU | nouser2 | 1 | nouser2 | 1 | 3 | Opened |
>| 4 |  | Scanning VIP<br/><br/><br/>fdsfdsfsdfsdfsdfsdf | 23 | #23 - Scanning VIP | 11/22/2023 | CERT-EU-2316346 | cd85ed04-fa5a-4f47-8a3f-0280297a3d53 | information-gathering:scanner | 11 | CERT-EU | nouser2 | 1 | nouser2 | 1 | 3 | Opened |
>| 4 |  | virus id 2244<br/><br/>testing 123<br/><br/>machine 10.0.0.1 | 20 | #20 - virus id 2244 | 11/22/2023 | CERT-EU-55 | 6e71ba63-ad61-4c7e-8b4e-10f16a65cb36 | malicious-code:virus | 4 | CERT-EU | nouser2 | 1 | nouser2 | 1 | 3 | Opened |
>| 4 |  | rootkit blabla<br/><br/>machine.dark.local malware baisfldasnfadsf | 19 | #19 - rootkit blabla | 09/29/2023 | CERT--EU-444 | a48eed36-cc03-4a42-a13b-3af41a76dccb | malicious-code:rootkit | 10 | CERT-EU | nouser2 | 1 | nouser2 | 1 | 3 | Opened |
>| 4 | 09/28/2023 | Phishing EU member<br/><br/>blabla | 18 | #18 - Phishing EU member | 09/28/2023 | CERT-EU-77 | a9803459-461b-4442-a11e-b6440a91cd85 | fraud:phishing | 30 | CERT-EU | nouser2 | 1 | nouser2 | 1 | 9 | Closed |
>| 4 |  | Phishing EU official<br/><br/>test ticket !!! | 17 | #17 - #17 case custom attrib test | 08/09/2023 | soc_id_demo | c034f0fa-d19c-480a-8b1d-045b558915d0 | abusive-content:harmful-speech | 2 | CERT-EU | nouser2 | 1 | Natasha Carl | 2 | 4 | Containment |
>| 4 | 09/25/2023 | spam test ticket<br/><br/>blah | 16 | #16 - spam test ticket | 07/13/2023 | CERT-EU-21 | 71636b85-ef58-4d45-a5bf-faa2ac00031a | abusive-content:spam | 1 | CERT-EU | nouser2 | 1 | nouser2 | 1 | 9 | Closed |
>| 4 |  | dark.local<br/><br/>testing notes | 15 | #15 - Virus detected on VM dark.local | 07/13/2023 | CERT-EU-20 | 94e4a63a-3c8b-4a4e-ae02-b32c0c1b6386 | malicious-code:virus | 4 | CERT-EU | nouser2 | 1 | nouser2 | 1 | 2 | In progress |
>| 4 |  | ROOTKIT TEST<br/><br/>THIS IS A TEST FORM | 13 | #13 - ROOTKIT TEST | 06/08/2023 | CERT-EU-19 | 6f8a72b5-2c82-4654-b84a-e8e10e9299de | malicious-code:rootkit | 10 | CERT-EU | nouser2 | 1 | nouser2 | 1 | 3 | Opened |
>| 4 | 09/26/2023 | Scanning ports machine X<br/><br/><br/>- 1<br/>- 2<br/>- 3<br/>- <br/>**## EDITED** | 12 | #12 - Scanning ports machine X | 06/08/2023 | CERT-EU-18 | 3662a525-d572-495c-9d25-45920c3ad1ce | information-gathering:scanner | 11 | CERT-EU | nouser2 | 1 | nouser2 | 1 | 9 | Closed |
>| 4 |  | Code Dialer<br/><br/>### TEST CODE CODE  | 11 | #11 - Code Dialer | 06/08/2023 | CERT-EU-17 | f0b3b128-88f3-4a37-a908-58ecb5fc7c89 | malicious-code:dialer | 9 | CERT-EU | nouser2 | 1 | nouser2 | 1 | 3 | Opened |
>| 4 |  | spyware test 1 | 10 | #10 - spyware test 1 | 06/08/2023 | CERT-EU-16 | 38ba94bf-978f-4073-99af-291f79889b0b | malicious-code:spyware-rat | 8 | CERT-EU | nouser2 | 1 | nouser2 | 1 | 3 | Opened |
>| 4 |  | Social Eng | 9 | #9 - Social Eng | 06/07/2023 | CERT-EU-15 | 35070554-73c1-421a-bdbb-b840f09411b4 | information-gathering:social-engineering | 13 | CERT-EU | nouser2 | 1 | nouser2 | 1 | 3 | Opened |
>| 4 |  | WAF invaded | 8 | #8 - WAF invaded | 06/07/2023 | CERT-EU-15 | 9bab6e73-be89-497c-bfc1-25e213f933eb |  |  | CERT-EU | nouser2 | 1 | nouser2 | 1 | 3 | Opened |
>| 4 |  | A virus has been detected on machine **machine.darkside.in** <br/><br/>DDOS<br/><br/>\|  Port  \| Protocol   \|Hostname\|<br/>\|--\|--\|--\|<br/>\| 443   \| TCP   \|machine.darkside.in\|<br/><br/><br/>\`\`\`echo Please investigate !\`\`\`<br/><br/>### HELP ! | 7 | #7 - test command 1 | 06/07/2023 | CERT-EU-14 | e88efdc4-6811-4c59-aca6-7eeefab72a81 | availability:ddos | 23 | CERT-EU | nouser2 | 1 | nouser2 | 1 | 6 | Recovery |
>| 4 |  | A virus has been detected on machine **machine.darkside.in** <br/><br/>\|  Port  \| Protocol   \|Hostname\|<br/>\|--\|--\|--\|<br/>\| 443   \| TCP   \|machine.darkside.in\|<br/><br/><br/>\`\`\`echo Please investigate !\`\`\`<br/><br/>### HELP ! | 6 | #6 - Malware detected on machine.darkside.in | 06/07/2023 | CERT-EU-13 | 4f7d583d-7724-4be3-9137-7ca248630bc0 |  |  | CERT-EU | nouser2 | 1 | nouser2 | 1 | 3 | Opened |
>| 4 |  | Ransomware test | 3 | #3 - CERT-EU Ransomware test | 06/05/2023 | CERT-EU-82 | 7b9ec75f-f194-4d73-a98a-b657b40b2cc4 | malicious-code:ransomware | 6 | CERT-EU | nouser2 | 1 | nouser2 | 1 | 3 | Opened |
>| 4 |  | A virus has been detected on machine **darkpace.evil** <br/><br/>\|  Port  \| Protocol   \|Hostname\|<br/>\|--\|--\|--\|<br/>\| 443   \| TCP   \|darkplace.evil\|<br/><br/><br/>\`\`\`echo Please investigate !\`\`\`<br/><br/>### HELP ! | 2 | #2 - virus-windows-11 | 06/05/2023 | CERT-EU-12 | 1a5e6534-571f-4788-b4f5-47cc6b0c18bc | malicious-code:virus | 4 | CERT-EU | nouser2 | 1 | nouser2 | 1 | 3 | Opened |
>| 4 | 06/05/2023 | This is a demonstration. | 1 | #1 - Initial Demo | 06/05/2023 | soc_id_demo | 46480e7c-5b78-42c5-8b2e-678991a8a495 |  |  | CERT-EU | nouser2 | 1 | nouser2 | 1 | 2 | In progress |


### iris-close-case-id

***
Close a specific case by ID.

#### Base Command

`iris-close-case-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Provide Case ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IRIS.case_name | unknown | case name | 
| IRIS.case_soc_id | unknown | case soc ID | 
| IRIS.open_date | unknown | case open date | 
| IRIS.close_date | unknown | case close date | 

#### Command example
```!iris-close-case-id case_id=9```
#### Context Example
```json
{
    "IRIS": {
        "case_customer": 1,
        "case_description": "Social Eng",
        "case_id": 9,
        "case_name": "#9 - Social Eng",
        "case_soc_id": "CERT-EU-15",
        "case_uuid": "35070554-73c1-421a-bdbb-b840f09411b4",
        "classification_id": 13,
        "close_date": "2024-01-22",
        "closing_note": null,
        "custom_attributes": {},
        "modification_history": {
            "1686161424.82484": {
                "action": "created",
                "user": "nouser2",
                "user_id": 1
            },
            "1694445948.238388": {
                "action": "case closed",
                "user": "nouser2",
                "user_id": 1
            },
            "1694446268.42952": {
                "action": "case closed",
                "user": "nouser2",
                "user_id": 1
            },
            "1694446597.253438": {
                "action": "case closed",
                "user": "nouser2",
                "user_id": 1
            },
            "1694446626.551442": {
                "action": "case closed",
                "user": "nouser2",
                "user_id": 1
            },
            "1694447102.368478": {
                "action": "case closed",
                "user": "nouser2",
                "user_id": 1
            },
            "1694447187.785556": {
                "action": "case closed",
                "user": "nouser2",
                "user_id": 1
            },
            "1694447233.805542": {
                "action": "case closed",
                "user": "nouser2",
                "user_id": 1
            },
            "1694447256.462593": {
                "action": "case closed",
                "user": "nouser2",
                "user_id": 1
            },
            "1694447324.542543": {
                "action": "case closed",
                "user": "nouser2",
                "user_id": 1
            },
            "1694447772.724512": {
                "action": "case reopened",
                "user": "nouser2",
                "user_id": 1
            },
            "1694448681.95518": {
                "action": "case closed",
                "user": "nouser2",
                "user_id": 1
            },
            "1694449204.048061": {
                "action": "case closed",
                "user": "nouser2",
                "user_id": 1
            },
            "1694449647.332296": {
                "action": "case reopened",
                "user": "nouser2",
                "user_id": 1
            },
            "1694449754.493539": {
                "action": "case closed",
                "user": "nouser2",
                "user_id": 1
            },
            "1694450199.853172": {
                "action": "case reopened",
                "user": "nouser2",
                "user_id": 1
            },
            "1694452250.114495": {
                "action": "case closed",
                "user": "nouser2",
                "user_id": 1
            },
            "1694452672.978887": {
                "action": "case reopened",
                "user": "nouser2",
                "user_id": 1
            },
            "1704711697.835427": {
                "action": "case closed",
                "user": "nouser2",
                "user_id": 1
            },
            "1704711700.739643": {
                "action": "case reopened",
                "user": "nouser2",
                "user_id": 1
            },
            "1704711947.950361": {
                "action": "case closed",
                "user": "nouser2",
                "user_id": 1
            },
            "1704711950.774661": {
                "action": "case reopened",
                "user": "nouser2",
                "user_id": 1
            },
            "1705935117.44055": {
                "action": "case closed",
                "user": "nouser2",
                "user_id": 1
            }
        },
        "open_date": "2023-06-07",
        "owner_id": 1,
        "state_id": 9,
        "status_id": 0,
        "user_id": 1
    }
}
```

#### Human Readable Output

>### Command successfully sent to IRIS DFIR"
>|case_customer|case_description|case_id|case_name|case_soc_id|case_uuid|classification_id|close_date|modification_history|open_date|owner_id|state_id|status_id|user_id|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1 | Social Eng | 9 | #9 - Social Eng | CERT-EU-15 | 35070554-73c1-421a-bdbb-b840f09411b4 | 13 | 2024-01-22 | 1686161424.82484: {"user": "nouser2", "user_id": 1, "action": "created"}<br/>1694445948.238388: {"user": "nouser2", "user_id": 1, "action": "case closed"}<br/>1694446268.42952: {"user": "nouser2", "user_id": 1, "action": "case closed"}<br/>1694446597.253438: {"user": "nouser2", "user_id": 1, "action": "case closed"}<br/>1694446626.551442: {"user": "nouser2", "user_id": 1, "action": "case closed"}<br/>1694447102.368478: {"user": "nouser2", "user_id": 1, "action": "case closed"}<br/>1694447187.785556: {"user": "nouser2", "user_id": 1, "action": "case closed"}<br/>1694447233.805542: {"user": "nouser2", "user_id": 1, "action": "case closed"}<br/>1694447256.462593: {"user": "nouser2", "user_id": 1, "action": "case closed"}<br/>1694447324.542543: {"user": "nouser2", "user_id": 1, "action": "case closed"}<br/>1694447772.724512: {"user": "nouser2", "user_id": 1, "action": "case reopened"}<br/>1694448681.95518: {"user": "nouser2", "user_id": 1, "action": "case closed"}<br/>1694449204.048061: {"user": "nouser2", "user_id": 1, "action": "case closed"}<br/>1694449647.332296: {"user": "nouser2", "user_id": 1, "action": "case reopened"}<br/>1694449754.493539: {"user": "nouser2", "user_id": 1, "action": "case closed"}<br/>1694450199.853172: {"user": "nouser2", "user_id": 1, "action": "case reopened"}<br/>1694452250.114495: {"user": "nouser2", "user_id": 1, "action": "case closed"}<br/>1694452672.978887: {"user": "nouser2", "user_id": 1, "action": "case reopened"}<br/>1704711697.835427: {"user": "nouser2", "user_id": 1, "action": "case closed"}<br/>1704711700.739643: {"user": "nouser2", "user_id": 1, "action": "case reopened"}<br/>1704711947.950361: {"user": "nouser2", "user_id": 1, "action": "case closed"}<br/>1704711950.774661: {"user": "nouser2", "user_id": 1, "action": "case reopened"}<br/>1705935117.44055: {"user": "nouser2", "user_id": 1, "action": "case closed"} | 2023-06-07 | 1 | 9 | 0 | 1 |


### iris-reopen-case-id

***
Reopen a specific case by ID.

#### Base Command

`iris-reopen-case-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | case ID. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IRIS.case_soc_id | unknown | case soc ID | 
| IRIS.case_id | unknown | case ID | 
| IRIS.close_date | unknown | case close date | 
| IRIS.open_date | unknown | case open date | 
| IRIS.case_name | unknown | case name | 
| IRIS.closing_note | unknown | case closing note | 

#### Command example
```!iris-reopen-case-id case_id=9```
#### Context Example
```json
{
    "IRIS": {
        "case_customer": 1,
        "case_description": "Social Eng",
        "case_id": 9,
        "case_name": "#9 - Social Eng",
        "case_soc_id": "CERT-EU-15",
        "case_uuid": "35070554-73c1-421a-bdbb-b840f09411b4",
        "classification_id": 13,
        "close_date": null,
        "closing_note": null,
        "custom_attributes": {},
        "modification_history": {
            "1686161424.82484": {
                "action": "created",
                "user": "nouser2",
                "user_id": 1
            },
            "1694445948.238388": {
                "action": "case closed",
                "user": "nouser2",
                "user_id": 1
            },
            "1694446268.42952": {
                "action": "case closed",
                "user": "nouser2",
                "user_id": 1
            },
            "1694446597.253438": {
                "action": "case closed",
                "user": "nouser2",
                "user_id": 1
            },
            "1694446626.551442": {
                "action": "case closed",
                "user": "nouser2",
                "user_id": 1
            },
            "1694447102.368478": {
                "action": "case closed",
                "user": "nouser2",
                "user_id": 1
            },
            "1694447187.785556": {
                "action": "case closed",
                "user": "nouser2",
                "user_id": 1
            },
            "1694447233.805542": {
                "action": "case closed",
                "user": "nouser2",
                "user_id": 1
            },
            "1694447256.462593": {
                "action": "case closed",
                "user": "nouser2",
                "user_id": 1
            },
            "1694447324.542543": {
                "action": "case closed",
                "user": "nouser2",
                "user_id": 1
            },
            "1694447772.724512": {
                "action": "case reopened",
                "user": "nouser2",
                "user_id": 1
            },
            "1694448681.95518": {
                "action": "case closed",
                "user": "nouser2",
                "user_id": 1
            },
            "1694449204.048061": {
                "action": "case closed",
                "user": "nouser2",
                "user_id": 1
            },
            "1694449647.332296": {
                "action": "case reopened",
                "user": "nouser2",
                "user_id": 1
            },
            "1694449754.493539": {
                "action": "case closed",
                "user": "nouser2",
                "user_id": 1
            },
            "1694450199.853172": {
                "action": "case reopened",
                "user": "nouser2",
                "user_id": 1
            },
            "1694452250.114495": {
                "action": "case closed",
                "user": "nouser2",
                "user_id": 1
            },
            "1694452672.978887": {
                "action": "case reopened",
                "user": "nouser2",
                "user_id": 1
            },
            "1704711697.835427": {
                "action": "case closed",
                "user": "nouser2",
                "user_id": 1
            },
            "1704711700.739643": {
                "action": "case reopened",
                "user": "nouser2",
                "user_id": 1
            },
            "1704711947.950361": {
                "action": "case closed",
                "user": "nouser2",
                "user_id": 1
            },
            "1704711950.774661": {
                "action": "case reopened",
                "user": "nouser2",
                "user_id": 1
            },
            "1705935117.44055": {
                "action": "case closed",
                "user": "nouser2",
                "user_id": 1
            },
            "1705935120.30414": {
                "action": "case reopened",
                "user": "nouser2",
                "user_id": 1
            }
        },
        "open_date": "2023-06-07",
        "owner_id": 1,
        "state_id": 3,
        "status_id": 0,
        "user_id": 1
    }
}
```

#### Human Readable Output

>### Command successfully sent to IRIS DFIR"
>|case_customer|case_description|case_id|case_name|case_soc_id|case_uuid|classification_id|modification_history|open_date|owner_id|state_id|status_id|user_id|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1 | Social Eng | 9 | #9 - Social Eng | CERT-EU-15 | 35070554-73c1-421a-bdbb-b840f09411b4 | 13 | 1686161424.82484: {"user": "nouser2", "user_id": 1, "action": "created"}<br/>1694445948.238388: {"user": "nouser2", "user_id": 1, "action": "case closed"}<br/>1694446268.42952: {"user": "nouser2", "user_id": 1, "action": "case closed"}<br/>1694446597.253438: {"user": "nouser2", "user_id": 1, "action": "case closed"}<br/>1694446626.551442: {"user": "nouser2", "user_id": 1, "action": "case closed"}<br/>1694447102.368478: {"user": "nouser2", "user_id": 1, "action": "case closed"}<br/>1694447187.785556: {"user": "nouser2", "user_id": 1, "action": "case closed"}<br/>1694447233.805542: {"user": "nouser2", "user_id": 1, "action": "case closed"}<br/>1694447256.462593: {"user": "nouser2", "user_id": 1, "action": "case closed"}<br/>1694447324.542543: {"user": "nouser2", "user_id": 1, "action": "case closed"}<br/>1694447772.724512: {"user": "nouser2", "user_id": 1, "action": "case reopened"}<br/>1694448681.95518: {"user": "nouser2", "user_id": 1, "action": "case closed"}<br/>1694449204.048061: {"user": "nouser2", "user_id": 1, "action": "case closed"}<br/>1694449647.332296: {"user": "nouser2", "user_id": 1, "action": "case reopened"}<br/>1694449754.493539: {"user": "nouser2", "user_id": 1, "action": "case closed"}<br/>1694450199.853172: {"user": "nouser2", "user_id": 1, "action": "case reopened"}<br/>1694452250.114495: {"user": "nouser2", "user_id": 1, "action": "case closed"}<br/>1694452672.978887: {"user": "nouser2", "user_id": 1, "action": "case reopened"}<br/>1704711697.835427: {"user": "nouser2", "user_id": 1, "action": "case closed"}<br/>1704711700.739643: {"user": "nouser2", "user_id": 1, "action": "case reopened"}<br/>1704711947.950361: {"user": "nouser2", "user_id": 1, "action": "case closed"}<br/>1704711950.774661: {"user": "nouser2", "user_id": 1, "action": "case reopened"}<br/>1705935117.44055: {"user": "nouser2", "user_id": 1, "action": "case closed"}<br/>1705935120.30414: {"user": "nouser2", "user_id": 1, "action": "case reopened"} | 2023-06-07 | 1 | 3 | 0 | 1 |


### iris-change-case-state

***
Change case state status

#### Base Command

`iris-change-case-state`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Case ID. | Required | 
| case_name | Case name. | Required | 
| case_state | Case state. Possible values are: In progress, Opened, Containement, Eradication, Recovery, Post-Incident, Reporting, Closed. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IRIS.case_id | number | Case ID | 
| IRIS.case_name | string | Case name | 
| IRIS.case_state | string | Case state | 

#### Command example
```!iris-change-case-state case_id=1 case_state="In progress" case_name="#1 - Initial Demo"```
#### Context Example
```json
{
    "IRIS": {
        "case_customer": 1,
        "case_description": "This is a demonstration.",
        "case_id": 1,
        "case_name": "#1 - Initial Demo",
        "case_soc_id": "soc_id_demo",
        "case_uuid": "46480e7c-5b78-42c5-8b2e-678991a8a495",
        "classification_id": null,
        "close_date": "2023-06-05",
        "closing_note": null,
        "custom_attributes": null,
        "modification_history": {
            "1685985574.367342": {
                "action": "case closed",
                "user": "nouser2",
                "user_id": 1
            },
            "1704711960.320669": {
                "action": "case info updated",
                "user": "nouser2",
                "user_id": 1
            },
            "1705935129.662093": {
                "action": "case info updated",
                "user": "nouser2",
                "user_id": 1
            }
        },
        "open_date": "2023-06-05",
        "owner_id": 1,
        "state_id": 2,
        "status_id": 0,
        "user_id": 1
    }
}
```

#### Human Readable Output

>### Command successfully sent to IRIS DFIR"
>|case_customer|case_description|case_id|case_name|case_soc_id|case_uuid|close_date|modification_history|open_date|owner_id|state_id|status_id|user_id|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1 | This is a demonstration. | 1 | #1 - Initial Demo | soc_id_demo | 46480e7c-5b78-42c5-8b2e-678991a8a495 | 2023-06-05 | 1685985574.367342: {"user": "nouser2", "user_id": 1, "action": "case closed"}<br/>1704711960.320669: {"user": "nouser2", "user_id": 1, "action": "case info updated"}<br/>1705935129.662093: {"user": "nouser2", "user_id": 1, "action": "case info updated"} | 2023-06-05 | 1 | 2 | 0 | 1 |


### iris-create-notes-group

***
Creates notes group

#### Base Command

`iris-create-notes-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Case ID. | Required | 
| group_title | Notes group tittle. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!iris-create-notes-group case_id=1 group_title="test group"```
#### Context Example
```json
{
    "IRIS": {
        "group_creationdate": "2024-01-22T14:52:12.540571",
        "group_id": 57,
        "group_lastupdate": "2024-01-22T14:52:12.540571",
        "group_title": "test group",
        "group_uuid": "62742497-8cf6-4cea-bac4-5ff50e4bb4e5"
    }
}
```

#### Human Readable Output

>### Command successfully sent to IRIS DFIR"
>|group_creationdate|group_id|group_lastupdate|group_title|group_uuid|
>|---|---|---|---|---|
>| 2024-01-22T14:52:12.540571 | 57 | 2024-01-22T14:52:12.540571 | test group | 62742497-8cf6-4cea-bac4-5ff50e4bb4e5 |


### iris-add-new-note-to-group

***
Add a new note to an existing group.

#### Base Command

`iris-add-new-note-to-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Case ID. | Required | 
| note_title | Note tittle. | Required | 
| note_content | Note content. | Required | 
| group_id | Group ID. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!iris-add-new-note-to-group case_id=1 group_id=55 note_content="test content" note_title="test tittle"```
#### Context Example
```json
{
    "IRIS": {
        "custom_attributes": {},
        "note_content": "test content",
        "note_creationdate": "2024-01-22T14:52:15.366100",
        "note_id": 63,
        "note_lastupdate": "2024-01-22T14:52:15.366100",
        "note_title": "test tittle",
        "note_uuid": "a2cf6b17-d8be-4ca0-814d-12910aefa2f2"
    }
}
```

#### Human Readable Output

>### Command successfully sent to IRIS DFIR"
>|note_content|note_creationdate|note_id|note_lastupdate|note_title|note_uuid|
>|---|---|---|---|---|---|
>| test content | 2024-01-22T14:52:15.366100 | 63 | 2024-01-22T14:52:15.366100 | test tittle | a2cf6b17-d8be-4ca0-814d-12910aefa2f2 |


### iris-get-list-of-groups-and-notes

***
Get a list of the notes and groups.

#### Base Command

`iris-get-list-of-groups-and-notes`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Case ID. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!iris-get-list-of-groups-and-notes case_id=1```
#### Context Example
```json
{
    "IRIS": {
        "groups": [
            {
                "group_id": 1,
                "group_title": "test group",
                "group_uuid": "98a49bf1-66a3-4014-94a3-b84f7465129e",
                "notes": []
            },
            {
                "group_id": 55,
                "group_title": "test group",
                "group_uuid": "89085dde-aa63-467b-a17a-d78d20bdc794",
                "notes": [
                    {
                        "note_id": 61,
                        "note_lastupdate": "2024-01-08T11:04:41.529018",
                        "note_title": "test tittle",
                        "note_uuid": "1e7cfa4e-6ce0-4261-ae5d-a70eba2b1462",
                        "user": "nouser2"
                    },
                    {
                        "note_id": 62,
                        "note_lastupdate": "2024-01-08T11:06:05.840447",
                        "note_title": "test tittle",
                        "note_uuid": "c1ceef5b-0020-48d7-ac0f-c0c4c40ef396",
                        "user": "nouser2"
                    },
                    {
                        "note_id": 63,
                        "note_lastupdate": "2024-01-22T14:52:15.366100",
                        "note_title": "test tittle",
                        "note_uuid": "a2cf6b17-d8be-4ca0-814d-12910aefa2f2",
                        "user": "nouser2"
                    }
                ]
            },
            {
                "group_id": 56,
                "group_title": "test group",
                "group_uuid": "36da7617-6eca-49d9-bbb6-64737db54aab",
                "notes": []
            },
            {
                "group_id": 57,
                "group_title": "test group",
                "group_uuid": "62742497-8cf6-4cea-bac4-5ff50e4bb4e5",
                "notes": []
            }
        ],
        "state": {
            "object_last_update": "2024-01-22T14:52:15.373121",
            "object_state": 8
        }
    }
}
```

#### Human Readable Output

>### Command successfully sent to IRIS DFIR"
>|groups|state|
>|---|---|
>| {'group_id': 1, 'group_uuid': '98a49bf1-66a3-4014-94a3-b84f7465129e', 'group_title': 'test group', 'notes': []},<br/>{'group_id': 55, 'group_uuid': '89085dde-aa63-467b-a17a-d78d20bdc794', 'group_title': 'test group', 'notes': [{'note_id': 61, 'note_uuid': '1e7cfa4e-6ce0-4261-ae5d-a70eba2b1462', 'note_title': 'test tittle', 'user': 'nouser2', 'note_lastupdate': '2024-01-08T11:04:41.529018'}, {'note_id': 62, 'note_uuid': 'c1ceef5b-0020-48d7-ac0f-c0c4c40ef396', 'note_title': 'test tittle', 'user': 'nouser2', 'note_lastupdate': '2024-01-08T11:06:05.840447'}, {'note_id': 63, 'note_uuid': 'a2cf6b17-d8be-4ca0-814d-12910aefa2f2', 'note_title': 'test tittle', 'user': 'nouser2', 'note_lastupdate': '2024-01-22T14:52:15.366100'}]},<br/>{'group_id': 56, 'group_uuid': '36da7617-6eca-49d9-bbb6-64737db54aab', 'group_title': 'test group', 'notes': []},<br/>{'group_id': 57, 'group_uuid': '62742497-8cf6-4cea-bac4-5ff50e4bb4e5', 'group_title': 'test group', 'notes': []} | object_state: 8<br/>object_last_update: 2024-01-22T14:52:15.373121 |


### iris-get-list-of-iocs

***
Returns a list of IOCs as well as any existing linked with other cases.

#### Base Command

`iris-get-list-of-iocs`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Case ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IRIS.case_id | number | Case ID. | 
| IRIS.case_name | string | Case Name. | 

#### Command example
```!iris-get-list-of-iocs case_id=1```
#### Context Example
```json
{
    "IRIS": {
        "ioc": [
            {
                "ioc_description": "This is an example",
                "ioc_id": 5,
                "ioc_misp": null,
                "ioc_tags": "",
                "ioc_tlp_id": 2,
                "ioc_type": "github-username",
                "ioc_type_id": 65,
                "ioc_uuid": "93ca5e50-13a5-4d59-8b92-b99bf4bb70fd",
                "ioc_value": "github-username-example",
                "link": [],
                "misp_link": null,
                "tlp_bscolor": "warning",
                "tlp_name": "amber"
            }
        ],
        "state": {
            "object_last_update": "2024-01-08T10:45:20.129696",
            "object_state": 1
        }
    }
}
```

#### Human Readable Output

>### Command successfully sent to IRIS DFIR"
>|ioc|state|
>|---|---|
>| {'ioc_id': 5, 'ioc_uuid': '93ca5e50-13a5-4d59-8b92-b99bf4bb70fd', 'ioc_value': 'github-username-example', 'ioc_type_id': 65, 'ioc_type': 'github-username', 'ioc_description': 'This is an example', 'ioc_tags': '', 'ioc_misp': None, 'tlp_name': 'amber', 'tlp_bscolor': 'warning', 'ioc_tlp_id': 2, 'link': [], 'misp_link': None} | object_state: 1<br/>object_last_update: 2024-01-08T10:45:20.129696 |


### iris-get-ioc-content

***
Fetch the content of an ioc.

#### Base Command

`iris-get-ioc-content`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Case ID. | Required | 
| ioc_id | IoC ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IRIS.case_id | number | Case ID. | 
| IRIS.ioc_description | string | IoC Description. | 
| IRIS.ioc_id | number | IoC ID. | 
| IRIS.ioc_value | string | IoC Value. | 
| IRIS.ioc_type | string | IoC Type. | 

#### Command example
```!iris-get-ioc-content case_id=1 ioc_id=5```
#### Context Example
```json
{
    "IRIS": {
        "custom_attributes": {},
        "ioc_description": "This is an example",
        "ioc_enrichment": null,
        "ioc_id": 5,
        "ioc_misp": null,
        "ioc_tags": "",
        "ioc_tlp_id": 2,
        "ioc_type": {
            "type_description": "A github user name",
            "type_id": 65,
            "type_name": "github-username",
            "type_taxonomy": null,
            "type_validation_expect": null,
            "type_validation_regex": null
        },
        "ioc_type_id": 65,
        "ioc_uuid": "93ca5e50-13a5-4d59-8b92-b99bf4bb70fd",
        "ioc_value": "github-username-example",
        "user_id": 1
    }
}
```

#### Human Readable Output

>### Command successfully sent to IRIS DFIR"
>|ioc_description|ioc_id|ioc_tlp_id|ioc_type|ioc_type_id|ioc_uuid|ioc_value|user_id|
>|---|---|---|---|---|---|---|---|
>| This is an example | 5 | 2 | type_description: A github user name<br/>type_taxonomy: null<br/>type_id: 65<br/>type_name: github-username<br/>type_validation_regex: null<br/>type_validation_expect: null | 65 | 93ca5e50-13a5-4d59-8b92-b99bf4bb70fd | github-username-example | 1 |
