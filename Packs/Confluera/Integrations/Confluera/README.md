
## Confluera Integration

This is Confluera Integration.

Please make sure you look at the integration source code and comments.

This integration was built to get the insights of Confluera API(Autonomouse Detetcions and Response).

This integration was tested against product version 2.2.3

Supported Product Versions: 2.2.3 and above.


## Configure Confluera in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| IQ-Hub url | Server URL \(e.g. https://test.confluera.com\) | True |
| Trust any certificate | Not Secure | False |
| Use system proxy settings | Proxy Settings | False |
| Username |Usernme \(e.g. username@confluera.com\) | True|
| Password | Password \(e.g. userpassword\) | True |


## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### confluera-fetch-detections
***
Fetches list of detections in confluera for past x hours.


#### Base Command

`confluera-fetch-detections`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hours | Specifies the time duration for which detections need to be fetched  | Optional | 



#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Confluera.Detections | Unknown | Detections Response |


#### Command Example
```!confluera-fetch-detections hours="23"```

#### Context Example
```
[
  {
    "agentId": "prod_0_7_.agent-7",
    "allowListId": null,
    "attackIdList": [
      1561190
    ],
    "iocDetail": "MODIFIES file (/var/lib/apt/periodic/download-upgradeable-stamp) ",
    "iocHash": "CreateModify-d596b00c51bc196d83a1c09736067986-1618187993765144524",
    "iocSummary": "modifies file (/var/lib/apt/periodic/download-upgradeable-stamp) ",
    "iocTactic": "Defense Evasion",
    "ruleid": 0,
    "scoreContribution": 0,
    "seenTime": 1618187993765144600,
    "trailId": "3343680",
    "trailIocInfoType": "DETECTION",
    "trailList": [
      "prod_0_7_.agent-7:3343680"
    ],
    "trailStateList": [
      "ACTIVE"
    ]
  },
  {
    "agentId": "prod_0_7_.agent-7",
    "allowListId": null,
    "attackIdList": [
      1561190
    ],
    "iocDetail": "CREATES file (/tmp/fileutl.message.f9ZBRG) ",
    "iocHash": "CreateModify-3a46fad59032e3456e1c5bbf4fbc139e-1618187993710159633",
    "iocSummary": "creates file (/tmp/fileutl.message.f9ZBRG) ",
    "iocTactic": "Defense Evasion",
    "ruleid": 0,
    "scoreContribution": 0,
    "seenTime": 1618187993710159600,
    "trailId": "3343680",
    "trailIocInfoType": "DETECTION",
    "trailList": [
      "prod_0_7_.agent-7:3343680"
    ],
    "trailStateList": [
      "ACTIVE"
    ]
  }
]
```

#### Human Readable Output

>### Results
>|agentId |allowListId |attackIdList|iocDetail |iocHash|iocSummary| iocTactic| ruleid|scoreContribution|seenTime |trailId|trailIocInfoType |trailList | trailStateList |
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|prod_0_7_.agent-39 || 985860| ["prod_0_7_.agent-39:16351"] | InfluencedBy-9a56be0d76fe58f2373d64c4910aa40b-1618511546260570882 | Uses tainted file (/var/lib/amazon/ssm/i-0736b112f2496f381/document/state/current/fd2b1a18-2c09-47f2-afc3-fe013a364250) influencerTrails ["prod_0_7_.agent-39:16351"] | Defense Evasion|0 |2 |1618511546260570882 | 22016|DETECTION| prod_0_7_.agent-39:22016|ACTIVE |
>|prod_0_7_.agent-39 || 985860| ["prod_0_7_.agent-39:16351"] | InfluencedBy-9a56be0d76fe58f2373d64c4910aa40b-1618511546260570882 | Uses tainted file (/var/lib/amazon/ssm/i-0736b112f2496f381/document/state/current/fd2b1a18-2c09-47f2-afc3-fe013a364250) influencerTrails ["prod_0_7_.agent-39:16351"] | Defense Evasion|0 |2 |1618511546260570882 | 22016|DETECTION| prod_0_7_.agent-39:22016|ACTIVE |
>|prod_0_7_.agent-39 || 972763| User  accessing website | Edge-ae3b3d9a3c5d4b17491d3f6d924bd3b8-1618509851233674054 | Long sleep executed by process| Lateral Movement|0 |2 |1618511546260570882 | 22016|DETECTION| prod_0_7_.agent-39:22016|ACTIVE |
>|prod_0_7_.agent-39 || 972763| User  accessing website | InfluencedBy-9a56be0d76fe58f2373d64c4910aa40b-1618511546260570882 | Uses tainted file (/var/lib/amazon/ssm/i-0736b112f2496f381/document/state/current/fd2b1a18-2c09-47f2-afc3-fe013a364250) influencerTrails ["prod_0_7_.agent-39:16351"] | Defense Evasion|0 |2 |1618511546260570882 | 22016|DETECTION| prod_0_7_.agent-39:22016|ACTIVE |
### confluera-fetch-progressions
***
Fetches list of progressions in confluera for past x hours.


#### Base Command

`confluera-fetch-progressions`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
|hours|Specifies the time duration for which progressions need to be fetched |Optional|


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Confluera.Progressions | Unknown | Progressions response |


#### Command Example
```!confluera-fetch-progressions hours="72"```

#### Context Example
```
[
  {
    "agentId": "prod_0_17_.agent-17",
    "attackId": 7124733,
    "containsAnchor": false,
    "fingerprint": "df8519f5bbe6a8503c4b63da7a569cb1a1d51cd2d5784301e8d6dcec1950c93f",
    "hostTimeInfoMap": {
      "prod_0_17_.agent-17": 1618122605017392000
    },
    "lastIocSeenTime": 1618125575564836600,
    "lastIocSeenTimeInternal": 0,
    "lastMitigatedTime": 0,
    "local": true,
    "mitigateTime": 1618125575564836600,
    "numberOfDetections": 2,
    "numberOfHosts": 1,
    "numberOfLateralMovements": 0,
    "riskMomentum": 0,
    "riskScore": 6,
    "startTime": 1618122605017392000,
    "state": "ACTIVE",
    "trailIdHash": "prod_0_17_.agent-17:339738705",
    "trailRiskHistInfoList": [
      {
        "agentId": "prod_0_17_.agent-17",
        "scoreContribution": 0,
        "seenTime": 1618122605017392000,
        "trailId": "339738705"
      },
      {
        "agentId": "prod_0_17_.agent-17",
        "scoreContribution": 5,
        "seenTime": 1618125575564836600,
        "trailId": "339738705"
      }
    ],
    "trailTacticSet": [
      "discovery",
      "exfiltration"
    ],
    "trailTechniqueSet": [
      "T1046",
      "T1048"
    ]
  },
  {
    "agentId": "prod_0_27_.agent-27",
    "attackId": 6977718,
    "containsAnchor": true,
    "fingerprint": "73bb36f06ffc5917ac3399baa99b833583ba4b3b6d44fa9ce68da2ed1c374ecf",
    "hostTimeInfoMap": {
      "prod_0_27_.agent-27": 1617982165439958500
    },
    "lastIocSeenTime": 1617987480554035200,
    "lastIocSeenTimeInternal": 0,
    "lastMitigatedTime": 0,
    "local": true,
    "mitigateTime": 1617987480554035200,
    "numberOfDetections": 13,
    "numberOfHosts": 1,
    "numberOfLateralMovements": 1,
    "riskMomentum": 0,
    "riskScore": 10,
    "startTime": 1617982165439958500,
    "state": "ACTIVE",
    "trailIdHash": "prod_0_27_.agent-27:1082130441",
    "trailRiskHistInfoList": [
      {
        "agentId": "prod_0_27_.agent-27",
        "scoreContribution": 0,
        "seenTime": 1617982165439958500,
        "trailId": "1082130441"
      },
      {
        "agentId": "prod_0_27_.agent-27",
        "scoreContribution": 10,
        "seenTime": 1617986780899034000,
        "trailId": "1082130441"
      }
    ],
    "trailTacticSet": [
      "execution",
      "privilege_escalation",
      "lateral_movement"
    ],
    "trailTechniqueSet": [
      "T1166"
    ]
  }
]
```

#### Human Readable Output

>### Progressions Log:
>|Progression URL|Total Progressions|
>|---|---|
>||19|
>### Successfully fetched 19 progressions.
>|agentId|attackId|containsAnchor|fingerprint|hostTimeInfoMap|lastIocSeenTime|lastIocSeenTimeInternal|lastMitigatedTime|local|mitigateTime|numberOfDetections|numberOfHosts|numberOfLateralMovements|riskMomentum|riskScore|startTime|state|trailIdHash|trailRiskHistInfoList|trailTacticSet|trailTechniqueSet|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|prod_0_26_.agent-26|942184|true|34386ee468f53dc45582f45ed15f204794d|prod_0_26_.agent-26: 1618466218792013459|1618466218792013459|0|0|true|1618466218792013459|1|1|0|0|10|1618466218792013459|ACTIVE|prod_0_26_.agent-26:164626437|{'agentId': 'prod_0_26_.agent-26', 'scoreContribution': 0, 'seenTime': 1618466218792013459, 'trailId': '164626437'}|command_and_control|T1219|
>|prod_0_26_.agent-26|559633|true|2fca6467a9dccd2729ace9ce1832334386ee468f53dc45582f45ed15f204794d|prod_0_26_.agent-26: 1618378594837195479|1618378594837195479|0|0|true|1618379630722739179|1|1|0|0|10|1618466218792013459|ACTIVE|prod_0_26_.agent-26:157286403|{'agentId': 'prod_0_26_.agent-26', 'scoreContribution': 0, 'seenTime': 1618378594837195479, 'trailId': '157286403'}|command_and_control|T1219|
>|prod_0_26_.agent-26|769367|true|34386ee468f53dc45582f45ed15f204794d|prod_0_26_.agent-26: 1618417629053160077|1618417629053160077|0|0|true|1618417629053160077|4|1|0|0|40|1618419753818041182|ACTIVE|prod_0_26_.agent-26:162529286|{'agentId': 'prod_0_26_.agent-26', 'scoreContribution': 10, 'seenTime': 1618419753818041182, 'trailId': '162529286'}|command_and_control|T1219|

### confluera-fetch-trail-details
***
Fetches progression details of which provided trailId is a part of.


#### Base Command

`confluera-fetch-trail-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| trail_id| Id of a detection in iq-hub protal. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Confluera.TrailDetails | Unknown | Progression Details |


#### Command Example
```!confluera-fetch-trail-details trail-id="22796349"```

#### Context Example
```
{
  "attackId": 7164528,
  "fingerprint": "c15ca700c08839b1b26ef8bfdb7599cb52d68307845e4317b355b080fb989170",
  "hostList": [
    "prod_0_3_.agent-35"
  ],
  "influenceeList": [],
  "influencerList": [],
  "lastMitigatedTime": 0,
  "lateralMovementEdges": [],
  "markedIocs": [],
  "numberOfDetections": 1,
  "numberOfHosts": 1,
  "numberOfLateralMovements": 0,
  "riskScore": 10,
  "similarTrails": [
    "prod_0_3_.agent-35:10002087"
  ],
  "startTime": 1618216658903757800,
  "state": "ACTIVE",
  "trailIocInfoList": [
    {
      "actionMap": null,
      "agentId": "prod_0_3_.agent-35",
      "attackIdList": [],
      "containerId": null,
      "iocDetail": "Incoming traffic from malicious external IP address (Greynoise)",
      "iocEventsList": [
        {
          "agentId": "prod_0_3_.agent-35",
          "artifactPath": "",
          "artifactScore": 0,
          "clonedPid": "8652",
          "clonedPidHash": "agent-35-p-8652-1618246163438993400",
          "edgeName": "TcpAcceptListenerComplete",
          "edgeType": "ACCEPTS",
          "exefilehash": "agent-35-f-1753326844-562949953725973-1563567751620348100",
          "externalIPIntelMetadata": {
            "city": "Xinpu",
            "country": "CN",
            "latitude": 34.5997,
            "longitude": 119.1594,
            "subdivision": "JS"
          },
          "localHost": "172.31.14.50",
          "localPort": 22,
          "os": "Windows",
          "parentBinaryName": "",
          "parentBinaryScore": 0,
          "parentProcessName": "services.exe",
          "parentSessionid": 0,
          "parentSid": "",
          "parentVertexHash": "agent-35-p-780-1614631840327003000",
          "remoteHost": "218.92.0.207",
          "remotePort": 16037,
          "ret": 0,
          "score": "HIGH",
          "socketFamily": 2,
          "sourceBinaryName": "/device/harddiskvolume1/windows/system32/openssh/sshd.exe",
          "sourceBinaryScore": 0,
          "sourceCommandLine": "/device/harddiskvolume1/windows/system32/openssh/sshd.exe",
          "sourcePid": 2752,
          "sourcePpid": 780,
          "sourceProcessName": "sshd.exe",
          "sourceSessionid": 0,
          "sourceSid": "S-1-5-18",
          "sourceVertexHash": "agent-35-p-2752-1614631842699633100",
          "spawnedBinaryName": "/device/harddiskvolume1/windows/system32/openssh/sshd.exe",
          "spawnedCommandLine": "/device/harddiskvolume1/windows/system32/openssh/sshd.exe",
          "spawnedPid": 2752,
          "spawnedPpid": 780,
          "spawnedProcessName": "sshd.exe",
          "spawnedSessionid": 0,
          "taintedFile": false,
          "targetSid": "S-1-5-18",
          "targetVertexHash": "agent-35-p-2752-1614631842699633100",
          "technique": "T1190",
          "threatIntelMetadata": {
            "actor": "unknown",
            "classification": "malicious",
            "first_seen": "2019-03-22",
            "ip": "218.92.0.207",
            "last_seen_timestamp": "2021-02-26 13:08:40",
            "metadata": {
              "asn": "AS4134",
              "category": "isp",
              "city": "Shanghai",
              "country": "China",
              "organization": "CHINANET-BACKBONE",
              "os": "Linux 3.11+"
            },
            "seen": true,
            "spoofable": "false",
            "tags": [
              "SSH Bruteforcer",
              "SSH Scanner",
              "ZMap Client"
            ],
            "vpn": "false"
          },
          "timestamp": 1618216658903757800,
          "trailScore": 10,
          "trailScoreAndMomentum": 10
        }
      ],
      "iocHash": "Edge-33cc15406f131e0b5d5030a23de7f5af-1618216658903757800",
      "iocSummary": "Incoming traffic from malicious external IP address (Greynoise)",
      "iocTactic": "INITIAL_ACCESS",
      "occurrence": 1,
      "recommendation": [
        {
          "action": "kill-process@@@agent-35-p-2752-1614631842699633100",
          "compatibleAgent": true,
          "duplicate": false,
          "index": 0,
          "justification": "The process /device/harddiskvolume1/windows/system32/openssh/sshd.exe has been involved in an indicator of compromise. The process should be terminated to prevent further execution\n",
          "priority": "medium",
          "recommendation": "Kill process /device/harddiskvolume1/windows/system32/openssh/sshd.exe with pid 2752",
          "valid": false
        }
      ],
      "trailTacticSet": [
        "initial_access"
      ]
    }
  ]
}
```

#### Human Readable Output

>### Trail Details:
>|agentId|attackId|containsAnchor|fingerprint|hostTimeInfoMap|lastIocSeenTime|lastIocSeenTimeInternal|lastMitigatedTime|local|mitigateTime|numberOfDetections|numberOfHosts|numberOfLateralMovements|riskMomentum|riskScore|startTime|state|trailIdHash|trailRiskHistInfoList|trailTacticSet|trailTechniqueSet|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|prod_0_26_.agent-26|942184|true|34386ee468f53dc45582f45ed15f204794d|prod_0_26_.agent-26: 1618466218792013459|1618466218792013459|0|0|true|1618466218792013459|1|1|0|0|10|1618466218792013459|ACTIVE|prod_0_26_.agent-26:164626437|{'agentId': 'prod_0_26_.agent-26', 'scoreContribution': 0, 'seenTime': 1618466218792013459, 'trailId': '164626437'}|command_and_control|T1219|
>|prod_0_26_.agent-26|559633|true|2fca6467a9dccd2729ace9ce1832334386ee468f53dc45582f45ed15f204794d|prod_0_26_.agent-26: 1618378594837195479|1618378594837195479|0|0|true|1618379630722739179|1|1|0|0|10|1618466218792013459|ACTIVE|prod_0_26_.agent-26:157286403|{'agentId': 'prod_0_26_.agent-26', 'scoreContribution': 0, 'seenTime': 1618378594837195479, 'trailId': '157286403'}|command_and_control|T1219|
>|prod_0_26_.agent-26|769367|true|34386ee468f53dc45582f45ed15f204794d|prod_0_26_.agent-26: 1618417629053160077|1618417629053160077|0|0|true|1618417629053160077|4|1|0|0|40|1618419753818041182|ACTIVE|prod_0_26_.agent-26:162529286|{'agentId': 'prod_0_26_.agent-26', 'scoreContribution': 10, 'seenTime': 1618419753818041182, 'trailId': '162529286'}|command_and_control|T1219|



---