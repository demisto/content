The ArcusTeam API allows the user to inspect connected devices' attack surface. By feeding device identifiers and the software it runs: DeviceTotal will return a map of the device’s attack surface. DeviceTotal was built from the ground up in order to provide complete visibility into connected devices and mitigate 3rd party risk. DeviceTotal can continuously identify & predict such that the connected device security posture is being assessed, prioritized and mitigated effectively.
This integration was integrated and tested with version 6.11.0 of ArcusTeam
## Get Your API Key
Please visit our [dedicated page](https://arcusteam.com/pa-partnership/) to obtain your API key.

## Configure ArcusTeam in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g. https://web.prod.arcusteam.com) | The FQDN/IP the integration should connect to. | True |
| API Key |  The API Key required to authenticate to the service. | True |
| The client ID | The client ID from ArcusTeam dashboard | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### arcusteam-get-devices
***
 Find ArcusTeam Device


#### Base Command

`arcusteam-get-devices`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vendor | Device vendor. | Required | 
| model | Device model. | Optional | 
| series |  Device series. | Optional | 
| firmware_version | Firmware version. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ArcusTeamDevices.devices.categories | Unknown |  Device categories | 
| ArcusTeamDevices.devices.device_key | string |  Arcus Team Device ID | 
| ArcusTeamDevices.devices.model | string |  Device model | 
| ArcusTeamDevices.devices.series | string |  Device series | 
| ArcusTeamDevices.devices.vendor | string |  Device vendor | 
| ArcusTeamDevices.devices.score | number | The similarity score | 
| ArcusTeamDevices.devices.firmware.firmwareid | string |  Firmware ID | 
| ArcusTeamDevices.devices.firmware.name | string |  Firmware name | 
| ArcusTeamDevices.devices.firmware.version | string | Firmware version | 


#### Command Example
```!arcusteam-get-devices vendor="Cisco" model="Nexus 6001" series="Nexus 6000"```

#### Context Example
```json
{
    "ArcusTeamDevices": {
        "devices": [
            {
                "categories": [
                    "SWITCH",
                    "NETWORK"
                ],
                "device_key": "e91e3216d1d0f6480a89acbd9536a1ca",
                "firmware": [
                    {
                        "firmwareid": "a2eca61d015b73f4401dad8fd93d4ac4",
                        "name": "NX-OS System Software",
                        "version": "7.2(1)N1(1)"
                    },
                    {
                        "firmwareid": "fea10272507045a37373556935122a5a",
                        "name": "NX-OS System Software",
                        "version": "7.3(1)N1(1)"
                    },
                    {
                        "firmwareid": "2e29893957761ce93f64db41933a4b70",
                        "name": "NX-OS System Software",
                        "version": "7.1(5)N1(1)"
                    },
                    {
                        "firmwareid": "ed746be84164c3a3e80d7a3a29983ffe",
                        "name": "NX-OS XML Schema Definition",
                        "version": "7.0(6)N1(1)"
                    },
                    {
                        "firmwareid": "72e98966800e371832b77a167f56e43e",
                        "name": "NX-OS XML Schema Definition",
                        "version": "7.1(0)N1(1a)"
                    },
                    {
                        "firmwareid": "7105d7a2484da9605d9dfc433f375666",
                        "name": "NX-OS System Software",
                        "version": "7.1(3)N1(1)"
                    },
                    {
                        "firmwareid": "370fd34dd9ba8fb90790d1eac233a11e",
                        "name": "NX-OS System Software",
                        "version": "7.0(1)N1(1)"
                    },
                    {
                        "firmwareid": "42b120bd04856cf7ec60bcd82710ff4d",
                        "name": "NX-OS XML Schema Definition",
                        "version": "7.0(3)N1(1)"
                    },
                    {
                        "firmwareid": "0890d99611596739e04ef1ce6c7a9133",
                        "name": "NX-OS XML Schema Definition",
                        "version": "7.0(2)N1(1)"
                    },
                    {
                        "firmwareid": "89bce497c81f19d2e3edc03b65e81c80",
                        "name": "NX-OS System Software",
                        "version": "7.3(7)N1(1)"
                    },
                    {
                        "firmwareid": "4d36d85663d6a29fee8a077eabf5e316",
                        "name": "NX-OS System Software",
                        "version": "7.0(4)N1(1)"
                    },
                    {
                        "firmwareid": "56132106f92df878b5894b440ffbc456",
                        "name": "NX-OS XML Schema Definition",
                        "version": "7.2(0)N1(1)"
                    },
                    {
                        "firmwareid": "8dd3916ab0c4d04720aeadd81fd77f78",
                        "name": "NX-OS Kick Start",
                        "version": "7.1(1)N1(1)"
                    },
                    {
                        "firmwareid": "ae4f5adb0281a76575dc9e1fa00ffdc9",
                        "name": "NX-OS XML Schema Definition",
                        "version": "7.0(5)N1(1)"
                    },
                    {
                        "firmwareid": "b2e9ce36dfa6ce078748e2936cdea90d",
                        "name": "NX-OS Kick Start",
                        "version": "7.0(6)N1(1)"
                    },
                    {
                        "firmwareid": "b70cd3277917305f6d74fa0f50f4a899",
                        "name": "NX-OS Kick Start",
                        "version": "7.0(1)N1(1)"
                    },
                    {
                        "firmwareid": "4d7d143acfe8855b513cf056dd7298a0",
                        "name": "NX-OS System Software",
                        "version": "7.3(7)N1(1b)"
                    },
                    {
                        "firmwareid": "0590acb584ea89d36266943b3d5a4b5c",
                        "name": "NX-OS System Software",
                        "version": "7.3(6)N1(1)"
                    },
                    {
                        "firmwareid": "71e6e5a473d39167fc7357d3ad24f587",
                        "name": "NX-OS Kick Start",
                        "version": "7.1(5)N1(1b)"
                    },
                    {
                        "firmwareid": "4ba51fa1c8c7afe9e06ccc0a3073dcda",
                        "name": "NX-OS System Software",
                        "version": "7.1(3)N1(2)"
                    },
                    {
                        "firmwareid": "27292d2b55a9df248032bd1f1fa03a48",
                        "name": "NX-OS Kick Start",
                        "version": "7.2(1)N1(1)"
                    },
                    {
                        "firmwareid": "6736f6105f96ad2b3eaac58a4d1743a2",
                        "name": "NX-OS Kick Start",
                        "version": "7.0(8)N1(1)"
                    },
                    {
                        "firmwareid": "36eba4a64f131297f24658118e5a5320",
                        "name": "NX-OS System Software",
                        "version": "7.1(1)N1(1)"
                    },
                    {
                        "firmwareid": "e1b360d2eb32949caea7abba0683d75c",
                        "name": "NX-OS System Software",
                        "version": "7.0(0)N1(1)"
                    },
                    {
                        "firmwareid": "90c8ed73ff57b0ad28c9993e89926f92",
                        "name": "NX-OS System Software",
                        "version": "7.0(7)N1(1)"
                    },
                    {
                        "firmwareid": "78eaf65d85e427cdc0f7c1dced5493ca",
                        "name": "NX-OS Kick Start",
                        "version": "7.3(7)N1(1)"
                    },
                    {
                        "firmwareid": "d9c570cb112b8ded7a583b3a3f24c68d",
                        "name": "NX-OS System Software",
                        "version": "7.0(3)N1(1)"
                    },
                    {
                        "firmwareid": "f5db998da08c1917bb76ea98b051bff6",
                        "name": "NX-OS System Software",
                        "version": "7.1(0)N1(1b)"
                    },
                    {
                        "firmwareid": "88211351b6739a8f9aa0c0ac01162b70",
                        "name": "NX-OS Kick Start",
                        "version": "7.3(7)N1(1a)"
                    },
                    {
                        "firmwareid": "a9430bb6c616d5300628f328e0bf3f99",
                        "name": "NX-OS Kick Start",
                        "version": "7.3(6)N1(1)"
                    },
                    {
                        "firmwareid": "60b6b0880ea9b139c09c5f5c84c8a2ce",
                        "name": "NX-OS System Software",
                        "version": "7.3(7)N1(1a)"
                    },
                    {
                        "firmwareid": "68dd1c8e68d7d9c5a3af251f6555a4d3",
                        "name": "NX-OS System Software",
                        "version": "7.0(6)N1(1)"
                    },
                    {
                        "firmwareid": "6d4d6b7373ce6b06a55585a4ea9b979f",
                        "name": "NX-OS System Software",
                        "version": "7.0(5)N1(1)"
                    },
                    {
                        "firmwareid": "ae90b06c9f44a0eae0d3eaba82bfc8ee",
                        "name": "NX-OS System Software",
                        "version": "7.3(2)N1(1)"
                    },
                    {
                        "firmwareid": "6caace1917787970457630829974b505",
                        "name": "NX-OS System Software",
                        "version": "7.0(5)N1(1a)"
                    },
                    {
                        "firmwareid": "1ca6ba2c4e764ac4728f5f965766063f",
                        "name": "NX-OS System Software",
                        "version": "7.3(5)N1(1)"
                    },
                    {
                        "firmwareid": "8ae8c9d274dd843768a66f8eec9dab03",
                        "name": "NX-OS System Software",
                        "version": "7.1(5)N1(1b)"
                    },
                    {
                        "firmwareid": "6dae9b841c0a36e2e02b2a17e3856af8",
                        "name": "NX-OS System Software",
                        "version": "7.1(0)N1(1a)"
                    },
                    {
                        "firmwareid": "a6387db4d583f3a987bf41fde8f435b3",
                        "name": "NX-OS Kick Start",
                        "version": "7.1(0)N1(1a)"
                    },
                    {
                        "firmwareid": "61cfb54e591b074037f796cca06d50b8",
                        "name": "NX-OS System Software",
                        "version": "7.1(4)N1(1)"
                    },
                    {
                        "firmwareid": "306bf0ead653d435245a3fcd597ccf25",
                        "name": "NX-OS Kick Start",
                        "version": "7.0(5)N1(1a)"
                    },
                    {
                        "firmwareid": "de814b78db5c9dfd3359c8d113589e15",
                        "name": "NX-OS System Software",
                        "version": "7.3(0)N1(1)"
                    },
                    {
                        "firmwareid": "a75068fb4557cdef95e113a5b6623977",
                        "name": "NX-OS XML Schema Definition",
                        "version": "7.0(5)N1(1a)"
                    },
                    {
                        "firmwareid": "9cf146a7b33150f348dabd1a80d32696",
                        "name": "NX-OS Kick Start",
                        "version": "7.3(7)N1(1b)"
                    },
                    {
                        "firmwareid": "68bf3d37af54863726e5318e89fcb4f8",
                        "name": "NX-OS XML Schema Definition",
                        "version": "7.0(1)N1(1)"
                    },
                    {
                        "firmwareid": "681f438e1d5d37d7cb4eb51b32c137a6",
                        "name": "NX-OS Kick Start",
                        "version": "7.1(3)N1(2)"
                    },
                    {
                        "firmwareid": "18b4381c59a00b891a49955ff16c722c",
                        "name": "NX-OS Kick Start",
                        "version": "7.1(0)N1(1b)"
                    },
                    {
                        "firmwareid": "4dc05d971c6a329436269ce10396a61a",
                        "name": "NX-OS System Software",
                        "version": "7.1(0)N1(1)"
                    },
                    {
                        "firmwareid": "f03f0a381d74eb2c8bef16ce5c69d749",
                        "name": "NX-OS System Software",
                        "version": "7.0(8)N1(1)"
                    },
                    {
                        "firmwareid": "d8b89ac1dd6ed65d55498b9e35782462",
                        "name": "NX-OS System Software",
                        "version": "7.1(2)N1(1)"
                    },
                    {
                        "firmwareid": "45f457a87dc482ff9045620ff052c085",
                        "name": "NX-OS Kick Start",
                        "version": "7.3(2)N1(1)"
                    },
                    {
                        "firmwareid": "16982d268d25bd1fa3cd758f9a0f73d0",
                        "name": "NX-OS Kick Start",
                        "version": "7.3(3)N1(1)"
                    },
                    {
                        "firmwareid": "09dde9c8f0a71a81fcc7e80f0c24855b",
                        "name": "NX-OS Kick Start",
                        "version": "7.3(1)N1(1)"
                    },
                    {
                        "firmwareid": "0e176309fe8d808aca1593edde6711d0",
                        "name": "NX-OS System Software",
                        "version": "7.3(4)N1(1)"
                    },
                    {
                        "firmwareid": "5ad4a6edef078ebb9de03cede2d9fe8d",
                        "name": "NX-OS Kick Start",
                        "version": "7.3(4)N1(1)"
                    },
                    {
                        "firmwareid": "383540dc529b128a28481cfacbdb49cd",
                        "name": "NX-OS System Software",
                        "version": "7.2(0)N1(1)"
                    },
                    {
                        "firmwareid": "6fac6f0a458803091c39ff5a687ffd86",
                        "name": "NX-OS Kick Start",
                        "version": "7.0(3)N1(1)"
                    },
                    {
                        "firmwareid": "f405a5f672ab8e7d893be2f8f1837f01",
                        "name": "NX-OS Kick Start",
                        "version": "7.1(2)N1(1)"
                    },
                    {
                        "firmwareid": "f0a14bb11b9bac0b8636d040dded1b97",
                        "name": "NX-OS System Software",
                        "version": "7.3(8)N1(1)"
                    },
                    {
                        "firmwareid": "1347cbf7ba4401dcbb77a44035b0bdd1",
                        "name": "NX-OS Kick Start",
                        "version": "7.1(4)N1(1)"
                    },
                    {
                        "firmwareid": "6b9e9b07fd81ebfdb996b5c69379bb2c",
                        "name": "NX-OS Kick Start",
                        "version": "7.0(5)N1(1)"
                    },
                    {
                        "firmwareid": "13a4be2661431a141607d1e45ba48576",
                        "name": "NX-OS XML Schema Definition",
                        "version": "7.0(0)N1(1)"
                    },
                    {
                        "firmwareid": "befc05ccce51abce9df9f21cca64eda4",
                        "name": "NX-OS Kick Start",
                        "version": "7.0(2)N1(1)"
                    },
                    {
                        "firmwareid": "1548c2557d3ca5d6b8462fd4407df353",
                        "name": "NX-OS Kick Start",
                        "version": "7.3(0)N1(1)"
                    },
                    {
                        "firmwareid": "db79885ecae70e404b63411cb7f7d334",
                        "name": "NX-OS Kick Start",
                        "version": "7.1(0)N1(1)"
                    },
                    {
                        "firmwareid": "bb0f0a358c17bee17f28b23caaf2bf01",
                        "name": "NX-OS Kick Start",
                        "version": "7.1(3)N1(1)"
                    },
                    {
                        "firmwareid": "809082e9cc549c5c85ac0ca9c13f4a66",
                        "name": "NX-OS Kick Start",
                        "version": "7.0(4)N1(1)"
                    },
                    {
                        "firmwareid": "e411041ffe31883e627c27cf51aa210f",
                        "name": "NX-OS Kick Start",
                        "version": "7.1(5)N1(1)"
                    },
                    {
                        "firmwareid": "a2aa471189f30f989d9d6a20fc4f24c0",
                        "name": "NX-OS Kick Start",
                        "version": "7.3(8)N1(1)"
                    },
                    {
                        "firmwareid": "f2e1e0ff5bf1b26956bff042cc432967",
                        "name": "NX-OS System Software",
                        "version": "7.0(2)N1(1)"
                    },
                    {
                        "firmwareid": "5ce43e35313dcc4ee7c39584a5e1a66c",
                        "name": "NX-OS System Software",
                        "version": "7.3(3)N1(1)"
                    },
                    {
                        "firmwareid": "98d66a2e1fe7a56ff93c9fafacca72da",
                        "name": "NX-OS Kick Start",
                        "version": "7.0(7)N1(1)"
                    },
                    {
                        "firmwareid": "02c3dfdb2bb77566084f0e4199701abe",
                        "name": "NX-OS XML Schema Definition",
                        "version": "7.1(0)N1(1)"
                    },
                    {
                        "firmwareid": "8adcfea7ee4132853217aa3d7b8ee59e",
                        "name": "NX-OS XML Schema Definition",
                        "version": "7.0(4)N1(1)"
                    },
                    {
                        "firmwareid": "6d168afb5ec0e3efde8a1e091dafaefd",
                        "name": "NX-OS Kick Start",
                        "version": "7.3(5)N1(1)"
                    }
                ],
                "model": "Nexus 6001 Switch",
                "score": 0.76,
                "series": "Nexus 6000 Series Switches",
                "vendor": "CISCO"
            },
            {
                "categories": [
                    "SWITCH",
                    "NETWORK"
                ],
                "device_key": "688f206b8f4766c2eb9db9fc970c924c",
                "firmware": [
                    {
                        "firmwareid": "8dd3916ab0c4d04720aeadd81fd77f78",
                        "name": "NX-OS Kick Start",
                        "version": "7.1(1)N1(1)"
                    },
                    {
                        "firmwareid": "45f457a87dc482ff9045620ff052c085",
                        "name": "NX-OS Kick Start",
                        "version": "7.3(2)N1(1)"
                    },
                    {
                        "firmwareid": "e411041ffe31883e627c27cf51aa210f",
                        "name": "NX-OS Kick Start",
                        "version": "7.1(5)N1(1)"
                    },
                    {
                        "firmwareid": "6d168afb5ec0e3efde8a1e091dafaefd",
                        "name": "NX-OS Kick Start",
                        "version": "7.3(5)N1(1)"
                    },
                    {
                        "firmwareid": "27292d2b55a9df248032bd1f1fa03a48",
                        "name": "NX-OS Kick Start",
                        "version": "7.2(1)N1(1)"
                    },
                    {
                        "firmwareid": "1548c2557d3ca5d6b8462fd4407df353",
                        "name": "NX-OS Kick Start",
                        "version": "7.3(0)N1(1)"
                    },
                    {
                        "firmwareid": "809082e9cc549c5c85ac0ca9c13f4a66",
                        "name": "NX-OS Kick Start",
                        "version": "7.0(4)N1(1)"
                    },
                    {
                        "firmwareid": "9d61b0520ce7d36c4ea246bc040d1b43",
                        "name": "Data Center Network Manager",
                        "version": "11.5(1)"
                    },
                    {
                        "firmwareid": "98d66a2e1fe7a56ff93c9fafacca72da",
                        "name": "NX-OS Kick Start",
                        "version": "7.0(7)N1(1)"
                    },
                    {
                        "firmwareid": "f405a5f672ab8e7d893be2f8f1837f01",
                        "name": "NX-OS Kick Start",
                        "version": "7.1(2)N1(1)"
                    },
                    {
                        "firmwareid": "71e6e5a473d39167fc7357d3ad24f587",
                        "name": "NX-OS Kick Start",
                        "version": "7.1(5)N1(1b)"
                    },
                    {
                        "firmwareid": "f723df0f15bc87a234332f61d72f3926",
                        "name": "Data Center Network Manager",
                        "version": "10.4(2)"
                    },
                    {
                        "firmwareid": "a2aa471189f30f989d9d6a20fc4f24c0",
                        "name": "NX-OS Kick Start",
                        "version": "7.3(8)N1(1)"
                    },
                    {
                        "firmwareid": "5ad4a6edef078ebb9de03cede2d9fe8d",
                        "name": "NX-OS Kick Start",
                        "version": "7.3(4)N1(1)"
                    },
                    {
                        "firmwareid": "6736f6105f96ad2b3eaac58a4d1743a2",
                        "name": "NX-OS Kick Start",
                        "version": "7.0(8)N1(1)"
                    },
                    {
                        "firmwareid": "a9430bb6c616d5300628f328e0bf3f99",
                        "name": "NX-OS Kick Start",
                        "version": "7.3(6)N1(1)"
                    },
                    {
                        "firmwareid": "6b9e9b07fd81ebfdb996b5c69379bb2c",
                        "name": "NX-OS Kick Start",
                        "version": "7.0(5)N1(1)"
                    },
                    {
                        "firmwareid": "18b4381c59a00b891a49955ff16c722c",
                        "name": "NX-OS Kick Start",
                        "version": "7.1(0)N1(1b)"
                    },
                    {
                        "firmwareid": "681f438e1d5d37d7cb4eb51b32c137a6",
                        "name": "NX-OS Kick Start",
                        "version": "7.1(3)N1(2)"
                    },
                    {
                        "firmwareid": "306bf0ead653d435245a3fcd597ccf25",
                        "name": "NX-OS Kick Start",
                        "version": "7.0(5)N1(1a)"
                    },
                    {
                        "firmwareid": "db79885ecae70e404b63411cb7f7d334",
                        "name": "NX-OS Kick Start",
                        "version": "7.1(0)N1(1)"
                    },
                    {
                        "firmwareid": "a6387db4d583f3a987bf41fde8f435b3",
                        "name": "NX-OS Kick Start",
                        "version": "7.1(0)N1(1a)"
                    },
                    {
                        "firmwareid": "09dde9c8f0a71a81fcc7e80f0c24855b",
                        "name": "NX-OS Kick Start",
                        "version": "7.3(1)N1(1)"
                    },
                    {
                        "firmwareid": "b2e9ce36dfa6ce078748e2936cdea90d",
                        "name": "NX-OS Kick Start",
                        "version": "7.0(6)N1(1)"
                    },
                    {
                        "firmwareid": "9cf146a7b33150f348dabd1a80d32696",
                        "name": "NX-OS Kick Start",
                        "version": "7.3(7)N1(1b)"
                    },
                    {
                        "firmwareid": "78eaf65d85e427cdc0f7c1dced5493ca",
                        "name": "NX-OS Kick Start",
                        "version": "7.3(7)N1(1)"
                    },
                    {
                        "firmwareid": "16982d268d25bd1fa3cd758f9a0f73d0",
                        "name": "NX-OS Kick Start",
                        "version": "7.3(3)N1(1)"
                    },
                    {
                        "firmwareid": "6fac6f0a458803091c39ff5a687ffd86",
                        "name": "NX-OS Kick Start",
                        "version": "7.0(3)N1(1)"
                    },
                    {
                        "firmwareid": "b70cd3277917305f6d74fa0f50f4a899",
                        "name": "NX-OS Kick Start",
                        "version": "7.0(1)N1(1)"
                    },
                    {
                        "firmwareid": "1347cbf7ba4401dcbb77a44035b0bdd1",
                        "name": "NX-OS Kick Start",
                        "version": "7.1(4)N1(1)"
                    },
                    {
                        "firmwareid": "bb0f0a358c17bee17f28b23caaf2bf01",
                        "name": "NX-OS Kick Start",
                        "version": "7.1(3)N1(1)"
                    },
                    {
                        "firmwareid": "befc05ccce51abce9df9f21cca64eda4",
                        "name": "NX-OS Kick Start",
                        "version": "7.0(2)N1(1)"
                    },
                    {
                        "firmwareid": "9e6af5b38fc11b70820e6257f2147695",
                        "name": "NX-OS Kick Start",
                        "version": "7.0(0)N1(1)"
                    },
                    {
                        "firmwareid": "88211351b6739a8f9aa0c0ac01162b70",
                        "name": "NX-OS Kick Start",
                        "version": "7.3(7)N1(1a)"
                    }
                ],
                "model": "Nexus 6004 Switch",
                "score": 0.61,
                "series": "Nexus 6000 Series Switches",
                "vendor": "CISCO"
            }
        ]
    }
}
```

#### Human Readable Output

>## Found 2 devices
>---
>### Device Nexus 6001 Switch
>**Model Name**: Nexus 6001 Switch
>**Vendor**: CISCO
>**Series**: Nexus 6000 Series Switches
>**Categories**: SWITCH,NETWORK
>**DeviceID**: e91e3216d1d0f6480a89acbd9536a1ca
>**Match Score**: 76.0%
>### Firmwares
>|firmwareid|version|name|
>|---|---|---|
>| a2eca61d015b73f4401dad8fd93d4ac4 | 7.2(1)N1(1) | NX-OS System Software |
>| fea10272507045a37373556935122a5a | 7.3(1)N1(1) | NX-OS System Software |
>| 2e29893957761ce93f64db41933a4b70 | 7.1(5)N1(1) | NX-OS System Software |
>| ed746be84164c3a3e80d7a3a29983ffe | 7.0(6)N1(1) | NX-OS XML Schema Definition |
>| 72e98966800e371832b77a167f56e43e | 7.1(0)N1(1a) | NX-OS XML Schema Definition |
>| 7105d7a2484da9605d9dfc433f375666 | 7.1(3)N1(1) | NX-OS System Software |
>| 370fd34dd9ba8fb90790d1eac233a11e | 7.0(1)N1(1) | NX-OS System Software |
>| 42b120bd04856cf7ec60bcd82710ff4d | 7.0(3)N1(1) | NX-OS XML Schema Definition |
>| 0890d99611596739e04ef1ce6c7a9133 | 7.0(2)N1(1) | NX-OS XML Schema Definition |
>| 89bce497c81f19d2e3edc03b65e81c80 | 7.3(7)N1(1) | NX-OS System Software |
>| 4d36d85663d6a29fee8a077eabf5e316 | 7.0(4)N1(1) | NX-OS System Software |
>| 56132106f92df878b5894b440ffbc456 | 7.2(0)N1(1) | NX-OS XML Schema Definition |
>| 8dd3916ab0c4d04720aeadd81fd77f78 | 7.1(1)N1(1) | NX-OS Kick Start |
>| ae4f5adb0281a76575dc9e1fa00ffdc9 | 7.0(5)N1(1) | NX-OS XML Schema Definition |
>| b2e9ce36dfa6ce078748e2936cdea90d | 7.0(6)N1(1) | NX-OS Kick Start |
>| b70cd3277917305f6d74fa0f50f4a899 | 7.0(1)N1(1) | NX-OS Kick Start |
>| 4d7d143acfe8855b513cf056dd7298a0 | 7.3(7)N1(1b) | NX-OS System Software |
>| 0590acb584ea89d36266943b3d5a4b5c | 7.3(6)N1(1) | NX-OS System Software |
>| 71e6e5a473d39167fc7357d3ad24f587 | 7.1(5)N1(1b) | NX-OS Kick Start |
>| 4ba51fa1c8c7afe9e06ccc0a3073dcda | 7.1(3)N1(2) | NX-OS System Software |
>| 27292d2b55a9df248032bd1f1fa03a48 | 7.2(1)N1(1) | NX-OS Kick Start |
>| 6736f6105f96ad2b3eaac58a4d1743a2 | 7.0(8)N1(1) | NX-OS Kick Start |
>| 36eba4a64f131297f24658118e5a5320 | 7.1(1)N1(1) | NX-OS System Software |
>| e1b360d2eb32949caea7abba0683d75c | 7.0(0)N1(1) | NX-OS System Software |
>| 90c8ed73ff57b0ad28c9993e89926f92 | 7.0(7)N1(1) | NX-OS System Software |
>| 78eaf65d85e427cdc0f7c1dced5493ca | 7.3(7)N1(1) | NX-OS Kick Start |
>| d9c570cb112b8ded7a583b3a3f24c68d | 7.0(3)N1(1) | NX-OS System Software |
>| f5db998da08c1917bb76ea98b051bff6 | 7.1(0)N1(1b) | NX-OS System Software |
>| 88211351b6739a8f9aa0c0ac01162b70 | 7.3(7)N1(1a) | NX-OS Kick Start |
>| a9430bb6c616d5300628f328e0bf3f99 | 7.3(6)N1(1) | NX-OS Kick Start |
>| 60b6b0880ea9b139c09c5f5c84c8a2ce | 7.3(7)N1(1a) | NX-OS System Software |
>| 68dd1c8e68d7d9c5a3af251f6555a4d3 | 7.0(6)N1(1) | NX-OS System Software |
>| 6d4d6b7373ce6b06a55585a4ea9b979f | 7.0(5)N1(1) | NX-OS System Software |
>| ae90b06c9f44a0eae0d3eaba82bfc8ee | 7.3(2)N1(1) | NX-OS System Software |
>| 6caace1917787970457630829974b505 | 7.0(5)N1(1a) | NX-OS System Software |
>| 1ca6ba2c4e764ac4728f5f965766063f | 7.3(5)N1(1) | NX-OS System Software |
>| 8ae8c9d274dd843768a66f8eec9dab03 | 7.1(5)N1(1b) | NX-OS System Software |
>| 6dae9b841c0a36e2e02b2a17e3856af8 | 7.1(0)N1(1a) | NX-OS System Software |
>| a6387db4d583f3a987bf41fde8f435b3 | 7.1(0)N1(1a) | NX-OS Kick Start |
>| 61cfb54e591b074037f796cca06d50b8 | 7.1(4)N1(1) | NX-OS System Software |
>| 306bf0ead653d435245a3fcd597ccf25 | 7.0(5)N1(1a) | NX-OS Kick Start |
>| de814b78db5c9dfd3359c8d113589e15 | 7.3(0)N1(1) | NX-OS System Software |
>| a75068fb4557cdef95e113a5b6623977 | 7.0(5)N1(1a) | NX-OS XML Schema Definition |
>| 9cf146a7b33150f348dabd1a80d32696 | 7.3(7)N1(1b) | NX-OS Kick Start |
>| 68bf3d37af54863726e5318e89fcb4f8 | 7.0(1)N1(1) | NX-OS XML Schema Definition |
>| 681f438e1d5d37d7cb4eb51b32c137a6 | 7.1(3)N1(2) | NX-OS Kick Start |
>| 18b4381c59a00b891a49955ff16c722c | 7.1(0)N1(1b) | NX-OS Kick Start |
>| 4dc05d971c6a329436269ce10396a61a | 7.1(0)N1(1) | NX-OS System Software |
>| f03f0a381d74eb2c8bef16ce5c69d749 | 7.0(8)N1(1) | NX-OS System Software |
>| d8b89ac1dd6ed65d55498b9e35782462 | 7.1(2)N1(1) | NX-OS System Software |
>| 45f457a87dc482ff9045620ff052c085 | 7.3(2)N1(1) | NX-OS Kick Start |
>| 16982d268d25bd1fa3cd758f9a0f73d0 | 7.3(3)N1(1) | NX-OS Kick Start |
>| 09dde9c8f0a71a81fcc7e80f0c24855b | 7.3(1)N1(1) | NX-OS Kick Start |
>| 0e176309fe8d808aca1593edde6711d0 | 7.3(4)N1(1) | NX-OS System Software |
>| 5ad4a6edef078ebb9de03cede2d9fe8d | 7.3(4)N1(1) | NX-OS Kick Start |
>| 383540dc529b128a28481cfacbdb49cd | 7.2(0)N1(1) | NX-OS System Software |
>| 6fac6f0a458803091c39ff5a687ffd86 | 7.0(3)N1(1) | NX-OS Kick Start |
>| f405a5f672ab8e7d893be2f8f1837f01 | 7.1(2)N1(1) | NX-OS Kick Start |
>| f0a14bb11b9bac0b8636d040dded1b97 | 7.3(8)N1(1) | NX-OS System Software |
>| 1347cbf7ba4401dcbb77a44035b0bdd1 | 7.1(4)N1(1) | NX-OS Kick Start |
>| 6b9e9b07fd81ebfdb996b5c69379bb2c | 7.0(5)N1(1) | NX-OS Kick Start |
>| 13a4be2661431a141607d1e45ba48576 | 7.0(0)N1(1) | NX-OS XML Schema Definition |
>| befc05ccce51abce9df9f21cca64eda4 | 7.0(2)N1(1) | NX-OS Kick Start |
>| 1548c2557d3ca5d6b8462fd4407df353 | 7.3(0)N1(1) | NX-OS Kick Start |
>| db79885ecae70e404b63411cb7f7d334 | 7.1(0)N1(1) | NX-OS Kick Start |
>| bb0f0a358c17bee17f28b23caaf2bf01 | 7.1(3)N1(1) | NX-OS Kick Start |
>| 809082e9cc549c5c85ac0ca9c13f4a66 | 7.0(4)N1(1) | NX-OS Kick Start |
>| e411041ffe31883e627c27cf51aa210f | 7.1(5)N1(1) | NX-OS Kick Start |
>| a2aa471189f30f989d9d6a20fc4f24c0 | 7.3(8)N1(1) | NX-OS Kick Start |
>| f2e1e0ff5bf1b26956bff042cc432967 | 7.0(2)N1(1) | NX-OS System Software |
>| 5ce43e35313dcc4ee7c39584a5e1a66c | 7.3(3)N1(1) | NX-OS System Software |
>| 98d66a2e1fe7a56ff93c9fafacca72da | 7.0(7)N1(1) | NX-OS Kick Start |
>| 02c3dfdb2bb77566084f0e4199701abe | 7.1(0)N1(1) | NX-OS XML Schema Definition |
>| 8adcfea7ee4132853217aa3d7b8ee59e | 7.0(4)N1(1) | NX-OS XML Schema Definition |
>| 6d168afb5ec0e3efde8a1e091dafaefd | 7.3(5)N1(1) | NX-OS Kick Start |
>---
>### Device Nexus 6004 Switch
>**Model Name**: Nexus 6004 Switch
>**Vendor**: CISCO
>**Series**: Nexus 6000 Series Switches
>**Categories**: SWITCH,NETWORK
>**DeviceID**: 688f206b8f4766c2eb9db9fc970c924c
>**Match Score**: 61.0%
>### Firmwares
>|firmwareid|version|name|
>|---|---|---|
>| 8dd3916ab0c4d04720aeadd81fd77f78 | 7.1(1)N1(1) | NX-OS Kick Start |
>| 45f457a87dc482ff9045620ff052c085 | 7.3(2)N1(1) | NX-OS Kick Start |
>| e411041ffe31883e627c27cf51aa210f | 7.1(5)N1(1) | NX-OS Kick Start |
>| 6d168afb5ec0e3efde8a1e091dafaefd | 7.3(5)N1(1) | NX-OS Kick Start |
>| 27292d2b55a9df248032bd1f1fa03a48 | 7.2(1)N1(1) | NX-OS Kick Start |
>| 1548c2557d3ca5d6b8462fd4407df353 | 7.3(0)N1(1) | NX-OS Kick Start |
>| 809082e9cc549c5c85ac0ca9c13f4a66 | 7.0(4)N1(1) | NX-OS Kick Start |
>| 9d61b0520ce7d36c4ea246bc040d1b43 | 11.5(1) | Data Center Network Manager |
>| 98d66a2e1fe7a56ff93c9fafacca72da | 7.0(7)N1(1) | NX-OS Kick Start |
>| f405a5f672ab8e7d893be2f8f1837f01 | 7.1(2)N1(1) | NX-OS Kick Start |
>| 71e6e5a473d39167fc7357d3ad24f587 | 7.1(5)N1(1b) | NX-OS Kick Start |
>| f723df0f15bc87a234332f61d72f3926 | 10.4(2) | Data Center Network Manager |
>| a2aa471189f30f989d9d6a20fc4f24c0 | 7.3(8)N1(1) | NX-OS Kick Start |
>| 5ad4a6edef078ebb9de03cede2d9fe8d | 7.3(4)N1(1) | NX-OS Kick Start |
>| 6736f6105f96ad2b3eaac58a4d1743a2 | 7.0(8)N1(1) | NX-OS Kick Start |
>| a9430bb6c616d5300628f328e0bf3f99 | 7.3(6)N1(1) | NX-OS Kick Start |
>| 6b9e9b07fd81ebfdb996b5c69379bb2c | 7.0(5)N1(1) | NX-OS Kick Start |
>| 18b4381c59a00b891a49955ff16c722c | 7.1(0)N1(1b) | NX-OS Kick Start |
>| 681f438e1d5d37d7cb4eb51b32c137a6 | 7.1(3)N1(2) | NX-OS Kick Start |
>| 306bf0ead653d435245a3fcd597ccf25 | 7.0(5)N1(1a) | NX-OS Kick Start |
>| db79885ecae70e404b63411cb7f7d334 | 7.1(0)N1(1) | NX-OS Kick Start |
>| a6387db4d583f3a987bf41fde8f435b3 | 7.1(0)N1(1a) | NX-OS Kick Start |
>| 09dde9c8f0a71a81fcc7e80f0c24855b | 7.3(1)N1(1) | NX-OS Kick Start |
>| b2e9ce36dfa6ce078748e2936cdea90d | 7.0(6)N1(1) | NX-OS Kick Start |
>| 9cf146a7b33150f348dabd1a80d32696 | 7.3(7)N1(1b) | NX-OS Kick Start |
>| 78eaf65d85e427cdc0f7c1dced5493ca | 7.3(7)N1(1) | NX-OS Kick Start |
>| 16982d268d25bd1fa3cd758f9a0f73d0 | 7.3(3)N1(1) | NX-OS Kick Start |
>| 6fac6f0a458803091c39ff5a687ffd86 | 7.0(3)N1(1) | NX-OS Kick Start |
>| b70cd3277917305f6d74fa0f50f4a899 | 7.0(1)N1(1) | NX-OS Kick Start |
>| 1347cbf7ba4401dcbb77a44035b0bdd1 | 7.1(4)N1(1) | NX-OS Kick Start |
>| bb0f0a358c17bee17f28b23caaf2bf01 | 7.1(3)N1(1) | NX-OS Kick Start |
>| befc05ccce51abce9df9f21cca64eda4 | 7.0(2)N1(1) | NX-OS Kick Start |
>| 9e6af5b38fc11b70820e6257f2147695 | 7.0(0)N1(1) | NX-OS Kick Start |
>| 88211351b6739a8f9aa0c0ac01162b70 | 7.3(7)N1(1a) | NX-OS Kick Start |


### arcusteam-get-vulnerabilities
***
 Retrieve CVEs for an ArcusTeam device


#### Base Command

`arcusteam-get-vulnerabilities`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| firmware_id |  ArcusTeam Firmware ID (as returned by the arcusteam-get-devices command). | Required | 
| device_id |  ArcusTeam Device ID (as returned by the arcusteam-get-devices command). | Required | 
| page_size | Page size. Minimum page size is 1, maximum is 100. Default is 10. | Optional | 
| page_number |  Page number. Default is 1. | Optional | 
| sort_order |  Sorting order (“asc”,”desc”). Possible values are: desc, asc. Default is desc. | Optional | 
| sort_field |  Sorting field. Possible values are: risk, cve, description, codename, cwe, exploit_published, exploit_used, modified_date. Default is risk. | Optional | 
| return_fields |  The fields to return. Possible values are: risk, cve, description, codename, cwe, exploit_published, exploit_used, modified_date. Default is cve,risk. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ArcusTeamVulnerabilities.max_items | number | Number of results | 
| ArcusTeamVulnerabilities.has_next | boolean | If there is another page | 
| ArcusTeamVulnerabilities.results.cve | string | CVE name | 
| ArcusTeamVulnerabilities.results.risk | number | CVE risk | 
| ArcusTeamVulnerabilities.results.description | string | CVE description | 
| ArcusTeamVulnerabilities.results.codename | string | CVE codename | 
| ArcusTeamVulnerabilities.results.cwe | string | CVE cwe | 
| ArcusTeamVulnerabilities.results.exploit_published | string | If exploit was published | 
| ArcusTeamVulnerabilities.results.exploit_used | string | If exploit was used | 
| ArcusTeamVulnerabilities.results.modified_date | string | If date was modified | 
| ArcusTeamVulnerabilities.results.ownership | string | CVE ownership | 
| ArcusTeamVulnerabilities.results.published_date | string | The date the CVE was published  | 
| ArcusTeamVulnerabilities.results.title | string | CVE title | 
| ArcusTeamVulnerabilities.results.url | string | CVE url | 


#### Command Example
```!arcusteam-get-vulnerabilities firmware_id=f5db998da08c1917bb76ea98b051bff6 device_id=e91e3216d1d0f6480a89acbd9536a1ca return_fields=risk,cve,cwe,description,exploit_published,exploit_used,modified_date```

#### Context Example
```json
{
    "ArcusTeamVulnerabilities": {
        "has_next": true,
        "max_items": 15,
        "results": [
            {
                "cve": "CVE-2021-1368",
                "cwe": "CWE-787",
                "description": "A vulnerability in the Unidirectional Link Detection (UDLD) feature of Cisco FXOS Software and Cisco NX-OS Software could allow an unauthenticated, adjacent attacker to execute arbitrary code with administrative privileges or cause a denial of service (DoS) condition on an affected device. This vulnerability is due to insufficient input validation. An attacker could exploit this vulnerability by sending crafted Cisco UDLD protocol packets to a directly connected, affected device. A successful exploit could allow the attacker to execute arbitrary code with administrative privileges or cause the Cisco UDLD process to crash and restart multiple times, causing the affected device to reload and resulting in a DoS condition. Note: The UDLD feature is disabled by default, and the conditions to exploit this vulnerability are strict. The attacker needs full control of a directly connected device. That device must be connected over a port channel that has UDLD enabled. To trigger arbitrary code execution, both the UDLD-enabled port channel and specific system conditions must exist. In the absence of either the UDLD-enabled port channel or the system conditions, attempts to exploit this vulnerability will result in a DoS condition. It is possible, but highly unlikely, that an attacker could control the necessary conditions for exploitation. The CVSS score reflects this possibility. However, given the complexity of exploitation, Cisco has assigned a Medium Security Impact Rating (SIR) to this vulnerability.",
                "exploit_published": null,
                "exploit_used": null,
                "modified_date": 1614799320,
                "risk": "88.0%"
            },
            {
                "cve": "CVE-2020-3172",
                "cwe": "CWE-20",
                "description": null,
                "exploit_published": false,
                "exploit_used": false,
                "modified_date": 1583512958,
                "risk": "88.0%"
            },
            {
                "cve": "CVE-2020-3217",
                "cwe": "CWE-20",
                "description": null,
                "exploit_published": false,
                "exploit_used": false,
                "modified_date": 1591200000,
                "risk": "88.0%"
            },
            {
                "cve": "CVE-2020-3517",
                "cwe": "CWE-476",
                "description": null,
                "exploit_published": false,
                "exploit_used": false,
                "modified_date": 1598476998,
                "risk": "86.0%"
            },
            {
                "cve": "CVE-2021-1387",
                "cwe": "CWE-401",
                "description": "A vulnerability in the network stack of Cisco NX-OS Software could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition on an affected device. This vulnerability exists because the software improperly releases resources when it processes certain IPv6 packets that are destined to an affected device. An attacker could exploit this vulnerability by sending multiple crafted IPv6 packets to an affected device. A successful exploit could cause the network stack to run out of available buffers, impairing operations of control plane and management plane protocols and resulting in a DoS condition. Manual intervention would be required to restore normal operations on the affected device. For more information about the impact of this vulnerability, see the Details section of this advisory.",
                "exploit_published": null,
                "exploit_used": null,
                "modified_date": 1614791760,
                "risk": "86.0%"
            },
            {
                "cve": "CVE-2019-12717",
                "cwe": "CWE-78",
                "description": "A vulnerability in a CLI command related to the virtualization manager (VMAN) in Cisco NX-OS Software could allow an authenticated, local attacker to execute arbitrary commands on the underlying Linux operating system with root privileges. The vulnerability is due to insufficient validation of arguments passed to a specific VMAN CLI command on an affected device. An attacker could exploit this vulnerability by including malicious input as the argument of an affected command. A successful exploit could allow the attacker to execute arbitrary commands on the underlying Linux operating system with root privileges, which may lead to complete system compromise. An attacker would need valid administrator credentials to exploit this vulnerability.",
                "exploit_published": null,
                "exploit_used": null,
                "modified_date": 1570664760,
                "risk": "78.0%"
            },
            {
                "cve": "CVE-2019-1965",
                "cwe": "CWE-772",
                "description": "A vulnerability in the Virtual Shell (VSH) session management for Cisco NX-OS Software could allow an authenticated, remote attacker to cause a VSH process to fail to delete upon termination. This can lead to a build-up of VSH processes that overtime can deplete system memory. When there is no system memory available, this can cause unexpected system behaviors and crashes. The vulnerability is due to the VSH process not being properly deleted when a remote management connection to the device is disconnected. An attacker could exploit this vulnerability by repeatedly performing a remote management connection to the device and terminating the connection in an unexpected manner. A successful exploit could allow the attacker to cause the VSH processes to fail to delete, which can lead to a system-wide denial of service (DoS) condition. The attacker must have valid user credentials to log in to the device using the remote management connection.",
                "exploit_published": null,
                "exploit_used": null,
                "modified_date": 1602857100,
                "risk": "77.0%"
            },
            {
                "cve": "CVE-2019-1962",
                "cwe": "CWE-20",
                "description": "A vulnerability in the Cisco Fabric Services component of Cisco NX-OS Software could allow an unauthenticated, remote attacker to cause process crashes, which can result in a denial of service (DoS) condition on an affected system. The vulnerability is due to insufficient validation of TCP packets when processed by the Cisco Fabric Services over IP (CFSoIP) feature. An attacker could exploit this vulnerability by sending a malicious Cisco Fabric Services TCP packet to an affected device. A successful exploit could allow the attacker to cause process crashes, resulting in a device reload and a DoS condition. Note: There are three distribution methods that can be configured for Cisco Fabric Services. This vulnerability affects only distribution method CFSoIP, which is disabled by default. See the Details section for more information.",
                "exploit_published": null,
                "exploit_used": null,
                "modified_date": 1570664880,
                "risk": "75.0%"
            },
            {
                "cve": "CVE-2020-3454",
                "cwe": "CWE-78",
                "description": "A vulnerability in the Call Home feature of Cisco NX-OS Software could allow an authenticated, remote attacker to inject arbitrary commands that could be executed with root privileges on the underlying operating system (OS). The vulnerability is due to insufficient input validation of specific Call Home configuration parameters when the software is configured for transport method HTTP. An attacker could exploit this vulnerability by modifying parameters within the Call Home configuration on an affected device. A successful exploit could allow the attacker to execute arbitrary commands with root privileges on the underlying OS.",
                "exploit_published": null,
                "exploit_used": null,
                "modified_date": 1599182340,
                "risk": "72.0%"
            },
            {
                "cve": "CVE-2019-12662",
                "cwe": "CWE-347",
                "description": null,
                "exploit_published": false,
                "exploit_used": false,
                "modified_date": 1569427200,
                "risk": "67.0%"
            }
        ]
    }
}
```

#### Human Readable Output

>## Scan results
>### Number of CVE's found: 15
>|risk|cve|cwe|description|exploit_published|exploit_used|modified_date|
>|---|---|---|---|---|---|---|
>| 88.0% | CVE-2021-1368 | CWE-787 | A vulnerability in the Unidirectional Link Detection (UDLD) feature of Cisco FXOS Software and Cisco NX-OS Software could allow an unauthenticated, adjacent attacker to execute arbitrary code with administrative privileges or cause a denial of service (DoS) condition on an affected device. This vulnerability is due to insufficient input validation. An attacker could exploit this vulnerability by sending crafted Cisco UDLD protocol packets to a directly connected, affected device. A successful exploit could allow the attacker to execute arbitrary code with administrative privileges or cause the Cisco UDLD process to crash and restart multiple times, causing the affected device to reload and resulting in a DoS condition. Note: The UDLD feature is disabled by default, and the conditions to exploit this vulnerability are strict. The attacker needs full control of a directly connected device. That device must be connected over a port channel that has UDLD enabled. To trigger arbitrary code execution, both the UDLD-enabled port channel and specific system conditions must exist. In the absence of either the UDLD-enabled port channel or the system conditions, attempts to exploit this vulnerability will result in a DoS condition. It is possible, but highly unlikely, that an attacker could control the necessary conditions for exploitation. The CVSS score reflects this possibility. However, given the complexity of exploitation, Cisco has assigned a Medium Security Impact Rating (SIR) to this vulnerability. |  |  | 1614799320 |
>| 88.0% | CVE-2020-3172 | CWE-20 |  | false | false | 1583512958 |
>| 88.0% | CVE-2020-3217 | CWE-20 |  | false | false | 1591200000 |
>| 86.0% | CVE-2020-3517 | CWE-476 |  | false | false | 1598476998 |
>| 86.0% | CVE-2021-1387 | CWE-401 | A vulnerability in the network stack of Cisco NX-OS Software could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition on an affected device. This vulnerability exists because the software improperly releases resources when it processes certain IPv6 packets that are destined to an affected device. An attacker could exploit this vulnerability by sending multiple crafted IPv6 packets to an affected device. A successful exploit could cause the network stack to run out of available buffers, impairing operations of control plane and management plane protocols and resulting in a DoS condition. Manual intervention would be required to restore normal operations on the affected device. For more information about the impact of this vulnerability, see the Details section of this advisory. |  |  | 1614791760 |
>| 78.0% | CVE-2019-12717 | CWE-78 | A vulnerability in a CLI command related to the virtualization manager (VMAN) in Cisco NX-OS Software could allow an authenticated, local attacker to execute arbitrary commands on the underlying Linux operating system with root privileges. The vulnerability is due to insufficient validation of arguments passed to a specific VMAN CLI command on an affected device. An attacker could exploit this vulnerability by including malicious input as the argument of an affected command. A successful exploit could allow the attacker to execute arbitrary commands on the underlying Linux operating system with root privileges, which may lead to complete system compromise. An attacker would need valid administrator credentials to exploit this vulnerability. |  |  | 1570664760 |
>| 77.0% | CVE-2019-1965 | CWE-772 | A vulnerability in the Virtual Shell (VSH) session management for Cisco NX-OS Software could allow an authenticated, remote attacker to cause a VSH process to fail to delete upon termination. This can lead to a build-up of VSH processes that overtime can deplete system memory. When there is no system memory available, this can cause unexpected system behaviors and crashes. The vulnerability is due to the VSH process not being properly deleted when a remote management connection to the device is disconnected. An attacker could exploit this vulnerability by repeatedly performing a remote management connection to the device and terminating the connection in an unexpected manner. A successful exploit could allow the attacker to cause the VSH processes to fail to delete, which can lead to a system-wide denial of service (DoS) condition. The attacker must have valid user credentials to log in to the device using the remote management connection. |  |  | 1602857100 |
>| 75.0% | CVE-2019-1962 | CWE-20 | A vulnerability in the Cisco Fabric Services component of Cisco NX-OS Software could allow an unauthenticated, remote attacker to cause process crashes, which can result in a denial of service (DoS) condition on an affected system. The vulnerability is due to insufficient validation of TCP packets when processed by the Cisco Fabric Services over IP (CFSoIP) feature. An attacker could exploit this vulnerability by sending a malicious Cisco Fabric Services TCP packet to an affected device. A successful exploit could allow the attacker to cause process crashes, resulting in a device reload and a DoS condition. Note: There are three distribution methods that can be configured for Cisco Fabric Services. This vulnerability affects only distribution method CFSoIP, which is disabled by default. See the Details section for more information. |  |  | 1570664880 |
>| 72.0% | CVE-2020-3454 | CWE-78 | A vulnerability in the Call Home feature of Cisco NX-OS Software could allow an authenticated, remote attacker to inject arbitrary commands that could be executed with root privileges on the underlying operating system (OS). The vulnerability is due to insufficient input validation of specific Call Home configuration parameters when the software is configured for transport method HTTP. An attacker could exploit this vulnerability by modifying parameters within the Call Home configuration on an affected device. A successful exploit could allow the attacker to execute arbitrary commands with root privileges on the underlying OS. |  |  | 1599182340 |
>| 67.0% | CVE-2019-12662 | CWE-347 |  | false | false | 1569427200 |
