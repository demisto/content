The ArcusTeam API allows the user to inspect connected devices' attack surface. By feeding device identifiers and the software it runs: DeviceTotal will return a map of the device’s attack surface. DeviceTotal was built from the ground up in order to provide complete visibility into connected devices and mitigate 3rd party risk. DeviceTotal can continuously identify & predict such that the connected device security posture is being assessed, prioritized and mitigated effectively.
This integration was integrated and tested with version 6.11.0 of ArcusTeam

## Get Your API Key
Please visit our [dedicated page](https://arcusteam.com/pa-partnership/) to obtain your API key.

## Configure ArcusTeam on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ArcusTeam.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL (e.g. https://web.prod.arcusteam.com) | The FQDN/IP the integration should connect to. | True |
    | API Key |  The API Key required to authenticate to the service. | True |
    |  The client ID | The client ID from ArcusTeam dashboard | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
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
```!arcusteam-get-devices vendor="cisco" model="2901_Integrated_Services_Router" series="2900_Series_Integrated_Services_Routers"```

#### Context Example
```json
{
    "ArcusTeamDevices": {
        "devices": [
            {
                "categories": [
                    "NETWORK",
                    "ROUTER"
                ],
                "device_key": "ce341ae9c368850f2f2f5de59f2d6071",
                "firmware": [
                    {
                        "firmwareid": "9c988101f9bd9e677f421cb1231d2c55",
                        "name": "Software on Chassis",
                        "version": "15.4.2T1"
                    }
                ],
                "model": "2901 Integrated Services Router",
                "score": 1,
                "series": "2900 Series Integrated Services Routers",
                "vendor": "CISCO"
            },
            {
                "categories": [
                    "NETWORK",
                    "ROUTER"
                ],
                "device_key": "c11eb29c5346d182b94ee1fcde6d0b21",
                "firmware": [
                    {
                        "firmwareid": "1afa9319f7a82012cf42d65b14431b72",
                        "name": "IOS XE Software",
                        "version": "16.9.4"
                    },
                    {
                        "firmwareid": "d8e81c52ba635da73458028d6514e8bb",
                        "name": "IOS XE Software",
                        "version": "3.16.6bS"
                    },
                    {
                        "firmwareid": "e68bc28082f959e6daa95ac178a4e202",
                        "name": "IOS XE Software",
                        "version": "3.16.4bS"
                    }
                ],
                "model": "4431 Integrated Services Router",
                "score": 0.85,
                "series": "4000 Series Integrated Services Routers",
                "vendor": "CISCO"
            },
            {
                "categories": [
                    "NETWORK",
                    "ROUTER"
                ],
                "device_key": "adc8495470b0bf3bc046d77fcf770d82",
                "firmware": [
                    {
                        "firmwareid": "30c54737553f3aa302188af5afe0c553",
                        "name": "Software on Chassis",
                        "version": "15.1.4M12a"
                    }
                ],
                "model": "1803 Integrated Services Router",
                "score": 0.85,
                "series": "1800 Series Integrated Services Routers",
                "vendor": "CISCO"
            },
            {
                "categories": [
                    "ROUTER",
                    "NETWORK"
                ],
                "device_key": "a829c4b2ce4d9662de8b046253b3fd98",
                "firmware": [
                    {
                        "firmwareid": "da8865f7b32445b8a1846cfe8845b424",
                        "name": "IOS XE Software",
                        "version": "Fuji-16.9.6"
                    },
                    {
                        "firmwareid": "41b2342bffc73f650f5b8256fdc35818",
                        "name": "IOS XE Software",
                        "version": "Amsterdam-17.2.1r"
                    },
                    {
                        "firmwareid": "679e7840100ef3561fdb842cbe3880d9",
                        "name": "IOS XE Software",
                        "version": "Amsterdam-17.3.2"
                    },
                    {
                        "firmwareid": "69904f98c71fa9a896b402d6e5e77379",
                        "name": "IOS XE Software",
                        "version": "Fuji-16.7.1"
                    },
                    {
                        "firmwareid": "d73684039e22e40445f9776e07af8cf9",
                        "name": "IOS XE Software",
                        "version": "Fuji-16.9.3"
                    },
                    {
                        "firmwareid": "b00f0e2b6684060e6a6650814954c541",
                        "name": "IOS XE Software",
                        "version": "Bengaluru-17.4.1a"
                    },
                    {
                        "firmwareid": "f1d2f361624da02aad0a63f0c52c7b52",
                        "name": "IOS XE Software",
                        "version": "Fuji-16.8.1"
                    },
                    {
                        "firmwareid": "e14fa3096a61f875c0f58ba3a7d0e9d9",
                        "name": "IOS XE Software",
                        "version": "Gibraltar-16.10.2"
                    },
                    {
                        "firmwareid": "1afa9319f7a82012cf42d65b14431b72",
                        "name": "IOS XE Software",
                        "version": "16.9.4"
                    },
                    {
                        "firmwareid": "73d1aed88774dee9cf7924244f104454",
                        "name": "IOS XE Software",
                        "version": "Gibraltar-16.10.1b"
                    },
                    {
                        "firmwareid": "2528514bdacd52435b1a687ba233649d",
                        "name": "IOS XE Software",
                        "version": "Fuji-16.9.5"
                    },
                    {
                        "firmwareid": "caf87c622d7565bff1f243aaedeccc0f",
                        "name": "IOS XE Software",
                        "version": "16.12.2"
                    },
                    {
                        "firmwareid": "731012493ae90a5aa1c8f2e1aa945037",
                        "name": "IOS XE Software",
                        "version": "Gibraltar-16.12.1a"
                    },
                    {
                        "firmwareid": "9f9f79ba1645c3c3b7877a00c828c613",
                        "name": "IOS XE Software",
                        "version": "Everest-16.6.1"
                    },
                    {
                        "firmwareid": "7d21f257a2f961d6a2f7fc9c5ce3a8b9",
                        "name": "IOS XE Software",
                        "version": "Gibraltar-16.10.3"
                    },
                    {
                        "firmwareid": "9ef8e3bb3a32fa0a054bb9920a8dea21",
                        "name": "IOS XE Software",
                        "version": "Fuji-16.9.2"
                    },
                    {
                        "firmwareid": "791a6571809b0e98d2ff883800feacef",
                        "name": "IOS XE Software",
                        "version": "Everest-16.6.3"
                    },
                    {
                        "firmwareid": "c001151557e5e1887bac29b6e85b82e2",
                        "name": "IOS XE Software",
                        "version": "Everest-16.6.8"
                    },
                    {
                        "firmwareid": "0608eb818330553de7f4bd0b408595db",
                        "name": "IOS XE Software",
                        "version": "Fuji-16.7.3"
                    },
                    {
                        "firmwareid": "1111850d9447c1783f146634d2c136ab",
                        "name": "IOS XE Software",
                        "version": "Fuji-16.7.2"
                    },
                    {
                        "firmwareid": "e2dc90b7eeda58effb664daedd11a4ab",
                        "name": "IOS XE Software",
                        "version": "Amsterdam-17.1.1"
                    },
                    {
                        "firmwareid": "526fcffa5f208823e972080fc50dc626",
                        "name": "IOS XE Software",
                        "version": "Fuji-16.8.2"
                    },
                    {
                        "firmwareid": "3702a76bcec4e6ed63b2717f49ad2f9e",
                        "name": "IOS XE Software",
                        "version": "Everest-16.6.5"
                    },
                    {
                        "firmwareid": "22b5bf97062b199352a56e705bebb6de",
                        "name": "IOS XE Software",
                        "version": "Everest-16.6.7"
                    },
                    {
                        "firmwareid": "49da4dceb3d3af1558eda9c1ccd11385",
                        "name": "IOS XE Software",
                        "version": "Gibraltar-16.12.3"
                    },
                    {
                        "firmwareid": "d1af2cd36aafebbc1fd952cd7fa05e61",
                        "name": "IOS XE Software",
                        "version": "Everest-16.6.2"
                    },
                    {
                        "firmwareid": "e25533d29fea76fe89e53add9eda2700",
                        "name": "IOS XE Software",
                        "version": "Fuji-16.8.3"
                    },
                    {
                        "firmwareid": "63cb7be1b27e03540f978fe046f2573d",
                        "name": "IOS XE Software",
                        "version": "Gibraltar-16.12.2s"
                    },
                    {
                        "firmwareid": "34104d43ad03802a1a050fbf507fde23",
                        "name": "IOS XE Software",
                        "version": "Gibraltar-16.11.1a"
                    },
                    {
                        "firmwareid": "570a81af84cf36b3ba24087bed8b6934",
                        "name": "IOS XE Software",
                        "version": "Everest-16.6.4"
                    },
                    {
                        "firmwareid": "fd703df5d0451b4bab30ee91348ea156",
                        "name": "IOS XE Software",
                        "version": "Gibraltar-16.12.4"
                    },
                    {
                        "firmwareid": "6c3bb65e8b0647f6f6b39db5f417b10e",
                        "name": "IOS XE Software",
                        "version": "Everest-16.6.6"
                    },
                    {
                        "firmwareid": "c9071bd2da79c56a1261a13246051101",
                        "name": "IOS XE Software",
                        "version": "Amsterdam-17.2.2"
                    },
                    {
                        "firmwareid": "f3bf1c94e25736f7812067808b30f9ff",
                        "name": "IOS XE Software",
                        "version": "Fuji-16.9.1"
                    },
                    {
                        "firmwareid": "19d889907ab4a11b0aa711e72bad1c1d",
                        "name": "IOS XE Software",
                        "version": "Amsterdam-17.3.1a"
                    }
                ],
                "model": "1100 Integrated Services Router",
                "score": 0.85,
                "series": "1000 Series Integrated Services Routers",
                "vendor": "CISCO"
            },
            {
                "categories": [
                    "ROUTER",
                    "NETWORK"
                ],
                "device_key": "26587157b19d63b20a916ca5cdea246e",
                "firmware": [
                    {
                        "firmwareid": "49da4dceb3d3af1558eda9c1ccd11385",
                        "name": "IOS XE Software",
                        "version": "Gibraltar-16.12.3"
                    },
                    {
                        "firmwareid": "ad477d7ac4176c17a7201477df834f29",
                        "name": "IOS XE Software",
                        "version": "Everest-16.5.3"
                    },
                    {
                        "firmwareid": "763c8b91e14200e2498ece2176b3a9b6",
                        "name": "IOS XE SD-WAN Software",
                        "version": "16.10.3"
                    },
                    {
                        "firmwareid": "63cb7be1b27e03540f978fe046f2573d",
                        "name": "IOS XE Software",
                        "version": "Gibraltar-16.12.2s"
                    },
                    {
                        "firmwareid": "54156e5f5b3e826922d8e7caf07790ff",
                        "name": "IOS XE Software",
                        "version": "Everest-16.5.2"
                    },
                    {
                        "firmwareid": "553fd37c3ce587bf931fd343099e0acb",
                        "name": "IOS XE SD-WAN Software",
                        "version": "16.10.1"
                    },
                    {
                        "firmwareid": "caf87c622d7565bff1f243aaedeccc0f",
                        "name": "IOS XE Software",
                        "version": "16.12.2"
                    },
                    {
                        "firmwareid": "19d889907ab4a11b0aa711e72bad1c1d",
                        "name": "IOS XE Software",
                        "version": "Amsterdam-17.3.1a"
                    },
                    {
                        "firmwareid": "2528514bdacd52435b1a687ba233649d",
                        "name": "IOS XE Software",
                        "version": "Fuji-16.9.5"
                    },
                    {
                        "firmwareid": "e25533d29fea76fe89e53add9eda2700",
                        "name": "IOS XE Software",
                        "version": "Fuji-16.8.3"
                    },
                    {
                        "firmwareid": "c9071bd2da79c56a1261a13246051101",
                        "name": "IOS XE Software",
                        "version": "Amsterdam-17.2.2"
                    },
                    {
                        "firmwareid": "679e7840100ef3561fdb842cbe3880d9",
                        "name": "IOS XE Software",
                        "version": "Amsterdam-17.3.2"
                    },
                    {
                        "firmwareid": "34104d43ad03802a1a050fbf507fde23",
                        "name": "IOS XE Software",
                        "version": "Gibraltar-16.11.1a"
                    },
                    {
                        "firmwareid": "fd703df5d0451b4bab30ee91348ea156",
                        "name": "IOS XE Software",
                        "version": "Gibraltar-16.12.4"
                    },
                    {
                        "firmwareid": "91365ff45799a4eac0afd6bea5e1ef57",
                        "name": "IOS XE Software",
                        "version": "Everest-16.4.3"
                    },
                    {
                        "firmwareid": "1111850d9447c1783f146634d2c136ab",
                        "name": "IOS XE Software",
                        "version": "Fuji-16.7.2"
                    },
                    {
                        "firmwareid": "b00f0e2b6684060e6a6650814954c541",
                        "name": "IOS XE Software",
                        "version": "Bengaluru-17.4.1a"
                    },
                    {
                        "firmwareid": "9b5f1d0c26f5993e32aaae13fde9595a",
                        "name": "IOS XE SD-WAN Software",
                        "version": "16.9.1"
                    },
                    {
                        "firmwareid": "c18ac6ad746677a4ce6a295fd9594bfe",
                        "name": "IOS XE SD-WAN Software",
                        "version": "16.12.4"
                    },
                    {
                        "firmwareid": "f1d2f361624da02aad0a63f0c52c7b52",
                        "name": "IOS XE Software",
                        "version": "Fuji-16.8.1"
                    },
                    {
                        "firmwareid": "9f9f79ba1645c3c3b7877a00c828c613",
                        "name": "IOS XE Software",
                        "version": "Everest-16.6.1"
                    },
                    {
                        "firmwareid": "791a6571809b0e98d2ff883800feacef",
                        "name": "IOS XE Software",
                        "version": "Everest-16.6.3"
                    },
                    {
                        "firmwareid": "d73684039e22e40445f9776e07af8cf9",
                        "name": "IOS XE Software",
                        "version": "Fuji-16.9.3"
                    },
                    {
                        "firmwareid": "22b5bf97062b199352a56e705bebb6de",
                        "name": "IOS XE Software",
                        "version": "Everest-16.6.7"
                    },
                    {
                        "firmwareid": "e2dc90b7eeda58effb664daedd11a4ab",
                        "name": "IOS XE Software",
                        "version": "Amsterdam-17.1.1"
                    },
                    {
                        "firmwareid": "731012493ae90a5aa1c8f2e1aa945037",
                        "name": "IOS XE Software",
                        "version": "Gibraltar-16.12.1a"
                    },
                    {
                        "firmwareid": "33231d2b20d5b0c25d60a712a7daee13",
                        "name": "IOS XE SD-WAN Software",
                        "version": "16.10.2"
                    },
                    {
                        "firmwareid": "da8865f7b32445b8a1846cfe8845b424",
                        "name": "IOS XE Software",
                        "version": "Fuji-16.9.6"
                    },
                    {
                        "firmwareid": "60e17bf92c152ab7356d537edd14da9f",
                        "name": "IOS XE Software",
                        "version": "Gibraltar-16.10.1a"
                    },
                    {
                        "firmwareid": "570a81af84cf36b3ba24087bed8b6934",
                        "name": "IOS XE Software",
                        "version": "Everest-16.6.4"
                    },
                    {
                        "firmwareid": "7d21f257a2f961d6a2f7fc9c5ce3a8b9",
                        "name": "IOS XE Software",
                        "version": "Gibraltar-16.10.3"
                    },
                    {
                        "firmwareid": "50183493390173eef932b1d25c37a6f5",
                        "name": "IOS XE Software",
                        "version": "Everest-16.4.2"
                    },
                    {
                        "firmwareid": "3702a76bcec4e6ed63b2717f49ad2f9e",
                        "name": "IOS XE Software",
                        "version": "Everest-16.6.5"
                    },
                    {
                        "firmwareid": "f3bf1c94e25736f7812067808b30f9ff",
                        "name": "IOS XE Software",
                        "version": "Fuji-16.9.1"
                    },
                    {
                        "firmwareid": "9ef8e3bb3a32fa0a054bb9920a8dea21",
                        "name": "IOS XE Software",
                        "version": "Fuji-16.9.2"
                    },
                    {
                        "firmwareid": "6c3bb65e8b0647f6f6b39db5f417b10e",
                        "name": "IOS XE Software",
                        "version": "Everest-16.6.6"
                    },
                    {
                        "firmwareid": "f85f5c6f8381a6a78c50be03467049dc",
                        "name": "IOS XE SD-WAN Software",
                        "version": "16.11.1a"
                    },
                    {
                        "firmwareid": "e14fa3096a61f875c0f58ba3a7d0e9d9",
                        "name": "IOS XE Software",
                        "version": "Gibraltar-16.10.2"
                    },
                    {
                        "firmwareid": "69904f98c71fa9a896b402d6e5e77379",
                        "name": "IOS XE Software",
                        "version": "Fuji-16.7.1"
                    },
                    {
                        "firmwareid": "5bdfdedcf432ffb3226e64ce6cc33125",
                        "name": "IOS XE SD-WAN Software",
                        "version": "16.12.4a"
                    },
                    {
                        "firmwareid": "aaf559b413fdbdba0ae5fc898b2ef0c4",
                        "name": "IOS XE SD-WAN Software",
                        "version": "16.9.2"
                    },
                    {
                        "firmwareid": "1afa9319f7a82012cf42d65b14431b72",
                        "name": "IOS XE Software",
                        "version": "16.9.4"
                    },
                    {
                        "firmwareid": "866c3f1990b07f2be74217a26e41d8f7",
                        "name": "IOS XE SD-WAN Software",
                        "version": "16.12.3"
                    },
                    {
                        "firmwareid": "d1af2cd36aafebbc1fd952cd7fa05e61",
                        "name": "IOS XE Software",
                        "version": "Everest-16.6.2"
                    },
                    {
                        "firmwareid": "0608eb818330553de7f4bd0b408595db",
                        "name": "IOS XE Software",
                        "version": "Fuji-16.7.3"
                    },
                    {
                        "firmwareid": "1287e24f31a52b8b0cc09eea0cb73a6e",
                        "name": "IOS XE SD-WAN Software",
                        "version": "16.9.4"
                    },
                    {
                        "firmwareid": "41b2342bffc73f650f5b8256fdc35818",
                        "name": "IOS XE Software",
                        "version": "Amsterdam-17.2.1r"
                    },
                    {
                        "firmwareid": "c001151557e5e1887bac29b6e85b82e2",
                        "name": "IOS XE Software",
                        "version": "Everest-16.6.8"
                    },
                    {
                        "firmwareid": "2085e15eb5d4b84addb00b2bbf85b917",
                        "name": "IOS XE Software",
                        "version": "Everest-16.5.1b"
                    }
                ],
                "model": "4221 Integrated Services Router",
                "score": 0.85,
                "series": "4000 Series Integrated Services Routers",
                "vendor": "CISCO"
            }
        ]
    }
}
```

#### Human Readable Output

>## Found 5 devices
>---
>### Device 2901 Integrated Services Router
>**Model Name**: 2901 Integrated Services Router
>**Vendor**: CISCO
>**Series**: 2900 Series Integrated Services Routers
>**Categories**: NETWORK,ROUTER
>**DeviceID**: ce341ae9c368850f2f2f5de59f2d6071
>**Match Score**: 100%
>### Firmwares
>|firmwareid|version|name|
>|---|---|---|
>| 9c988101f9bd9e677f421cb1231d2c55 | 15.4.2T1 | Software on Chassis |
>---
>### Device 4431 Integrated Services Router
>**Model Name**: 4431 Integrated Services Router
>**Vendor**: CISCO
>**Series**: 4000 Series Integrated Services Routers
>**Categories**: NETWORK,ROUTER
>**DeviceID**: c11eb29c5346d182b94ee1fcde6d0b21
>**Match Score**: 85.0%
>### Firmwares
>|firmwareid|version|name|
>|---|---|---|
>| 1afa9319f7a82012cf42d65b14431b72 | 16.9.4 | IOS XE Software |
>| d8e81c52ba635da73458028d6514e8bb | 3.16.6bS | IOS XE Software |
>| e68bc28082f959e6daa95ac178a4e202 | 3.16.4bS | IOS XE Software |
>---
>### Device 1803 Integrated Services Router
>**Model Name**: 1803 Integrated Services Router
>**Vendor**: CISCO
>**Series**: 1800 Series Integrated Services Routers
>**Categories**: NETWORK,ROUTER
>**DeviceID**: adc8495470b0bf3bc046d77fcf770d82
>**Match Score**: 85.0%
>### Firmwares
>|firmwareid|version|name|
>|---|---|---|
>| 30c54737553f3aa302188af5afe0c553 | 15.1.4M12a | Software on Chassis |
>---
>### Device 1100 Integrated Services Router
>**Model Name**: 1100 Integrated Services Router
>**Vendor**: CISCO
>**Series**: 1000 Series Integrated Services Routers
>**Categories**: ROUTER,NETWORK
>**DeviceID**: a829c4b2ce4d9662de8b046253b3fd98
>**Match Score**: 85.0%
>### Firmwares
>|firmwareid|version|name|
>|---|---|---|
>| da8865f7b32445b8a1846cfe8845b424 | Fuji-16.9.6 | IOS XE Software |
>| 41b2342bffc73f650f5b8256fdc35818 | Amsterdam-17.2.1r | IOS XE Software |
>| 679e7840100ef3561fdb842cbe3880d9 | Amsterdam-17.3.2 | IOS XE Software |
>| 69904f98c71fa9a896b402d6e5e77379 | Fuji-16.7.1 | IOS XE Software |
>| d73684039e22e40445f9776e07af8cf9 | Fuji-16.9.3 | IOS XE Software |
>| b00f0e2b6684060e6a6650814954c541 | Bengaluru-17.4.1a | IOS XE Software |
>| f1d2f361624da02aad0a63f0c52c7b52 | Fuji-16.8.1 | IOS XE Software |
>| e14fa3096a61f875c0f58ba3a7d0e9d9 | Gibraltar-16.10.2 | IOS XE Software |
>| 1afa9319f7a82012cf42d65b14431b72 | 16.9.4 | IOS XE Software |
>| 73d1aed88774dee9cf7924244f104454 | Gibraltar-16.10.1b | IOS XE Software |
>| 2528514bdacd52435b1a687ba233649d | Fuji-16.9.5 | IOS XE Software |
>| caf87c622d7565bff1f243aaedeccc0f | 16.12.2 | IOS XE Software |
>| 731012493ae90a5aa1c8f2e1aa945037 | Gibraltar-16.12.1a | IOS XE Software |
>| 9f9f79ba1645c3c3b7877a00c828c613 | Everest-16.6.1 | IOS XE Software |
>| 7d21f257a2f961d6a2f7fc9c5ce3a8b9 | Gibraltar-16.10.3 | IOS XE Software |
>| 9ef8e3bb3a32fa0a054bb9920a8dea21 | Fuji-16.9.2 | IOS XE Software |
>| 791a6571809b0e98d2ff883800feacef | Everest-16.6.3 | IOS XE Software |
>| c001151557e5e1887bac29b6e85b82e2 | Everest-16.6.8 | IOS XE Software |
>| 0608eb818330553de7f4bd0b408595db | Fuji-16.7.3 | IOS XE Software |
>| 1111850d9447c1783f146634d2c136ab | Fuji-16.7.2 | IOS XE Software |
>| e2dc90b7eeda58effb664daedd11a4ab | Amsterdam-17.1.1 | IOS XE Software |
>| 526fcffa5f208823e972080fc50dc626 | Fuji-16.8.2 | IOS XE Software |
>| 3702a76bcec4e6ed63b2717f49ad2f9e | Everest-16.6.5 | IOS XE Software |
>| 22b5bf97062b199352a56e705bebb6de | Everest-16.6.7 | IOS XE Software |
>| 49da4dceb3d3af1558eda9c1ccd11385 | Gibraltar-16.12.3 | IOS XE Software |
>| d1af2cd36aafebbc1fd952cd7fa05e61 | Everest-16.6.2 | IOS XE Software |
>| e25533d29fea76fe89e53add9eda2700 | Fuji-16.8.3 | IOS XE Software |
>| 63cb7be1b27e03540f978fe046f2573d | Gibraltar-16.12.2s | IOS XE Software |
>| 34104d43ad03802a1a050fbf507fde23 | Gibraltar-16.11.1a | IOS XE Software |
>| 570a81af84cf36b3ba24087bed8b6934 | Everest-16.6.4 | IOS XE Software |
>| fd703df5d0451b4bab30ee91348ea156 | Gibraltar-16.12.4 | IOS XE Software |
>| 6c3bb65e8b0647f6f6b39db5f417b10e | Everest-16.6.6 | IOS XE Software |
>| c9071bd2da79c56a1261a13246051101 | Amsterdam-17.2.2 | IOS XE Software |
>| f3bf1c94e25736f7812067808b30f9ff | Fuji-16.9.1 | IOS XE Software |
>| 19d889907ab4a11b0aa711e72bad1c1d | Amsterdam-17.3.1a | IOS XE Software |
>---
>### Device 4221 Integrated Services Router
>**Model Name**: 4221 Integrated Services Router
>**Vendor**: CISCO
>**Series**: 4000 Series Integrated Services Routers
>**Categories**: ROUTER,NETWORK
>**DeviceID**: 26587157b19d63b20a916ca5cdea246e
>**Match Score**: 85.0%
>### Firmwares
>|firmwareid|version|name|
>|---|---|---|
>| 49da4dceb3d3af1558eda9c1ccd11385 | Gibraltar-16.12.3 | IOS XE Software |
>| ad477d7ac4176c17a7201477df834f29 | Everest-16.5.3 | IOS XE Software |
>| 763c8b91e14200e2498ece2176b3a9b6 | 16.10.3 | IOS XE SD-WAN Software |
>| 63cb7be1b27e03540f978fe046f2573d | Gibraltar-16.12.2s | IOS XE Software |
>| 54156e5f5b3e826922d8e7caf07790ff | Everest-16.5.2 | IOS XE Software |
>| 553fd37c3ce587bf931fd343099e0acb | 16.10.1 | IOS XE SD-WAN Software |
>| caf87c622d7565bff1f243aaedeccc0f | 16.12.2 | IOS XE Software |
>| 19d889907ab4a11b0aa711e72bad1c1d | Amsterdam-17.3.1a | IOS XE Software |
>| 2528514bdacd52435b1a687ba233649d | Fuji-16.9.5 | IOS XE Software |
>| e25533d29fea76fe89e53add9eda2700 | Fuji-16.8.3 | IOS XE Software |
>| c9071bd2da79c56a1261a13246051101 | Amsterdam-17.2.2 | IOS XE Software |
>| 679e7840100ef3561fdb842cbe3880d9 | Amsterdam-17.3.2 | IOS XE Software |
>| 34104d43ad03802a1a050fbf507fde23 | Gibraltar-16.11.1a | IOS XE Software |
>| fd703df5d0451b4bab30ee91348ea156 | Gibraltar-16.12.4 | IOS XE Software |
>| 91365ff45799a4eac0afd6bea5e1ef57 | Everest-16.4.3 | IOS XE Software |
>| 1111850d9447c1783f146634d2c136ab | Fuji-16.7.2 | IOS XE Software |
>| b00f0e2b6684060e6a6650814954c541 | Bengaluru-17.4.1a | IOS XE Software |
>| 9b5f1d0c26f5993e32aaae13fde9595a | 16.9.1 | IOS XE SD-WAN Software |
>| c18ac6ad746677a4ce6a295fd9594bfe | 16.12.4 | IOS XE SD-WAN Software |
>| f1d2f361624da02aad0a63f0c52c7b52 | Fuji-16.8.1 | IOS XE Software |
>| 9f9f79ba1645c3c3b7877a00c828c613 | Everest-16.6.1 | IOS XE Software |
>| 791a6571809b0e98d2ff883800feacef | Everest-16.6.3 | IOS XE Software |
>| d73684039e22e40445f9776e07af8cf9 | Fuji-16.9.3 | IOS XE Software |
>| 22b5bf97062b199352a56e705bebb6de | Everest-16.6.7 | IOS XE Software |
>| e2dc90b7eeda58effb664daedd11a4ab | Amsterdam-17.1.1 | IOS XE Software |
>| 731012493ae90a5aa1c8f2e1aa945037 | Gibraltar-16.12.1a | IOS XE Software |
>| 33231d2b20d5b0c25d60a712a7daee13 | 16.10.2 | IOS XE SD-WAN Software |
>| da8865f7b32445b8a1846cfe8845b424 | Fuji-16.9.6 | IOS XE Software |
>| 60e17bf92c152ab7356d537edd14da9f | Gibraltar-16.10.1a | IOS XE Software |
>| 570a81af84cf36b3ba24087bed8b6934 | Everest-16.6.4 | IOS XE Software |
>| 7d21f257a2f961d6a2f7fc9c5ce3a8b9 | Gibraltar-16.10.3 | IOS XE Software |
>| 50183493390173eef932b1d25c37a6f5 | Everest-16.4.2 | IOS XE Software |
>| 3702a76bcec4e6ed63b2717f49ad2f9e | Everest-16.6.5 | IOS XE Software |
>| f3bf1c94e25736f7812067808b30f9ff | Fuji-16.9.1 | IOS XE Software |
>| 9ef8e3bb3a32fa0a054bb9920a8dea21 | Fuji-16.9.2 | IOS XE Software |
>| 6c3bb65e8b0647f6f6b39db5f417b10e | Everest-16.6.6 | IOS XE Software |
>| f85f5c6f8381a6a78c50be03467049dc | 16.11.1a | IOS XE SD-WAN Software |
>| e14fa3096a61f875c0f58ba3a7d0e9d9 | Gibraltar-16.10.2 | IOS XE Software |
>| 69904f98c71fa9a896b402d6e5e77379 | Fuji-16.7.1 | IOS XE Software |
>| 5bdfdedcf432ffb3226e64ce6cc33125 | 16.12.4a | IOS XE SD-WAN Software |
>| aaf559b413fdbdba0ae5fc898b2ef0c4 | 16.9.2 | IOS XE SD-WAN Software |
>| 1afa9319f7a82012cf42d65b14431b72 | 16.9.4 | IOS XE Software |
>| 866c3f1990b07f2be74217a26e41d8f7 | 16.12.3 | IOS XE SD-WAN Software |
>| d1af2cd36aafebbc1fd952cd7fa05e61 | Everest-16.6.2 | IOS XE Software |
>| 0608eb818330553de7f4bd0b408595db | Fuji-16.7.3 | IOS XE Software |
>| 1287e24f31a52b8b0cc09eea0cb73a6e | 16.9.4 | IOS XE SD-WAN Software |
>| 41b2342bffc73f650f5b8256fdc35818 | Amsterdam-17.2.1r | IOS XE Software |
>| c001151557e5e1887bac29b6e85b82e2 | Everest-16.6.8 | IOS XE Software |
>| 2085e15eb5d4b84addb00b2bbf85b917 | Everest-16.5.1b | IOS XE Software |


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
```!arcusteam-get-vulnerabilities firmware_id=d8e81c52ba635da73458028d6514e8bb device_id=c11eb29c5346d182b94ee1fcde6d0b21 return_fields=risk,cve,cwe,description,codename,exploit_published,exploit_used,modified_date```

#### Context Example
```json
{
    "ArcusTeamVulnerabilities": {
        "has_next": true,
        "max_items": 76,
        "results": [
            {
              "risk": 1,
              "cve": "CVE-2019-12643",
              "description": "A vulnerability in the Cisco REST API virtual service container for Cisco IOS XE Software could allow an unauthenticated, remote attacker to bypass authentication on the managed Cisco IOS XE device. The vulnerability is due to an improper check performed by the area of code that manages the REST API authentication service. An attacker could exploit this vulnerability by submitting malicious HTTP requests to the targeted device. A successful exploit could allow the attacker to obtain the token-id of an authenticated user. This token-id could be used to bypass authentication and execute privileged actions through the interface of the REST API virtual service container on the affected Cisco IOS XE device. The REST API interface is not enabled by default and must be installed and activated separately on IOS XE devices. See the Details section for more information.",
              "codename": null,
              "cwe": "CWE-287",
              "exploit_published": null,
              "exploit_used": null,
              "modified_date": 1570664700
            },
            {
              "risk": 0.9800000000000001,
              "cve": "CVE-2016-2148",
              "description": "Heap-based buffer overflow in the DHCP client (udhcpc) in BusyBox before 1.25.0 allows remote attackers to have unspecified impact via vectors involving OPTION_6RD parsing.",
              "codename": null,
              "cwe": "CWE-119",
              "exploit_published": null,
              "exploit_used": null,
              "modified_date": 1598559300
            },
            {
              "risk": 0.9800000000000001,
              "cve": "CVE-2018-0151",
              "description": "A vulnerability in the quality of service (QoS) subsystem of Cisco IOS Software and Cisco IOS XE Software could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition or execute arbitrary code with elevated privileges. The vulnerability is due to incorrect bounds checking of certain values in packets that are destined for UDP port 18999 of an affected device. An attacker could exploit this vulnerability by sending malicious packets to an affected device. When the packets are processed, an exploitable buffer overflow condition may occur. A successful exploit could allow the attacker to execute arbitrary code on the affected device with elevated privileges. The attacker could also leverage this vulnerability to cause the device to reload, causing a temporary DoS condition while the device is reloading. The malicious packets must be destined to and processed by an affected device. Traffic transiting a device will not trigger the vulnerability. Cisco Bug IDs: CSCvf73881.",
              "codename": null,
              "cwe": "CWE-119",
              "exploit_published": null,
              "exploit_used": null,
              "modified_date": 1575312840
            },
            {
              "risk": 0.9800000000000001,
              "cve": "CVE-2020-10188",
              "description": null,
              "codename": null,
              "cwe": "CWE-120",
              "exploit_published": false,
              "exploit_used": false,
              "modified_date": 1594227510
            },
            {
              "risk": 0.9800000000000001,
              "cve": "CVE-2018-1000517",
              "description": "BusyBox project BusyBox wget version prior to commit 8e2174e9bd836e53c8b9c6e00d1bc6e2a718686e contains a Buffer Overflow vulnerability in Busybox wget that can result in heap buffer overflow. This attack appear to be exploitable via network connectivity. This vulnerability appears to have been fixed in after commit 8e2174e9bd836e53c8b9c6e00d1bc6e2a718686e.",
              "codename": null,
              "cwe": "CWE-120",
              "exploit_published": null,
              "exploit_used": null,
              "modified_date": 1590612900
            },
            {
              "risk": 0.8800000000000001,
              "cve": "CVE-2017-16544",
              "description": "In the add_match function in libbb/lineedit.c in BusyBox through 1.27.2, the tab autocomplete feature of the shell, used to get a list of filenames in a directory, does not sanitize filenames and results in executing any escape sequence in the terminal. This could potentially result in code execution, arbitrary file writes, or other attacks.",
              "codename": null,
              "cwe": "CWE-94",
              "exploit_published": null,
              "exploit_used": null,
              "modified_date": 1610543700
            },
            {
              "risk": 0.8800000000000001,
              "cve": "CVE-2019-16009",
              "description": null,
              "codename": null,
              "cwe": "CWE-352",
              "exploit_published": false,
              "exploit_used": false,
              "modified_date": 1588096010
            },
            {
              "risk": 0.8800000000000001,
              "cve": "CVE-2020-3217",
              "description": null,
              "codename": null,
              "cwe": "CWE-20",
              "exploit_published": false,
              "exploit_used": false,
              "modified_date": 1591200000
            },
            {
              "risk": 0.8800000000000001,
              "cve": "CVE-2018-0167",
              "description": null,
              "codename": null,
              "cwe": "CWE-119",
              "exploit_published": false,
              "exploit_used": false,
              "modified_date": 1525269240
            },
            {
              "risk": 0.86,
              "cve": "CVE-2020-3226",
              "description": null,
              "codename": null,
              "cwe": "CWE-20",
              "exploit_published": false,
              "exploit_used": false,
              "modified_date": 1591200000
            }
        ]
    }
}
```

#### Human Readable Output

>## Scan results
>### Number of CVE's found: 76
>|risk|cve|cwe|description|codename|exploit_published|exploit_used|modified_date|
>|---|---|---|---|---|---|---|---|
>| 100.0% | CVE-2019-12643 | CWE-287 | A vulnerability in the Cisco REST API virtual service container for Cisco IOS XE Software could allow an unauthenticated, remote attacker to bypass authentication on the managed Cisco IOS XE device. The vulnerability is due to an improper check performed by the area of code that manages the REST API authentication service. An attacker could exploit this vulnerability by submitting malicious HTTP requests to the targeted device. A successful exploit could allow the attacker to obtain the token-id of an authenticated user. This token-id could be used to bypass authentication and execute privileged actions through the interface of the REST API virtual service container on the affected Cisco IOS XE device. The REST API interface is not enabled by default and must be installed and activated separately on IOS XE devices. See the Details section for more information. |  |  |  | 1570664700 |
>| 98.0% | CVE-2020-10188 | CWE-120 |  |  | false | false | 1594227510 |
>| 98.0% | CVE-2018-0151 | CWE-119 | A vulnerability in the quality of service (QoS) subsystem of Cisco IOS Software and Cisco IOS XE Software could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition or execute arbitrary code with elevated privileges. The vulnerability is due to incorrect bounds checking of certain values in packets that are destined for UDP port 18999 of an affected device. An attacker could exploit this vulnerability by sending malicious packets to an affected device. When the packets are processed, an exploitable buffer overflow condition may occur. A successful exploit could allow the attacker to execute arbitrary code on the affected device with elevated privileges. The attacker could also leverage this vulnerability to cause the device to reload, causing a temporary DoS condition while the device is reloading. The malicious packets must be destined to and processed by an affected device. Traffic transiting a device will not trigger the vulnerability. Cisco Bug IDs: CSCvf73881. |  |  |  | 1575312840 |
>| 98.0% | CVE-2018-1000517 | CWE-120 | BusyBox project BusyBox wget version prior to commit 8e2174e9bd836e53c8b9c6e00d1bc6e2a718686e contains a Buffer Overflow vulnerability in Busybox wget that can result in heap buffer overflow. This attack appear to be exploitable via network connectivity. This vulnerability appears to have been fixed in after commit 8e2174e9bd836e53c8b9c6e00d1bc6e2a718686e. |  |  |  | 1590612900 |
>| 98.0% | CVE-2016-2148 | CWE-119 | Heap-based buffer overflow in the DHCP client (udhcpc) in BusyBox before 1.25.0 allows remote attackers to have unspecified impact via vectors involving OPTION_6RD parsing. |  |  |  | 1598559300 |
>| 88.0% | CVE-2017-16544 | CWE-94 | In the add_match function in libbb/lineedit.c in BusyBox through 1.27.2, the tab autocomplete feature of the shell, used to get a list of filenames in a directory, does not sanitize filenames and results in executing any escape sequence in the terminal. This could potentially result in code execution, arbitrary file writes, or other attacks. |  |  |  | 1610543700 |
>| 88.0% | CVE-2019-16009 | CWE-352 |  |  | false | false | 1588096010 |
>| 88.0% | CVE-2020-3217 | CWE-20 |  |  | false | false | 1591200000 |
>| 88.0% | CVE-2018-0167 | CWE-119 |  |  | false | false | 1525269240 |
>| 86.0% | CVE-2019-1737 | CWE-770 | A vulnerability in the processing of IP Service Level Agreement (SLA) packets by Cisco IOS Software and Cisco IOS XE software could allow an unauthenticated, remote attacker to cause an interface wedge and an eventual denial of service (DoS) condition on the affected device. The vulnerability is due to improper socket resources handling in the IP SLA responder application code. An attacker could exploit this vulnerability by sending crafted IP SLA packets to an affected device. An exploit could allow the attacker to cause an interface to become wedged, resulting in an eventual denial of service (DoS) condition on the affected device. |  |  |  | 1602187260 |


