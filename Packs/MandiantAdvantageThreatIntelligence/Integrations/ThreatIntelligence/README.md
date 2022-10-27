Integrate with Mandiant Advantage
This integration was integrated and tested with version xx of Mandiant Advantage Threat Intelligence

## Configure Mandiant Advantage Threat Intelligence on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Mandiant Advantage Threat Intelligence.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | API Base URL | Leave as 'api.intelligence.mandiant.com' if unsure | False |
    | API Key | Your API Key from Mandiant Advantage Threat Intelligence | True |
    | Secret Key | Your Secret Key from Mandiant Advantage Threat Intelligence | True |
    | Fetch indicators |  | False |
    | Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
    | Source Reliability | Reliability of the source providing the intelligence data. | True |
    | Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed. | False |
    | Feed Expiration Policy |  | False |
    | Feed Expiration Interval |  | False |
    | Feed Fetch Interval |  | False |
    | Feed Minimum Confidence Score | The minimum MScore value to import as part of the feed | True |
    | Feed Exclude Open Source Intelligence | Whether to exclude Open Source Intelligence as part of the feed | True |
    | Mandiant indicator type | The type of indicators to fetch. Indicator type might include the following: Domains, IPs, Files and URLs. | False |
    | First fetch time | The maximum value allowed is 90 days. | False |
    | Maximum number of indicators per fetch |  | False |
    | Tags | Supports CSV values. | False |
    | Timeout | API calls timeout. | False |
    | Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
    | Retrieve indicator metadata | Retrieve additional information for each indicator. Note that this requires additional API calls. | False |
    | Create relationships | Note that this requires additional API calls. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### threat-intelligence-get-indicators
***
Get Mandiant indicators


#### Base Command

`threat-intelligence-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| update_context | Update context. | Optional | 
| limit | The maximum number of indicators to fetch. | Optional | 
| indicatorMetadata | Whether to retrieve additional data for each indicator. Possible values are: true, false. Default is false. | Optional | 
| indicatorRelationships | Whether to create indicator relationships. Possible values are: true, false. Default is false. | Optional | 
| type | The type of indicators to fetch. Possible values are: Malware, Indicators, Actors. Default is Malware,Indicators,Actors. | Required | 


#### Context Output

There is no context output for this command.
### get-indicator
***
Get Mandiant indicator


#### Base Command

`get-indicator`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_value | Value of the indicator to look up.  Can be URL, domain name, IP address, or file hash. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!get-indicator indicator_value=8.8.8.8```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "8.8.8.8",
        "Score": 0,
        "Type": "ip",
        "Vendor": "Mandiant Advantage Threat Intelligence"
    },
    "IP": {
        "Address": "8.8.8.8"
    },
    "ip": [
        {
            "first_seen": "2014-09-01T21:39:51.000Z",
            "id": "ipv4--ae71927b-78e2-5659-8576-af0dc232b3e9",
            "is_publishable": true,
            "last_seen": "2022-10-25T15:01:21.000Z",
            "last_updated": "2022-10-25T15:01:24.711Z",
            "misp": {
                "akamai": false,
                "alexa": false,
                "alexa_1M": false,
                "amazon-aws": false,
                "apple": false,
                "automated-malware-analysis": false,
                "bank-website": false,
                "cisco_1M": false,
                "cisco_top1000": false,
                "cisco_top10k": false,
                "cisco_top20k": false,
                "cisco_top5k": false,
                "cloudflare": false,
                "common-contact-emails": false,
                "common-ioc-false-positive": false,
                "covid": false,
                "covid-19-cyber-threat-coalition-whitelist": false,
                "covid-19-krassi-whitelist": false,
                "crl-hostname": false,
                "crl-ip": false,
                "dax30": false,
                "disposable-email": false,
                "dynamic-dns": false,
                "eicar.com": false,
                "empty-hashes": false,
                "fastly": false,
                "google": false,
                "google-gcp": false,
                "google-gmail-sending-ips": false,
                "googlebot": false,
                "ipv6-linklocal": false,
                "majestic_million": false,
                "majestic_million_1M": false,
                "microsoft": false,
                "microsoft-attack-simulator": false,
                "microsoft-azure": false,
                "microsoft-azure-china": false,
                "microsoft-azure-germany": false,
                "microsoft-azure-us-gov": false,
                "microsoft-office365": false,
                "microsoft-office365-cn": false,
                "microsoft-office365-ip": false,
                "microsoft-win10-connection-endpoints": false,
                "moz-top500": false,
                "mozilla-CA": false,
                "mozilla-IntermediateCA": false,
                "multicast": false,
                "nioc-filehash": false,
                "ovh-cluster": false,
                "phone_numbers": false,
                "public-dns-hostname": false,
                "public-dns-v4": true,
                "public-dns-v6": false,
                "rfc1918": false,
                "rfc3849": false,
                "rfc5735": false,
                "rfc6598": false,
                "rfc6761": false,
                "second-level-tlds": false,
                "security-provider-blogpost": false,
                "sinkholes": false,
                "smtp-receiving-ips": false,
                "smtp-sending-ips": false,
                "stackpath": false,
                "tenable-cloud-ipv4": false,
                "tenable-cloud-ipv6": false,
                "ti-falsepositives": false,
                "tlds": false,
                "tranco": false,
                "tranco10k": false,
                "university_domains": false,
                "url-shortener": false,
                "vpn-ipv4": false,
                "vpn-ipv6": false,
                "whats-my-ip": false,
                "wikimedia": false
            },
            "mscore": 0,
            "sources": [
                {
                    "category": [],
                    "first_seen": "2022-08-14T03:51:28.491+0000",
                    "last_seen": "2022-10-22T00:58:18.588+0000",
                    "osint": false,
                    "source_name": "Mandiant"
                },
                {
                    "category": [],
                    "first_seen": "2020-11-27T23:01:13.253+0000",
                    "last_seen": "2021-05-17T10:30:08.060+0000",
                    "osint": false,
                    "source_name": "Mandiant"
                },
                {
                    "category": [
                        "phishing"
                    ],
                    "first_seen": "2020-11-26T23:00:17.199+0000",
                    "last_seen": "2020-11-27T23:00:19.242+0000",
                    "osint": true,
                    "source_name": "phishtank"
                },
                {
                    "category": [],
                    "first_seen": "2022-09-06T15:17:26.914+0000",
                    "last_seen": "2022-10-18T19:21:24.788+0000",
                    "osint": false,
                    "source_name": "Mandiant"
                },
                {
                    "category": [],
                    "first_seen": "2020-11-09T10:43:27.120+0000",
                    "last_seen": "2022-10-25T00:02:26.653+0000",
                    "osint": false,
                    "source_name": "Mandiant"
                },
                {
                    "category": [],
                    "first_seen": "2020-11-08T22:00:57.000+0000",
                    "last_seen": "2021-05-26T08:45:36.000+0000",
                    "osint": false,
                    "source_name": "Mandiant"
                },
                {
                    "category": [],
                    "first_seen": "2021-05-16T00:25:00.172+0000",
                    "last_seen": "2021-06-06T10:57:02.904+0000",
                    "osint": false,
                    "source_name": "Mandiant"
                },
                {
                    "category": [],
                    "first_seen": "2014-09-01T21:39:51.000+0000",
                    "last_seen": "2021-11-23T16:52:56.000+0000",
                    "osint": false,
                    "source_name": "Mandiant"
                },
                {
                    "category": [],
                    "first_seen": "2021-03-24T23:00:56.877+0000",
                    "last_seen": "2021-03-26T23:09:31.740+0000",
                    "osint": false,
                    "source_name": "Mandiant"
                },
                {
                    "category": [],
                    "first_seen": "2016-06-09T05:49:30.000+0000",
                    "last_seen": "2022-05-23T12:21:48.000+0000",
                    "osint": false,
                    "source_name": "Mandiant"
                },
                {
                    "category": [
                        "phishing",
                        "malware"
                    ],
                    "first_seen": "2021-01-08T22:10:01.519+0000",
                    "last_seen": "2022-08-24T00:10:02.631+0000",
                    "osint": true,
                    "source_name": "phishstats"
                }
            ],
            "type": "ipv4",
            "value": {
                "8.8.8.8": "[8.8.8.8](#/indicator/2605)"
            }
        }
    ]
}
```

#### Human Readable Output

>### Results
>|first_seen|id|is_publishable|last_seen|last_updated|misp|mscore|sources|type|value|
>|---|---|---|---|---|---|---|---|---|---|
>| 2014-09-01T21:39:51.000Z | ipv4--ae71927b-78e2-5659-8576-af0dc232b3e9 | true | 2022-10-25T15:01:21.000Z | 2022-10-25T15:01:24.711Z | akamai: false<br/>alexa: false<br/>alexa_1M: false<br/>amazon-aws: false<br/>apple: false<br/>automated-malware-analysis: false<br/>bank-website: false<br/>cisco_1M: false<br/>cisco_top1000: false<br/>cisco_top10k: false<br/>cisco_top20k: false<br/>cisco_top5k: false<br/>cloudflare: false<br/>common-contact-emails: false<br/>common-ioc-false-positive: false<br/>covid: false<br/>covid-19-cyber-threat-coalition-whitelist: false<br/>covid-19-krassi-whitelist: false<br/>crl-hostname: false<br/>crl-ip: false<br/>dax30: false<br/>disposable-email: false<br/>dynamic-dns: false<br/>eicar.com: false<br/>empty-hashes: false<br/>fastly: false<br/>google: false<br/>google-gcp: false<br/>google-gmail-sending-ips: false<br/>googlebot: false<br/>ipv6-linklocal: false<br/>majestic_million: false<br/>majestic_million_1M: false<br/>microsoft: false<br/>microsoft-attack-simulator: false<br/>microsoft-azure: false<br/>microsoft-azure-china: false<br/>microsoft-azure-germany: false<br/>microsoft-azure-us-gov: false<br/>microsoft-office365: false<br/>microsoft-office365-cn: false<br/>microsoft-office365-ip: false<br/>microsoft-win10-connection-endpoints: false<br/>moz-top500: false<br/>mozilla-CA: false<br/>mozilla-IntermediateCA: false<br/>multicast: false<br/>nioc-filehash: false<br/>ovh-cluster: false<br/>phone_numbers: false<br/>public-dns-hostname: false<br/>public-dns-v4: true<br/>public-dns-v6: false<br/>rfc1918: false<br/>rfc3849: false<br/>rfc5735: false<br/>rfc6598: false<br/>rfc6761: false<br/>second-level-tlds: false<br/>security-provider-blogpost: false<br/>sinkholes: false<br/>smtp-receiving-ips: false<br/>smtp-sending-ips: false<br/>stackpath: false<br/>tenable-cloud-ipv4: false<br/>tenable-cloud-ipv6: false<br/>ti-falsepositives: false<br/>tlds: false<br/>tranco: false<br/>tranco10k: false<br/>university_domains: false<br/>url-shortener: false<br/>vpn-ipv4: false<br/>vpn-ipv6: false<br/>whats-my-ip: false<br/>wikimedia: false | 0 | {'first_seen': '2022-08-14T03:51:28.491+0000', 'last_seen': '2022-10-22T00:58:18.588+0000', 'osint': False, 'category': [], 'source_name': 'Mandiant'},<br/>{'first_seen': '2020-11-27T23:01:13.253+0000', 'last_seen': '2021-05-17T10:30:08.060+0000', 'osint': False, 'category': [], 'source_name': 'Mandiant'},<br/>{'first_seen': '2020-11-26T23:00:17.199+0000', 'last_seen': '2020-11-27T23:00:19.242+0000', 'osint': True, 'category': ['phishing'], 'source_name': 'phishtank'},<br/>{'first_seen': '2022-09-06T15:17:26.914+0000', 'last_seen': '2022-10-18T19:21:24.788+0000', 'osint': False, 'category': [], 'source_name': 'Mandiant'},<br/>{'first_seen': '2020-11-09T10:43:27.120+0000', 'last_seen': '2022-10-25T00:02:26.653+0000', 'osint': False, 'category': [], 'source_name': 'Mandiant'},<br/>{'first_seen': '2020-11-08T22:00:57.000+0000', 'last_seen': '2021-05-26T08:45:36.000+0000', 'osint': False, 'category': [], 'source_name': 'Mandiant'},<br/>{'first_seen': '2021-05-16T00:25:00.172+0000', 'last_seen': '2021-06-06T10:57:02.904+0000', 'osint': False, 'category': [], 'source_name': 'Mandiant'},<br/>{'first_seen': '2014-09-01T21:39:51.000+0000', 'last_seen': '2021-11-23T16:52:56.000+0000', 'osint': False, 'category': [], 'source_name': 'Mandiant'},<br/>{'first_seen': '2021-03-24T23:00:56.877+0000', 'last_seen': '2021-03-26T23:09:31.740+0000', 'osint': False, 'category': [], 'source_name': 'Mandiant'},<br/>{'first_seen': '2016-06-09T05:49:30.000+0000', 'last_seen': '2022-05-23T12:21:48.000+0000', 'osint': False, 'category': [], 'source_name': 'Mandiant'},<br/>{'first_seen': '2021-01-08T22:10:01.519+0000', 'last_seen': '2022-08-24T00:10:02.631+0000', 'osint': True, 'category': ['phishing', 'malware'], 'source_name': 'phishstats'} | ipv4 | 8.8.8.8: [8.8.8.8](#/indicator/2605) |


### get-actor
***
Get Mandiant Threat Actor


#### Base Command

`get-actor`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| actor_name | Name of the actor to look up. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!get-actor actor_name=ACTOR```
#### Context Example
```json
{
    "MANDIANTTI": {
        "ThreatActor": {
            "aliases": ["SOMEACTOR"],
            "description": "Description of ACTOR goes here",
            "firstseenbysource": [
                "2011-01-29T00:00:00.000Z"
            ],
            "lastseenbysource": [
                "2015-03-12T00:00:00.000Z",
            ],
            "name": {
                "ACTOR": "[ACTOR](#/indicator/0000)"
            },
            "primarymotivation": "MOTIVATION",
            "publications": [
              {
                    "link": "https://advantage.mandiant.com/reports/REPORT_ID",
                    "source": "Mandiant",
                    "title": "Report Title"
              }
            ],
            "stixid": "threat-actor--u-u-i-d",
            "tags": [
                "Example"
            ],
            "targets": [
              "Example Target"
            ],
            "updateddate": "2022-10-25T05:50:34.000Z"
        }
    }
}
```

#### Human Readable Output

>### Results
>|aliases|description|firstseenbysource|lastseenbysource|name|primarymotivation|publications|stixid|tags|targets|updateddate|
>|--|---|---|---|---|---|---|---|---|---|---|
>| SOMEACTOR | Description of ACTOR goes here | 2011-01-29T00:00:00.000Z | 2015-03-12T00:00:00.000Z | ACTOR: [ACTOR](#/indicator/0000) | MOTIVATION | {'source': 'Mandiant', 'title': 'Report Title', 'link': 'https:<span>//</span>advantage.mandiant.com/reports/REPORT_ID'} | threat-actor--7u-u-i-d | Example | Example Target | 2022-10-25T05:50:34.000Z |


### get-malware
***
Get Mandiant Malware Family


#### Base Command

`get-malware`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| malware_name | Name of the malware family to look up. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!get-malware malware_name=BADRABBIT```
#### Context Example
```json
{
    "MANDIANTTI": {
        "Malware": {
            "DBot Score": {
                "Indicator": "BADRABBIT",
                "Reliability": "A+ - 3rd party enrichment",
                "Score": 0,
                "Type": "custom",
                "Vendor": "Mandiant"
            },
            "Is Malware Family": true,
            "aliases": [
                "Diskcoder.D (ESET)"
            ],
            "capabilities": [
                {
                    "description": "Capable of detecting or evading Virtual Box",
                    "name": "Anti-VM: VirtualBox"
                },
                {
                    "description": "Capabilities associated with anti-debugging techniques. ",
                    "name": "Anti-debug capabilities"
                },
                {
                    "description": "Capable of calculating hashes using the MD5 message-digest algorithm.",
                    "name": "Calculates MD5 hashes"
                },
                {
                    "description": "Can capture or extract Network Share information.",
                    "name": "Capture Network Share information"
                },
                {
                    "description": "Can capture or extract disk information. ",
                    "name": "Capture disk information"
                },
                {
                    "description": "Can capture or extract the system hostname. ",
                    "name": "Capture hostname"
                },
                {
                    "description": "Can capture or extract network configuration information. ",
                    "name": "Capture network configuration"
                },
                {
                    "description": "Can capture or extract network interface information. ",
                    "name": "Capture network interfaces"
                },
                {
                    "description": "Can capture information about the system OS configuration.",
                    "name": "Capture operating system information"
                },
                {
                    "description": "Can capture or extract token information",
                    "name": "Capture token information"
                },
                {
                    "description": "Can communicate using the Server Message Block (SMB) protocol.",
                    "name": "Communicates using SMB"
                },
                {
                    "description": "Can communicate using the UDP protocol.",
                    "name": "Communicates using UDP"
                },
                {
                    "description": "Capable of connecting via TCP socket. ",
                    "name": "Connect to TCP socket"
                },
                {
                    "description": "Capable of connecting to a named pipe. ",
                    "name": "Connects to a named pipe"
                },
                {
                    "description": "Capable of executing constructing (creating) a mutex.",
                    "name": "Constructs mutex"
                },
                {
                    "description": "Capable of creating a Windows registry key value. ",
                    "name": "Create Windows registry key value"
                },
                {
                    "description": "Capable of creating a named pipe. ",
                    "name": "Create a named pipe"
                },
                {
                    "description": "Capable of creating a service or daemon, or uses APIs associated with service or daemon creation.",
                    "name": "Create a service"
                },
                {
                    "description": "Capable of creating a service or daemon, or uses APIs associated with service or daemon creation.",
                    "name": "Create a service"
                },
                {
                    "description": "Capable of creating a socket. ",
                    "name": "Create a socket"
                },
                {
                    "description": "Can create (write) files on a victim system. Contrast with the ability to download files to the victim system.",
                    "name": "Create files"
                },
                {
                    "description": "Capable of creating a thread. ",
                    "name": "Create thread"
                },
                {
                    "description": "Capable of creating a process, or uses APIs associated with creating a process.",
                    "name": "Creates processes"
                },
                {
                    "description": "Capable of decoding Base64 data. May refer to decoding used for data, files, or as part of network communications.",
                    "name": "Decodes Base64"
                },
                {
                    "description": "Capable of deleting a service or daemon.",
                    "name": "Delete a service"
                },
                {
                    "description": "Can delete files on a victim system (normal delete, does not include secure deletion with overwriting).",
                    "name": "Delete files"
                },
                {
                    "description": "Capable of encoding data using Base64. May refer to encoding used for data or files.",
                    "name": "Encodes using Base64"
                },
                {
                    "description": "Can encrypt or decrypt files on a victim system.",
                    "name": "Encrypt or decrypt files"
                },
                {
                    "description": "Can encrypt data using the AES encryption algorithm. May refer to encryption used for data or files.",
                    "name": "Encrypts data with AES"
                },
                {
                    "description": "Capable of encoding data using XOR.",
                    "name": "Encrypts data with XOR"
                },
                {
                    "description": "Can find files on a victim system based on some criteria (e.g., file name, extension, last modified date).",
                    "name": "Find files"
                },
                {
                    "description": "Capable of getting or retrieving the common file path. ",
                    "name": "Gets common file path"
                },
                {
                    "description": "Capable of killing a thread. ",
                    "name": "Kill thread"
                },
                {
                    "description": "Capable of listing file sizes on a victim system.",
                    "name": "List file sizes"
                },
                {
                    "description": "Capable of listing running processes.",
                    "name": "Lists processes"
                },
                {
                    "description": "Capable of listing running processes.",
                    "name": "Lists processes"
                },
                {
                    "description": "Can load data from a PE resource. ",
                    "name": "Loads data from a PE resource"
                },
                {
                    "description": "Capable of modifying process privileges. ",
                    "name": "Modify process privileges"
                },
                {
                    "description": "Capable of opening Windows registry keys. ",
                    "name": "Open Windows registry key"
                },
                {
                    "description": "Capabilities associated with pseudorandom number generation (PRNG). \"Parent\" aspect used to contain specific sub-aspects.",
                    "name": "Psuedo random number generation capabilities"
                },
                {
                    "description": "Capable of querying Windows registry key values. ",
                    "name": "Query Windows registry key values"
                },
                {
                    "description": "Threat actor methodologies associated with querying service information.",
                    "name": "Query service information"
                },
                {
                    "description": "Capable of reading a file through a named pipe. ",
                    "name": "Read a file through a named pipe"
                },
                {
                    "description": "Can read files on a victim system.",
                    "name": "Read files"
                },
                {
                    "description": "Capable of receiving data.",
                    "name": "Receive data"
                },
                {
                    "description": "Capable of resuming a thread.",
                    "name": "Resume thread"
                },
                {
                    "description": "Capable of sending data. ",
                    "name": "Send data"
                },
                {
                    "description": "Capable of shutting down the operating system / host.",
                    "name": "Shuts down the system"
                },
                {
                    "description": "Capable of starting a service or daemon.",
                    "name": "Start a service"
                },
                {
                    "description": "Capable of killing a running process.",
                    "name": "Terminates processes"
                }
            ],
            "description": "BADRABBIT is ransomware written in C/C++ that performs file and disk encryption. Disk encryption is facilitated using an embedded DiskCryptor driver. BADRABBIT can also employ an embedded MIMIKATZ payload to harvest credentials and perform lateral movement. An attacker can also specify credentials and systems to target for lateral movement via command line arguments. BADRABBIT's code borrows from the well-known ETERNALPETYA disruption tool including techniques for system enumeration and lateral movement. BADRABBIT is distributed primarily through strategic web compromises hosting the BACKSWING reconnaissance tool.",
            "lastseenbysource": "2022-10-25T02:11:39.000Z",
            "mandiantdetections": [
                "Trojan/Win32.ransom.pme (Palo Alto Networks)",
                "(http_inspect) unknown Content-Encoding used (Cisco Firepower)",
                "ET CURRENT_EVENTS Possible BadRabbit Driveby Download M2 Oct 24 2017 (ET OPEN)",
                "ET TROJAN Mimikatz x86 Executable Download Over HTTP (ET OPEN)",
                "Benign.LIVE.DTI.URL (Trellix)",
                "ET TROJAN Mimikatz x64 Executable Download Over HTTP (ET OPEN)",
                "Backswing JavaScript Detection (Palo Alto Networks)",
                "FILE-EXECUTABLE Portable Executable binary file magic detected (Cisco Firepower)",
                "Suspicious.URL (Trellix)",
                "Ransomware.BadRabbit",
                "FE_Worm_Win_BADRABBIT_1",
                "BADRABBIT (Trellix)",
                "FE_PUP_Win_DISKCRYPTOR_1 (Trellix)",
                "Win.Dropper.Diskcoder-6355411-0 (ClamAV)",
                "Trojan.Win64.BADRABBIT.CredentialDumper.1 (Trellix)",
                "FE_Trojan_Win_BADRABBIT_1 (Trellix)",
                "FE_Trojan_Win_BADRABBIT_1.FEC2 (Trellix)",
                "Trojan.JS.Generic (Trellix)",
                "Win.Ransomware.Agent-6331177-0 (ClamAV)",
                "FE_Dropper_Win_BADRABBIT_1",
                "ET SHELLCODE Possible TCP x86 JMP to CALL Shellcode Detected (ET OPEN)",
                "Malware.Binary (Trellix)",
                "ET POLICY exe download via HTTP - Informational (ET OPEN)",
                "Malware.Binary.url (Trellix)",
                "ET INFO SUSPICIOUS Dotted Quad Host MZ Response (ET OPEN)",
                "ET POLICY PE EXE or DLL Windows file download HTTP (ET OPEN)",
                "FE_CredTheft_Win64_BADRABBIT_1",
                "Tool.Win.DISKCRYPTOR (Trellix)",
                "ET INFO Executable Download from dotted-quad Host (ET OPEN)",
                "Trojan.BADRABBIT.CredentialDumper (Trellix)",
                "ET CURRENT_EVENTS Possible BadRabbit Driveby Download M1 Oct 24 2017 (ET OPEN)",
                "ET INFO Packed Executable Download (ET OPEN)",
                "RansomDownloader.BadRabbit",
                "FE_Trojan_Win_BADRABBIT_1",
                "Win.Ransomware.Diskcoder-6355410-0 (ClamAV)",
                "FE_Trojan_Win_BADRABBIT_3",
                "BADRABBIT RANSOMWARE (FAMILY)",
                "FE_Trojan_Win_BADRABBIT_2"
            ],
            "name": {},
            "operatingsystemrefs": [
                "Windows"
            ],
            "publications": [
                {
                    "link": "https://advantage.mandiant.com/reports/20-00017707",
                    "source": "Mandiant",
                    "title": "Country Profile: Ukraine (2020)"
                },
                {
                    "link": "https://advantage.mandiant.com/reports/17-00011954",
                    "source": "Mandiant",
                    "title": "BACKSWING - Pulling a BADRABBIT Out of a Hat"
                },
                {
                    "link": "https://advantage.mandiant.com/reports/22-00004460",
                    "source": "Mandiant",
                    "title": "Summary of Russian Disruptive and Destructive Cyber Attacks, Ukraine 2022 and Prior"
                },
                {
                    "link": "https://advantage.mandiant.com/reports/17-00011900",
                    "source": "Mandiant",
                    "title": "Ukrainian Critical Infrastructure and Russian Media Affected by BADRABBIT Ransomware Campaign"
                },
                {
                    "link": "https://advantage.mandiant.com/reports/21-00018084",
                    "source": "Mandiant",
                    "title": "Overview of State-Sponsored Threat Activity Pertinent to OT Asset Owners"
                },
                {
                    "link": "https://advantage.mandiant.com/reports/17-00012004",
                    "source": "Mandiant",
                    "title": "BADRABBIT Malware Profile"
                }
            ],
            "roles": [
                "Ransomware"
            ],
            "stixid": "malware--fa564497-7506-5c24-aa39-50666a674a6e",
            "tags": [
                "Chemicals & Materials",
                "Construction & Engineering",
                "Financial Services",
                "Healthcare",
                "Legal & Professional Services",
                "Manufacturing",
                "Technology",
                "Telecommunications"
            ],
            "updateddate": "2022-10-25T02:11:39.000Z",
            "yara": [
                [
                    "FE_Trojan_Win_BADRABBIT_3",
                    "signature--895e16bb-b89d-5d99-a8af-f7862201f7e9"
                ],
                [
                    "FE_Trojan_Win_BADRABBIT_1",
                    "signature--3d2a7f82-46b0-5a8c-aa2b-01236ba1dc56"
                ],
                [
                    "FE_CredTheft_Win64_BADRABBIT_1",
                    "signature--649beb24-f8d9-5033-a88d-17c8c61701ac"
                ],
                [
                    "FE_Worm_Win_BADRABBIT_1",
                    "signature--85d2ab3f-bf9c-559c-b0e9-c57af605ee45"
                ],
                [
                    "FE_Trojan_Win_BADRABBIT_2",
                    "signature--7f598cc9-b477-59e4-b0c7-e736c7749b49"
                ],
                [
                    "FE_Dropper_Win_BADRABBIT_1",
                    "signature--4e75ec76-d1a5-5052-9224-493af042469d"
                ]
            ]
        }
    }
}
```

#### Human Readable Output

>### Results
>|DBot Score|Is Malware Family|aliases|capabilities|description|lastseenbysource|mandiantdetections|name|operatingsystemrefs|publications|roles|stixid|tags|updateddate|yara|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Indicator: BADRABBIT<br/>Type: custom<br/>Vendor: Mandiant<br/>Score: 0<br/>Reliability: A+ - 3rd party enrichment | true | Diskcoder.D (ESET) | {'name': 'Anti-VM: VirtualBox', 'description': 'Capable of detecting or evading Virtual Box'},<br/>{'name': 'Anti-debug capabilities', 'description': 'Capabilities associated with anti-debugging techniques. '},<br/>{'name': 'Calculates MD5 hashes', 'description': 'Capable of calculating hashes using the MD5 message-digest algorithm.'},<br/>{'name': 'Capture Network Share information', 'description': 'Can capture or extract Network Share information.'},<br/>{'name': 'Capture disk information', 'description': 'Can capture or extract disk information. '},<br/>{'name': 'Capture hostname', 'description': 'Can capture or extract the system hostname. '},<br/>{'name': 'Capture network configuration', 'description': 'Can capture or extract network configuration information. '},<br/>{'name': 'Capture network interfaces', 'description': 'Can capture or extract network interface information. '},<br/>{'name': 'Capture operating system information', 'description': 'Can capture information about the system OS configuration.'},<br/>{'name': 'Capture token information', 'description': 'Can capture or extract token information'},<br/>{'name': 'Communicates using SMB', 'description': 'Can communicate using the Server Message Block (SMB) protocol.'},<br/>{'name': 'Communicates using UDP', 'description': 'Can communicate using the UDP protocol.'},<br/>{'name': 'Connect to TCP socket', 'description': 'Capable of connecting via TCP socket. '},<br/>{'name': 'Connects to a named pipe', 'description': 'Capable of connecting to a named pipe. '},<br/>{'name': 'Constructs mutex', 'description': 'Capable of executing constructing (creating) a mutex.'},<br/>{'name': 'Create Windows registry key value', 'description': 'Capable of creating a Windows registry key value. '},<br/>{'name': 'Create a named pipe', 'description': 'Capable of creating a named pipe. '},<br/>{'name': 'Create a service', 'description': 'Capable of creating a service or daemon, or uses APIs associated with service or daemon creation.'},<br/>{'name': 'Create a service', 'description': 'Capable of creating a service or daemon, or uses APIs associated with service or daemon creation.'},<br/>{'name': 'Create a socket', 'description': 'Capable of creating a socket. '},<br/>{'name': 'Create files', 'description': 'Can create (write) files on a victim system. Contrast with the ability to download files to the victim system.'},<br/>{'name': 'Create thread', 'description': 'Capable of creating a thread. '},<br/>{'name': 'Creates processes', 'description': 'Capable of creating a process, or uses APIs associated with creating a process.'},<br/>{'name': 'Decodes Base64', 'description': 'Capable of decoding Base64 data. May refer to decoding used for data, files, or as part of network communications.'},<br/>{'name': 'Delete a service', 'description': 'Capable of deleting a service or daemon.'},<br/>{'name': 'Delete files', 'description': 'Can delete files on a victim system (normal delete, does not include secure deletion with overwriting).'},<br/>{'name': 'Encodes using Base64', 'description': 'Capable of encoding data using Base64. May refer to encoding used for data or files.'},<br/>{'name': 'Encrypt or decrypt files', 'description': 'Can encrypt or decrypt files on a victim system.'},<br/>{'name': 'Encrypts data with AES', 'description': 'Can encrypt data using the AES encryption algorithm. May refer to encryption used for data or files.'},<br/>{'name': 'Encrypts data with XOR', 'description': 'Capable of encoding data using XOR.'},<br/>{'name': 'Find files', 'description': 'Can find files on a victim system based on some criteria (e.g., file name, extension, last modified date).'},<br/>{'name': 'Gets common file path', 'description': 'Capable of getting or retrieving the common file path. '},<br/>{'name': 'Kill thread', 'description': 'Capable of killing a thread. '},<br/>{'name': 'List file sizes', 'description': 'Capable of listing file sizes on a victim system.'},<br/>{'name': 'Lists processes', 'description': 'Capable of listing running processes.'},<br/>{'name': 'Lists processes', 'description': 'Capable of listing running processes.'},<br/>{'name': 'Loads data from a PE resource', 'description': 'Can load data from a PE resource. '},<br/>{'name': 'Modify process privileges', 'description': 'Capable of modifying process privileges. '},<br/>{'name': 'Open Windows registry key', 'description': 'Capable of opening Windows registry keys. '},<br/>{'name': 'Psuedo random number generation capabilities', 'description': 'Capabilities associated with pseudorandom number generation (PRNG). "Parent" aspect used to contain specific sub-aspects.'},<br/>{'name': 'Query Windows registry key values', 'description': 'Capable of querying Windows registry key values. '},<br/>{'name': 'Query service information', 'description': 'Threat actor methodologies associated with querying service information.'},<br/>{'name': 'Read a file through a named pipe', 'description': 'Capable of reading a file through a named pipe. '},<br/>{'name': 'Read files', 'description': 'Can read files on a victim system.'},<br/>{'name': 'Receive data', 'description': 'Capable of receiving data.'},<br/>{'name': 'Resume thread', 'description': 'Capable of resuming a thread.'},<br/>{'name': 'Send data', 'description': 'Capable of sending data. '},<br/>{'name': 'Shuts down the system', 'description': 'Capable of shutting down the operating system / host.'},<br/>{'name': 'Start a service', 'description': 'Capable of starting a service or daemon.'},<br/>{'name': 'Terminates processes', 'description': 'Capable of killing a running process.'} | BADRABBIT is ransomware written in C/C++ that performs file and disk encryption. Disk encryption is facilitated using an embedded DiskCryptor driver. BADRABBIT can also employ an embedded MIMIKATZ payload to harvest credentials and perform lateral movement. An attacker can also specify credentials and systems to target for lateral movement via command line arguments. BADRABBIT's code borrows from the well-known ETERNALPETYA disruption tool including techniques for system enumeration and lateral movement. BADRABBIT is distributed primarily through strategic web compromises hosting the BACKSWING reconnaissance tool. | 2022-10-25T02:11:39.000Z | Trojan/Win32.ransom.pme (Palo Alto Networks),<br/>(http_inspect) unknown Content-Encoding used (Cisco Firepower),<br/>ET CURRENT_EVENTS Possible BadRabbit Driveby Download M2 Oct 24 2017 (ET OPEN),<br/>ET TROJAN Mimikatz x86 Executable Download Over HTTP (ET OPEN),<br/>Benign.LIVE.DTI.URL (Trellix),<br/>ET TROJAN Mimikatz x64 Executable Download Over HTTP (ET OPEN),<br/>Backswing JavaScript Detection (Palo Alto Networks),<br/>FILE-EXECUTABLE Portable Executable binary file magic detected (Cisco Firepower),<br/>Suspicious.URL (Trellix),<br/>Ransomware.BadRabbit,<br/>FE_Worm_Win_BADRABBIT_1,<br/>BADRABBIT (Trellix),<br/>FE_PUP_Win_DISKCRYPTOR_1 (Trellix),<br/>Win.Dropper.Diskcoder-6355411-0 (ClamAV),<br/>Trojan.Win64.BADRABBIT.CredentialDumper.1 (Trellix),<br/>FE_Trojan_Win_BADRABBIT_1 (Trellix),<br/>FE_Trojan_Win_BADRABBIT_1.FEC2 (Trellix),<br/>Trojan.JS.Generic (Trellix),<br/>Win.Ransomware.Agent-6331177-0 (ClamAV),<br/>FE_Dropper_Win_BADRABBIT_1,<br/>ET SHELLCODE Possible TCP x86 JMP to CALL Shellcode Detected (ET OPEN),<br/>Malware.Binary (Trellix),<br/>ET POLICY exe download via HTTP - Informational (ET OPEN),<br/>Malware.Binary.url (Trellix),<br/>ET INFO SUSPICIOUS Dotted Quad Host MZ Response (ET OPEN),<br/>ET POLICY PE EXE or DLL Windows file download HTTP (ET OPEN),<br/>FE_CredTheft_Win64_BADRABBIT_1,<br/>Tool.Win.DISKCRYPTOR (Trellix),<br/>ET INFO Executable Download from dotted-quad Host (ET OPEN),<br/>Trojan.BADRABBIT.CredentialDumper (Trellix),<br/>ET CURRENT_EVENTS Possible BadRabbit Driveby Download M1 Oct 24 2017 (ET OPEN),<br/>ET INFO Packed Executable Download (ET OPEN),<br/>RansomDownloader.BadRabbit,<br/>FE_Trojan_Win_BADRABBIT_1,<br/>Win.Ransomware.Diskcoder-6355410-0 (ClamAV),<br/>FE_Trojan_Win_BADRABBIT_3,<br/>BADRABBIT RANSOMWARE (FAMILY),<br/>FE_Trojan_Win_BADRABBIT_2 |  | Windows | {'source': 'Mandiant', 'title': 'Country Profile: Ukraine (2020)', 'link': 'https:<span>//</span>advantage.mandiant.com/reports/20-00017707'},<br/>{'source': 'Mandiant', 'title': 'BACKSWING - Pulling a BADRABBIT Out of a Hat', 'link': 'https:<span>//</span>advantage.mandiant.com/reports/17-00011954'},<br/>{'source': 'Mandiant', 'title': 'Summary of Russian Disruptive and Destructive Cyber Attacks, Ukraine 2022 and Prior', 'link': 'https:<span>//</span>advantage.mandiant.com/reports/22-00004460'},<br/>{'source': 'Mandiant', 'title': 'Ukrainian Critical Infrastructure and Russian Media Affected by BADRABBIT Ransomware Campaign', 'link': 'https:<span>//</span>advantage.mandiant.com/reports/17-00011900'},<br/>{'source': 'Mandiant', 'title': 'Overview of State-Sponsored Threat Activity Pertinent to OT Asset Owners', 'link': 'https:<span>//</span>advantage.mandiant.com/reports/21-00018084'},<br/>{'source': 'Mandiant', 'title': 'BADRABBIT Malware Profile', 'link': 'https:<span>//</span>advantage.mandiant.com/reports/17-00012004'} | Ransomware | malware--fa564497-7506-5c24-aa39-50666a674a6e | Chemicals & Materials,<br/>Construction & Engineering,<br/>Financial Services,<br/>Healthcare,<br/>Legal & Professional Services,<br/>Manufacturing,<br/>Technology,<br/>Telecommunications | 2022-10-25T02:11:39.000Z | ('FE_Trojan_Win_BADRABBIT_3', 'signature--895e16bb-b89d-5d99-a8af-f7862201f7e9'),<br/>('FE_Trojan_Win_BADRABBIT_1', 'signature--3d2a7f82-46b0-5a8c-aa2b-01236ba1dc56'),<br/>('FE_CredTheft_Win64_BADRABBIT_1', 'signature--649beb24-f8d9-5033-a88d-17c8c61701ac'),<br/>('FE_Worm_Win_BADRABBIT_1', 'signature--85d2ab3f-bf9c-559c-b0e9-c57af605ee45'),<br/>('FE_Trojan_Win_BADRABBIT_2', 'signature--7f598cc9-b477-59e4-b0c7-e736c7749b49'),<br/>('FE_Dropper_Win_BADRABBIT_1', 'signature--4e75ec76-d1a5-5052-9224-493af042469d') |


### file
***
 


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | List of files. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!file file=fe09cf6d3a358305f8c2f687b6f6da02```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "fe09cf6d3a358305f8c2f687b6f6da02",
        "Score": 3,
        "Type": "file",
        "Vendor": "Mandiant Advantage Threat Intelligence"
    },
    "File": {
        "MD5": "fe09cf6d3a358305f8c2f687b6f6da02",
        "Malicious": {
            "Description": null,
            "Vendor": "Mandiant Advantage Threat Intelligence"
        },
        "SHA1": "30d64987a6903a9995ea74fe268689811b14b81b",
        "SHA256": "af95c55f3d09ee6c691afc248e8d4a9c07d4f304449c6f609bf9c4e4c202b070"
    },
    "file": {
        "associated_hashes": [
            {
                "id": "md5--e54a4f18-5d4d-56cd-8a41-a96938e9779f",
                "type": "md5",
                "value": "fe09cf6d3a358305f8c2f687b6f6da02"
            },
            {
                "id": "sha1--ad083435-4612-5b45-811a-157a77f65bdf",
                "type": "sha1",
                "value": "30d64987a6903a9995ea74fe268689811b14b81b"
            },
            {
                "id": "sha256--c17aca6a-7a35-5265-93f6-f6b5537cef7e",
                "type": "sha256",
                "value": "af95c55f3d09ee6c691afc248e8d4a9c07d4f304449c6f609bf9c4e4c202b070"
            }
        ],
        "attributed_associations": [
            {
                "id": "malware--ac3b8a90-57ad-5535-a672-0215cfa44d19",
                "name": "OXEEYE",
                "type": "malware"
            }
        ],
        "first_seen": "2022-01-13T23:01:27.000Z",
        "id": "md5--e54a4f18-5d4d-56cd-8a41-a96938e9779f",
        "is_exclusive": false,
        "is_publishable": true,
        "last_seen": "2022-08-12T22:05:41.000Z",
        "last_updated": "2022-10-19T00:37:24.612Z",
        "misp": {
            "akamai": false,
            "alexa": false,
            "alexa_1M": false,
            "amazon-aws": false,
            "apple": false,
            "automated-malware-analysis": false,
            "bank-website": false,
            "cisco_1M": false,
            "cisco_top1000": false,
            "cisco_top10k": false,
            "cisco_top20k": false,
            "cisco_top5k": false,
            "cloudflare": false,
            "common-contact-emails": false,
            "common-ioc-false-positive": false,
            "covid": false,
            "covid-19-cyber-threat-coalition-whitelist": false,
            "covid-19-krassi-whitelist": false,
            "crl-hostname": false,
            "crl-ip": false,
            "dax30": false,
            "disposable-email": false,
            "dynamic-dns": false,
            "eicar.com": false,
            "empty-hashes": false,
            "fastly": false,
            "google": false,
            "google-gcp": false,
            "google-gmail-sending-ips": false,
            "googlebot": false,
            "ipv6-linklocal": false,
            "majestic_million": false,
            "majestic_million_1M": false,
            "microsoft": false,
            "microsoft-attack-simulator": false,
            "microsoft-azure": false,
            "microsoft-azure-china": false,
            "microsoft-azure-germany": false,
            "microsoft-azure-us-gov": false,
            "microsoft-office365": false,
            "microsoft-office365-cn": false,
            "microsoft-office365-ip": false,
            "microsoft-win10-connection-endpoints": false,
            "moz-top500": false,
            "mozilla-CA": false,
            "mozilla-IntermediateCA": false,
            "multicast": false,
            "nioc-filehash": false,
            "ovh-cluster": false,
            "phone_numbers": false,
            "public-dns-hostname": false,
            "public-dns-v4": false,
            "public-dns-v6": false,
            "rfc1918": false,
            "rfc3849": false,
            "rfc5735": false,
            "rfc6598": false,
            "rfc6761": false,
            "second-level-tlds": false,
            "security-provider-blogpost": false,
            "sinkholes": false,
            "smtp-receiving-ips": false,
            "smtp-sending-ips": false,
            "stackpath": false,
            "tenable-cloud-ipv4": false,
            "tenable-cloud-ipv6": false,
            "ti-falsepositives": false,
            "tlds": false,
            "tranco": false,
            "tranco10k": false,
            "university_domains": false,
            "url-shortener": false,
            "vpn-ipv4": false,
            "vpn-ipv6": false,
            "whats-my-ip": false,
            "wikimedia": false
        },
        "mscore": 100,
        "sources": [
            {
                "category": [],
                "first_seen": "2022-01-13T23:01:27.000+0000",
                "last_seen": "2022-08-12T22:05:41.000+0000",
                "osint": false,
                "source_name": "Mandiant"
            }
        ],
        "type": "md5",
        "value": {
            "af95c55f3d09ee6c691afc248e8d4a9c07d4f304449c6f609bf9c4e4c202b070": "[af95c55f3d09ee6c691afc248e8d4a9c07d4f304449c6f609bf9c4e4c202b070](#/indicator/2609)"
        }
    }
}
```

#### Human Readable Output

>### Results
>|associated_hashes|attributed_associations|first_seen|id|is_exclusive|is_publishable|last_seen|last_updated|misp|mscore|sources|type|value|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| {'id': 'md5--e54a4f18-5d4d-56cd-8a41-a96938e9779f', 'type': 'md5', 'value': 'fe09cf6d3a358305f8c2f687b6f6da02'},<br/>{'id': 'sha1--ad083435-4612-5b45-811a-157a77f65bdf', 'type': 'sha1', 'value': '30d64987a6903a9995ea74fe268689811b14b81b'},<br/>{'id': 'sha256--c17aca6a-7a35-5265-93f6-f6b5537cef7e', 'type': 'sha256', 'value': 'af95c55f3d09ee6c691afc248e8d4a9c07d4f304449c6f609bf9c4e4c202b070'} | {'id': 'malware--ac3b8a90-57ad-5535-a672-0215cfa44d19', 'name': 'OXEEYE', 'type': 'malware'} | 2022-01-13T23:01:27.000Z | md5--e54a4f18-5d4d-56cd-8a41-a96938e9779f | false | true | 2022-08-12T22:05:41.000Z | 2022-10-19T00:37:24.612Z | akamai: false<br/>alexa: false<br/>alexa_1M: false<br/>amazon-aws: false<br/>apple: false<br/>automated-malware-analysis: false<br/>bank-website: false<br/>cisco_1M: false<br/>cisco_top1000: false<br/>cisco_top10k: false<br/>cisco_top20k: false<br/>cisco_top5k: false<br/>cloudflare: false<br/>common-contact-emails: false<br/>common-ioc-false-positive: false<br/>covid: false<br/>covid-19-cyber-threat-coalition-whitelist: false<br/>covid-19-krassi-whitelist: false<br/>crl-hostname: false<br/>crl-ip: false<br/>dax30: false<br/>disposable-email: false<br/>dynamic-dns: false<br/>eicar.com: false<br/>empty-hashes: false<br/>fastly: false<br/>google: false<br/>google-gcp: false<br/>google-gmail-sending-ips: false<br/>googlebot: false<br/>ipv6-linklocal: false<br/>majestic_million: false<br/>majestic_million_1M: false<br/>microsoft: false<br/>microsoft-attack-simulator: false<br/>microsoft-azure: false<br/>microsoft-azure-china: false<br/>microsoft-azure-germany: false<br/>microsoft-azure-us-gov: false<br/>microsoft-office365: false<br/>microsoft-office365-cn: false<br/>microsoft-office365-ip: false<br/>microsoft-win10-connection-endpoints: false<br/>moz-top500: false<br/>mozilla-CA: false<br/>mozilla-IntermediateCA: false<br/>multicast: false<br/>nioc-filehash: false<br/>ovh-cluster: false<br/>phone_numbers: false<br/>public-dns-hostname: false<br/>public-dns-v4: false<br/>public-dns-v6: false<br/>rfc1918: false<br/>rfc3849: false<br/>rfc5735: false<br/>rfc6598: false<br/>rfc6761: false<br/>second-level-tlds: false<br/>security-provider-blogpost: false<br/>sinkholes: false<br/>smtp-receiving-ips: false<br/>smtp-sending-ips: false<br/>stackpath: false<br/>tenable-cloud-ipv4: false<br/>tenable-cloud-ipv6: false<br/>ti-falsepositives: false<br/>tlds: false<br/>tranco: false<br/>tranco10k: false<br/>university_domains: false<br/>url-shortener: false<br/>vpn-ipv4: false<br/>vpn-ipv6: false<br/>whats-my-ip: false<br/>wikimedia: false | 100 | {'first_seen': '2022-01-13T23:01:27.000+0000', 'last_seen': '2022-08-12T22:05:41.000+0000', 'osint': False, 'category': [], 'source_name': 'Mandiant'} | md5 | af95c55f3d09ee6c691afc248e8d4a9c07d4f304449c6f609bf9c4e4c202b070: [af95c55f3d09ee6c691afc248e8d4a9c07d4f304449c6f609bf9c4e4c202b070](#/indicator/2609) |


### ip
***
 


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | List of IPs. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!ip ip=8.8.8.8```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "8.8.8.8",
        "Score": 0,
        "Type": "ip",
        "Vendor": "Mandiant Advantage Threat Intelligence"
    },
    "IP": {
        "Address": "8.8.8.8"
    },
    "ip": {
        "first_seen": "2014-09-01T21:39:51.000Z",
        "id": "ipv4--ae71927b-78e2-5659-8576-af0dc232b3e9",
        "is_publishable": true,
        "last_seen": "2022-10-25T15:01:21.000Z",
        "last_updated": "2022-10-25T15:01:24.711Z",
        "misp": {
            "akamai": false,
            "alexa": false,
            "alexa_1M": false,
            "amazon-aws": false,
            "apple": false,
            "automated-malware-analysis": false,
            "bank-website": false,
            "cisco_1M": false,
            "cisco_top1000": false,
            "cisco_top10k": false,
            "cisco_top20k": false,
            "cisco_top5k": false,
            "cloudflare": false,
            "common-contact-emails": false,
            "common-ioc-false-positive": false,
            "covid": false,
            "covid-19-cyber-threat-coalition-whitelist": false,
            "covid-19-krassi-whitelist": false,
            "crl-hostname": false,
            "crl-ip": false,
            "dax30": false,
            "disposable-email": false,
            "dynamic-dns": false,
            "eicar.com": false,
            "empty-hashes": false,
            "fastly": false,
            "google": false,
            "google-gcp": false,
            "google-gmail-sending-ips": false,
            "googlebot": false,
            "ipv6-linklocal": false,
            "majestic_million": false,
            "majestic_million_1M": false,
            "microsoft": false,
            "microsoft-attack-simulator": false,
            "microsoft-azure": false,
            "microsoft-azure-china": false,
            "microsoft-azure-germany": false,
            "microsoft-azure-us-gov": false,
            "microsoft-office365": false,
            "microsoft-office365-cn": false,
            "microsoft-office365-ip": false,
            "microsoft-win10-connection-endpoints": false,
            "moz-top500": false,
            "mozilla-CA": false,
            "mozilla-IntermediateCA": false,
            "multicast": false,
            "nioc-filehash": false,
            "ovh-cluster": false,
            "phone_numbers": false,
            "public-dns-hostname": false,
            "public-dns-v4": true,
            "public-dns-v6": false,
            "rfc1918": false,
            "rfc3849": false,
            "rfc5735": false,
            "rfc6598": false,
            "rfc6761": false,
            "second-level-tlds": false,
            "security-provider-blogpost": false,
            "sinkholes": false,
            "smtp-receiving-ips": false,
            "smtp-sending-ips": false,
            "stackpath": false,
            "tenable-cloud-ipv4": false,
            "tenable-cloud-ipv6": false,
            "ti-falsepositives": false,
            "tlds": false,
            "tranco": false,
            "tranco10k": false,
            "university_domains": false,
            "url-shortener": false,
            "vpn-ipv4": false,
            "vpn-ipv6": false,
            "whats-my-ip": false,
            "wikimedia": false
        },
        "mscore": 0,
        "sources": [
            {
                "category": [],
                "first_seen": "2022-08-14T03:51:28.491+0000",
                "last_seen": "2022-10-22T00:58:18.588+0000",
                "osint": false,
                "source_name": "Mandiant"
            },
            {
                "category": [],
                "first_seen": "2020-11-27T23:01:13.253+0000",
                "last_seen": "2021-05-17T10:30:08.060+0000",
                "osint": false,
                "source_name": "Mandiant"
            },
            {
                "category": [
                    "phishing"
                ],
                "first_seen": "2020-11-26T23:00:17.199+0000",
                "last_seen": "2020-11-27T23:00:19.242+0000",
                "osint": true,
                "source_name": "phishtank"
            },
            {
                "category": [],
                "first_seen": "2022-09-06T15:17:26.914+0000",
                "last_seen": "2022-10-18T19:21:24.788+0000",
                "osint": false,
                "source_name": "Mandiant"
            },
            {
                "category": [],
                "first_seen": "2020-11-09T10:43:27.120+0000",
                "last_seen": "2022-10-25T00:02:26.653+0000",
                "osint": false,
                "source_name": "Mandiant"
            },
            {
                "category": [],
                "first_seen": "2020-11-08T22:00:57.000+0000",
                "last_seen": "2021-05-26T08:45:36.000+0000",
                "osint": false,
                "source_name": "Mandiant"
            },
            {
                "category": [],
                "first_seen": "2021-05-16T00:25:00.172+0000",
                "last_seen": "2021-06-06T10:57:02.904+0000",
                "osint": false,
                "source_name": "Mandiant"
            },
            {
                "category": [],
                "first_seen": "2014-09-01T21:39:51.000+0000",
                "last_seen": "2021-11-23T16:52:56.000+0000",
                "osint": false,
                "source_name": "Mandiant"
            },
            {
                "category": [],
                "first_seen": "2021-03-24T23:00:56.877+0000",
                "last_seen": "2021-03-26T23:09:31.740+0000",
                "osint": false,
                "source_name": "Mandiant"
            },
            {
                "category": [],
                "first_seen": "2016-06-09T05:49:30.000+0000",
                "last_seen": "2022-05-23T12:21:48.000+0000",
                "osint": false,
                "source_name": "Mandiant"
            },
            {
                "category": [
                    "phishing",
                    "malware"
                ],
                "first_seen": "2021-01-08T22:10:01.519+0000",
                "last_seen": "2022-08-24T00:10:02.631+0000",
                "osint": true,
                "source_name": "phishstats"
            }
        ],
        "type": "ipv4",
        "value": {
            "8.8.8.8": "[8.8.8.8](#/indicator/2605)"
        }
    }
}
```

#### Human Readable Output

>### Results
>|first_seen|id|is_publishable|last_seen|last_updated|misp|mscore|sources|type|value|
>|---|---|---|---|---|---|---|---|---|---|
>| 2014-09-01T21:39:51.000Z | ipv4--ae71927b-78e2-5659-8576-af0dc232b3e9 | true | 2022-10-25T15:01:21.000Z | 2022-10-25T15:01:24.711Z | akamai: false<br/>alexa: false<br/>alexa_1M: false<br/>amazon-aws: false<br/>apple: false<br/>automated-malware-analysis: false<br/>bank-website: false<br/>cisco_1M: false<br/>cisco_top1000: false<br/>cisco_top10k: false<br/>cisco_top20k: false<br/>cisco_top5k: false<br/>cloudflare: false<br/>common-contact-emails: false<br/>common-ioc-false-positive: false<br/>covid: false<br/>covid-19-cyber-threat-coalition-whitelist: false<br/>covid-19-krassi-whitelist: false<br/>crl-hostname: false<br/>crl-ip: false<br/>dax30: false<br/>disposable-email: false<br/>dynamic-dns: false<br/>eicar.com: false<br/>empty-hashes: false<br/>fastly: false<br/>google: false<br/>google-gcp: false<br/>google-gmail-sending-ips: false<br/>googlebot: false<br/>ipv6-linklocal: false<br/>majestic_million: false<br/>majestic_million_1M: false<br/>microsoft: false<br/>microsoft-attack-simulator: false<br/>microsoft-azure: false<br/>microsoft-azure-china: false<br/>microsoft-azure-germany: false<br/>microsoft-azure-us-gov: false<br/>microsoft-office365: false<br/>microsoft-office365-cn: false<br/>microsoft-office365-ip: false<br/>microsoft-win10-connection-endpoints: false<br/>moz-top500: false<br/>mozilla-CA: false<br/>mozilla-IntermediateCA: false<br/>multicast: false<br/>nioc-filehash: false<br/>ovh-cluster: false<br/>phone_numbers: false<br/>public-dns-hostname: false<br/>public-dns-v4: true<br/>public-dns-v6: false<br/>rfc1918: false<br/>rfc3849: false<br/>rfc5735: false<br/>rfc6598: false<br/>rfc6761: false<br/>second-level-tlds: false<br/>security-provider-blogpost: false<br/>sinkholes: false<br/>smtp-receiving-ips: false<br/>smtp-sending-ips: false<br/>stackpath: false<br/>tenable-cloud-ipv4: false<br/>tenable-cloud-ipv6: false<br/>ti-falsepositives: false<br/>tlds: false<br/>tranco: false<br/>tranco10k: false<br/>university_domains: false<br/>url-shortener: false<br/>vpn-ipv4: false<br/>vpn-ipv6: false<br/>whats-my-ip: false<br/>wikimedia: false | 0 | {'first_seen': '2022-08-14T03:51:28.491+0000', 'last_seen': '2022-10-22T00:58:18.588+0000', 'osint': False, 'category': [], 'source_name': 'Mandiant'},<br/>{'first_seen': '2020-11-27T23:01:13.253+0000', 'last_seen': '2021-05-17T10:30:08.060+0000', 'osint': False, 'category': [], 'source_name': 'Mandiant'},<br/>{'first_seen': '2020-11-26T23:00:17.199+0000', 'last_seen': '2020-11-27T23:00:19.242+0000', 'osint': True, 'category': ['phishing'], 'source_name': 'phishtank'},<br/>{'first_seen': '2022-09-06T15:17:26.914+0000', 'last_seen': '2022-10-18T19:21:24.788+0000', 'osint': False, 'category': [], 'source_name': 'Mandiant'},<br/>{'first_seen': '2020-11-09T10:43:27.120+0000', 'last_seen': '2022-10-25T00:02:26.653+0000', 'osint': False, 'category': [], 'source_name': 'Mandiant'},<br/>{'first_seen': '2020-11-08T22:00:57.000+0000', 'last_seen': '2021-05-26T08:45:36.000+0000', 'osint': False, 'category': [], 'source_name': 'Mandiant'},<br/>{'first_seen': '2021-05-16T00:25:00.172+0000', 'last_seen': '2021-06-06T10:57:02.904+0000', 'osint': False, 'category': [], 'source_name': 'Mandiant'},<br/>{'first_seen': '2014-09-01T21:39:51.000+0000', 'last_seen': '2021-11-23T16:52:56.000+0000', 'osint': False, 'category': [], 'source_name': 'Mandiant'},<br/>{'first_seen': '2021-03-24T23:00:56.877+0000', 'last_seen': '2021-03-26T23:09:31.740+0000', 'osint': False, 'category': [], 'source_name': 'Mandiant'},<br/>{'first_seen': '2016-06-09T05:49:30.000+0000', 'last_seen': '2022-05-23T12:21:48.000+0000', 'osint': False, 'category': [], 'source_name': 'Mandiant'},<br/>{'first_seen': '2021-01-08T22:10:01.519+0000', 'last_seen': '2022-08-24T00:10:02.631+0000', 'osint': True, 'category': ['phishing', 'malware'], 'source_name': 'phishstats'} | ipv4 | 8.8.8.8: [8.8.8.8](#/indicator/2605) |


### url
***
 


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | List of URLs. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!url url=https://google.com```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "https://google.com",
        "Score": 0,
        "Type": "url",
        "Vendor": "Mandiant Advantage Threat Intelligence"
    },
    "URL": {
        "Data": "https://google.com"
    },
    "url": {
        "first_seen": "2021-06-19T09:13:28.000Z",
        "id": "url--431bfcd3-a8a5-5103-9ad7-ac7f05891875",
        "is_publishable": true,
        "last_seen": "2022-10-26T13:58:08.000Z",
        "last_updated": "2022-10-26T13:58:11.126Z",
        "misp": {
            "akamai": false,
            "alexa": true,
            "alexa_1M": true,
            "amazon-aws": false,
            "apple": false,
            "automated-malware-analysis": false,
            "bank-website": false,
            "cisco_1M": true,
            "cisco_top1000": true,
            "cisco_top10k": true,
            "cisco_top20k": true,
            "cisco_top5k": true,
            "cloudflare": false,
            "common-contact-emails": false,
            "common-ioc-false-positive": false,
            "covid": false,
            "covid-19-cyber-threat-coalition-whitelist": false,
            "covid-19-krassi-whitelist": false,
            "crl-hostname": false,
            "crl-ip": false,
            "dax30": false,
            "disposable-email": false,
            "dynamic-dns": false,
            "eicar.com": false,
            "empty-hashes": false,
            "fastly": false,
            "google": true,
            "google-gcp": false,
            "google-gmail-sending-ips": false,
            "googlebot": false,
            "ipv6-linklocal": false,
            "majestic_million": true,
            "majestic_million_1M": true,
            "microsoft": false,
            "microsoft-attack-simulator": false,
            "microsoft-azure": false,
            "microsoft-azure-china": false,
            "microsoft-azure-germany": false,
            "microsoft-azure-us-gov": false,
            "microsoft-office365": false,
            "microsoft-office365-cn": false,
            "microsoft-office365-ip": false,
            "microsoft-win10-connection-endpoints": false,
            "moz-top500": false,
            "mozilla-CA": false,
            "mozilla-IntermediateCA": false,
            "multicast": false,
            "nioc-filehash": false,
            "ovh-cluster": false,
            "phone_numbers": false,
            "public-dns-hostname": false,
            "public-dns-v4": false,
            "public-dns-v6": false,
            "rfc1918": false,
            "rfc3849": false,
            "rfc5735": false,
            "rfc6598": false,
            "rfc6761": false,
            "second-level-tlds": true,
            "security-provider-blogpost": false,
            "sinkholes": false,
            "smtp-receiving-ips": false,
            "smtp-sending-ips": false,
            "stackpath": false,
            "tenable-cloud-ipv4": false,
            "tenable-cloud-ipv6": false,
            "ti-falsepositives": false,
            "tlds": true,
            "tranco": true,
            "tranco10k": true,
            "university_domains": false,
            "url-shortener": false,
            "vpn-ipv4": false,
            "vpn-ipv6": false,
            "whats-my-ip": false,
            "wikimedia": false
        },
        "mscore": 0,
        "sources": [
            {
                "category": [],
                "first_seen": "2021-09-02T18:26:26.000+0000",
                "last_seen": "2022-09-01T00:21:24.000+0000",
                "osint": false,
                "source_name": "Mandiant"
            },
            {
                "category": [],
                "first_seen": "2021-12-14T01:45:13.505+0000",
                "last_seen": "2021-12-16T19:37:16.127+0000",
                "osint": false,
                "source_name": "Mandiant"
            },
            {
                "category": [],
                "first_seen": "2022-05-15T03:06:18.295+0000",
                "last_seen": "2022-10-26T13:58:08.908+0000",
                "osint": true,
                "source_name": "dtm.blackbeard"
            },
            {
                "category": [
                    "control-server",
                    "botnet"
                ],
                "first_seen": "2021-07-02T15:17:26.283+0000",
                "last_seen": "2021-08-06T19:18:00.231+0000",
                "osint": false,
                "source_name": "Mandiant"
            },
            {
                "category": [],
                "first_seen": "2022-06-04T12:59:02.280+0000",
                "last_seen": "2022-10-19T22:16:52.422+0000",
                "osint": false,
                "source_name": "Mandiant"
            }
        ],
        "type": "url",
        "value": {}
    }
}
```

#### Human Readable Output

>### Results
>|first_seen|id|is_publishable|last_seen|last_updated|misp|mscore|sources|type|value|
>|---|---|---|---|---|---|---|---|---|---|
>| 2021-06-19T09:13:28.000Z | url--431bfcd3-a8a5-5103-9ad7-ac7f05891875 | true | 2022-10-26T13:58:08.000Z | 2022-10-26T13:58:11.126Z | akamai: false<br/>alexa: true<br/>alexa_1M: true<br/>amazon-aws: false<br/>apple: false<br/>automated-malware-analysis: false<br/>bank-website: false<br/>cisco_1M: true<br/>cisco_top1000: true<br/>cisco_top10k: true<br/>cisco_top20k: true<br/>cisco_top5k: true<br/>cloudflare: false<br/>common-contact-emails: false<br/>common-ioc-false-positive: false<br/>covid: false<br/>covid-19-cyber-threat-coalition-whitelist: false<br/>covid-19-krassi-whitelist: false<br/>crl-hostname: false<br/>crl-ip: false<br/>dax30: false<br/>disposable-email: false<br/>dynamic-dns: false<br/>eicar.com: false<br/>empty-hashes: false<br/>fastly: false<br/>google: true<br/>google-gcp: false<br/>google-gmail-sending-ips: false<br/>googlebot: false<br/>ipv6-linklocal: false<br/>majestic_million: true<br/>majestic_million_1M: true<br/>microsoft: false<br/>microsoft-attack-simulator: false<br/>microsoft-azure: false<br/>microsoft-azure-china: false<br/>microsoft-azure-germany: false<br/>microsoft-azure-us-gov: false<br/>microsoft-office365: false<br/>microsoft-office365-cn: false<br/>microsoft-office365-ip: false<br/>microsoft-win10-connection-endpoints: false<br/>moz-top500: false<br/>mozilla-CA: false<br/>mozilla-IntermediateCA: false<br/>multicast: false<br/>nioc-filehash: false<br/>ovh-cluster: false<br/>phone_numbers: false<br/>public-dns-hostname: false<br/>public-dns-v4: false<br/>public-dns-v6: false<br/>rfc1918: false<br/>rfc3849: false<br/>rfc5735: false<br/>rfc6598: false<br/>rfc6761: false<br/>second-level-tlds: true<br/>security-provider-blogpost: false<br/>sinkholes: false<br/>smtp-receiving-ips: false<br/>smtp-sending-ips: false<br/>stackpath: false<br/>tenable-cloud-ipv4: false<br/>tenable-cloud-ipv6: false<br/>ti-falsepositives: false<br/>tlds: true<br/>tranco: true<br/>tranco10k: true<br/>university_domains: false<br/>url-shortener: false<br/>vpn-ipv4: false<br/>vpn-ipv6: false<br/>whats-my-ip: false<br/>wikimedia: false | 0 | {'first_seen': '2021-09-02T18:26:26.000+0000', 'last_seen': '2022-09-01T00:21:24.000+0000', 'osint': False, 'category': [], 'source_name': 'Mandiant'},<br/>{'first_seen': '2021-12-14T01:45:13.505+0000', 'last_seen': '2021-12-16T19:37:16.127+0000', 'osint': False, 'category': [], 'source_name': 'Mandiant'},<br/>{'first_seen': '2022-05-15T03:06:18.295+0000', 'last_seen': '2022-10-26T13:58:08.908+0000', 'osint': True, 'category': [], 'source_name': 'dtm.blackbeard'},<br/>{'first_seen': '2021-07-02T15:17:26.283+0000', 'last_seen': '2021-08-06T19:18:00.231+0000', 'osint': False, 'category': ['control-server', 'botnet'], 'source_name': 'Mandiant'},<br/>{'first_seen': '2022-06-04T12:59:02.280+0000', 'last_seen': '2022-10-19T22:16:52.422+0000', 'osint': False, 'category': [], 'source_name': 'Mandiant'} | url |  |


### domain
***
 


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | List of domains. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!domain domain=google.com```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "google.com",
        "Score": 0,
        "Type": "domain",
        "Vendor": "Mandiant Advantage Threat Intelligence"
    },
    "Domain": {
        "DNS": "google.com",
        "Name": "google.com"
    },
    "domain": {
        "first_seen": "2014-09-01T21:39:23.000Z",
        "id": "fqdn--7baea406-cc1b-53f9-b1b2-ea4ad2f56dc1",
        "is_publishable": true,
        "last_seen": "2022-10-25T16:51:58.000Z",
        "last_updated": "2022-10-25T17:03:58.528Z",
        "misp": {
            "akamai": false,
            "alexa": true,
            "alexa_1M": true,
            "amazon-aws": false,
            "apple": false,
            "automated-malware-analysis": false,
            "bank-website": false,
            "cisco_1M": true,
            "cisco_top1000": true,
            "cisco_top10k": true,
            "cisco_top20k": true,
            "cisco_top5k": true,
            "cloudflare": false,
            "common-contact-emails": false,
            "common-ioc-false-positive": false,
            "covid": false,
            "covid-19-cyber-threat-coalition-whitelist": false,
            "covid-19-krassi-whitelist": false,
            "crl-hostname": false,
            "crl-ip": false,
            "dax30": false,
            "disposable-email": false,
            "dynamic-dns": false,
            "eicar.com": false,
            "empty-hashes": false,
            "fastly": false,
            "google": true,
            "google-gcp": false,
            "google-gmail-sending-ips": false,
            "googlebot": false,
            "ipv6-linklocal": false,
            "majestic_million": true,
            "majestic_million_1M": true,
            "microsoft": false,
            "microsoft-attack-simulator": false,
            "microsoft-azure": false,
            "microsoft-azure-china": false,
            "microsoft-azure-germany": false,
            "microsoft-azure-us-gov": false,
            "microsoft-office365": false,
            "microsoft-office365-cn": false,
            "microsoft-office365-ip": false,
            "microsoft-win10-connection-endpoints": false,
            "moz-top500": false,
            "mozilla-CA": false,
            "mozilla-IntermediateCA": false,
            "multicast": false,
            "nioc-filehash": false,
            "ovh-cluster": false,
            "phone_numbers": false,
            "public-dns-hostname": false,
            "public-dns-v4": false,
            "public-dns-v6": false,
            "rfc1918": false,
            "rfc3849": false,
            "rfc5735": false,
            "rfc6598": false,
            "rfc6761": false,
            "second-level-tlds": true,
            "security-provider-blogpost": false,
            "sinkholes": false,
            "smtp-receiving-ips": false,
            "smtp-sending-ips": false,
            "stackpath": false,
            "tenable-cloud-ipv4": false,
            "tenable-cloud-ipv6": false,
            "ti-falsepositives": false,
            "tlds": true,
            "tranco": true,
            "tranco10k": true,
            "university_domains": false,
            "url-shortener": false,
            "vpn-ipv4": false,
            "vpn-ipv6": false,
            "whats-my-ip": false,
            "wikimedia": false
        },
        "mscore": 0,
        "sources": [
            {
                "category": [],
                "first_seen": "2021-12-13T23:51:44.068+0000",
                "last_seen": "2021-12-16T20:38:38.965+0000",
                "osint": false,
                "source_name": "Mandiant"
            },
            {
                "category": [],
                "first_seen": "2021-12-14T21:07:25.784+0000",
                "last_seen": "2022-10-24T08:02:09.623+0000",
                "osint": false,
                "source_name": "Mandiant"
            },
            {
                "category": [],
                "first_seen": "2020-01-30T15:49:31.326+0000",
                "last_seen": "2020-01-30T15:49:31.326+0000",
                "osint": false,
                "source_name": "Mandiant"
            },
            {
                "category": [],
                "first_seen": "2021-12-14T04:32:32.348+0000",
                "last_seen": "2022-10-25T16:51:58.567+0000",
                "osint": true,
                "source_name": "dtm.blackbeard"
            },
            {
                "category": [],
                "first_seen": "2021-09-23T23:00:39.636+0000",
                "last_seen": "2021-09-24T23:01:22.370+0000",
                "osint": false,
                "source_name": "Mandiant"
            },
            {
                "category": [],
                "first_seen": "2021-06-24T23:25:00.803+0000",
                "last_seen": "2021-06-24T23:25:00.803+0000",
                "osint": true,
                "source_name": "futex.re"
            },
            {
                "category": [],
                "first_seen": "2021-09-23T23:02:11.244+0000",
                "last_seen": "2021-10-10T22:40:25.469+0000",
                "osint": false,
                "source_name": "Mandiant"
            },
            {
                "category": [],
                "first_seen": "2020-02-16T16:12:57.000+0000",
                "last_seen": "2021-12-04T00:12:41.000+0000",
                "osint": false,
                "source_name": "Mandiant"
            },
            {
                "category": [],
                "first_seen": "2020-02-29T04:38:11.915+0000",
                "last_seen": "2020-04-16T10:17:05.796+0000",
                "osint": false,
                "source_name": "Mandiant"
            },
            {
                "category": [],
                "first_seen": "2014-09-01T21:39:23.000+0000",
                "last_seen": "2018-09-05T14:26:02.000+0000",
                "osint": false,
                "source_name": "Mandiant"
            },
            {
                "category": [
                    "control-server",
                    "botnet"
                ],
                "first_seen": "2021-07-02T15:17:26.283+0000",
                "last_seen": "2021-08-06T19:18:00.231+0000",
                "osint": false,
                "source_name": "Mandiant"
            },
            {
                "category": [],
                "first_seen": "2021-09-22T17:49:34.000+0000",
                "last_seen": "2021-09-22T17:49:34.000+0000",
                "osint": false,
                "source_name": "Mandiant"
            },
            {
                "category": [],
                "first_seen": "2020-08-30T15:42:25.470+0000",
                "last_seen": "2020-08-30T15:42:25.470+0000",
                "osint": false,
                "source_name": "Mandiant"
            },
            {
                "category": [
                    "infostealer",
                    "control-server",
                    "banker"
                ],
                "first_seen": "2021-06-18T04:31:40.390+0000",
                "last_seen": "2022-09-16T14:48:54.200+0000",
                "osint": false,
                "source_name": "Mandiant"
            },
            {
                "category": [],
                "first_seen": "2021-12-14T00:19:22.164+0000",
                "last_seen": "2021-12-16T18:37:17.664+0000",
                "osint": false,
                "source_name": "Mandiant"
            }
        ],
        "type": "fqdn",
        "value": {
            "google.com": "[google.com](#/indicator/2611)"
        }
    }
}
```

#### Human Readable Output

>### Results
>|first_seen|id|is_publishable|last_seen|last_updated|misp|mscore|sources|type|value|
>|---|---|---|---|---|---|---|---|---|---|
>| 2014-09-01T21:39:23.000Z | fqdn--7baea406-cc1b-53f9-b1b2-ea4ad2f56dc1 | true | 2022-10-25T16:51:58.000Z | 2022-10-25T17:03:58.528Z | akamai: false<br/>alexa: true<br/>alexa_1M: true<br/>amazon-aws: false<br/>apple: false<br/>automated-malware-analysis: false<br/>bank-website: false<br/>cisco_1M: true<br/>cisco_top1000: true<br/>cisco_top10k: true<br/>cisco_top20k: true<br/>cisco_top5k: true<br/>cloudflare: false<br/>common-contact-emails: false<br/>common-ioc-false-positive: false<br/>covid: false<br/>covid-19-cyber-threat-coalition-whitelist: false<br/>covid-19-krassi-whitelist: false<br/>crl-hostname: false<br/>crl-ip: false<br/>dax30: false<br/>disposable-email: false<br/>dynamic-dns: false<br/>eicar.com: false<br/>empty-hashes: false<br/>fastly: false<br/>google: true<br/>google-gcp: false<br/>google-gmail-sending-ips: false<br/>googlebot: false<br/>ipv6-linklocal: false<br/>majestic_million: true<br/>majestic_million_1M: true<br/>microsoft: false<br/>microsoft-attack-simulator: false<br/>microsoft-azure: false<br/>microsoft-azure-china: false<br/>microsoft-azure-germany: false<br/>microsoft-azure-us-gov: false<br/>microsoft-office365: false<br/>microsoft-office365-cn: false<br/>microsoft-office365-ip: false<br/>microsoft-win10-connection-endpoints: false<br/>moz-top500: false<br/>mozilla-CA: false<br/>mozilla-IntermediateCA: false<br/>multicast: false<br/>nioc-filehash: false<br/>ovh-cluster: false<br/>phone_numbers: false<br/>public-dns-hostname: false<br/>public-dns-v4: false<br/>public-dns-v6: false<br/>rfc1918: false<br/>rfc3849: false<br/>rfc5735: false<br/>rfc6598: false<br/>rfc6761: false<br/>second-level-tlds: true<br/>security-provider-blogpost: false<br/>sinkholes: false<br/>smtp-receiving-ips: false<br/>smtp-sending-ips: false<br/>stackpath: false<br/>tenable-cloud-ipv4: false<br/>tenable-cloud-ipv6: false<br/>ti-falsepositives: false<br/>tlds: true<br/>tranco: true<br/>tranco10k: true<br/>university_domains: false<br/>url-shortener: false<br/>vpn-ipv4: false<br/>vpn-ipv6: false<br/>whats-my-ip: false<br/>wikimedia: false | 0 | {'first_seen': '2021-12-13T23:51:44.068+0000', 'last_seen': '2021-12-16T20:38:38.965+0000', 'osint': False, 'category': [], 'source_name': 'Mandiant'},<br/>{'first_seen': '2021-12-14T21:07:25.784+0000', 'last_seen': '2022-10-24T08:02:09.623+0000', 'osint': False, 'category': [], 'source_name': 'Mandiant'},<br/>{'first_seen': '2020-01-30T15:49:31.326+0000', 'last_seen': '2020-01-30T15:49:31.326+0000', 'osint': False, 'category': [], 'source_name': 'Mandiant'},<br/>{'first_seen': '2021-12-14T04:32:32.348+0000', 'last_seen': '2022-10-25T16:51:58.567+0000', 'osint': True, 'category': [], 'source_name': 'dtm.blackbeard'},<br/>{'first_seen': '2021-09-23T23:00:39.636+0000', 'last_seen': '2021-09-24T23:01:22.370+0000', 'osint': False, 'category': [], 'source_name': 'Mandiant'},<br/>{'first_seen': '2021-06-24T23:25:00.803+0000', 'last_seen': '2021-06-24T23:25:00.803+0000', 'osint': True, 'category': [], 'source_name': 'futex.re'},<br/>{'first_seen': '2021-09-23T23:02:11.244+0000', 'last_seen': '2021-10-10T22:40:25.469+0000', 'osint': False, 'category': [], 'source_name': 'Mandiant'},<br/>{'first_seen': '2020-02-16T16:12:57.000+0000', 'last_seen': '2021-12-04T00:12:41.000+0000', 'osint': False, 'category': [], 'source_name': 'Mandiant'},<br/>{'first_seen': '2020-02-29T04:38:11.915+0000', 'last_seen': '2020-04-16T10:17:05.796+0000', 'osint': False, 'category': [], 'source_name': 'Mandiant'},<br/>{'first_seen': '2014-09-01T21:39:23.000+0000', 'last_seen': '2018-09-05T14:26:02.000+0000', 'osint': False, 'category': [], 'source_name': 'Mandiant'},<br/>{'first_seen': '2021-07-02T15:17:26.283+0000', 'last_seen': '2021-08-06T19:18:00.231+0000', 'osint': False, 'category': ['control-server', 'botnet'], 'source_name': 'Mandiant'},<br/>{'first_seen': '2021-09-22T17:49:34.000+0000', 'last_seen': '2021-09-22T17:49:34.000+0000', 'osint': False, 'category': [], 'source_name': 'Mandiant'},<br/>{'first_seen': '2020-08-30T15:42:25.470+0000', 'last_seen': '2020-08-30T15:42:25.470+0000', 'osint': False, 'category': [], 'source_name': 'Mandiant'},<br/>{'first_seen': '2021-06-18T04:31:40.390+0000', 'last_seen': '2022-09-16T14:48:54.200+0000', 'osint': False, 'category': ['infostealer', 'control-server', 'banker'], 'source_name': 'Mandiant'},<br/>{'first_seen': '2021-12-14T00:19:22.164+0000', 'last_seen': '2021-12-16T18:37:17.664+0000', 'osint': False, 'category': [], 'source_name': 'Mandiant'} | fqdn | google.com: [google.com](#/indicator/2611) |


### cve
***
 


#### Base Command

`cve`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve | List of CVEs. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!cve cve=CVE-2022-38418```
#### Context Example
```json
{
    "CVE": {
        "CVSS": CVSS_SCORE,
        "Description": "DESCRIPTION",
        "ID": "CVE-YEAR-ID",
        "Modified": "2022-10-17T21:32:00.000",
        "Published": "2022-10-17T21:32:00.000"
    },
    "DBotScore": {
        "Indicator": "CVE-YEAR-ID",
        "Score": 0,
        "Type": "cve",
        "Vendor": "Mandiant Advantage Threat Intelligence"
    },
    "cve": {
        "affects_ot": false,
        "aliases": [],
        "analysis": "ANALYSIS",
        "associated_actors": [],
        "associated_malware": [],
        "associated_reports": [
            {
                "audience": [
                    "vulnerability"
                ],
                "published_date": "2022-10-17T21:32:05.956Z",
                "report_id": "REPORT_ID",
                "report_type": "Vulnerability Report",
                "title": "REPORT_TITLE"
            }
        ],
        "audience": [
            "intel_vuln"
        ],
        "available_mitigation": [
            "Patch"
        ],
        "cisa_known_exploited": null,
        "common_vulnerability_scores": {
            "v2.0": {
                "access_complexity": "HIGH",
                "access_vector": "NETWORK",
                "authentication": "NONE",
                "availability_impact": "COMPLETE",
                "base_score": 7.6,
                "confidentiality_impact": "COMPLETE",
                "exploitability": "UNPROVEN",
                "integrity_impact": "COMPLETE",
                "remediation_level": "OFFICIAL_FIX",
                "report_confidence": "CONFIRMED",
                "temporal_score": 5.6,
                "vector_string": "AV:N/AC:H/Au:N/C:C/I:C/A:C/E:U/RL:OF/RC:C"
            }
        },
        "cpe_ranges": [],
        "cve_id": {
            "CVE-YEAR-ID": "[CVE-YEAR-ID](#/indicator/0000)"
        },
        "cwe": "Path Traversal",
        "cwe_details": null,
        "date_of_disclosure": "2022-10-11T06:00:00.000Z",
        "days_to_patch": null,
        "description": "DESCRIPTION",
        "epss": null,
        "executive_summary": "SUMMARY",
        "exploitation_consequence": "Code Execution",
        "exploitation_state": "No Known",
        "exploitation_vectors": [
            "General Network Connectivity",
            "Open Port"
        ],
        "exploits": [],
        "id": "vulnerability--u-u-i-d",
        "intel_free": false,
        "is_publishable": true,
        "last_modified_date": "2022-10-17T21:32:00.000Z",
        "observed_in_the_wild": false,
        "publish_date": "2022-10-17T21:32:00.000Z",
        "risk_rating": "MEDIUM",
        "sources": [
        ],
        "title": "TITLE",
        "type": "vulnerability",
        "updated_date": "2022-10-17T21:32:00.000Z",
        "vendor_fix_references": [
            {
                "name": "Vendor Fix",
                "unique_id": "ID",
                "url": "EXAMPLE URL"
            }
        ],
        "version_history": [],
        "vulnerable_cpes": [
        ],
        "vulnerable_products": "VULNERABLE_PRODUCTS",
        "was_zero_day": false,
        "workarounds": null,
        "workarounds_list": []
    }
}
```

#### Human Readable Output

>### Results
>|affects_ot|aliases| analysis |associated_actors|associated_malware| associated_reports                                                                                                                                                      |audience|available_mitigation|cisa_known_exploited| common_vulnerability_scores                                                                                                                                                                                                                                                                                                                                                                                            |cpe_ranges| cve_id                                       |cwe|cwe_details|date_of_disclosure|days_to_patch| description |epss| executive_summary |exploitation_consequence|exploitation_state|exploitation_vectors|exploits| id                     |intel_free|is_publishable|last_modified_date|observed_in_the_wild|publish_date|risk_rating|sources| title |type|updated_date| vendor_fix_references                                       |version_history|vulnerable_cpes| vulnerable_products |was_zero_day|workarounds|workarounds_list|
>|---|----------|---|---|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---|---|---|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---|----------------------------------------------|---|---|---|---|-------------|---|-------------------|---|---|---|---|------------------------|---|---|---|---|---|---|---|-------|---|---|-------------------------------------------------------------|---|---|---------------------|---|---|---|---|
>| false |  | ANALYSIS |  |  | {'report_id': 'REPORT_ID', 'report_type': 'Vulnerability Report', 'title': 'REPORT_TITLE', 'published_date': '2022-10-17T21:32:05.956Z', 'audience': ['vulnerability']} | intel_vuln | Patch |  | v2.0: {"access_complexity": "HIGH", "access_vector": "NETWORK", "authentication": "NONE", "availability_impact": "COMPLETE", "base_score": CVSS_SCORE, "confidentiality_impact": "COMPLETE", "exploitability": "UNPROVEN", "integrity_impact": "COMPLETE", "remediation_level": "OFFICIAL_FIX", "report_confidence": "CONFIRMED", "temporal_score": 5.6, "vector_string": "AV:N/AC:H/Au:N/C:C/I:C/A:C/E:U/RL:OF/RC:C"} |  | CVE-YEAR-ID: [CVE-YEAR-ID](#/indicator/0000) | Path Traversal |  | 2022-10-11T06:00:00.000Z |  | DESCRIPTION |  | EXECUTIVE_SUMMARY | Code Execution | No Known | General Network Connectivity,<br/>Open Port |  | vulnerability--u-u-i-d | false | true | 2022-10-17T21:32:00.000Z | false | 2022-10-17T21:32:00.000Z | MEDIUM |  | TITLE | vulnerability | 2022-10-17T21:32:00.000Z | {'url': 'FIX URL', 'name': 'Vendor Fix', 'unique_id': 'ID'} |  |  | VULNERABLE PRODUCTS | false |  |  |

