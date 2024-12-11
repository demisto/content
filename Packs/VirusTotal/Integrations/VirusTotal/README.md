Analyze suspicious hashes, URLs, domains, and IP addresses.
## Configure VirusTotal in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g. https://192.168.0.1) |  | True |
| API Key |  | True |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |
| File Threshold. Minimum number of positive results from VT scanners to consider the file malicious. |  | False |
| IP Threshold. Minimum number of positive results from VT scanners to consider the IP malicious. |  | False |
| URL Threshold. Minimum number of positive results from VT scanners to consider the URL malicious. |  | False |
| Domain Threshold. Minimum number of positive results from VT scanners to consider the domain malicious. |  | False |
| Preferred Vendors List. CSV list of vendors which are considered more trustworthy. |  | False |
| Preferred Vendor Threshold. The minimum number of highly trusted vendors required to consider a domain, IP address, URL, or file as malicious.  |  | False |
| Determines whether to return all results, which can number in the thousands. If “true”, returns all results and overrides the _fullResponse_, _long_ arguments (if set to “false”) in a command. If “false”, the _fullResponse_, _long_ arguments in the command determines how results are returned. |  | False |
| IP Relationships | Select the list of relationships to retrieve from the API. Some of the relationships are signed with * key which indicates that they are available only when using a premium API key. | False |
| Domain Relationships | Select the list of relationships to retrieve from the API. Some of the relationships are signed with * key which indicates that they are available only when using a premium API key. | False |
| URL Relationships | Select the list of relationships to retrieve from the API. Some of the relationships are signed with * key which indicates that they are available only when using a premium API key. | False |
| File Relationships | Select the list of relationships to retrieve from the API. Some of the relationships are signed with * key which indicates that they are available only when using a premium API key. | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### file
***
Checks the file reputation of the specified hash.


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | A CSV list of hashes of the file to query. Supports MD5, SHA1, and SHA256. | Required | 
| long | Whether to return full response for scans. Default is "false". Possible values are: true, false. Default is false. | Optional | 
| threshold | If the number of positives is higher than the threshold, the file will be considered malicious. If the threshold is not specified, the default file threshold, as configured in the instance settings, will be used. | Optional | 
| wait | Time (in seconds) to wait between tries if the API rate limit is reached. Default is "60". Default is 60. | Optional | 
| retries | Number of retries for the API rate limit. Default is "0". Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.MD5 | unknown | Bad MD5 hash. | 
| File.SHA1 | unknown | Bad SHA1 hash. | 
| File.SHA256 | unknown | Bad SHA256 hash. |
| File.Malicious.Vendor | unknown | For malicious files, the vendor that made the decision. | 
| File.Malicious.Detections | unknown | For malicious files, the total number of detections. | 
| File.Malicious.TotalEngines | unknown | For malicious files, the total number of engines that checked the file hash. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| File.VirusTotal.Scans.Source | unknown | Vendor used to scan the hash. | 
| File.VirusTotal.Scans.Detected | unknown | Scan detection for this hash \(True or False\). | 
| File.VirusTotal.Scans.Result | unknown | Scan result for this hash, for example, signature. | 
| File.VirusTotal.ScanID | string | Scan ID for this hash. | 
| File.PositiveDetections | number | Number of engines that positively detected the indicator as malicious. | 
| File.DetectionEngines | number | Total number of engines that checked the indicator. | 
| File.VirusTotal.vtLink | string | Virus Total permanent link. | 


#### Command Example
``` ```

#### Human Readable Output



### ip
***
Checks the reputation of an IP address.


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP address to check. | Required | 
| long | Whether to return a full response for detected URLs. Default is "false". Possible values are: "true" and "false". | Optional | 
| threshold | If the number of positives is higher than the threshold, the IP address will be considered malicious. If the threshold is not specified, the default IP threshold, as configured in the instance settings, will be used. | Optional | 
| sampleSize | The number of samples from each type (resolutions, detections, etc.) to display in the long format. Default is "10". | Optional | 
| wait | Time (in seconds) to wait between tries if the API rate limit is reached. Default is "60". | Optional | 
| retries | Number of retries for the API rate limit. Default is "0". | Optional | 
| fullResponse | Whether to return all results, which can be thousands. We recommend that you don't return full results in playbooks. Possible values are: "true" and "false". Default is "false". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | unknown | Bad IP address. |
| IP.ASN | unknown | Bad IP ASN. | 
| IP.Geo.Country | unknown | Bad IP country. | 
| IP.Malicious.Vendor | unknown | For malicious IPs, the vendor that made the decision. | 
| IP.Malicious.Description | unknown | For malicious IPs, the reason that the vendor made the decision. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| IP.VirusTotal.DownloadedHashes | unknown | Latest files that were detected by at least one antivirus solution, and were downloaded by VirusTotal from the IP address. | 
| IP.VirusTotal.UnAVDetectedDownloadedHashes | unknown | Latest files that were not detected by any antivirus solution, and were downloaded by VirusTotal from the specified IP address. | 
| IP.VirusTotal.DetectedURLs | unknown | Latest URLs hosted in this IP address that were detected by at least one URL scanner. | 
| IP.VirusTotal.CommunicatingHashes | unknown | Latest detected files that communicate with this IP address. | 
| IP.VirusTotal.UnAVDetectedCommunicatingHashes | unknown | Latest undetected files that communicate with this IP address. | 
| IP.VirusTotal.Resolutions.hostname | unknown | Domains that resolved to the specified IP address. | 
| IP.VirusTotal.ReferrerHashes | unknown | Latest detected files that embed this IP address in their strings. | 
| IP.VirusTotal.UnAVDetectedReferrerHashes | unknown | Latest undetected files that embed this IP address in their strings. | 
| IP.VirusTotal.Resolutions.last_resolved | unknown | Last resolution times of the domains that resolved to the specified IP address. | 


#### Command Example
``` ```

#### Human Readable Output



### url
***
Checks the reputation of a URL.


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | A comma-separated list of URLs to check. This command will not work properly on URLs containing commas. | Required | 
| sampleSize | The number of samples from each type (resolutions, detections, etc.) to display for long format. Default is "10". | Optional | 
| long | Whether to return the full response for the detected URLs. Possible values are: "true" and "false". Default is "false". | Optional | 
| threshold | If the number of positives is higher than the threshold, the URL will be considered malicious. If the threshold is not specified, the default URL threshold, as configured in the instance settings, will be used. | Optional | 
| submitWait | Time (in seconds) to wait if the URL does not exist and is submitted for scanning. Default is "0".  | Optional | 
| wait | Time (in seconds) to wait between tries if the API rate limit is reached. Default is "60".  | Optional | 
| retries | Number of retries for the API rate limit. Default is "0".  | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL.Data | unknown | Bad URLs found. |
| URL.Malicious.Vendor | unknown | For malicious URLs, the vendor that made the decision. | 
| URL.Malicious.Description | unknown | For malicious URLs, the reason that the vendor made the decision. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| URL.VirusTotal.Scans.Source | unknown | Vendor that scanned this URL. | 
| URL.VirusTotal.Scans.Detected | unknown | Scan detection for this URL \(True or False\). | 
| URL.VirusTotal.Scans.Result | unknown | Scan result for this URL, for example, signature. | 
| URL.DetectionEngines | number | Total number of engines that checked the indicator. | 
| URL.PositiveDetections | number | Number of engines that positively detected the indicator as malicious. | 
| url.VirusTotal.ScanID | string | Scan ID for this URL. | 
| File.VirusTotal.vtLink | string | Virus Total permanent link. | 


#### Command Example
```!url url=https://example.com using=vt```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "https://example.com",
        "Reliability": "C - Fairly reliable",
        "Score": 1,
        "Type": "url",
        "Vendor": "VirusTotal"
    },
    "URL": {
        "Data": "https://example.com",
        "DetectionEngines": 87,
        "PositiveDetections": 2,
        "VirusTotal": {
            "ScanID": "0f115db062b7c0dd030b16878c99dea5c354b49dc37b38eb8846179c7783e9d7-1618315592",
            "vtLink": "https://www.virustotal.com/gui/url/0f115db062b7c0dd030b16878c99dea5c354b49dc37b38eb8846179c7783e9d7/detection/u-0f115db062b7c0dd030b16878c99dea5c354b49dc37b38eb8846179c7783e9d7-1618315592"
        }
    }
}
```

#### Human Readable Output

>## VirusTotal URL Reputation for: https://example.com
>Last scan date: *2021-04-13 12:06:32*
>Total scans: **87**
>Positive scans: **2**
>VT Link: [https://example.com](https://www.virustotal.com/gui/url/0f115db062b7c0dd030b16878c99dea5c354b49dc37b38eb8846179c7783e9d7/detection/u-0f115db062b7c0dd030b16878c99dea5c354b49dc37b38eb8846179c7783e9d7-1618315592)


### domain
***
Checks the reputation of a domain.


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain name to check. | Required | 
| long | Whether to return the full response for detected URLs. Default is "false". Possible values are: true, false. Default is false. | Optional | 
| sampleSize | The number of samples from each type (resolutions, detections, etc.) to display for long format. Default is 10. | Optional | 
| threshold | If the number of positives is higher than the threshold, the domain will be considered malicious. If the threshold is not specified, the default domain threshold, as configured in the instance settings, will be used. | Optional | 
| wait | Time (in seconds) to wait between tries if the API rate limit is reached. Default is "60". Default is 60. | Optional | 
| retries | Number of retries for API rate limit. Default is "0". Default is 0. | Optional | 
| fullResponse | Whether to return all results, which can be thousands. Default is "false". We recommend that you don't return full results in playbooks. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | unknown | Bad domain found. |
| Domain.Malicious.Vendor | unknown | For malicious domains, the vendor that made the decision. | 
| Domain.Malicious.Description | unknown | For malicious domains, the reason that the vendor made the decision. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| Domain.VirusTotal.DownloadedHashes | unknown | Hashes of files that were downloaded from this domain. | 
| Domain.VirusTotal.CommunicatingHashes | unknown | Hashes of files that communicated with this domain in a sandbox. | 
| Domain.VirusTotal.Resolutions.ip_address | unknown | IP addresses that resolved to this domain. | 
| Domain.VirusTotal.Whois | unknown | Whois report. | 
| Domain.VirusTotal.Subdomains | unknown | Subdomains. | 
| Domain.VirusTotal.UnAVDetectedDownloadedHashes | unknown | Latest files that were not detected by any antivirus solution, and were downloaded by VirusTotal from the specified IP address. | 
| Domain.VirusTotal.DetectedURLs | unknown | Latest URLs hosted in this domain address that were detected by at least one URL scanner. | 
| Domain.VirusTotal.ReferrerHashes | unknown | Latest detected files that embed this domain address in their strings. | 
| Domain.VirusTotal.UnAVDetectedReferrerHashes | unknown | Latest undetected files that embed this domain address in their strings. | 
| Domain.VirusTotal.UnAVDetectedCommunicatingHashes | unknown | Latest undetected files that communicated with this domain in a sandbox. | 
| Domain.VirusTotal.Resolutions.last_resolved | unknown | Last resolution times of the IP addresses that resolve to this domain. | 


#### Command Example
```!domain domain=example.com using=vt```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "example.com",
        "Reliability": "C - Fairly reliable",
        "Score": 1,
        "Type": "domain",
        "Vendor": "VirusTotal"
    },
    "Domain": {
        "Name": "example.com",
        "VirusTotal": {
            "CommunicatingHashes": [
                {
                    "date": "2021-04-12 09:26:02",
                    "positives": 57,
                    "sha256": "6a5ac92cbc785fc963b4864db51c8aa3f1dae9e85d4fe20bd05816be301355cf",
                    "total": 75
                },
                {
                    "date": "2021-04-11 13:15:27",
                    "positives": 50,
                    "sha256": "d0a08d52eb9e5446b701f01ee13b361d4d9109af7f434e71bbfbc8d485277eea",
                    "total": 74
                },
                {
                    "date": "2021-04-11 13:07:33",
                    "positives": 53,
                    "sha256": "0c3ed8d6f0261ac2ad08a3a73a61f0bf6796e3169790cdb20aa1e08846a972cc",
                    "total": 75
                },
                {
                    "date": "2021-04-11 11:12:34",
                    "positives": 8,
                    "sha256": "ffdedea9146387fa9bbacfa309e805bb2300b43fddc00bb8397c4fb0f85b5501",
                    "total": 74
                },
                {
                    "date": "2021-04-03 23:26:17",
                    "positives": 50,
                    "sha256": "7dbc608ef30c02bf02b1f88fbe386bfd4e8ba103cc23788df8a418d897b27e1d",
                    "total": 75
                },
                {
                    "date": "2021-04-07 17:43:15",
                    "positives": 8,
                    "sha256": "735ca98e2f84b9d08c2cba3b89e3e764083e5477ff0e0d941a1eeeda729a8911",
                    "total": 74
                },
                {
                    "date": "2021-04-07 14:40:22",
                    "positives": 1,
                    "sha256": "06fd36ed7c44f84397f07cca63ac2e82fd30587d00f0affef5bbac6ff41ccda3",
                    "total": 74
                },
                {
                    "date": "2021-04-07 10:57:59",
                    "positives": 7,
                    "sha256": "2e962f34024aa2791b4c906ff525ff3a9a077334cb62171f7ac94071b4043383",
                    "total": 73
                },
                {
                    "date": "2021-04-06 03:54:19",
                    "positives": 21,
                    "sha256": "a4a5bc74a7781871b3a42aaf14b08defee495a3c68815b5bdbd1848bf96699ab",
                    "total": 74
                },
                {
                    "date": "2021-04-05 05:20:13",
                    "positives": 57,
                    "sha256": "07ff0e704905783cc89e465e98e9fa99180333849a4bffd42a0c7e45598c2a94",
                    "total": 75
                },
                {
                    "date": "2021-04-05 09:57:27",
                    "positives": 56,
                    "sha256": "e97ff8d59861937e89ba807b8b6319d4ff35d07c49333627267929797ae20b49",
                    "total": 75
                },
                {
                    "date": "2021-04-05 03:35:28",
                    "positives": 56,
                    "sha256": "723b542d0e9c9dfb1e7afe2b8a80d0f483afc4dd052a8f5e434d6f81dfa2ff8a",
                    "total": 75
                },
                {
                    "date": "2021-04-05 10:56:01",
                    "positives": 56,
                    "sha256": "d87d92ee041dc88a23bd07667fbea624efc12855645122a7e86e9ebcbe8b2a6b",
                    "total": 75
                },
                {
                    "date": "2021-04-05 03:04:54",
                    "positives": 56,
                    "sha256": "01b4d96e716e7fc862a34e7bdb0b245071e9b4d4e1303d00735e8faea4cb99c8",
                    "total": 75
                },
                {
                    "date": "2021-04-04 21:03:52",
                    "positives": 56,
                    "sha256": "acffdd944badb0f6e6d5d145351fa7a672186e48c94181902f7eb5b730d841c8",
                    "total": 75
                },
                {
                    "date": "2021-04-05 17:22:20",
                    "positives": 1,
                    "sha256": "ccc2e90645b94d52e6b8f38de03ca281397673e546f620fd61a91a21985759e5",
                    "total": 73
                },
                {
                    "date": "2021-04-05 15:41:30",
                    "positives": 1,
                    "sha256": "4aa5c9349b5fce3af90f9d28f9520f0281db62ed346d54af9d8ead5b7e2f5921",
                    "total": 74
                },
                {
                    "date": "2021-04-04 13:29:47",
                    "positives": 33,
                    "sha256": "e52c38ba6c1a046fb4086946c6f8821074084758df5dff7d7ee554f5360e8b7b",
                    "total": 74
                },
                {
                    "date": "2021-04-02 05:31:33",
                    "positives": 18,
                    "sha256": "255f91ad437f817eb9d747cd08566b67613f500e306001c4f7c0ee94557f39a3",
                    "total": 77
                },
                {
                    "date": "2021-04-02 06:31:22",
                    "positives": 1,
                    "sha256": "5c84c2ba0834908eb07f75b9ba69d4b6aa23b61b7e93569671a094ca9c8e13c4",
                    "total": 74
                },
                {
                    "date": "2021-04-02 06:19:55",
                    "positives": 1,
                    "sha256": "a4d82173a09d6a8db5b1a44368ce49219be6f73af0f0700a872c47cb47dbb8ed",
                    "total": 74
                },
                {
                    "date": "2021-03-31 05:59:30",
                    "positives": 26,
                    "sha256": "be0a2ead16231cf5930c2da7f4edd8d858277bc3ead7e92d261093ed7c584046",
                    "total": 72
                },
                {
                    "date": "2021-03-31 05:56:45",
                    "positives": 30,
                    "sha256": "8ea80869b77006c0a20831d36ee0d2d0c28da79b5e9a99d52cdf81ff18b19520",
                    "total": 74
                },
                {
                    "date": "2021-03-30 06:08:32",
                    "positives": 34,
                    "sha256": "94bcc974165ba9ec90dfc40d0438b5cfdba7969032c82a53981e3af513164f2f",
                    "total": 75
                },
                {
                    "date": "2021-03-31 01:45:41",
                    "positives": 53,
                    "sha256": "853a44dbfe639a6c1e6dcf1a994f88363db62a9ec6e62ebf05b23b6ffb1e6d7d",
                    "total": 75
                },
                {
                    "date": "2021-03-31 12:52:49",
                    "positives": 32,
                    "sha256": "256390f58c23ca6dba40bc47dafd6edc2ab4cd25ac8c2eeb6e7ad6d6033437b8",
                    "total": 75
                },
                {
                    "date": "2021-03-31 11:25:49",
                    "positives": 1,
                    "sha256": "627f76e441e262e5e70a72c56d9786aad0419047f305c16990fc9bc206161644",
                    "total": 74
                },
                {
                    "date": "2021-03-31 00:02:58",
                    "positives": 49,
                    "sha256": "88412954cbbe227fecaeaab582ee6e39cd4c804510f60829601a18bbce50b60a",
                    "total": 75
                },
                {
                    "date": "2021-03-29 12:34:56",
                    "positives": 4,
                    "sha256": "8ac46f12d893ce84faab11d07b8c76fe7b0516dfc8506df70b0edcca43114de4",
                    "total": 73
                },
                {
                    "date": "2021-03-30 11:32:14",
                    "positives": 7,
                    "sha256": "8cfb1b8afecda4772031f37fd4aa00b024cd2874b797352c949dfbd751fc062a",
                    "total": 74
                },
                {
                    "date": "2021-03-30 10:06:58",
                    "positives": 1,
                    "sha256": "c3c0df231c0b9d294c795aa9fac2f1308eb2bc1bcdd705ef6d2af8452227b02c",
                    "total": 74
                },
                {
                    "date": "2021-03-30 08:29:41",
                    "positives": 13,
                    "sha256": "cffde7d6b903801343146e003a11eba0ac619298191424358e30befdc1391beb",
                    "total": 74
                },
                {
                    "date": "2021-03-25 04:25:38",
                    "positives": 50,
                    "sha256": "81ae5f6bbae13b0890578ff3ec885cba237e176401af21d7a9eea8a0d4b22e29",
                    "total": 76
                },
                {
                    "date": "2021-03-21 01:06:53",
                    "positives": 58,
                    "sha256": "7aa0a8b91487ff2949595271c3bfe0f07f09ce87292f0006498dc1ed5241c167",
                    "total": 76
                },
                {
                    "date": "2021-03-21 01:00:45",
                    "positives": 61,
                    "sha256": "d989c2c04ee6cb62296dcad1c8cbc27d5279190741306fee1afcf531e2c2fa25",
                    "total": 76
                },
                {
                    "date": "2021-03-22 01:03:13",
                    "positives": 2,
                    "sha256": "d14e0419671b376f3a59bd2a1354672951ae02e2b8fd9a7797e9e5050b0d6ec9",
                    "total": 75
                },
                {
                    "date": "2021-03-22 00:08:29",
                    "positives": 2,
                    "sha256": "1aafb6f2f4c5efc0c452cf0e2836932b0902929838bf3971e0e252251b23e83c",
                    "total": 75
                },
                {
                    "date": "2021-03-20 09:34:18",
                    "positives": 59,
                    "sha256": "a08f569f3bdd6b520013304aef6ed5f35830cf3002744c4cda6924801947ca1c",
                    "total": 76
                },
                {
                    "date": "2021-03-20 09:30:13",
                    "positives": 56,
                    "sha256": "a8e648026dbd8f36f01c6c5aa9a623efad26668e2ab762c26e8be70eef23cf66",
                    "total": 75
                },
                {
                    "date": "2021-03-20 08:49:18",
                    "positives": 55,
                    "sha256": "7debc7a47d65fcbfaa3382d2e89d85a52c55c10a6db561f52991054088923294",
                    "total": 76
                },
                {
                    "date": "2021-03-20 07:25:24",
                    "positives": 56,
                    "sha256": "a820eed0dfe429b760c0b47fbb1e493d8490aef6cd30c590165cc2fe9eede6d7",
                    "total": 76
                },
                {
                    "date": "2020-12-22 15:25:58",
                    "positives": 51,
                    "sha256": "d0f734894dc7b566c1f5ace8ac310544c645f14e80a234f4a5047bb42e702a8b",
                    "total": 77
                },
                {
                    "date": "2020-01-17 13:09:05",
                    "positives": 37,
                    "sha256": "41996bbd9ca19c2059338a9da58beb6f69a20cc71028f37da6daff0b31888437",
                    "total": 75
                },
                {
                    "date": "2019-10-07 23:36:41",
                    "positives": 45,
                    "sha256": "e9919f7b2dd46796bb1f07d6a43203a999e4d433558a7dea2dd48318e5691547",
                    "total": 72
                },
                {
                    "date": "2021-03-19 08:26:29",
                    "positives": 52,
                    "sha256": "da952562e7781cf8378a3347743d5f2007634a2b213d901b78629403f6df257f",
                    "total": 77
                },
                {
                    "date": "2021-03-19 08:21:47",
                    "positives": 56,
                    "sha256": "984511529324f7274de09d07c34453ede6208c4e2a65c3b3abe327e266cf8c0c",
                    "total": 76
                },
                {
                    "date": "2021-03-19 07:40:38",
                    "positives": 54,
                    "sha256": "a89dd2d356bccbe088bc8f0bee75c51e1d445a0062b40952c80c1dd004edb122",
                    "total": 76
                },
                {
                    "date": "2021-03-19 06:17:54",
                    "positives": 58,
                    "sha256": "d923610aed1d4118e26b249bbbf77d2e392c20e7c551e733dfdab62d5899b3e2",
                    "total": 76
                },
                {
                    "date": "2021-03-19 03:10:38",
                    "positives": 51,
                    "sha256": "0c6bc15182a12afdd5e159b897bac95761c3cd0fd34f61a63c50208703661f4a",
                    "total": 75
                },
                {
                    "date": "2021-03-19 13:25:34",
                    "positives": 49,
                    "sha256": "9b692f46029dede131518da13ea94528328bc24183d97218ab8d237837f01598",
                    "total": 76
                }
            ],
            "DetectedURLs": [
                {
                    "positives": 2,
                    "scan_date": "2021-04-11 11:17:31",
                    "total": 85,
                    "url": "http://example.com/"
                },
                {
                    "positives": 2,
                    "scan_date": "2021-04-10 14:06:18",
                    "total": 85,
                    "url": "https://example.com/blackhole/"
                },
                {
                    "positives": 2,
                    "scan_date": "2021-04-10 04:39:45",
                    "total": 85,
                    "url": "http://example.com/evil.ps1"
                },
                {
                    "positives": 2,
                    "scan_date": "2021-04-09 00:59:51",
                    "total": 85,
                    "url": "http://example.com/foo.jpg"
                },
                {
                    "positives": 1,
                    "scan_date": "2021-04-05 13:49:23",
                    "total": 85,
                    "url": "http://example.com/player?id=123"
                },
                {
                    "positives": 1,
                    "scan_date": "2021-04-03 13:53:06",
                    "total": 85,
                    "url": "http://example.com/foo/bar"
                },
                {
                    "positives": 1,
                    "scan_date": "2021-04-02 13:51:01",
                    "total": 85,
                    "url": "http://example.com/great-multiplication-intro.html"
                },
                {
                    "positives": 1,
                    "scan_date": "2021-03-30 07:21:30",
                    "total": 85,
                    "url": "https://example.com/"
                },
                {
                    "positives": 1,
                    "scan_date": "2021-03-26 16:20:25",
                    "total": 85,
                    "url": "http://example.com/z1vey0sjjfm"
                },
                {
                    "positives": 1,
                    "scan_date": "2021-03-24 04:02:11",
                    "total": 85,
                    "url": "http://example.com/music-videos/"
                },
                {
                    "positives": 1,
                    "scan_date": "2021-03-23 01:00:01",
                    "total": 85,
                    "url": "http://example.com/http"
                },
                {
                    "positives": 1,
                    "scan_date": "2021-03-16 03:39:30",
                    "total": 85,
                    "url": "http://example.com/?goal=0_1dfca2ec74-7d92b78da0-133981889&mc_cid=7d92b78da0&mc_eid=UNIQID"
                },
                {
                    "positives": 1,
                    "scan_date": "2021-03-14 17:59:45",
                    "total": 85,
                    "url": "https://example.com/?firstName=John&lastName=Adams&dateOfBirth=March%204,%201797&address=Braintree,%20MA"
                },
                {
                    "positives": 1,
                    "scan_date": "2021-03-13 03:14:44",
                    "total": 85,
                    "url": "https://yygelbbkauxnbcqliovy-dot-level-elevator-279110.nw.r.appspot.com%23example@example.com/"
                },
                {
                    "positives": 1,
                    "scan_date": "2021-03-12 03:00:59",
                    "total": 85,
                    "url": "http://example.com/ns/leafref"
                },
                {
                    "positives": 1,
                    "scan_date": "2021-03-12 02:54:31",
                    "total": 85,
                    "url": "http://example.com/media/orudie/orujeinaia-kollekciia-i-lichnoe-orujie-stalina-i-gitlera-5c0d1f3006bd7000abdb7c31/"
                },
                {
                    "positives": 1,
                    "scan_date": "2021-03-11 13:00:45",
                    "total": 85,
                    "url": "http://example.com/page.php"
                },
                {
                    "positives": 1,
                    "scan_date": "2021-03-10 10:20:23",
                    "total": 84,
                    "url": "http://example.com/@clickme"
                },
                {
                    "positives": 1,
                    "scan_date": "2021-03-10 02:22:07",
                    "total": 84,
                    "url": "http://example.com/login"
                },
                {
                    "positives": 1,
                    "scan_date": "2021-03-09 22:03:10",
                    "total": 84,
                    "url": "http://example.com/cancel/"
                },
                {
                    "positives": 1,
                    "scan_date": "2021-03-09 01:21:40",
                    "total": 84,
                    "url": "http://example.com/maps/"
                },
                {
                    "positives": 1,
                    "scan_date": "2021-03-07 11:41:07",
                    "total": 84,
                    "url": "http://example.com/media/nauka/amerikancy-sozdali-perchatki-chelovekapauka-5bb4833889643a00ad010bdb/"
                },
                {
                    "positives": 1,
                    "scan_date": "2021-03-07 10:49:34",
                    "total": 84,
                    "url": "http://example.com/downloads/7tt_setup.exe"
                },
                {
                    "positives": 1,
                    "scan_date": "2021-03-07 10:45:39",
                    "total": 84,
                    "url": "http://example.com/cmd_get/cmd_get.jsp"
                },
                {
                    "positives": 1,
                    "scan_date": "2021-03-06 15:16:46",
                    "total": 84,
                    "url": "https://example.com/foo/bar"
                },
                {
                    "positives": 1,
                    "scan_date": "2021-03-05 13:08:26",
                    "total": 84,
                    "url": "https://example.com/reauth"
                },
                {
                    "positives": 1,
                    "scan_date": "2021-03-04 05:34:22",
                    "total": 84,
                    "url": "https://example.com/example/path"
                },
                {
                    "positives": 1,
                    "scan_date": "2021-03-02 21:18:52",
                    "total": 84,
                    "url": "https://example.com/wp-content/plugins/wp-ticket/assets/ext/zebraform/process.php?form=f&control="
                },
                {
                    "positives": 1,
                    "scan_date": "2021-02-27 13:46:44",
                    "total": 84,
                    "url": "example.comhttp://example.com/files.lst.bz2"
                },
                {
                    "positives": 1,
                    "scan_date": "2021-02-20 09:41:25",
                    "total": 83,
                    "url": "http://example.com/maps/?freehaiku_stats=saskia99@famwinkel.nl&src=pnl"
                },
                {
                    "positives": 1,
                    "scan_date": "2021-02-19 17:43:05",
                    "total": 83,
                    "url": "http://example.com/files.lst.bz2"
                },
                {
                    "positives": 1,
                    "scan_date": "2021-02-17 11:35:45",
                    "total": 83,
                    "url": "https://example.com/app/uploads/2021/02/image_602cf5656e71a-150x150.jpg"
                },
                {
                    "positives": 1,
                    "scan_date": "2021-02-15 00:46:40",
                    "total": 83,
                    "url": "https://example.com/wp-content/plugins/wp-ticket/assets/ext/zebraform/process.php?form=f&control=</script><svg/onload=alert(/XSS-control"
                },
                {
                    "positives": 1,
                    "scan_date": "2021-02-14 10:19:23",
                    "total": 83,
                    "url": "http://example.com/clickme"
                },
                {
                    "positives": 1,
                    "scan_date": "2021-02-13 14:52:43",
                    "total": 83,
                    "url": "http://example.com/?a=1&b=2"
                },
                {
                    "positives": 1,
                    "scan_date": "2021-02-13 11:07:22",
                    "total": 83,
                    "url": "http://example.com/hop.php?/12345"
                },
                {
                    "positives": 1,
                    "scan_date": "2021-01-29 01:31:32",
                    "total": 83,
                    "url": "https://example.com/remoteDesktopGateway/"
                },
                {
                    "positives": 1,
                    "scan_date": "2021-01-23 05:18:11",
                    "total": 83,
                    "url": "https://example.com/evil.xsl"
                },
                {
                    "positives": 1,
                    "scan_date": "2021-01-19 10:17:45",
                    "total": 83,
                    "url": "https://example.com/route/that/will/404"
                },
                {
                    "positives": 1,
                    "scan_date": "2021-01-18 17:17:29",
                    "total": 83,
                    "url": "https://example.com/key/repo-key.gpg"
                },
                {
                    "positives": 1,
                    "scan_date": "2021-01-13 12:08:51",
                    "total": 83,
                    "url": "http://example.com/?q=..\\..\\log"
                },
                {
                    "positives": 1,
                    "scan_date": "2021-01-13 12:07:42",
                    "total": 83,
                    "url": "http://example.com/?q=<sCrIPt>aLerT()</sCripT>"
                },
                {
                    "positives": 1,
                    "scan_date": "2020-07-22 18:23:26",
                    "total": 79,
                    "url": "https://ncguyixqhjhoifmwcgjg-dot-level-elevator-279110.nw.r.appspot.com%23example@example.com/"
                },
                {
                    "positives": 1,
                    "scan_date": "2020-07-15 06:10:04",
                    "total": 79,
                    "url": "https://cloanfiwhugwxuasvjgh-dot-level-elevator-279110.nw.r.appspot.com%23example@example.com/"
                },
                {
                    "positives": 1,
                    "scan_date": "2019-01-02 16:53:24",
                    "total": 70,
                    "url": "http://example.com/media/usedcars/krossover-ot-datsun-za-235-tysiach-rublei-skoro-startuiut-prodaji-5c18d81892487b00aa3e270e/"
                },
                {
                    "positives": 1,
                    "scan_date": "2019-01-02 12:53:42",
                    "total": 70,
                    "url": "http://example.com/media/lubopytnaya_istoria/zverstva-nemcev-v-russkih-derevniah-5c288b5987b8d700aa621dc5/"
                },
                {
                    "positives": 1,
                    "scan_date": "2019-01-02 11:53:46",
                    "total": 70,
                    "url": "http://example.com/b/ss/undefined/1/JS-2.2.0/s74246280472176/"
                },
                {
                    "positives": 1,
                    "scan_date": "2019-01-01 01:52:25",
                    "total": 70,
                    "url": "http://example.com/b/ss/undefined/1/JS-2.2.0/s64779176403000/"
                },
                {
                    "positives": 1,
                    "scan_date": "2018-12-30 13:52:22",
                    "total": 70,
                    "url": "http://example.com/media/history_of_weapons/besshumnyi-revolver-gurevicha-s-jidkostnymi-patronami-5bdaac646fa35900ab19ba43/"
                },
                {
                    "positives": 1,
                    "scan_date": "2018-12-30 11:52:39",
                    "total": 70,
                    "url": "http://example.com/media/vzglyad_naroda/zapadnye-ukraincy-rasskazali-chto-gotovy-progolosovat-za-poroshenko-lish-by-ne-bylo-timoshenko-5c15ed4cb42df700ae52834f/"
                }
            ],
            "DownloadedHashes": [],
            "ReferrerHashes": [
                {
                    "date": "2021-04-13 12:03:36",
                    "positives": 2,
                    "sha256": "d3bee955045b8b38f32be52408d13995076c322fdb416991c905793e2394ee4a",
                    "total": 74
                },
                {
                    "date": "2018-08-26 07:38:59",
                    "positives": 16,
                    "sha256": "8c9bd61e30edfe0a5c1f17b0deaebd3a92f69bd319cb73fa9d7a10d187a6ff20",
                    "total": 71
                },
                {
                    "date": "2021-04-13 12:11:39",
                    "positives": 4,
                    "sha256": "a948e9d7923d45802d5343c1a1a9d127a3223f4cd002a3a56ce5fe6919a5de06",
                    "total": 74
                },
                {
                    "date": "2021-04-13 12:09:11",
                    "positives": 1,
                    "sha256": "d71de33f3f2a9df915e231ba9cc76fb5c024dada8301fc62bbeb41c0b07e5a15",
                    "total": 74
                },
                {
                    "date": "2021-04-13 12:04:59",
                    "positives": 31,
                    "sha256": "8f8e30556a96475a39234b2e03aa77a7a0a2716e9077d99c5784cb5c37ed67a0",
                    "total": 75
                },
                {
                    "date": "2021-04-13 12:05:10",
                    "positives": 2,
                    "sha256": "e49097755b5cc3b25ee3d7c590e6087dcd3e17962a7758313aac17fffa53583f",
                    "total": 74
                },
                {
                    "date": "2021-04-13 12:01:49",
                    "positives": 1,
                    "sha256": "4eef8b6e4f6f4808803b92f51f4a2d37b9ccaef1c18af62e5204641b3023c2f5",
                    "total": 73
                },
                {
                    "date": "2021-04-06 06:34:41",
                    "positives": 31,
                    "sha256": "52f79b45b79455b2a35c609c613c586197d1a2d09c5391861683680f43166b2d",
                    "total": 74
                },
                {
                    "date": "2021-04-13 11:59:01",
                    "positives": 53,
                    "sha256": "8c968e692366e2fad68120c8a4e81706dd9d105f15c47d7f4850b506b46b5dab",
                    "total": 75
                },
                {
                    "date": "2018-06-03 17:13:40",
                    "positives": 7,
                    "sha256": "8c949d2dd011a35ae7b6c5c0bb4e795dd90197189c2c5802aa7a63d5693f0765",
                    "total": 71
                },
                {
                    "date": "2021-04-13 11:35:09",
                    "positives": 51,
                    "sha256": "8ce04cbf12a0904cd86a59b8f6d49723e3d008cb45a5d060e264ade7a23aa136",
                    "total": 75
                },
                {
                    "date": "2021-04-13 11:47:58",
                    "positives": 1,
                    "sha256": "f3c2c933c1bf864d0723995ec580a931e788b6e625b5d3906be24995ac1e24a8",
                    "total": 74
                },
                {
                    "date": "2021-04-13 11:49:01",
                    "positives": 10,
                    "sha256": "569c74eaeb3ae682b11fcc6d047f0f4d9f24a27665478ac32510b77c798dc4ae",
                    "total": 74
                },
                {
                    "date": "2021-04-13 11:34:44",
                    "positives": 1,
                    "sha256": "f105e2f9f07c1a0ccb6dface42bf7e5aceed7ea1bed708f77960662ba57948c0",
                    "total": 74
                },
                {
                    "date": "2021-04-13 11:41:56",
                    "positives": 47,
                    "sha256": "8c9e609fc3b4fc55b79ee32f7f673897b4c9f8b538614730db7d5838f6ab00d3",
                    "total": 75
                },
                {
                    "date": "2018-05-07 17:04:23",
                    "positives": 35,
                    "sha256": "8c984efa63dcf0f25264d02b4235d70dd486b14a76d20607e001b1eb0996380a",
                    "total": 71
                },
                {
                    "date": "2021-04-13 11:35:00",
                    "positives": 1,
                    "sha256": "49e5120d299c41cb9e6de4661db6a990f2e013909c00b4955368f3442a8afc9b",
                    "total": 74
                },
                {
                    "date": "2021-04-06 11:36:16",
                    "positives": 2,
                    "sha256": "8a836b9e25320896fa970b4ec3a9d107fbabf35aa3711e6809863d9eacffd520",
                    "total": 74
                },
                {
                    "date": "2021-04-13 11:35:12",
                    "positives": 16,
                    "sha256": "e437c669788cd5d3714d3fcec89d69457ecd61adc3ce3b3451354c7c705fce9f",
                    "total": 74
                },
                {
                    "date": "2021-04-13 11:07:59",
                    "positives": 17,
                    "sha256": "c7c1d6fe52ffed91223284ac38b6e5ae089b268a145e2f9f11a47d35bd18f965",
                    "total": 74
                },
                {
                    "date": "2021-03-29 02:20:12",
                    "positives": 2,
                    "sha256": "b9f2c0da284ee280575d32dd84b3dac78c7a26988490fe101f18f39dfbc3e593",
                    "total": 74
                },
                {
                    "date": "2021-04-13 11:30:00",
                    "positives": 49,
                    "sha256": "6d16a19819ab3109a232fafe0e41065a71a5d6d5aa94621e0f6dc86ca9dbe211",
                    "total": 75
                },
                {
                    "date": "2021-03-29 02:13:56",
                    "positives": 4,
                    "sha256": "31865f8fa4485a5b0be98e0201695aa088bc990e91fdd7e76d4edcfc727d909b",
                    "total": 74
                },
                {
                    "date": "2021-04-13 11:24:03",
                    "positives": 53,
                    "sha256": "8c88519cc8e6fa7f6aa5aec64cac379926057eb18b34094a20c8100f66f38a6d",
                    "total": 75
                },
                {
                    "date": "2021-04-13 11:20:14",
                    "positives": 27,
                    "sha256": "8c924794d3923a6f51a496fc84a9f0037ce4f451e7c0fadb830cf76fa41e49c0",
                    "total": 74
                },
                {
                    "date": "2021-04-13 11:21:36",
                    "positives": 39,
                    "sha256": "8c8e4869d70d0330bb2d246157ac6eda4fafdb0a49f0b02be08602a6ec1dd762",
                    "total": 74
                },
                {
                    "date": "2021-04-13 11:17:53",
                    "positives": 38,
                    "sha256": "8c8972e2bab903ada41cb7e1d9db833b9ef7164d799c5d18a00b0f7e72ae7b91",
                    "total": 74
                },
                {
                    "date": "2021-04-13 11:12:39",
                    "positives": 55,
                    "sha256": "c71fed9fdcf7b01142792628d809a476a2a6cee7382425d3e4c1257b53605f98",
                    "total": 75
                },
                {
                    "date": "2021-04-13 11:11:40",
                    "positives": 55,
                    "sha256": "8c89bcab68f478830cd3b8e221060e6cf8f6986cd24c8be3e194c7b5bbf97917",
                    "total": 75
                },
                {
                    "date": "2021-04-13 11:04:54",
                    "positives": 59,
                    "sha256": "8bcdaa5c203e5b0e3625ffa74450e926afcf68fe884016f7dc8af5d9dc624588",
                    "total": 75
                },
                {
                    "date": "2021-04-13 11:05:05",
                    "positives": 58,
                    "sha256": "8bec045a9fd5a773a0003f59034c5f1f9aefcb58581410ace75076170b85ee93",
                    "total": 75
                },
                {
                    "date": "2021-04-13 11:05:08",
                    "positives": 58,
                    "sha256": "8bf5e163fdd195916e72c5a9292fb2c376354906b0fd3924e6416dc4e47aa632",
                    "total": 75
                },
                {
                    "date": "2021-04-13 11:04:52",
                    "positives": 56,
                    "sha256": "8bb65409c4b912be8eccc84e4c170c829b622832c930d972762905a1dfecfaf8",
                    "total": 75
                },
                {
                    "date": "2021-04-12 12:06:21",
                    "positives": 26,
                    "sha256": "8bda235e48d9da651e759a2a62ab9bb3a6952536e75c96eb5c163b728f5a167f",
                    "total": 75
                },
                {
                    "date": "2021-04-12 08:22:03",
                    "positives": 33,
                    "sha256": "8bbb95d7371101e68c47323d3a9aad2858e9bf76b5d46dcaab836c651dadcf1d",
                    "total": 75
                },
                {
                    "date": "2021-04-13 10:56:02",
                    "positives": 33,
                    "sha256": "8c91a402dc909ed3cf63e6a9586bf6e05ee518c4b693e64c902cf97816d150f7",
                    "total": 75
                },
                {
                    "date": "2021-04-13 10:56:06",
                    "positives": 3,
                    "sha256": "459d071829a5977e8c0f288be2cb473cd8cc44f450b65e8d8ddb240bccd59f84",
                    "total": 74
                }
            ],
            "Resolutions": [
                {
                    "ip_address": "x.x.x.x",
                    "last_resolved": "2013-07-27 00:00:00"
                },
                {
                    "ip_address": "x.x.x.x",
                    "last_resolved": "2019-11-04 09:44:13"
                },
                
            ],
            "Subdomains": [],
            "UnAVDetectedCommunicatingHashes": [
                {
                    "date": "2021-04-13 08:44:59",
                    "positives": 0,
                    "sha256": "9ff8e09233ae7d2a31e2af560d0f23c30046bb1cdd7a2fcb9393d09c6bd4a925",
                    "total": 74
                },
                {
                    "date": "2021-04-13 07:58:52",
                    "positives": 0,
                    "sha256": "9d5e14e02a3adcc7972e43279f4147ef8d2073a57f5698f2d93f626e8807d817",
                    "total": 0
                },
                {
                    "date": "2021-04-13 06:57:53",
                    "positives": 0,
                    "sha256": "33730737dff653312e84d12a3d524b8aa5e19aaf91068c40c04385e5a415936e",
                    "total": 73
                },
                {
                    "date": "2021-04-12 07:13:43",
                    "positives": 0,
                    "sha256": "cebffba34f248b5ed6cd672d9c191459d8bf519e04b0c692dc86c8df853444fc",
                    "total": 74
                },
                {
                    "date": "2021-04-12 06:00:33",
                    "positives": 0,
                    "sha256": "9aeb15a10958fb07c2fd42180340a60eacf6b5eae0cfdc6c9593401403be3400",
                    "total": 0
                },
                {
                    "date": "2021-04-12 05:20:43",
                    "positives": 0,
                    "sha256": "073b67c61e60bd0a704c2bfcf3e10a5544a055a0ee367b90412c1a1257a1d3da",
                    "total": 74
                },
                {
                    "date": "2021-04-11 08:36:18",
                    "positives": 0,
                    "sha256": "3958f0c07a3e9c0f476ab5b87360f40182c7fdca523b5cc69b6479a88a059452",
                    "total": 74
                },
                {
                    "date": "2021-04-10 05:13:04",
                    "positives": 0,
                    "sha256": "083fdacff6294ad3c2aa9722a2a211060961e47c348643ce5d87e9863a2b70b7",
                    "total": 0
                },
                {
                    "date": "2021-04-09 14:27:00",
                    "positives": 0,
                    "sha256": "8c2090b65d25bfc863033dfc9767ebbed9792ffb2e70a090f22aa4d689956cea",
                    "total": 74
                },
                {
                    "date": "2021-04-08 22:48:26",
                    "positives": 0,
                    "sha256": "2ec98d41654712f8e514ae4289c6a1c65f62a291b80c017cbf50e31393dbba2c",
                    "total": 74
                },
                {
                    "date": "2021-04-08 06:40:33",
                    "positives": 0,
                    "sha256": "c54867b37513970f1585b4176642e0b914cc104979e905e6add47dfb6899b79e",
                    "total": 74
                },
                {
                    "date": "2021-04-08 03:49:47",
                    "positives": 0,
                    "sha256": "81b85ab7f868a2644bf65f24dbea9a5d5fb0980add17602c0179f65ae4b24e9f",
                    "total": 73
                },
                {
                    "date": "2021-04-07 10:19:10",
                    "positives": 0,
                    "sha256": "a333e59a164cd8003029e07e57c8656710a8b52b885aae826351677c5bee3f5f",
                    "total": 0
                },
                {
                    "date": "2021-04-07 10:10:57",
                    "positives": 0,
                    "sha256": "2205fe299eb92849d17b0efc5cb53db1369be40a845f88d3f4908e394d647909",
                    "total": 74
                },
                {
                    "date": "2021-04-07 07:52:59",
                    "positives": 0,
                    "sha256": "ecf3fd62079f659d31ff2293e782e13c1acd16c6341757a788722467f6136911",
                    "total": 0
                },
                {
                    "date": "2021-04-05 14:16:28",
                    "positives": 0,
                    "sha256": "30f86152b3ed7f6255ca10b0568f6ac71ae4674fd146b250832fea7c08e12a28",
                    "total": 74
                },
                {
                    "date": "2021-04-04 14:02:52",
                    "positives": 0,
                    "sha256": "ff43358c0bbdc1fa21234eaab2d091f5cab07a08bbcfd2e9c4fbbb2c888b9bdd",
                    "total": 75
                },
                {
                    "date": "2021-04-05 12:21:35",
                    "positives": 0,
                    "sha256": "d1f8b548a13f9163404149b822623ef66b42259f1dbf822bb3f45e200e5df837",
                    "total": 74
                },
                {
                    "date": "2021-04-02 15:50:25",
                    "positives": 0,
                    "sha256": "32acedef4dade6fed034179f5ea7471ae8afb3c5a375ed8748088d686077523d",
                    "total": 73
                },
                {
                    "date": "2021-04-01 16:52:38",
                    "positives": 0,
                    "sha256": "28612ccdfbd56ff674d1a6a132ebdb60e370976b03fada2dc20b53bed3531758",
                    "total": 0
                },
                {
                    "date": "2021-03-24 03:31:15",
                    "positives": 0,
                    "sha256": "376ed48303a45425e95e674f7a59c05d58bbf897a97e1753a74a3ce448dfc6e3",
                    "total": 75
                },
                {
                    "date": "2021-03-24 03:31:17",
                    "positives": 0,
                    "sha256": "07e2f15e7c2805defa7b34ee8086114525c7a75921430792894a94dc17852579",
                    "total": 75
                },
                {
                    "date": "2021-03-30 17:21:48",
                    "positives": 0,
                    "sha256": "01a3ecb648878993c59ec4a8c5113df381985b359ec3620ed98a7082e5f1b8fa",
                    "total": 0
                },
                {
                    "date": "2021-03-30 12:00:51",
                    "positives": 0,
                    "sha256": "464220016d9d1475ed3e3a7460e37f0468733a70e76b4372b05a56a24e782a31",
                    "total": 72
                },
                {
                    "date": "2021-03-30 09:31:18",
                    "positives": 0,
                    "sha256": "a8234d9240264b17c0e202ef4a521451cf91a7436671472f539e23768597a3e7",
                    "total": 74
                },
                {
                    "date": "2021-03-30 01:19:33",
                    "positives": 0,
                    "sha256": "a378b9128082b3c311a3305448dbb13b6e85b121f164602befbd4f6b6cf64012",
                    "total": 75
                },
                {
                    "date": "2021-03-21 10:30:57",
                    "positives": 0,
                    "sha256": "ff05ea38620518bae86f9213ede8ceb43b23f71d299802e87c531c2391659e16",
                    "total": 75
                },
                {
                    "date": "2021-03-28 07:13:43",
                    "positives": 0,
                    "sha256": "1ef52b71b557b2f4de5112aa52bdcb9d27368434550bdc707cc3a70c3d30cf1c",
                    "total": 74
                },
                {
                    "date": "2021-03-27 18:51:47",
                    "positives": 0,
                    "sha256": "90b52b9d8be0110d19a1e66ff4afc88f161d8a42b00c2899b1461f204fce1ce2",
                    "total": 0
                },
                {
                    "date": "2021-03-27 16:06:34",
                    "positives": 0,
                    "sha256": "38bdf7ec57cd818363335e41e84e6557b88666a53547c5d9f43f98fc2d4654c6",
                    "total": 0
                },
                {
                    "date": "2021-03-27 12:09:44",
                    "positives": 0,
                    "sha256": "9ceb70eba03e49782693d42fb8bd7eeaa4dfef58ab6a74c25b7973dee9a393cb",
                    "total": 0
                },
                {
                    "date": "2021-03-27 07:31:00",
                    "positives": 0,
                    "sha256": "a2ded103297b1556dc1c65b78f2f38c9157b7f4ad45802118afe552385f49ee4",
                    "total": 74
                },
                {
                    "date": "2021-03-26 01:19:18",
                    "positives": 0,
                    "sha256": "72d1ebd2df546ed67f8ceb269c56a9db15b494a0b4694fe566e909fed8856887",
                    "total": 75
                },
                {
                    "date": "2021-03-25 04:51:39",
                    "positives": 0,
                    "sha256": "b7f2d0479a6ba57321a60162fddea73bc556d907bad1717af352badd967d0eb3",
                    "total": 74
                },
                {
                    "date": "2021-03-23 08:48:29",
                    "positives": 0,
                    "sha256": "8a788af40d529d8720725fdc3cf9e4dcd6819c2bbdc74040471a56235fe6ed44",
                    "total": 75
                },
                {
                    "date": "2021-03-23 04:55:34",
                    "positives": 0,
                    "sha256": "2c4fb6fdef39ca787e8ca8d07529e6ab14429c9c31e1e2717aa5bef38b40547d",
                    "total": 75
                },
                {
                    "date": "2021-03-22 07:45:37",
                    "positives": 0,
                    "sha256": "4a99fbf9d7c4ba70536ee59990f2b91b1c36ecda78b8075338441509d4165e0f",
                    "total": 75
                },
                {
                    "date": "2021-03-22 01:07:30",
                    "positives": 0,
                    "sha256": "edf70fcaa011f53a014f7ee65d66be0515fc8ee567b7b543f38c822f1cee2abf",
                    "total": 73
                },
                {
                    "date": "2021-03-22 01:06:33",
                    "positives": 0,
                    "sha256": "3eeae2cba7ca59ce61fa085ab3afa7c43894c181fd5c8ed00eebae2518e06561",
                    "total": 75
                },
                {
                    "date": "2021-03-22 01:04:33",
                    "positives": 0,
                    "sha256": "55fd6c3125e8fefc3a0a730c17d6895b6525451924a18777ec60ad69b02d7f9b",
                    "total": 75
                },
                {
                    "date": "2021-03-22 01:03:56",
                    "positives": 0,
                    "sha256": "f06586ecc69360c30f8634172208a12a894a1ad8f3b20ab910b59923e395b564",
                    "total": 73
                },
                {
                    "date": "2021-03-20 15:44:12",
                    "positives": 0,
                    "sha256": "3403b62ce4ad37a968bf9d3a841fa0a7f1f48b91da2c550b502a24a65cb9126e",
                    "total": 0
                },
                {
                    "date": "2021-03-20 12:20:08",
                    "positives": 0,
                    "sha256": "d55db1b78c494e80907f5ef249d6ef5ba895568e9370e2473cfe0fa47cc76aa0",
                    "total": 75
                },
                {
                    "date": "2021-03-18 00:46:08",
                    "positives": 0,
                    "sha256": "4d661d8e1257f35d4a3ff9fbb59e469e4a324c64a05fa65d246bb2479a86cee6",
                    "total": 0
                },
                {
                    "date": "2021-03-17 08:27:43",
                    "positives": 0,
                    "sha256": "2414ff9def2f33ac6c9adb8e4c56a1c79c6410940052faa15c91f619368ca945",
                    "total": 74
                },
                {
                    "date": "2021-03-17 02:51:59",
                    "positives": 0,
                    "sha256": "ec199cde83563c4bdf8551265054e3c558066933920f34c6a24e96508e6ab5af",
                    "total": 75
                },
                {
                    "date": "2021-03-16 21:44:35",
                    "positives": 0,
                    "sha256": "9961267c1210a290f43eaddbc9e1a68b1e15a15b964e841f68309a759c55e722",
                    "total": 75
                },
                {
                    "date": "2021-03-16 09:39:26",
                    "positives": 0,
                    "sha256": "926d501053710dd3bb6b8bc08f6432f633349fddc0f279cbc4c20ee5c1cf4293",
                    "total": 0
                },
                {
                    "date": "2021-03-16 07:52:37",
                    "positives": 0,
                    "sha256": "1c41d2657116754078cadc0d46d154e118cbf3bcdbb054ee19ca21a869ff71bb",
                    "total": 74
                },
                {
                    "date": "2021-03-15 22:43:10",
                    "positives": 0,
                    "sha256": "ff19eee38b60874aff7611df12870d3873cf79a9e7e478b849f2c77838e9115b",
                    "total": 73
                }
            ],
            "UnAVDetectedDownloadedHashes": [
                {
                    "date": "2021-03-27 08:16:44",
                    "positives": 0,
                    "sha256": "ea8fac7c65fb589b0d53560f5251f74f9e9b243478dcb6b3ea79b5e36449c8d9",
                    "total": 74
                },
                {
                    "date": "2019-06-11 23:35:41",
                    "positives": 0,
                    "sha256": "4ff8742a8007a9fd554675e6d94f94e72d74163871961952e44449cfb1907851",
                    "total": 71
                },
                {
                    "date": "2019-10-14 07:58:03",
                    "positives": 0,
                    "sha256": "3587cb776ce0e4e8237f215800b7dffba0f25865cb84550e87ea8bbac838c423",
                    "total": 70
                },
                {
                    "date": "2018-05-14 00:07:24",
                    "positives": 0,
                    "sha256": "1c11c4246b306b5d74cea14ff787b4763bd6413d9b8c37e40f20a6b21b603c79",
                    "total": 57
                },
                {
                    "date": "2018-05-03 00:06:02",
                    "positives": 0,
                    "sha256": "ba85b4903f044b3eb20df400f97f33d8ed96dd8d43edd9cb84e3bcfc900649ff",
                    "total": 60
                },
                {
                    "date": "2017-10-24 23:23:47",
                    "positives": 0,
                    "sha256": "d9f7e0aa1bff501986995b7c69742a14f373819ab6ecd599af29d67f9d8b4794",
                    "total": 60
                },
                {
                    "date": "2017-06-28 09:57:27",
                    "positives": 0,
                    "sha256": "991d8e217a039406c56753de79744d7a02c6a86ee2a97d740b8815e9f42c5d29",
                    "total": 56
                },
                {
                    "date": "2017-02-11 20:10:52",
                    "positives": 0,
                    "sha256": "2000f27da89d0034703895d71bb046b89b58ff64d08bf506824bd3bcae56b334",
                    "total": 55
                },
                {
                    "date": "2013-04-25 11:05:19",
                    "positives": 0,
                    "sha256": "9332592b1b6ee784ab0c775cbf511fb339c5687c21900bdbc9bb44a44aa330d3",
                    "total": 46
                }
            ],
            "UnAVDetectedReferrerHashes": [
                {
                    "date": "2021-04-13 12:10:17",
                    "positives": 0,
                    "sha256": "42d4d43c64d9f9d2238dd9f5eca711f1b429dcdc867fc3988e22fa1518a27cc3",
                    "total": 75
                },
                {
                    "date": "2021-04-13 12:08:08",
                    "positives": 0,
                    "sha256": "0e98240f3654c63cf599927b35a4ca30b2abbc13dd8b75936f7223be074e188c",
                    "total": 74
                },
                {
                    "date": "2021-04-13 12:02:48",
                    "positives": 0,
                    "sha256": "59fec080c5297cc6ca47a1c362aed12c63458f44eca2890871472c0a3e008309",
                    "total": 74
                },
                {
                    "date": "2021-04-13 11:57:36",
                    "positives": 0,
                    "sha256": "31ccb44717eeab6fa2d648f7161db368d3696d80d1adb3537d440c0dad2b67d9",
                    "total": 74
                },
                {
                    "date": "2021-04-13 11:43:34",
                    "positives": 0,
                    "sha256": "8b1a9566070e5d937a8b27394beeedbc50c3b390656ea7250bab9bac8c28840d",
                    "total": 74
                },
                {
                    "date": "2021-04-13 11:57:29",
                    "positives": 0,
                    "sha256": "405ecd80c2ef2618ac60a68d514498cc99a86f17ebd0a2c7478bb8d5700a04e3",
                    "total": 72
                },
                {
                    "date": "2021-04-13 11:53:58",
                    "positives": 0,
                    "sha256": "51660ab4e7e4c5588424577d34697f7b5d2474dfc376047ad7ada9dd38061b3c",
                    "total": 73
                },
                {
                    "date": "2021-04-13 11:42:46",
                    "positives": 0,
                    "sha256": "c0ae9cc4e8ace5539bdf82aeba8ef4b55489799639e0d88179cb671b50e733bc",
                    "total": 74
                },
                {
                    "date": "2021-04-13 11:51:54",
                    "positives": 0,
                    "sha256": "5689671d166dfb4859b1b9cc02d7af2f3dc6ace98f564a53993f9a2789a4c4a0",
                    "total": 74
                },
                {
                    "date": "2021-04-13 11:50:48",
                    "positives": 0,
                    "sha256": "6301b609b945297f02b33cd14c1ac6002177ed3b84da3ca84f6774ad30df1967",
                    "total": 74
                },
                {
                    "date": "2021-04-13 11:47:12",
                    "positives": 0,
                    "sha256": "f7248c83625c4ad8d1b9c3a0fdf23deff11cbff7c25d5b2942acba95e92a4e31",
                    "total": 74
                },
                {
                    "date": "2021-04-13 11:35:20",
                    "positives": 0,
                    "sha256": "76e5558fb3552de0bb7e4db65d2c0c3e9d41179a5e2ca1fd2dcd4bba4544e8d2",
                    "total": 74
                },
                {
                    "date": "2021-04-13 11:42:35",
                    "positives": 0,
                    "sha256": "8c7c6c2ad4be26fc24247c7c5b254cf520602e2b598fb648c6fc66faa5defbda",
                    "total": 74
                },
                {
                    "date": "2021-04-13 11:38:11",
                    "positives": 0,
                    "sha256": "ffad7aae49dd1349114b6efd2ca6c9fefba63cec5c8dbba6a73276fe7657df32",
                    "total": 74
                },
                {
                    "date": "2021-04-13 11:30:08",
                    "positives": 0,
                    "sha256": "12feafe949b47c97fe1f485b04e4643e7f0fd7e74259912795ee61d878c54fc3",
                    "total": 74
                },
                {
                    "date": "2021-04-13 11:10:42",
                    "positives": 0,
                    "sha256": "d8e24b79e82f272d2f07d16b900221cec8d89aa20958b9c31aaab23c25c73306",
                    "total": 74
                },
                {
                    "date": "2021-04-13 11:31:56",
                    "positives": 0,
                    "sha256": "4073952c7de8c93359294ebabaa072e0517f4e178d33b5470c5c59016e8c0b57",
                    "total": 73
                },
                {
                    "date": "2021-04-13 11:30:02",
                    "positives": 0,
                    "sha256": "c7802d36322159fbd4b0102fdd1ed2eab4c08c6cd864f5ebbca7a14120782ee9",
                    "total": 72
                },
                {
                    "date": "2021-04-13 10:56:04",
                    "positives": 0,
                    "sha256": "969dfdfa27ea0dd21b0d29a75e51dd0803a34c24f99e66fb5b7c14ac3871328b",
                    "total": 75
                },
                {
                    "date": "2021-04-13 11:17:39",
                    "positives": 0,
                    "sha256": "d9bcc103dfb10fc11c7c6f5360a377c8e5902040be6b4ad3fcc13d44d26cdfcc",
                    "total": 74
                },
                {
                    "date": "2021-04-13 11:22:02",
                    "positives": 0,
                    "sha256": "18c284237c17282ef786cd14d8b41b151458397661aaf46d9081745bb763a4de",
                    "total": 74
                },
                {
                    "date": "2021-04-13 11:12:49",
                    "positives": 0,
                    "sha256": "c6ce3196f8ebbaa8fd34efac23e742be0ceece3a637ae7ecdb0ea410237423d6",
                    "total": 74
                },
                {
                    "date": "2021-04-13 11:16:46",
                    "positives": 0,
                    "sha256": "08b310f469487c3e19e5ecb871aa16973be1adca882a87c1650eb49580086fcc",
                    "total": 74
                },
                {
                    "date": "2021-04-13 11:15:55",
                    "positives": 0,
                    "sha256": "e7e98804bc4aac970de3807e5b3e4b27eb8e8ee3c965b3883f52793991c3dba7",
                    "total": 74
                },
                {
                    "date": "2021-04-13 11:11:01",
                    "positives": 0,
                    "sha256": "166774884d53f94db1e0b1a058ff1c31a788df64580b72094f2e3b4712a6d105",
                    "total": 74
                },
                {
                    "date": "2021-04-13 11:11:28",
                    "positives": 0,
                    "sha256": "32761230ba1f96e63be016eaa95b2800057e4fe217d4bc9bd5e7a80967470129",
                    "total": 73
                },
                {
                    "date": "2021-04-13 10:51:33",
                    "positives": 0,
                    "sha256": "984eae0809959efd8d503e3b1b68d1bfef58df46f50357bcbbcab029cf7f3531",
                    "total": 74
                },
                {
                    "date": "2021-04-13 10:58:33",
                    "positives": 0,
                    "sha256": "0f3d1caadb32d9eba8759b8c7108ad04a596167adf15e9be3b493936f4b90265",
                    "total": 74
                },
                {
                    "date": "2021-04-13 10:58:57",
                    "positives": 0,
                    "sha256": "9e0a6f55801d11b354d6e372ab1da816ab2d982f7755725ce59442507062d946",
                    "total": 73
                },
                {
                    "date": "2021-04-13 10:55:31",
                    "positives": 0,
                    "sha256": "26531f10c9021541eadf37921805e49ef32dbf621a872f82b9a636ad70429086",
                    "total": 74
                },
                {
                    "date": "2021-04-13 10:53:13",
                    "positives": 0,
                    "sha256": "eb9834e0e22049e68f7b84bce3ac0da93f8396c958e77f4c886100e9f148e01e",
                    "total": 74
                },
                {
                    "date": "2021-04-13 10:46:18",
                    "positives": 0,
                    "sha256": "e68c0e2cfb2a2b33e5268f6343cbf0b68b8e332eb13d5b36bc5288b96f797be6",
                    "total": 74
                },
                {
                    "date": "2021-04-13 10:44:03",
                    "positives": 0,
                    "sha256": "f828458311f5c2020a559fb237d87e8be3a020debbe17ac7750aa8c07f05ef92",
                    "total": 74
                },
                {
                    "date": "2021-04-13 10:45:08",
                    "positives": 0,
                    "sha256": "151fce19a2131e99c396eb8616ffe9064fee2006b801f6efcd19acaba96752af",
                    "total": 74
                },
                {
                    "date": "2021-04-13 10:42:56",
                    "positives": 0,
                    "sha256": "b71a84c24023945b5e7d775cc953a58fc73212bfc07c9e3ea269c740f1bfa17f",
                    "total": 73
                },
                {
                    "date": "2021-04-13 10:39:14",
                    "positives": 0,
                    "sha256": "ce3af97a274fc0ff0c28d4025e3ba4da7e8c46eab088a9e6d2aa62b5dc34b8d2",
                    "total": 73
                },
                {
                    "date": "2021-04-13 10:38:19",
                    "positives": 0,
                    "sha256": "d28c11ec140cf749dcbd9f6f8f5c98a8bd8068770f586ba6ac9f53de81edd691",
                    "total": 74
                },
                {
                    "date": "2021-04-13 10:34:41",
                    "positives": 0,
                    "sha256": "fc8b6f2666973c890ed34b2dbd15e74d834ce761d2d82e048cb6b38797a18a71",
                    "total": 74
                },
                {
                    "date": "2021-04-13 10:34:25",
                    "positives": 0,
                    "sha256": "5753f0d3556c3c7ccdc3a16d21246f76c6ad323b2b55ceed5175960e7a6ea476",
                    "total": 74
                },
                {
                    "date": "2021-04-13 10:14:33",
                    "positives": 0,
                    "sha256": "02b1913e506dd88b5200ec3e846c46c7832ee8992045628706ca1cc87ad7d0ef",
                    "total": 74
                },
                {
                    "date": "2021-04-13 10:17:31",
                    "positives": 0,
                    "sha256": "ffc2ee00007156875f579937e07021e0fc493184018814520cb9430480054e33",
                    "total": 74
                },
                {
                    "date": "2021-04-13 10:03:38",
                    "positives": 0,
                    "sha256": "a714741710992455a1a71163755b2c8396a53a9882e5714864a6460b47f69d8e",
                    "total": 73
                },
                {
                    "date": "2021-04-13 10:10:43",
                    "positives": 0,
                    "sha256": "c58426d8cd15d978f4211678bb80056496184068850c3bbc532909efa55dabe9",
                    "total": 73
                },
                {
                    "date": "2021-04-13 10:06:16",
                    "positives": 0,
                    "sha256": "e6bef08d062627965174eb9f48ae2f6165d15c9804107a249f54f62a91204511",
                    "total": 73
                },
                {
                    "date": "2021-04-13 10:05:17",
                    "positives": 0,
                    "sha256": "670c1734c279205a4abafd18d859172f12083f6d1d33b2fc8a1a1b37f85c2458",
                    "total": 74
                },
                {
                    "date": "2021-04-13 10:00:17",
                    "positives": 0,
                    "sha256": "f52b47763375603157e3e79f290ab0ae5d6b2bef6c5d04861a9714043eac9555",
                    "total": 74
                },
                {
                    "date": "2021-04-13 09:59:06",
                    "positives": 0,
                    "sha256": "fc0a99614f754dc863528ceca5f166e3d81c9a641cae2f458e4972791b431db6",
                    "total": 74
                },
                {
                    "date": "2021-04-13 09:40:33",
                    "positives": 0,
                    "sha256": "63fb10579256883326391291c451de9ecd7e6831ed3edd51535376b882d5b333",
                    "total": 74
                },
                {
                    "date": "2021-04-13 09:31:56",
                    "positives": 0,
                    "sha256": "53afe10be3ef39bd2ba8233cd058057683dea6c02805011d5331ee7a795bb9ba",
                    "total": 74
                },
                {
                    "date": "2021-04-13 09:44:27",
                    "positives": 0,
                    "sha256": "3f3d834df6b986189780b68cc058ae239f6bd554bba4807a9c8e9a41a0df0266",
                    "total": 73
                }
            ],
            "Whois": "Creation Date: 1995-08-14T04:00:00Z\nDNSSEC: signedDelegation\nDomain Name: EXAMPLE.COM\nDomain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited\nDomain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\nDomain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited\nName Server: A.IANA-SERVERS.NET\nName Server: B.IANA-SERVERS.NET\nRegistrar IANA ID: 376\nRegistrar URL: http://example.example.org\nRegistrar WHOIS Server: whois.iana.org\nRegistrar: RESERVED-Internet Assigned Numbers Authority\nRegistry Domain ID: 2336799_DOMAIN_COM-VRSN\nRegistry Expiry Date: 2021-08-13T04:00:00Z\nUpdated Date: 2020-08-14T07:02:37Z\ncreated: 1992-01-01\ndomain: EXAMPLE.COM\norganisation: Internet Assigned Numbers Authority\nsource: IANA"
        }
    }
}
```

#### Human Readable Output

>## VirusTotal Domain Reputation for: example.com
>#### Domain categories: *undefined*
>VT Link: [example.com](https://www.virustotal.com/en/search?query=example.com)
>Detected URL count: **100**
>Detected downloaded sample count: **0**
>Undetected downloaded sample count: **9**
>Detected communicating sample count: **100**
>Undetected communicating sample count: **100**
>Detected referrer sample count: **100**
>Undetected referrer sample count: **100**
>Resolutions count: **4**
>### Whois Lookup
>**Creation Date**: 1995-08-14T04:00:00Z
>**DNSSEC**: signedDelegation
>**Domain Name**: EXAMPLE.COM
>**Domain Status**: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
>**Domain Status**: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
>**Domain Status**: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
>**Name Server**: A.IANA-SERVERS.NET
>**Name Server**: B.IANA-SERVERS.NET
>**Registrar IANA ID**: 376
>**Registrar URL**: http://example.example.org
>**Registrar WHOIS Server**: whois.iana.org
>**Registrar**: RESERVED-Internet Assigned Numbers Authority
>**Registry Domain ID**: 2336799_DOMAIN_COM-VRSN
>**Registry Expiry Date**: 2021-08-13T04:00:00Z
>**Updated Date**: 2020-08-14T07:02:37Z
>**created**: 1992-01-01
>**domain**: EXAMPLE.COM
>**organisation**: Internet Assigned Numbers Authority
>**source**: IANA


### file-scan
***
Submits a file for scanning.


#### Base Command

`file-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entryID | The file entry ID to submit. | Required | 
| uploadURL | Private API extension. Special upload URL for files larger than 32 MB. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| vtScanID | unknown | Scan IDs of the submitted files. | 
| vtLink | string | Virus Total permanent link. | 


#### Command Example
``` ```

#### Human Readable Output



### file-rescan
***
Re-scans an already submitted file. This avoids having to upload the file again.


#### Base Command

`file-rescan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | Hash of the file to re-scan. Supports MD5, SHA1, and SHA256. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| vtScanID | unknown | Scan IDs of the submitted files. | 
| vtLink | string | Virus Total permanent link. | 


#### Command Example
``` ```

#### Human Readable Output



### url-scan
***
Scans a specified URL.


#### Base Command

`url-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The URL to scan. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| vtScanID | unknown | Scan IDs of the submitted URLs. | 
| vtLink | string | Virus Total permanent link. | 


#### Command Example
```!url-scan url=https://example.com using=vt```

#### Context Example
```json
{
    "vtLink": [
        "https://www.virustotal.com/gui/url/0f115db062b7c0dd030b16878c99dea5c354b49dc37b38eb8846179c7783e9d7/detection/u-0f115db062b7c0dd030b16878c99dea5c354b49dc37b38eb8846179c7783e9d7-1618315592"
    ],
    "vtScanID": [
        "0f115db062b7c0dd030b16878c99dea5c354b49dc37b38eb8846179c7783e9d7-1618315592"
    ]
}
```

#### Human Readable Output

>## VirusTotal URL scan for: [https://example.com/](https://www.virustotal.com/gui/url/0f115db062b7c0dd030b16878c99dea5c354b49dc37b38eb8846179c7783e9d7/detection/u-0f115db062b7c0dd030b16878c99dea5c354b49dc37b38eb8846179c7783e9d7-1618315592)
>Scan ID: **0f115db062b7c0dd030b16878c99dea5c354b49dc37b38eb8846179c7783e9d7-1618315592**
>Scan Date: **2021-04-13 12:16:00**
>


### vt-comments-add
***
Adds comments to files and URLs.


#### Base Command

`vt-comments-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource | The file hash (MD5, SHA1, or SHA256) or URL on which you're commenting. | Required | 
| comment | The actual review, which you can tag by using the "#" twitter-like syntax, for example, #disinfection #zbot, and reference users using the "@" syntax, for example, @VirusTotalTeam). | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!vt-comments-add resource=paloaltonetworks.com resource_type=domain comment="this is a comment" using=vt```

#### Human Readable Output

>Invalid resource

### vt-file-scan-upload-url
***
Private API. Get a special URL for files larger than 32 MB.


#### Base Command

`vt-file-scan-upload-url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| vtUploadURL | unknown | The special upload URL for large files. | 


#### Command Example
``` ```

#### Human Readable Output



### vt-comments-get
***
Private API. Retrieves comments for a given resource.


#### Base Command

`vt-comments-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource | The file hash (MD5, SHA1, orSHA256) or URL from which you're retrieving comments. | Required | 
| before | Datetime token in the format YYYYMMDDHHMISS. You can use this for paging. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!vt-comments-get resource=https://paloaltonetworks.com using=vt```

#### Human Readable Output

