This integration fetches indicators from the USTA Threat Stream feed. The indicators can be of type malicious URLs or malware hashes.
This integration was integrated and tested with version 4.1.0 of FeedUstaThreatStream.

## Configure USTA Threat Stream IOC Feed on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for USTA Threat Stream IOC Feed.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Fetch indicators |  | False |
    | Server's URL |  | True |
    | API Key | The API Key to use for connection | True |
    | IOC Feed Type |  | True |
    | Indicator Reputation | Indicators from this integration instance will be marked with this reputation | False |
    | Source Reliability | Reliability of the source providing the intelligence data | True |
    | Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |
    | Feed Fetch Interval |  | False |
    | Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    |  |  | False |
    |  |  | False |
    | Tags | Supports CSV values. | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### usta-tsa-search-malware-hash

***
Search malware hash indicators from the feed.

#### Base Command

`usta-tsa-search-malware-hash`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. Default is 10. | Optional | 
| hash | The hash to search for. It can be a SHA-1, SHA-256, or MD5 hash. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| USTA.ThreatStreamMalwareHashes.id | String | The ID of the alert | 
| USTA.ThreatStreamMalwareHashes.hashes[0].sha256 | String | The SHA-256 hash of the malware | 
| USTA.ThreatStreamMalwareHashes.hashes[0].md5 | String | The MD5 hash of the malware | 
| USTA.ThreatStreamMalwareHashes.hashes[0].sha1 | String | The SHA-1 hash of the malware | 
| USTA.ThreatStreamMalwareHashes.tags | Array | The tags of the malware | 
| USTA.ThreatStreamMalwareHashes.created | Date | The creation date of the malware | 
| USTA.ThreatStreamMalwareHashes.valid_from | Date | The valid from date of the malware | 
| USTA.ThreatStreamMalwareHashes.valid_until | Date | The valid until date of the malware | 

### Command Example

```!usta-tsa-search-malware-hash hash=d5d8c33957e90d1caca4b5207d8da5ab1bc4caa9f702abc0ec006d0518ea9aec```

### Context Example

```json
{
    "USTA" :{
        "ThreatStreamMalwareHashes":[
             {
                "id": "bf89614f-0ec8-4a88-a4e7-085b113a871b",
                "hashes": {
                    "sha256": "d5d8c33957e90d1caca4b5207d8da5ab1bc4caa9f702abc0ec006d0518ea9aec",
                    "sha1": "659661291eb5fd6452d6cabdc24cd9fbc1fb17f7",
                    "md5": "4a15ed0feb9e90b56e82c2e45a3b3f5e"
                },
                "tags": [
                    "SnakeKeylogger"
                ],
                "valid_from": "2024-11-22T07:30:07.000Z",
                "valid_until": "2025-11-22T07:30:07.000Z",
                "created": "2024-11-22T07:37:40.729Z"
            }
        ]
    }
}
```

### usta-tsa-search-malicious-url

***
Search malicious URL indicators from the feed.

#### Base Command

`usta-tsa-search-malicious-url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. Default is 10. | Optional | 
| url | The URL to search for. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| USTA.ThreatStreamMaliciousUrls.id | String | The ID of the alert | 
| USTA.ThreatStreamMaliciousUrls.url | String | The URL of the malicious site | 
| USTA.ThreatStreamMaliciousUrls.is_domain | Boolean | Whether the malicious site is a domain | 
| USTA.ThreatStreamMaliciousUrls.ip_addresses | Array | The IP addresses of the malicious site | 
| USTA.ThreatStreamMaliciousUrls.tags | Array | The tags of the malicious site | 
| USTA.ThreatStreamMaliciousUrls.created | Date | The creation date of the malicious site | 
| USTA.ThreatStreamMaliciousUrls.valid_from | Date | The valid from date of the malicious site | 
| USTA.ThreatStreamMaliciousUrls.valid_until | Date | The valid until date of the malicious site | 

### Command Example

```!usta-tsa-search-malicious-url url=http://192.168.100.1:38082/i```

### Context Example

```json

{
    "USTA" :{
        "ThreatStreamMaliciousUrls":[
             {
                "id": "28cffb9a-add5-480c-8968-539863695770",
                "url": "http://192.168.100.1:38082/i",
                "host": "192.168.100.1",
                "is_domain": false,
                "ip_addresses": [
                    "192.168.100.1"
                ],
                "tags": [
                    "elf.mozi"
                ],
                "valid_from": "2024-11-22T07:24:06.000Z",
                "valid_until": "2025-11-22T07:24:06.000Z",
                "created": "2024-11-22T08:30:03.055Z"
            }
        ]
    }
}
```

### usta-tsa-search-phishing-site

***
Search malicious URL indicators from the feed.

#### Base Command

`usta-tsa-search-phishing-site`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. Default is 10. | Optional | 
| url | The URL to search for. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| USTA.ThreatStreamPhishingSites.id | String | The ID of the alert | 
| USTA.ThreatStreamPhishingSites.url | String | The URL of the phishing site | 
| USTA.ThreatStreamPhishingSites.is_domain | Boolean | Whether the phishing site is a domain | 
| USTA.ThreatStreamPhishingSites.ip_addresses | Array | The IP addresses of the phishing site | 
| USTA.ThreatStreamPhishingSites.created | Date | The creation date of the phishing site | 

### Command Example

```!usta-tsa-search-phishing-site url=example.com```

### Context Example

```json
{
    "USTA" :{
        "ThreatStreamMaliciousUrls":[
            {
                "id": 219286,
                "url": "https://example.com",
                "host": "example.com",
                "is_domain": true,
                "ip_addresses": [
                    "192.168.100.1"
                ],
                "country": null,
                "created": "2024-02-05T15:23:11.646011Z"
            }
        ]
    }
}
```