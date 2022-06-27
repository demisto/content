Use the IOCParser integration to extract IOCs and intelligence from different data sources.
This integration was integrated and tested with version v1 of IOCParser

## Configure IOCParser on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for IOCParser.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Use system proxy settings | False |
    | Trust any certificate (not secure) | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ioc-parser-parse-url
***
Parses and extracts IOCs from a given URL.


#### Base Command

`ioc-parser-parse-url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The URL from which the IOCs will be extracted. | Required | 
| keys | IOC Types to return. The supported types are 'ASN', 'BITCOIN_ADDRESS', 'CVE', 'DOMAIN', 'EMAIL', 'FILE_HASH_MD5', 'FILE_HASH_SHA1', 'FILE_HASH_SHA256', 'IPV4', 'IPV6', 'MAC_ADDRESS', 'MITRE_ATT&amp;CK', 'URL', 'YARA_RULE'. | Optional | 
| limit | limits the results to the specified number. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IOCParser.parseFromUrl | String | All IOCs that were parsed from the URL. | 


#### Command Example
```ioc-parser-parse-url url=https://example.com/url```

#### Human Readable Output



### ioc-parser-parse-text
***
Parses and extracts IOCs from a given JSON.


#### Base Command

`ioc-parser-parse-text`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| data | The JSON from which the IOCs will be extracted. | Required | 
| keys | IOC Types to return. The supported types are 'ASN', 'BITCOIN_ADDRESS', 'CVE', 'DOMAIN', 'EMAIL', 'FILE_HASH_MD5', 'FILE_HASH_SHA1', 'FILE_HASH_SHA256', 'IPV4', 'IPV6', 'MAC_ADDRESS', 'MITRE_ATT&amp;CK', 'URL', 'YARA_RULE'. | Optional | 
| limit | limits the results to the specified number. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IOCParser.parseFromJSONText | Unknown | All IOCs that were parsed from the JSON text. | 


#### Command Example
```ioc-parser-parse-text data={"example": ["jsontext"]}```

#### Human Readable Output



### ioc-parser-parse-raw-text
***
Parses and extracts IOCs from a given text.


#### Base Command

`ioc-parser-parse-raw-text`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| data | The text from which the IOCs will be extracted. If an entry ID is supplied, do not use this argument. | Optional | 
| keys | IOC Types to return. The supported types are 'ASN', 'BITCOIN_ADDRESS', 'CVE', 'DOMAIN', 'EMAIL', 'FILE_HASH_MD5', 'FILE_HASH_SHA1', 'FILE_HASH_SHA256', 'IPV4', 'IPV6', 'MAC_ADDRESS', 'MITRE_ATT&amp;CK', 'URL', 'YARA_RULE'. | Optional | 
| limit | limits the results to the specified number. | Optional | 
| entry_id | The text file from which the IOCs will be extracted. If data is supplied, do not use this argument. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IOCParser.parseFromRawText | Unknown | All IOCs that were parsed from the raw text. | 


#### Command Example
```ioc-parser-parse-raw-text data=raw data example```
```ioc-parser-parse-raw-text entry_id=@123```

#### Human Readable Output



### ioc-parser-parse-twitter
***
Parses and extracts IOCs from a given twitter account.


#### Base Command

`ioc-parser-parse-twitter`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| data | The twitter account (user name) from which the IOCs will be extracted. | Required | 
| keys | IOC Types to return. The supported types are 'ASN', 'BITCOIN_ADDRESS', 'CVE', 'DOMAIN', 'EMAIL', 'FILE_HASH_MD5', 'FILE_HASH_SHA1', 'FILE_HASH_SHA256', 'IPV4', 'IPV6', 'MAC_ADDRESS', 'MITRE_ATT&amp;CK', 'URL', 'YARA_RULE'. | Optional | 
| limit | limits the results to the specified number. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IOCParser.parseFromTwitter | Unknown | All IOCs that were parsed from the twitter account. | 


#### Command Example
```ioc-parser-parse-twitter data=example```

#### Human Readable Output


