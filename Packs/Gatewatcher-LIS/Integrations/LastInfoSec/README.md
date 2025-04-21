This integration allow to interact with the Gatewatcher LastInfoSec product via API.
This integration was integrated and tested with version 2 of LastInfoSec.

## Configure LastInfoSec in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| LastInfoSec API token | The API Key to use for connection | True |
| Check the TLS certificate |  | False |
| Use system proxy settings |  | False |
| Integration Reliability | Reliability of the source providing the intelligence data | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### gw-lis-get-by-minute

***
Retrieve the data from Gatewatcher CTI feed by minute.
Max 1440 minutes.

#### Base Command

`gw-lis-get-by-minute`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| Minute |  Number of minutes to get.<br/>Max 1440 minutes. | Required | 
| Categories | Filter IoC by categories. Possible values are: phishing, malware, trojan, exploit, ransom, ransomware, tool, keylogger, agent, backdoor. | Optional | 
| Type | Filter IoC by type. Possible values are: SHA1, SHA256, MD5, URL, Host. | Optional | 
| Mode | Filter IoC by mode. Possible values are: detection, hunting. | Optional | 
| Risk | Filter IoC by risk. Possible values are: Malicious, Suspicious, High suspicious. | Optional | 
| TLP | Filter IoC by TLP. Possible values are: green, white. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LIS.GetByMinute.Value | String | Value. | 

#### Command example
```!gw-lis-get-by-minute Minute=10```
#### Context Example
```json
{
    "LIS": {
        "GetByMinute": [
            "http://103.182.16.23/900/HTMLcode.vbs",
            "http://103.182.16.23/900/i0ioi0iooioo0IOI0OIOIOiooioi00IOIoioioio0ioi0iOIOioiiOIoiOIOIOioIO0IOIO0.doc",
            "http://94.156.253.128/2144/io0Ioi0IOIOOIOi0i00ioioii0ioi0oiOII0OIO0OIOI0I0000%23%23%23%23%23%23%23%23%23%23%23%23%23%230000000%23%23%23%23%23%23%23%23%23%23%23%23%23%2300000000.doc",
        ]
    }
}
```

#### Human Readable Output

>### Get IoC by minute
>|Value|
>|---|
>| http:<span>//</span>103.182.16.23/900/HTMLcode.vbs |
>| http:<span>//</span>103.182.16.23/900/i0ioi0iooioo0IOI0OIOIOiooioi00IOIoioioio0ioi0iOIOioiiOIoiOIOIOioIO0IOIO0.doc |
>| http:<span>//</span>94.156.253.128/2144/io0Ioi0IOIOOIOi0i00ioioii0ioi0oiOII0OIO0OIOI0I0000%23%23%23%23%23%23%23%23%23%23%23%23%23%230000000%23%23%23%23%23%23%23%23%23%23%23%23%23%2300000000.doc |


### gw-lis-get-by-value

***
Allows you to search for an IOC (url, hash, host) or a vulnerability in the Gatewatcher CTI database. If the data is known, only the IOC corresponding to the value will be returned.

#### Base Command

`gw-lis-get-by-value`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| Value | Value to be search. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LIS.GetByValue.Categories | String | Categories. | 
| LIS.GetByValue.Risk | String | Risk. | 
| LIS.GetByValue.TLP | String | TLP. | 
| LIS.GetByValue.Type | String | Type. | 
| LIS.GetByValue.UsageMode | String | UsageMode. | 
| LIS.GetByValue.Value | String | Value. | 
| LIS.GetByValue.Vulnerabilities | String | Vulnerabilities. | 

#### Command example
```!gw-lis-get-by-value Value="58b525579968cba0c68e8f7ae12e51e0b5542acc2c14a2e75fa6df44556e373f"```
#### Context Example
```json
{
    "LIS": {
        "GetByValue": {
            "Categories": [
                "trojan",
                "malware",
                "agent"
            ],
            "Risk": "Suspicious",
            "TLP": "green",
            "Type": "SHA256",
            "UsageMode": "detection",
            "Value": "58b525579968cba0c68e8f7ae12e51e0b5542acc2c14a2e75fa6df44556e373f",
            "Vulnerabilities": []
        }
    }
}
```

#### Human Readable Output

>### Get IoC corresponding to the value
>|Categories|Risk|TLP|Type|UsageMode|Value|Vulnerabilities|
>|---|---|---|---|---|---|---|
>| trojan,<br/>malware,<br/>agent | Suspicious | green | SHA256 | detection | 58b525579968cba0c68e8f7ae12e51e0b5542acc2c14a2e75fa6df44556e373f |  |


### gw-lis-leaked-email-by-domain

***
Allows you to search for leaked emails via a domain in Gatewatcher's CTI database. If the data is found, a list of emails is returned. otherwise, nothing is returned.

#### Base Command

`gw-lis-leaked-email-by-domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| Domain | domain to be searched. | Required | 
| After | Only return emails that have leaked after this date (date format: 2023-01-15T10:00:00). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LIS.LeakedEmail.GetByDomain | String | leaked emails. | 

#### Command example
```!gw-lis-leaked-email-by-domain Domain=foobar.com```
#### Context Example
```json
{
    "LIS": {
        "LeakedEmail": {
            "GetByDomain": [
                "lucien@fr.foobar.com",
                "valerie@fr.foobar.com",
                "cyrille@nl.foobar.com",
                "patrique@us.foobar.com",
            ]
        }
    }
}
```

#### Human Readable Output

>### Leaked email
>|Emails|
>|---|
>| lucien@fr.foobar.com |
>| valerie@fr.foobar.com |
>| cyrille@nl.foobar.com |
>| patrique@us.foobar.com |


### gw-lis-is-email-leaked

***
Allows you to search if a specific email was leaked in Gatewatcher's CTI database. If the data is found, the email is returned. otherwise, nothing is returned.

#### Base Command

`gw-lis-is-email-leaked`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| Email | email to be searched. | Required | 
| After | Only return a value if the email has leaked after this date (date format: 2023-01-15T10:00:00). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LIS.LeakedEmail.GetByEmail | String | leaked email. | 

#### Command example
```!gw-lis-is-email-leaked Email=lucien@fr.foobar.com```
#### Context Example
```json
{
    "LIS": {
        "LeakedEmail": {
            "GetByEmail": "lucien@fr.foobar.com"
        }
    }
}
```

#### Human Readable Output

>### Is email leaked
>|Value|
>|---|
>| lucien@fr.foobar.com |


### url

***
search IOCs for URLs in Gatewatcher's CTI database.

#### Base Command

`url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | list of URLs to search for, (comma separated values). | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| URL.Data | String | The URL. | 
| URL.Description | String | Description of the URL. | 
| URL.TrafficLightProtocol | String | TLP level. | 
| LIS.URL.Categories | String | Categories matching this url. | 
| LIS.URL.Risk | String | Risk associated to this URL. | 
| LIS.URL.TLP | String | TLP level. | 
| LIS.URL.UsageMode | String | Usage mode for LIS. | 
| LIS.URL.Value | String | The URL. | 
| LIS.URL.Vulnerabilities | String | Vulnerabilities associated to this URL. | 

#### Command example
```!url url=http://217.196.96.84/WatchDog.exe```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "http://217.196.96.84/WatchDog.exe",
        "Reliability": "B - Usually reliable",
        "Score": 2,
        "Type": "url",
        "Vendor": "LastInfoSec"
    },
    "LIS": {
        "URL": {
            "Categories": [
                "malware"
            ],
            "Risk": "Suspicious",
            "TLP": "green",
            "Type": "URL",
            "UsageMode": "detection",
            "Value": "http://217.196.96.84/WatchDog.exe",
            "Vulnerabilities": []
        }
    },
    "URL": {
        "Data": "http://217.196.96.84/WatchDog.exe",
        "Description": "'http://217.196.96.84/WatchDog.exe' is a Suspicious URL. It is linked to a PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows file with a size of 62.0322265625 KB.\nThis URL is linked to a malware attack.\nThe related TTP is: T1027.002 .\nWe advised to use this IoC in detection mode.",
        "TrafficLightProtocol": "green"
    }
}
```

#### Human Readable Output

>### Get IoC corresponding to the value
>|Categories|Risk|TLP|Type|UsageMode|Value|Vulnerabilities|
>|---|---|---|---|---|---|---|
>| malware | Suspicious | green | URL | detection | http:<span>//</span>217.196.96.84/WatchDog.exe |  |


### file

***
search IOCs for file hashes in Gatewatcher's CTI database.

#### Base Command

`file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | list of files to search for, (comma separated values). | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| File.Hashes | String | List of hashes for this file. | 
| File.Imphash | String | Imphash of the file. | 
| File.SSDeep | String | SSDeep of the file. | 
| File.TrafficLightProtocol | String | TLP level. | 
| File.Type | String | Type of file. | 
| File.MD5 | String | MD5 of the file. | 
| File.SHA1 | String | SHA1 of the file. | 
| File.SHA256 | String | SHA256 of the file. | 
| File.SHA512 | String | SHA512 of the file. | 
| LIS.File.Categories | String | Categories matching this file. | 
| LIS.File.Risk | String | Risk associated to this file. | 
| LIS.File.TLP | String | TLP level. | 
| LIS.File.UsageMode | String | Usage mode for LIS. | 
| LIS.File.Value | String | Hash of the file. | 
| LIS.File.Vulnerabilities | String | Vulnerabilities associated to this file. | 
| DBotScore.Indicator | String | The indicator that was tested. | 

#### Command example
```!file file=58b525579968cba0c68e8f7ae12e51e0b5542acc2c14a2e75fa6df44556e373f```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "58b525579968cba0c68e8f7ae12e51e0b5542acc2c14a2e75fa6df44556e373f",
        "Reliability": "B - Usually reliable",
        "Score": 2,
        "Type": "file",
        "Vendor": "LastInfoSec"
    },
    "File": {
        "Hashes": [
            {
                "type": "SHA256",
                "value": "58b525579968cba0c68e8f7ae12e51e0b5542acc2c14a2e75fa6df44556e373f"
            },
            {
                "type": "SSDeep",
                "value": "1536:zhu9D+Oy/Dn/hP8PGTzBwZ6YWKSO5T3rZvSwEKSK99jzpma:zhu9WL/hEPeGU5S5TbZawEKSK99jVH"
            },
            {
                "type": "Imphash",
                "value": "3:rGsLdAIEK:tf"
            }
        ],
        "Imphash": "3:rGsLdAIEK:tf",
        "SHA256": "58b525579968cba0c68e8f7ae12e51e0b5542acc2c14a2e75fa6df44556e373f",
        "SSDeep": "1536:zhu9D+Oy/Dn/hP8PGTzBwZ6YWKSO5T3rZvSwEKSK99jzpma:zhu9WL/hEPeGU5S5TbZawEKSK99jVH",
        "TrafficLightProtocol": "green",
        "Type": "PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows"
    },
    "LIS": {
        "File": {
            "Categories": [
                "trojan",
                "malware",
                "agent"
            ],
            "Risk": "Suspicious",
            "TLP": "green",
            "Type": "SHA256",
            "UsageMode": "detection",
            "Value": "58b525579968cba0c68e8f7ae12e51e0b5542acc2c14a2e75fa6df44556e373f",
            "Vulnerabilities": []
        }
    }
}
```

#### Human Readable Output

>### Get IoC corresponding to the value
>|Categories|Risk|TLP|Type|UsageMode|Value|Vulnerabilities|
>|---|---|---|---|---|---|---|
>| trojan,<br/>malware,<br/>agent | Suspicious | green | SHA256 | detection | 58b525579968cba0c68e8f7ae12e51e0b5542acc2c14a2e75fa6df44556e373f |  |


### domain

***
search IOCs for domains in Gatewatcher's CTI database.

#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | list of domains to search for, (comma separated values). | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| Domain.Name | String | Domain found. | 
| Domain.Description | String | description of the domain. | 
| Domain.TrafficLightProtocol | String | TLP level. | 
| LIS.Domain.Categories | String | Categories matching this domain. | 
| LIS.Domain.Risk | String | Risk associated to this domain. | 
| LIS.Domain.TLP | String | TLP level. | 
| LIS.Domain.Type | String | Type of domain. | 
| LIS.Domain.UsageMode | String | Usage mode for LIS. | 
| LIS.Domain.Value | String | The domain name. | 
| LIS.Domain.Vulnerabilities | String | Vulnerabilities associated to this domain. | 

#### Command example
```!domain domain=kopabayport.co.tz```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "kopabayport.co.tz",
        "Reliability": "B - Usually reliable",
        "Score": 2,
        "Type": "domain",
        "Vendor": "LastInfoSec"
    },
    "Domain": {
        "Description": "'kopabayport.co.tz' is a Suspicious Host.\nThis Host is linked to a malware attack.\nWe advised to use this IoC in detection mode.",
        "Name": "kopabayport.co.tz",
        "TrafficLightProtocol": "green"
    },
    "LIS": {
        "Domain": {
            "Categories": [
                "malware"
            ],
            "Risk": "Suspicious",
            "TLP": "green",
            "Type": "Host",
            "UsageMode": "detection",
            "Value": "kopabayport.co.tz",
            "Vulnerabilities": []
        }
    }
}
```

#### Human Readable Output

>### Get IoC corresponding to the value
>|Categories|Risk|TLP|Type|UsageMode|Value|Vulnerabilities|
>|---|---|---|---|---|---|---|
>| malware | Suspicious | green | Host | detection | kopabayport.co.tz |  |