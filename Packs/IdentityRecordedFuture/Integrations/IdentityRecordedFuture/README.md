Unique threat intel technology that automatically serves up relevant insights in real time.
Recorded Future Identity




## Configure Recorded Future Identity on Cortex XSOAR

## Information




A valid API Token for Recorded Future Identity Intelligence needed to fetch information.
[Get help with Recorded Future for Cortex XSOAR](https://www.recordedfuture.com/integrations/).

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Recorded Future Identity.
3. Click **Add instance** to create and configure a new integration instance.

---

## Configuration




| Parameter                        | Description                                                       |
|----------------------------------|-------------------------------------------------------------------|
| Server URL                       | The URL to the Recorded Future ConnectAPI                         |
| API Token                        | Valid API Token from Recorded Future                              |
| unsecure                         | Trust any certificate \(unsecure\)                                |
| proxy                            | Use system proxy settings                                         |
| Password properties              | Password properties that are used as a filter                     |
| Limit Identities                 | Limit of identities to get min is 0 and max is 10 000             |
| Domains                          | List of domains to use in search and lookup commands(e.g. mycompany.com, nextcompany.com )|



4. Click **Test** to validate the URLs, token, and connection.

Several of the outputs below have been reduced in size to improve readability.

## Commands




You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.




### recordedfuture-identity-search




***
Get a list of identities for the specified period of time.


#### Base Command

`recordedfuture-identity-search`




#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| latest-downloaded | Time frame for the leaked identities          | Optional |
| domain-type       | Type of the domain(Email, Authorization, All) | Optional |
| domains           | Domains separated by comma (if not specified, domains from app instance will be used) | Optional |



#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RecordedFuture.Credentials.SearchIdentities | List | List of Identities that were found in search command |



#### Command Example




```!recordedfuture-identity-search latest-downloaded="All time" domain-type=Authorization```

#### Context Example




```
{
    "RecordedFuture": {
        "Credentials": {
            "SearchIdentities": [
                {
                    "login": "30fake",
                    "domain": "fakeyahoo.com"
                },
                {
                    "login": "3072882fake",
                    "domain": "fakeyahoo.com"
                },
                "fake3@fake.com",
                "test@fakeyahoo.com"
            ]
        }
    }
}
```

#### Human Readable Output

>##### This is search results for fakeyahoo.com, fake.com :
>
>
>
>
>- **30fake**  in domain  fakeyahoo.com
>- **3072882fake**  in domain  fakeyahoo.com
>- **fake3@fake.com**
>- **test@fakeyahoo.com**

### recordedfuture-identity-lookup




***
Get a detailed info regarding identities.


#### Base Command

`recordedfuture-identity-lookup`




#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identities        | String of identities separated by comma   | Required |
| first-downloaded  | Time frame for the leaked identities      | Optional |
| domains           | Domains separated by comma                | Optional |



#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RecordedFuture.Credentials.Identities.identity.subjects | string | Identity value |
| RecordedFuture.Credentials.Identities.count | number | Leaked credentials count number |
| RecordedFuture.Credentials.Identities.credentials.subject | string | Identity value |
| RecordedFuture.Credentials.Identities.credentials.dumps.name | string | Dump name |
| RecordedFuture.Credentials.Identities.credentials.dumps.description | string | Dump description |
| RecordedFuture.Credentials.Identities.credentials.dumps.downloaded | string | Datetime string that show the day when dump was downloaded |
| RecordedFuture.Credentials.Identities.credentials.type | string | Dump type |
| RecordedFuture.Credentials.Identities.credentials.breaches.name | string | Breach name |
| RecordedFuture.Credentials.Identities.credentials.breaches.domain | string | Breach domain |
| RecordedFuture.Credentials.Identities.credentials.breaches.type | string | Breach type |
| RecordedFuture.Credentials.Identities.credentials.breaches.breached | string | Datetime string that show the day when breach happened |
| RecordedFuture.Credentials.Identities.credentials.breaches.description | string | Breach description |
| RecordedFuture.Credentials.Identities.credentials.breaches.site_description | string | Breach site description |
| RecordedFuture.Credentials.Identities.credentials.first_downloaded | string | Datetime string representing firs time downloaded |
| RecordedFuture.Credentials.Identities.credentials.latest_downloaded | string | Datetime string representing last time downloaded |
| RecordedFuture.Credentials.Identities.credentials.exposed_secret.type | string | Exposed secret type |
| RecordedFuture.Credentials.Identities.credentials.exposed_secret.hashes.algorithm | string | Exposed secret hash algorithm |
| RecordedFuture.Credentials.Identities.credentials.exposed_secret.hashes.hash | string | Exposed secret hash value |
| RecordedFuture.Credentials.Identities.credentials.exposed_secret.effectively_clear | boolean | Exposed secret clear or not |
| RecordedFuture.Credentials.Identities.credentials.exposed_secret.details.properties | string | Exposed secret properties |
| RecordedFuture.Credentials.Identities.credentials.exposed_secret.details.clear_text_hint | string | Exposed secret text hint |
| RecordedFuture.Credentials.Identities.credentials.exposed_secret.details.rank | string | Rank for the exposed password |


#### Command Example




```!recordedfuture-identity-lookup identities="fake@fakeyahoo.com,real@notfake.com" first-downloaded="3 Months ago"```

#### Context Example




```
{
    "RecordedFuture": {
        "Credentials": {
            "Identities": [
                {
                    "identity":{
                        "subjects":[
                            "fake@yahoo.com"
                        ]
                    },
                    "count":4,
                    "credentials":[
                        {
                            "subject":"fake@yahoo.com",
                            "dumps":[
                                {
                                    "name":"FAKE Dump November 2020",
                                    "description":"This SQL Dump linked to the 2020",
                                    "downloaded":"2020-11-05T00:00:00.000Z",
                                    "type":"SQL Dump",
                                    "breaches":[
                                        {
                                            "name":"FAKE",
                                            "domain":"fake.com",
                                            "type":"breach",
                                            "breached":"2020-10-01T00:00:00.000Z",
                                            "description":"In October 2020, fake suffered a breach that exposed a portion of their backup data from November 2017. The exposed data included",
                                            "site_description":"Fale provides backup and related services for mobile devices."
                                        }
                                    ]
                                }
                            ],
                            "first_downloaded":"2020-11-05T00:00:00.000Z",
                            "latest_downloaded":"2020-11-05T00:00:00.000Z",
                            "exposed_secret":{
                                "type":"pbkdf2_sha256",
                                "hashes":[
                                    {
                                        "algorithm":"PBKDF2_SHA256",
                                        "hash":"12000$IWIs9x2tM7U3afasdasd3d23nRfo0sFRjpkMlim2GA2+p/2Y7RQLpODP4S0="
                                    }
                                ],
                                "effectively_clear":false
                            }
                        },
                        {
                            "subject":"fake@yahoo.com",
                            "dumps":[
                                {
                                    "name":"Dark Web Dump October 2019",
                                    "description":"This combo list of email addresses and clear passwords is not associated with any specific breach",
                                    "downloaded":"2019-10-31T00:00:00.000Z",
                                    "type":"Combo List"
                                },
                                {
                                    "name":"Dark Web Dump September 2019",
                                    "description":"This combo list of email addresses and clear passwords is not associated with any specific breach..",
                                    "downloaded":"2019-09-02T00:00:00.000Z",
                                    "type":"Combo List"
                                }
                            ],
                            "first_downloaded":"2019-09-02T00:00:00.000Z",
                            "latest_downloaded":"2019-10-31T00:00:00.000Z",
                            "exposed_secret":{
                                "type":"clear",
                                "hashes":[
                                    {
                                        "algorithm":"SHA1",
                                        "hash":"bbebf4e24e6631570cd8f60e1b0f77c"
                                    },
                                    {
                                        "algorithm":"SHA256",
                                        "hash":"7bf5626ca4944595aa89bf5fdsdfsdf9c9a1e9b014356d9b10ef31c9e9aadc7835e4"
                                    },
                                    {
                                        "algorithm":"NTLM",
                                        "hash":"1b408e981311312e21eefc0f5e37a20808"
                                    },
                                    {
                                        "algorithm":"MD5",
                                        "hash":"a6b9607b296pfk941dd390d9e690ade8e"
                                    }
                                ],
                                "details":{
                                    "properties":[
                                        "Letter",
                                        "Number",
                                        "UpperCase",
                                        "LowerCase",
                                        "AtLeast8Characters"
                                    ],
                                    "clear_text_hint":"oo"
                                },
                                "effectively_clear":true
                            }
                        }
                    ]
                },
                {
                    "identity":{
                        "subjects":[
                            "007"
                        ]
                    },
                    "count":1,
                    "credentials":[
                        {
                            "subject":"007",
                            "dumps":[
                                {
                                    "name":"Dark Web Password Dump 2020-11-07"
                                },
                                {
                                    "name":"Dark Web Password Dump 2020-09-28"
                                }
                            ],
                            "first_downloaded":"2020-09-28T15:52:05.000Z",
                            "latest_downloaded":"2020-11-07T08:38:56.000Z",
                            "exposed_secret":{
                                "type":"clear",
                                "hashes":[
                                    {
                                        "algorithm":"SHA1",
                                        "hash":"6204f1659eb8dasdas871be7f4b3ee560207bda2c5"
                                    },
                                    {
                                        "algorithm":"SHA256",
                                        "hash":"2fff03500b9335t4g5427fa105aa0bb0d5b3e770d314352aef010b6ae0dff7ab9a"
                                    },
                                    {
                                        "algorithm":"NTLM",
                                        "hash":"a2abf21c7669d58137kffsa83381d55cc"
                                    },
                                    {
                                        "algorithm":"MD5",
                                        "hash":"c399d3ec33214df310b11dcb30b1b5e03"
                                    }
                                ],
                                "details":{
                                    "properties":[
                                        "Letter",
                                        "LowerCase"
                                    ],
                                    "clear_text_hint":"lo"
                                },
                                "effectively_clear":true
                            },
                            "compromise":{
                                "exfiltration_date":"2020-11-07T08:38:56.000Z"
                            },
                            "authorization_service":{
                                "url":"https://login.fakeyahoo.com/",
                                "domain":"fakeyahoo.com"
                            }
                        }
                    ]
                }
            ]
        }
    }
}
```

#### Human Readable Output

>## Credentials Lookup




>*****

>## Results for **fake1@fake.com**:


>## Results for **fake1@fake.com**:

>## Results for __fake1@fake.com__:

>## Results for **fake1@fake.com**:


>## Results for **fake1@fake.com**:

>## We found 1 passwords that were leaked for this identity:




>*****
>*****




>## Password 1:




>Rank: TopMillionCommonPasswords
>
>Properties: Letter, Number, LowerCase, AtLeast8Characters
>
>Type: clear
>
>Effectively Clear: True
>
>Clear Text Hint: wa
>
>Algorithm: SHA1 	 Hash:21b1ee2d6764b61b038605378f361599a8b503ed
>
>Algorithm: SHA256 	 Hash:99dbda619dfd82cf9dae074b5c3168e75961b642f3245fe7f400ad03940a0bd8
>
>Algorithm: NTLM 	 Hash:da89071afe87527dc0e89a09d35cb9c0
>
>Algorithm: MD5 	 Hash:a0b1c21221b29780fc5e3373e626ab9b
>
>Authorization service url: <https://signup.norsegods.online/signup>
>Authorization service url: <https://signup.norsegods.online/signup>
>Authorization service url: https://signup.norsegods.online/signup
>Authorization service url: <https://signup.norsegods.online/signup>
>Authorization service url: <https://signup.norsegods.online/signup>
>
>Domain: norsegods.online
>
>First Downloaded: Nov 2022
>
>Last Downloaded: Nov 2022
>
>Exfiltration date: N/A
>
>Malware Family: RedLine Stealer
>
>## Information about dumps where we found for Password 1:




>*****
> Stealer Malware Logs 2022-11-03, Nov 2022
>
>Description: This credential data was derived from stealer malware logs.
>Dump type: N/A
>
>Compromised Host
>	Operating System: Windows 10 Enterprise x64
>
>	OS User Name: gabi2
>
>	File Path Location: C:\Windows\Microsoft.NET\Framework\v4.0.30319\AppLaunch.exe
>
>	Time Zone: UTC+01:00
>
>	Name of the Machine: N/A
>
>	User Account Control Setting: AllowAll
>
>	Antivirus: Windows Defender
>
>IP Address: 138.255.250.246
>
>Country: DO
>
>Postal Code: 11403

`recordedfuture-password-lookup`




#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| password-hash    | Hash representation of password                          | Required |
| hash-algorithm   | Hash algorithm for the password(MD5, NTLM, SHA1, SHA256) | Required |



#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RecordedFuture.Credentials.Password.Password.Hash | String | Recorded Future password hash value. |
| RecordedFuture.Credentials.Password.Password.Algorithm | String | Recorded Future password hash algorithm. |
| RecordedFuture.Credentials.Password.ExposureStatus | String | Recorded Future password exposure status. One of Common, UnCommon, NeverExposed |


#### Command Example




```!recordedfuture-password-lookup password-hash="0e44ce7308af2b3de5232e4616403ce7d49ba2aec83f79c196409556422a4927" hash-algorithm="SHA256"```

exposure_status:NeverExposed
algorithm:SHA256
hash:da6a0f1c706df7e864f9d6f9431de9950450880e

#### Context Example




```
{
    "RecordedFuture": {
        "Credentials": {
            "Password": [
                {
                    "password": {
                        "algorithm": "SHA256"
                        "hash": "da6a0f1c706df7e864f9d6f9431de9950450880e"
                    }
                    "exposure_status": NeverExposed
                },
                {
                    "password": {
                        "algorithm": "SHA256"
                        "hash": "0e44ce7308af2b3de5232e4616403ce7d49ba2aec83f79c196409556422a"
                    }
                    "exposure_status": Common
                },
            ]
        }
    }
}
```

#### Human Readable Output

>## This is search results for password you provided:




>Password hash: 0e44ce7308af2b3de5232e4616403ce7d49ba2aec83f79c196409556422a4927
>
>Password hash algorithm: SHA256
>
>Password status: Common
