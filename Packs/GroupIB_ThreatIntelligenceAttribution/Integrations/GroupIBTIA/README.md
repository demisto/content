




Pack helps to integrate Group-IB Threat Intelligence and get incidents directly into Cortex XSOAR. 
The list of included collections:
Compromised Accounts, Compromised Cards, Brand Protection Phishing, Brand Protection Phishing Kit, OSI Git Leak, OSI Public Leak, Targeted Malware.
This integration was integrated and tested with version 1.0 of Group-IB Threat Intelligence

## Configure Group-IB Threat Intelligence in Cortex


| **Parameter**                  | **Description** | **Required** |
|--------------------------------| --- | --- |
| GIB TI  URL                    | The FQDN/IP the integration should connect to. | True |
| Username                       | The API Key and Username required to authenticate to the service. | True |
| Trust any certificate (not secure) | Whether to allow connections without verifying SSL certificates validity. | False |
| Use system proxy settings      | Whether to use XSOAR system proxy settings to connect to the API. | False |
| Colletions to fetch            | Type\(s\) of incidents to fetch from the third party API. | False |
| Incidents first fetch          | Date to start fetching incidents from. | False |
| Number of requests per collection | A number of requests per collection that integration sends in one faetch iteration \(each request picks up to 200 incidents\). If you face some runtime errors, lower the value. | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### gibtia-get-compromised-account-info

***
Command performs Group IB event lookup in compromised/account collection with provided ID.


#### Base Command

`gibtia-get-compromised-account-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | GIB event id.<br/>e.g.: 253b9a136f0d574149fc43691eaf7ae27aff141a. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTIA.CompromisedAccount.client.ipv4.asn | String | Victim IP address | 
| GIBTIA.CompromisedAccount.client.ipv4.countryName | String | Country name | 
| GIBTIA.CompromisedAccount.client.ipv4.ip | String | Victim IP address | 
| GIBTIA.CompromisedAccount.client.ipv4.region | String | Region name | 
| GIBTIA.CompromisedAccount.cnc.domain | String | Event CNC domain | 
| GIBTIA.CompromisedAccount.cnc.url | String | CNC URL | 
| GIBTIA.CompromisedAccount.cnc.ipv4.ip | String | CNC IP address | 
| GIBTIA.CompromisedAccount.dateCompromised | Date | Date of compromise | 
| GIBTIA.CompromisedAccount.dateDetected | Date | Date of detection | 
| GIBTIA.CompromisedAccount.dropEmail.email | String | Email where compromised data were sent to | 
| GIBTIA.CompromisedAccount.dropEmail.domain | String | Email domain | 
| GIBTIA.CompromisedAccount.login | String | Compromised login | 
| GIBTIA.CompromisedAccount.password | String | Compromised password | 
| GIBTIA.CompromisedAccount.malware.name | String | Malware name | 
| GIBTIA.CompromisedAccount.malware.id | String | Group IB malware ID | 
| GIBTIA.CompromisedAccount.person.name | String | Card owner name | 
| GIBTIA.CompromisedAccount.person.email | String | Card owner e-mail | 
| GIBTIA.CompromisedAccount.portalLink | String | Link to GIB incident | 
| GIBTIA.CompromisedAccount.threatActor.name | String | Associated threat actor | 
| GIBTIA.CompromisedAccount.threatActor.isAPT | Boolean | Is threat actor APT group | 
| GIBTIA.CompromisedAccount.threatActor.id | String | Threat actor GIB ID | 
| GIBTIA.CompromisedAccount.id | String | Group IB incident ID | 
| GIBTIA.CompromisedAccount.evaluation.severity | String | Event severity | 


#### Command Example

```!gibtia-get-compromised-account-info id=253b9a136f0d574149fc43691eaf7ae27aff141a```

#### Context Example

```json
{
    "DBotScore": [
        {
            "Indicator": "http://some.ru",
            "Score": 3,
            "Type": "url",
            "Vendor": "GIB TI&A"
        },
        {
            "Indicator": "some.ru",
            "Score": 3,
            "Type": "domain",
            "Vendor": "GIB TI&A"
        },
        {
            "Indicator": "11.11.11.11",
            "Score": 3,
            "Type": "ip",
            "Vendor": "GIB TI&A"
        }
    ],
    "Domain": {
        "Malicious": {
            "Description": null,
            "Vendor": "GIB TI&A"
        },
        "Name": "some.ru"
    },
    "GIBTIA": {
        "CompromisedAccount": {
            "botId": null,
            "client": {
                "ipv4": {
                    "asn": null,
                    "city": null,
                    "countryCode": null,
                    "countryName": null,
                    "ip": "0.0.0.0",
                    "provider": null,
                    "region": null
                }
            },
            "cnc": {
                "cnc": "http://some.ru",
                "domain": "some.ru",
                "ipv4": {
                    "asn": "AS1111",
                    "city": "Moscow",
                    "countryCode": "RU",
                    "countryName": "Russian Federation",
                    "ip": "11.11.11.11",
                    "provider": "some.ru",
                    "region": "Moscow"
                },
                "ipv6": null,
                "url": "http://some.ru"
            },
            "company": null,
            "companyId": -1,
            "dateCompromised": null,
            "dateDetected": "2020-02-22T01:21:03+00:00",
            "device": null,
            "domain": "some.ru",
            "dropEmail": {
                "domain": null,
                "email": "",
                "ipv4": {
                    "asn": null,
                    "city": null,
                    "countryCode": null,
                    "countryName": null,
                    "ip": null,
                    "provider": null,
                    "region": null
                }
            },
            "evaluation": {
                "admiraltyCode": "A2",
                "credibility": 80,
                "reliability": 100,
                "severity": "red",
                "tlp": "red",
                "ttl": 90
            },
            "favouriteForCompanies": [],
            "hideForCompanies": [],
            "id": "253b9a136f0d574149fc43691eaf7ae27aff141a",
            "login": "some.ru",
            "malware": {
                "id": "411ac9df6c5515922a56e30013e8b8b366eeec80",
                "name": "PredatorStealer",
                "stixGuid": "2f7650f4-bc72-2068-d1a5-467b688975d8"
            },
            "oldId": "396792583",
            "password": "@some@",
            "person": {
                "address": null,
                "birthday": null,
                "city": null,
                "countryCode": null,
                "email": null,
                "name": null,
                "passport": null,
                "phone": null,
                "state": null,
                "taxNumber": null,
                "zip": null
            },
            "port": null,
            "portalLink": "https://bt.group-ib.com/cd/accounts?searchValue=id:253b9a136f0d574149fc43691eaf7ae27aff141a",
            "silentInsert": 0,
            "sourceLink": "",
            "sourceType": "Botnet",
            "stixGuid": "8abb3aa9-e351-f837-d61a-856901c3dc9d",
            "threatActor": null
        }
    },
    "IP": {
        "ASN": "AS11111",
        "Address": "11.11.11.11",
        "Geo": {
            "Country": "Russian Federation",
            "Description": "Moscow City"
        },
        "Malicious": {
            "Description": null,
            "Vendor": "GIB TI&A"
        }
    },
    "URL": {
        "Data": "http://some.ru",
        "Malicious": {
            "Description": null,
            "Vendor": "GIB TI&A"
        }
    }
}
```

#### Human Readable Output

>### Feed from compromised/account with ID 253b9a136f0d574149fc43691eaf7ae27aff141a

>|client ipv4 ip|cnc cnc|cnc domain|cnc ipv4 asn|cnc ipv4 city|cnc ipv4 countryCode|cnc ipv4 countryName|cnc ipv4 ip|cnc ipv4 provider|cnc ipv4 region|cnc url|companyId|dateDetected|domain|evaluation admiraltyCode|evaluation credibility|evaluation reliability|evaluation severity|evaluation tlp|evaluation ttl|id|login|malware id|malware name|malware stixGuid|oldId|password|portalLink|silentInsert|sourceType|stixGuid|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 0.0.0.0 | <http://some.ru> | some.ru | AS1111 | Moscow | RU | Russian Federation | 11.11.11.11 | some.ru | Moscow | http://some.ru | -1 | 2020-02-22T01:21:03+00:00 | some.ru | A2 | 80 | 100 | red | red | 90 | 253b9a136f0d574149fc43691eaf7ae27aff141a | some.ru | 411ac9df6c5515922a56e30013e8b8b366eeec80 | PredatorStealer | 2f7650f4-bc72-2068-d1a5-467b688975d8 | 396792583 | @some@ | <https://bt.group-ib.com/cd/accounts?searchValue=id:253b9a136f0d574149fc43691eaf7ae27aff141a> | 0 | Botnet | 8abb3aa9-e351-f837-d61a-856901c3dc9d |

>### URL indicator

>|gibid|severity|value|
>|---|---|---|
>| 253b9a136f0d574149fc43691eaf7ae27aff141a | red | <http://some.ru> |

>### Domain indicator

>|gibid|severity|value|
>|---|---|---|
>| 253b9a136f0d574149fc43691eaf7ae27aff141a | red | some.ru |

>### IP indicator

>|asn|geocountry|geolocation|gibid|severity|value|
>|---|---|---|---|---|---|
>| AS1111 | Russian Federation | Moscow | 253b9a136f0d574149fc43691eaf7ae27aff141a | red | 11.11.11.11 |



### gibtia-get-compromised-card-info

***
Command performs Group IB event lookup in compromised/card collection with provided ID.


#### Base Command

`gibtia-get-compromised-card-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | GIB event id.<br/>e.g.: ecda6f4dc85596f447314ce01e2152db9c9d3cbc. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTIA.CompromisedCard.cardInfo.cvv | String | Compromised card CVV | 
| GIBTIA.CompromisedCard.cardInfo.issuer.issuer | String | Card issuer | 
| GIBTIA.CompromisedCard.cardInfo.number | String | Compromised card number | 
| GIBTIA.CompromisedCard.cardInfo.system | String | Payment system | 
| GIBTIA.CompromisedCard.cardInfo.type | String | Internal issuer card type | 
| GIBTIA.CompromisedCard.cardInfo.validThru | String | Card expiration date | 
| GIBTIA.CompromisedCard.client.ipv4.asn | String | Compromised client ASN | 
| GIBTIA.CompromisedCard.client.ipv4.countryName | String | Country name | 
| GIBTIA.CompromisedCard.client.ipv4.ip | String | Victim IP address | 
| GIBTIA.CompromisedCard.client.ipv4.region | String | Region name | 
| GIBTIA.CompromisedCard.dateCompromised | Date | Date of compromise | 
| GIBTIA.CompromisedCard.dateDetected | Date | Date detected | 
| GIBTIA.CompromisedCard.malware.name | String | Related malware name | 
| GIBTIA.CompromisedCard.malware.id | String | Related GIB malware ID | 
| GIBTIA.CompromisedCard.portalLink | String | Link to GIB incident | 
| GIBTIA.CompromisedCard.threatActor.name | String | Associated  threat actor | 
| GIBTIA.CompromisedCard.threatActor.isAPT | Boolean | Is threat actor APT group | 
| GIBTIA.CompromisedCard.threatActor.id | String | Threat actor GIB ID | 
| GIBTIA.CompromisedCard.id | String | Group IB incident ID | 
| GIBTIA.CompromisedCard.sourceType | String | Information source | 
| GIBTIA.CompromisedCard.evaluation.severity | String | Event severity | 


#### Command Example

```!gibtia-get-compromised-card-info id=ecda6f4dc85596f447314ce01e2152db9c9d3cbc```

#### Context Example

```json
{
    "DBotScore": [
        {
            "Indicator": "some.ru",
            "Score": 3,
            "Type": "domain",
            "Vendor": "GIB TI&A"
        },
        {
            "Indicator": "11.11.11.11",
            "Score": 3,
            "Type": "ip",
            "Vendor": "GIB TI&A"
        }
    ],
    "Domain": {
        "Malicious": {
            "Description": null,
            "Vendor": "GIB TI&A"
        },
        "Name": "some.ru"
    },
    "GIBTIA": {
        "CompromisedCard": {
            "baseName": "United States",
            "cardInfo": {
                "cvv": null,
                "dump": null,
                "issuer": {
                    "countryCode": "US",
                    "countryName": "UNITED STATES",
                    "issuer": "SOME BANK"
                },
                "number": "XXXXXXXXXXXXXXXX",
                "system": "VISA",
                "type": "CLASSIC",
                "validThru": "01/2021"
            },
            "client": {
                "ipv4": {
                    "asn": null,
                    "city": null,
                    "countryCode": null,
                    "countryName": null,
                    "ip": null,
                    "provider": null,
                    "region": null
                }
            },
            "cnc": {
                "cnc": "some.ru",
                "domain": "some.ru",
                "ipv4": {
                    "asn": null,
                    "city": "Some",
                    "countryCode": "US",
                    "countryName": "United States",
                    "ip": "11.11.11.11",
                    "provider": "Some",
                    "region": "Some"
                },
                "ipv6": null,
                "url": null
            },
            "company": null,
            "companyId": -1,
            "dateCompromised": "2020-02-22T12:21:00+00:00",
            "dateDetected": "2020-01-11T10:12:49+00:00",
            "evaluation": {
                "admiraltyCode": "A2",
                "credibility": 80,
                "reliability": 90,
                "severity": "red",
                "tlp": "red",
                "ttl": 90
            },
            "externalId": "26579",
            "favouriteForCompanies": [],
            "hideForCompanies": [],
            "id": "ecda6f4dc85596f447314ce01e2152db9c9d3cbc",
            "ignoreForCompanies": [],
            "isDump": false,
            "isExpired": false,
            "isIgnore": false,
            "isMasked": true,
            "malware": {
                "id": "53013c863116aae720581ff2aa2b4f92d3cb2bd7",
                "name": "mandarincc",
                "stixGuid": "8c843ab8-f019-e455-c78b-47ee80f3bb0c"
            },
            "oldId": "396798216",
            "owner": {
                "address": null,
                "birthday": null,
                "city": "Some",
                "countryCode": "US",
                "email": null,
                "name": "Some Person",
                "passport": null,
                "phone": "111111",
                "state": "Some",
                "taxNumber": null,
                "zip": null
            },
            "portalLink": "https://bt.group-ib.com/cd/cards?searchValue=id:ecda6f4dc85596f447314ce01e2152db9c9d3cbc",
            "price": {
                "currency": "USD",
                "value": "1"
            },
            "serviceCode": null,
            "silentInsert": 1,
            "sourceLink": "",
            "sourceType": "Card shop",
            "stixGuid": "00eccda0-aae6-c111-6080-c51f857450bf",
            "threatActor": null,
            "track": []
        }
    },
    "IP": {
        "Address": "11.11.11.11",
        "Geo": {
            "Country": "United States",
            "Description": "Some"
        },
        "Malicious": {
            "Description": null,
            "Vendor": "GIB TI&A"
        }
    }
}
```

#### Human Readable Output

>### Feed from compromised/card with ID ecda6f4dc85596f447314ce01e2152db9c9d3cbc

>|baseName|cardInfo issuer countryCode|cardInfo issuer countryName|cardInfo issuer issuer|cardInfo number|cardInfo system|cardInfo type|cardInfo validThru|cnc cnc|cnc domain|cnc ipv4 city|cnc ipv4 countryCode|cnc ipv4 countryName|cnc ipv4 ip|cnc ipv4 provider|cnc ipv4 region|companyId|dateCompromised|dateDetected|evaluation admiraltyCode|evaluation credibility|evaluation reliability|evaluation severity|evaluation tlp|evaluation ttl|externalId|id|isDump|isExpired|isIgnore|isMasked|malware id|malware name|malware stixGuid|oldId|owner city|owner countryCode|owner name|owner phone|owner state|portalLink|price currency|price value|silentInsert|sourceType|stixGuid|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| United States | US | UNITED STATES | SOME BANK | XXXXXXXXXXXXXXXX | VISA | CLASSIC | 01/2021 | some.ru | some.ru | Some | US | United States | 11.11.11.11 | Some | Some | -1 | 2020-02-22T12:21:00+00:00 | 2020-01-11T10:12:49+00:00 | A2 | 80 | 90 | red | red | 90 | 26579 | ecda6f4dc85596f447314ce01e2152db9c9d3cbc | false | false | false | true | 53013c863116aae720581ff2aa2b4f92d3cb2bd7 | mandarincc | 8c843ab8-f019-e455-c78b-47ee80f3bb0c | 396798216 | Some | US | Some Person | 111111 | Some | <https://bt.group-ib.com/cd/cards?searchValue=id:ecda6f4dc85596f447314ce01e2152db9c9d3cbc> | USD | 1 | 1 | Card shop | 00eccda0-aae6-c111-6080-c51f857450bf |

>### Domain indicator

>|gibid|severity|value|
>|---|---|---|
>| ecda6f4dc85596f447314ce01e2152db9c9d3cbc | red | some.ru |

>### IP indicator

>|geocountry|geolocation|gibid|severity|value|
>|---|---|---|---|---|
>| United States | Some | ecda6f4dc85596f447314ce01e2152db9c9d3cbc | red | 11.11.11.11 |



### gibtia-get-compromised-breached-info

***
Command performs Group IB event lookup in compromised/breached collection with provided ID.


#### Base Command

`gibtia-get-compromised-breached-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | GIB event id.<br/>e.g.: 6fd344f340f4bdc08548cb36ded62bdf. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTIA.DataBreach.email | String | List of breached emails | 
| GIBTIA.DataBreach.leakName | String | Name of the leak | 
| GIBTIA.DataBreach.password | String | List of breached passwords | 
| GIBTIA.DataBreach.uploadTime | Date | Date of breached data upload | 
| GIBTIA.DataBreach.id | String | Group IB incident ID | 
| GIBTIA.DataBreach.evaluation.severity | String | Event severity | 


#### Command Example

```!gibtia-get-compromised-breached-info id=277c4112d348c91f6dabe9467f0d18ba```

#### Context Example

```json
{
    "GIBTIA": {
        "DataBreach": {
            "addInfo": {
                "address": [
                    ""
                ],
            },
            "description": "",
            "downloadLinkList": [],
            "email": [
                "some@gmail.com"
            ],
            "evaluation": {
                "admiraltyCode": "C3",
                "credibility": 50,
                "reliability": 50,
                "severity": "green",
                "tlp": "amber",
                "ttl": null
            },
            "id": "277c4112d348c91f6dabe9467f0d18ba",
            "leakName": "some.com",
            "leakPublished": "",
            "password": [
                "AC91C480FDE9D7ACB8AC4B78310EB2TD",
                "1390DDDFA28AE085D23518A035703112"
            ],
            "reaperMessageId": "",
            "taName": [],
            "uploadTime": "2021-06-12T03:02:00"
        }
    }
}
```

#### Human Readable Output

>### Feed from compromised/breached with ID 277c4112d348c91f6dabe9467f0d18ba

>|addInfo|email|evaluation|id|leakName|password|uploadTime|
>|---|---|---|---|---|---|---|
>| address: <br/> | some@gmail.com | admiraltyCode: C3<br/>credibility: 50<br/>reliability: 50<br/>severity: green<br/>tlp: amber<br/>ttl: null | 277c4112d348c91f6dabe9467f0d18ba | some.com | AC91C480FDE9D7ACB8AC4B78310EB2TD,<br/>1390DDDFA28AE085D23518A035703112 | 2021-06-12T03:02:00 |



### gibtia-get-compromised-mule-info

***
Command performs Group IB event lookup in compromised/mule collection with provided ID.


#### Base Command

`gibtia-get-compromised-mule-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | GIB event id.<br/>e.g.: 50a3b4abbfca5dcbec9c8b3a110598f61ba93r33. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTIA.CompromisedMule.account | String | Account number \(card/phone\), which was used by threat actor to cash out | 
| GIBTIA.CompromisedMule.cnc.ipv4.asn | String | CNC ASN | 
| GIBTIA.CompromisedMule.cnc.ipv4.countryName | String | Country name | 
| GIBTIA.CompromisedMule.cnc.ipv4.ip | String | Victim IP address | 
| GIBTIA.CompromisedMule.cnc.ipv4.region | String | Region name | 
| GIBTIA.CompromisedMule.cnc.url | String | CNC URL | 
| GIBTIA.CompromisedMule.cnc.domain | String | CNC domain | 
| GIBTIA.CompromisedMule.dateAdd | Date | Date of detection | 
| GIBTIA.CompromisedMule.malware.name | String | Malware name | 
| GIBTIA.CompromisedMule.portalLink | String | Link to GIB incident | 
| GIBTIA.CompromisedMule.threatActor.name | String | Associated threat actor | 
| GIBTIA.CompromisedMule.threatActor.id | String | Threat actor GIB ID | 
| GIBTIA.CompromisedMule.threatActor.isAPT | Boolean | Is threat actor APT group | 
| GIBTIA.CompromisedMule.id | String | Group IB incident ID | 
| GIBTIA.CompromisedMule.sourceType | String | Information source | 
| GIBTIA.CompromisedMule.evaluation.severity | String | Event severity | 


#### Command Example

```!gibtia-get-compromised-mule-info id=50a3b4abbfca5dcbec9c8b3a110598f61ba90a99```

#### Context Example

```json
{
    "DBotScore": [
        {
            "Indicator": "http://some.ru",
            "Score": 3,
            "Type": "url",
            "Vendor": "GIB TI&A"
        },
        {
            "Indicator": "some.ru",
            "Score": 3,
            "Type": "domain",
            "Vendor": "GIB TI&A"
        },
        {
            "Indicator": "11.11.11.11",
            "Score": 3,
            "Type": "ip",
            "Vendor": "GIB TI&A"
        }
    ],
    "Domain": {
        "Malicious": {
            "Description": null,
            "Vendor": "GIB TI&A"
        },
        "Name": "some"
    },
    "GIBTIA": {
        "CompromisedMule": {
            "account": "XXXXXXXXXXXXXXXX",
            "cnc": {
                "cnc": "http://some.ru",
                "domain": "some.ru",
                "ipv4": {
                    "asn": null,
                    "city": null,
                    "countryCode": null,
                    "countryName": null,
                    "ip": "11.11.11.11",
                    "provider": null,
                    "region": null
                },
                "ipv6": null,
                "url": "http://some.ru"
            },
            "dateAdd": "2020-02-21T13:02:00+00:00",
            "dateIncident": null,
            "evaluation": {
                "admiraltyCode": "A2",
                "credibility": 80,
                "reliability": 100,
                "severity": "red",
                "tlp": "amber",
                "ttl": 30
            },
            "favouriteForCompanies": [],
            "fraudId": null,
            "hash": "some",
            "hideForCompanies": [],
            "id": "50a3b4abbfca5dcbec9c8b3a110598f61ba90a99",
            "info": null,
            "malware": {
                "id": "5a2b741f8593f88178623848573abc899f9157d4",
                "name": "Anubis",
                "stixGuid": "7d837524-7b01-ddc9-a357-46e7136a9852"
            },
            "oldId": "392993084",
            "organization": {
                "bic": null,
                "bicRu": null,
                "bsb": null,
                "iban": null,
                "name": "Some",
                "swift": null
            },
            "person": {
                "address": null,
                "birthday": null,
                "city": null,
                "countryCode": null,
                "email": null,
                "name": null,
                "passport": null,
                "phone": null,
                "state": null,
                "taxNumber": null,
                "zip": null
            },
            "portalLink": "https://bt.group-ib.com/cd/mules?searchValue=id:50a3b4abbfca5dcbec9c8b3a110598f61ba90a99",
            "sourceType": "Botnet",
            "stixGuid": "2da6b164-9a12-6db5-4346-2a80a4e03255",
            "threatActor": null,
            "type": "Person"
        }
    },
    "IP": {
        "Address": "11.11.11.11",
        "Malicious": {
            "Description": null,
            "Vendor": "GIB TI&A"
        }
    },
    "URL": {
        "Data": "http://some.ru",
        "Malicious": {
            "Description": null,
            "Vendor": "GIB TI&A"
        }
    }
}
```

#### Human Readable Output


>### Feed from compromised/mule with ID 50a3b4abbfca5dcbec9c8b3a110598f61ba90a99

>|account|cnc cnc|cnc domain|cnc ipv4 ip|cnc url|dateAdd|evaluation admiraltyCode|evaluation credibility|evaluation reliability|evaluation severity|evaluation tlp|evaluation ttl|hash|id|malware id|malware name|malware stixGuid|oldId|organization name|portalLink|sourceType|stixGuid|type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1111111111111111 | <http://some.ru> | some | 11.11.11.11 | http://some.ru | 2020-02-21T13:02:00+00:00 | A2 | 80 | 100 | red | amber | 30 | some | 50a3b4abbfca5dcbec9c8b3a110598f61ba90a99 | 5a2b741f8593f88178623848573abc899f9157d4 | Anubis | 7d837524-7b01-ddc9-a357-46e7136a9852 | 392993084 | Some | <https://bt.group-ib.com/cd/mules?searchValue=id:50a3b4abbfca5dcbec9c8b3a110598f61ba90a99> | Botnet | 2da6b164-9a12-6db5-4346-2a80a4e03255 | Person |

>### URL indicator

>|gibid|severity|value|
>|---|---|---|
>| 50a3b4abbfca5dcbec9c8b3a110598f61ba90a99 | red | <http://some.ru> |

>### Domain indicator

>|gibid|severity|value|
>|---|---|---|
>| 50a3b4abbfca5dcbec9c8b3a110598f61ba90a99 | red | some |

>### IP indicator

>|gibid|severity|value|
>|---|---|---|
>| 50a3b4abbfca5dcbec9c8b3a110598f61ba90a99 | red | 11.11.11.11 |


### gibtia-get-compromised-imei-info

***
Command performs Group IB event lookup in compromised/imei collection with provided ID.


#### Base Command

`gibtia-get-compromised-imei-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | GIB event id.<br/>e.g.: 0c1426048474df19ada9d0089ef8b3efce906556. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTIA.CompromisedIMEI.client.ipv4.asn | String | Compromised client ASN | 
| GIBTIA.CompromisedIMEI.client.ipv4.countryName | String | Country name | 
| GIBTIA.CompromisedIMEI.client.ipv4.ip | String | Victim IP address | 
| GIBTIA.CompromisedIMEI.client.ipv4.region | String | Region name | 
| GIBTIA.CompromisedIMEI.cnc.domain | String | CNC URL | 
| GIBTIA.CompromisedIMEI.cnc.ipv4.asn | String | CNC ASN | 
| GIBTIA.CompromisedIMEI.cnc.ipv4.countryName | String | CNC IP country name | 
| GIBTIA.CompromisedIMEI.cnc.ipv4.ip | String | CNC IP address | 
| GIBTIA.CompromisedIMEI.cnc.ipv4.region | String | CNC region name | 
| GIBTIA.CompromisedIMEI.dateCompromised | Date | Date compromised | 
| GIBTIA.CompromisedIMEI.dateDetected | Date | Date detected | 
| GIBTIA.CompromisedIMEI.device.imei | String | Compromised IMEI | 
| GIBTIA.CompromisedIMEI.device.model | String | Compromised device model | 
| GIBTIA.CompromisedIMEI.malware.name | String | Associated malware | 
| GIBTIA.CompromisedIMEI.threatActor.id | String | Associated threat actor ID | 
| GIBTIA.CompromisedIMEI.threatActor.name | String | Associated threat actor | 
| GIBTIA.CompromisedIMEI.threatActor.isAPT | Boolean |  Is threat actor APT group | 
| GIBTIA.CompromisedIMEI.id | String | Group IB incident ID | 
| GIBTIA.CompromisedIMEI.evaluation.severity | String | Event severity | 


#### Command Example

```!gibtia-get-compromised-imei-info id=0c1426048474df19ada9d0089ef8b3efce906556```

#### Context Example

```json
{
    "DBotScore": [
        {
            "Indicator": "http://some.ru",
            "Score": 3,
            "Type": "url",
            "Vendor": "GIB TI&A"
        },
        {
            "Indicator": "some.ru",
            "Score": 3,
            "Type": "domain",
            "Vendor": "GIB TI&A"
        },
        {
            "Indicator": "11.11.11.11",
            "Score": 3,
            "Type": "ip",
            "Vendor": "GIB TI&A"
        }
    ],
    "Domain": {
        "Malicious": {
            "Description": null,
            "Vendor": "GIB TI&A"
        },
        "Name": "some.ru"
    },
    "GIBTIA": {
        "CompromisedIMEI": {
            "client": {
                "ipv4": {
                    "asn": "AS11111",
                    "city": null,
                    "countryCode": "NL",
                    "countryName": "Netherlands",
                    "ip": "11.11.11.11",
                    "provider": "Some Company",
                    "region": null
                }
            },
            "cnc": {
                "cnc": "http://some.ru",
                "domain": "some.ru",
                "ipv4": {
                    "asn": "AS11111",
                    "city": null,
                    "countryCode": "FR",
                    "countryName": "France",
                    "ip": "11.11.11.11",
                    "provider": "Some",
                    "region": null
                },
                "ipv6": null,
                "url": "http://some.ru"
            },
            "dateCompromised": null,
            "dateDetected": "2020-02-11T03:12:43+00:00",
            "device": {
                "iccid": "~",
                "imei": "Some",
                "imsi": "~",
                "model": "Nexus S/2.3.7 ($$$Flexnet v.5.5)",
                "os": null
            },
            "evaluation": {
                "admiraltyCode": "A2",
                "credibility": 80,
                "reliability": 100,
                "severity": "red",
                "tlp": "red",
                "ttl": 30
            },
            "favouriteForCompanies": [],
            "hideForCompanies": [],
            "id": "0c1426048474df19ada9d0089ef8b3efce906556",
            "malware": {
                "id": "8790a290230b3b4c059c2516a6adace1eac16066",
                "name": "FlexNet",
                "stixGuid": "b51140c2-a88b-a95c-f5b0-1c5d1855ffde"
            },
            "oldId": "396766002",
            "operator": {
                "countryCode": null,
                "name": null,
                "number": "~"
            },
            "portalLink": "https://bt.group-ib.com/cd/imei?searchValue=id:0c1426048474df19ada9d0089ef8b3efce906556",
            "sourceType": "Botnet",
            "stixGuid": "9cff66e9-c2b3-26ca-771a-c9e4d501c453",
            "threatActor": null
        }
    },
    "IP": {
        "ASN": "AS11111",
        "Address": "11.11.11.11",
        "Geo": {
            "Country": "France"
        },
        "Malicious": {
            "Description": null,
            "Vendor": "GIB TI&A"
        }
    },
    "URL": {
        "Data": "http://some.ru",
        "Malicious": {
            "Description": null,
            "Vendor": "GIB TI&A"
        }
    }
}
```

#### Human Readable Output


>### Feed from compromised/imei with ID 0c1426048474df19ada9d0089ef8b3efce906556

>|client ipv4 asn|client ipv4 countryCode|client ipv4 countryName|client ipv4 ip|client ipv4 provider|cnc cnc|cnc domain|cnc ipv4 asn|cnc ipv4 countryCode|cnc ipv4 countryName|cnc ipv4 ip|cnc ipv4 provider|cnc url|dateDetected|device iccid|device imei|device imsi|device model|evaluation admiraltyCode|evaluation credibility|evaluation reliability|evaluation severity|evaluation tlp|evaluation ttl|id|malware id|malware name|malware stixGuid|oldId|operator number|portalLink|sourceType|stixGuid|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| AS11111 | NL | Netherlands | 11.11.11.11 | Some Company | <http://some.ru> | some.ru | AS11111 | FR | France | 11.11.11.11 | Some | http://some.ru | 2020-02-11T03:12:43+00:00 | ~ | Some | ~ | Nexus S/2.3.7 ($$$Flexnet v.5.5) | A2 | 80 | 100 | red | red | 30 | 0c1426048474df19ada9d0089ef8b3efce906556 | 8790a290230b3b4c059c2516a6adace1eac16066 | FlexNet | b51140c2-a88b-a95c-f5b0-1c5d1855ffde | 396766002 | ~ | <https://bt.group-ib.com/cd/imei?searchValue=id:0c1426048474df19ada9d0089ef8b3efce906556> | Botnet | 9cff66e9-c2b3-26ca-771a-c9e4d501c453 |

>### URL indicator

>|gibid|severity|value|
>|---|---|---|
>| 0c1426048474df19ada9d0089ef8b3efce906556 | red | <http://some.ru> |

>### Domain indicator

>|gibid|severity|value|
>|---|---|---|
>| 0c1426048474df19ada9d0089ef8b3efce906556 | red | some.ru |

>### IP indicator

>|asn|geocountry|gibid|severity|value|
>|---|---|---|---|---|
>| AS11111 | France | 0c1426048474df19ada9d0089ef8b3efce906556 | red | 11.11.11.11 |


### gibtia-get-osi-git-leak-info

***
Command performs Group IB event lookup in osi/git_leak collection with provided ID.


#### Base Command

`gibtia-get-osi-git-leak-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | GIB event id.<br/>e.g.: f201c253ac71f7d78db39fa111a2af9d7ee7a3f7. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTIA.GitLeak.dateDetected | Date | Leak detection date | 
| GIBTIA.GitLeak.matchesType | String | List of matches type | 
| GIBTIA.GitLeak.name | String | GIT filename | 
| GIBTIA.GitLeak.repository | String | GIT repository | 
| GIBTIA.GitLeak.revisions.file | String | Leaked file link | 
| GIBTIA.GitLeak.revisions.fileDiff | String | Leaked file diff | 
| GIBTIA.GitLeak.revisions.info.authorName | String | Revision author | 
| GIBTIA.GitLeak.revisions.info.authorEmail | String | Author name | 
| GIBTIA.GitLeak.revisions.info.dateCreated | Date | Revision creation date | 
| GIBTIA.GitLeak.source | String | Source\(github/gitlab/etc.\) | 
| GIBTIA.GitLeak.evaluation.severity | String | Event severity | 


#### Command Example

```!gibtia-get-osi-git-leak-info id=ead0d8ae9f2347789941ebacde88ad2e3b1ef691```

#### Context Example

```json
{
    "GIBTIA": {
        "GitLeak": {
            "companyId": [
                40,
                1872,
                2060,
                2248,
                2522,
                2692
            ],
            "dateDetected": "2020-03-12T01:12:00+00:00",
            "dateUpdated": "2020-02-11T01:12:00+00:00",
            "evaluation": {
                "admiraltyCode": "A6",
                "credibility": 100,
                "reliability": 100,
                "severity": "green",
                "tlp": "amber",
                "ttl": 30
            },
            "file": "https://bt.group-ib.com/api/v2/osi/git_leak/ead0d8ae9f2347789941ebacde88ad2e3b1ef691/file/bWFpbi0zOTFkYjVkNWYxN2FiNmNiYmJmN2MzNWQxZjRkMDc2Y2I0YzgzMGYwOTdiMmE5ZWRkZDJkZjdiMDY1MDcwOWE3",
            "fileId": "391db5d5f17ab6cbbbf7c35d1f4d076cb4c830f097b2a9eddd2df7b0650709a7",
            "id": "ead0d8ae9f2347789941ebacde88ad2e3b1ef691",
            "matchesType": [
                "commonKeywords",
                "keyword"
            ],
            "matchesTypeCount": {
                "card": 0,
                "cisco": 0,
                "commonKeywords": 1,
                "domain": 0,
                "dsn": 0,
                "email": 0,
                "google": 0,
                "ip": 0,
                "keyword": 1,
                "login": 0,
                "metasploit": 0,
                "nmap": 0,
                "pgp": 0,
                "sha": 0,
                "slackAPI": 0,
                "ssh": 0
            },
            "name": "some",
            "repository": "some.ru",
            "revisions": [
                {
                    "bind": [
                        {
                            "bindBy": "cert",
                            "companyId": [
                                2692
                            ],
                            "data": "cert",
                            "type": "keyword"
                        }
                    ],
                    "companyId": [
                        2692
                    ],
                    "data": {
                        "commonKeywords": {
                            "password": [
                                "password"
                            ]
                        }
                    },
                    "file": "https://bt.group-ib.com/api/v2/osi/git_leak/ead0d8ae9f2347789941ebacde88ad2e3b1ef691/file/cmV2aXNpb24tZmlsZS0zOTFkYjVkNWYxN2FiNmNiYmJmN2MzNWQxZjRkMDc2Y2I0YzgzMGYwOTdiMmE5ZWRkZDJkZjdiMDY1MDcwOWE3",
                    "fileDiff": "https://bt.group-ib.com/api/v2/osi/git_leak/ead0d8ae9f2347789941ebacde88ad2e3b1ef691/file/cmV2aXNpb24tZmlsZURpZmYtMzkxZGI1ZDVmMTdhYjZjYmJiZjdjMzVkMWY0ZDA3NmNiNGM4MzBmMDk3YjJhOWVkZGQyZGY3YjA2NTA3MDlhNw==",
                    "fileDiffId": "a2187ee179076a22e550e8f7fbc51840e87aba260431ab9cb2d4e0192ad4134c",
                    "fileId": "391db5d5f17ab6cbbbf7c35d1f4d076cb4c830f097b2a9eddd2df7b0650709a7",
                    "hash": "Some",
                    "info": {
                        "authorEmail": "some@gmail.ru",
                        "authorName": "some",
                        "dateCreated": "2020-01-03T11:17:52+00:00",
                        "timestamp": 1617794272
                    },
                    "parentFileId": "ead0d8ae9f2347789941ebacde88ad2e3b1ef691"
                }
            ],
            "source": "github"
        }
    }
}
```

#### Human Readable Output


>### Feed from osi/git_leak with ID ead0d8ae9f2347789941ebacde88ad2e3b1ef691

>|companyId|dateDetected|dateUpdated|evaluation admiraltyCode|evaluation credibility|evaluation reliability|evaluation severity|evaluation tlp|evaluation ttl|file|fileId|id|matchesType|matchesTypeCount card|matchesTypeCount cisco|matchesTypeCount commonKeywords|matchesTypeCount domain|matchesTypeCount dsn|matchesTypeCount email|matchesTypeCount google|matchesTypeCount ip|matchesTypeCount keyword|matchesTypeCount login|matchesTypeCount metasploit|matchesTypeCount nmap|matchesTypeCount pgp|matchesTypeCount sha|matchesTypeCount slackAPI|matchesTypeCount ssh|name|repository|source|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 40,<br>1872,<br>2060,<br>2248,<br>2522,<br>2692 | 2020-03-12T01:12:00+00:00 | 2020-02-11T01:12:00+00:00 | A6 | 100 | 100 | green | amber | 30 | <https://bt.group-ib.com/api/v2/osi/git_leak/ead0d8ae9f2347789941ebacde88ad2e3b1ef691/file/bWFpbi0zOTFkYjVkNWYxN2FiNmNiYmJmN2MzNWQxZjRkMDc2Y2I0YzgzMGYwOTdiMmE5ZWRkZDJkZjdiMDY1MDcwOWE3> | 391db5d5f17ab6cbbbf7c35d1f4d076cb4c830f097b2a9eddd2df7b0650709a7 | ead0d8ae9f2347789941ebacde88ad2e3b1ef691 | commonKeywords,<br>keyword | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | some | some.ru | github |

>### revisions table

>|bind|companyId|data|file|fileDiff|fileDiffId|fileId|hash|info|parentFileId|
>|---|---|---|---|---|---|---|---|---|---|
>| {'bindBy': 'cert', 'companyId': [2692], 'data': 'cert', 'type': 'keyword'} | 2692 | commonKeywords: {"password": ["password"]} | <https://bt.group-ib.com/api/v2/osi/git_leak/ead0d8ae9f2347789941ebacde88ad2e3b1ef691/file/cmV2aXNpb24tZmlsZS0zOTFkYjVkNWYxN2FiNmNiYmJmN2MzNWQxZjRkMDc2Y2I0YzgzMGYwOTdiMmE5ZWRkZDJkZjdiMDY1MDcwOWE3> | <https://bt.group-ib.com/api/v2/osi/git_leak/ead0d8ae9f2347789941ebacde88ad2e3b1ef691/file/cmV2aXNpb24tZmlsZURpZmYtMzkxZGI1ZDVmMTdhYjZjYmJiZjdjMzVkMWY0ZDA3NmNiNGM4MzBmMDk3YjJhOWVkZGQyZGY3YjA2NTA3MDlhNw>== | a2187ee179076a22e550e8f7fbc51840e87aba260431ab9cb2d4e0192ad4134c | 391db5d5f17ab6cbbbf7c35d1f4d076cb4c830f097b2a9eddd2df7b0650709a7 | Some | authorEmail: some@gmail.ru <br>authorName: some<br>dateCreated: 2020-01-03T11:17:52+00:00<br>timestamp: 1617794272 | ead0d8ae9f2347789941ebacde88ad2e3b1ef691 |



### gibtia-get-osi-public-leak-info

***
Command performs Group IB event lookup in osi/public_leak collection with provided ID.


#### Base Command

`gibtia-get-osi-public-leak-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | GIB event id.<br/>e.g.: a9a5b5cb9b971a2a037e3a0a30654185ea148095. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTIA.PublicLeak.created | Date | Leak event detection date | 
| GIBTIA.PublicLeak.data | String | Leaked data | 
| GIBTIA.PublicLeak.hash | String | Leak data hash | 
| GIBTIA.PublicLeak.linkList.author | String | Leak entry author | 
| GIBTIA.PublicLeak.linkList.dateDetected | Date | Leak detection date | 
| GIBTIA.PublicLeak.linkList.datePublished | Date | Leak publish date | 
| GIBTIA.PublicLeak.linkList.hash | String | Leak hash | 
| GIBTIA.PublicLeak.linkList.link | String | Leak link | 
| GIBTIA.PublicLeak.linkList.source | String | Leak source | 
| GIBTIA.PublicLeak.matches | String | Matches | 
| GIBTIA.PublicLeak.portalLink | String | Group IB portal link | 
| GIBTIA.PublicLeak.evaluation.severity | String | Event severity | 


#### Command Example

```!gibtia-get-osi-public-leak-info id=a09f2354e52d5fa0a8697c8df0b4ed99cc956273```

#### Context Example

```json
{
    "GIBTIA": {
        "PublicLeak": {
            "bind": [],
            "created": "2020-02-02T13:52:01+03:00",
            "data": "Big chunk of data",
            "displayOptions": null,
            "evaluation": {
                "admiraltyCode": "C3",
                "credibility": 50,
                "reliability": 50,
                "severity": "green",
                "tlp": "amber",
                "ttl": 30
            },
            "hash": "a11f2354e52d5fa0a8697c8df0b4ed99cc956211",
            "id": "a11f2354e52d5fa0a8697c8df0b4ed99cc956211",
            "language": "java",
            "linkList": [
                {
                    "author": "",
                    "dateDetected": "2021-04-01T14:57:01+03:00",
                    "datePublished": "2021-04-01T14:50:45+03:00",
                    "hash": "5d9657dbdf59487a6031820add2cacbe54e86814",
                    "itemSource": "api",
                    "link": "https://some.ru",
                    "sequenceUpdate": null,
                    "size": 709,
                    "source": "some.ru",
                    "status": 1,
                    "title": ""
                }
            ],
            "matches": [],
            "oldId": null,
            "portalLink": "https://bt.group-ib.com/osi/public_leak?searchValue=id:a09f2354e52d5fa0a8697c8df0b4ed99cc956273",
            "size": "709 B",
            "updated": "2021-04-01T14:57:01+03:00",
            "useful": 1
        }
    }
}
```

#### Human Readable Output


>### Feed from osi/public_leak with ID a11f2354e52d5fa0a8697c8df0b4ed99cc956211

>|created|data|evaluation admiraltyCode|evaluation credibility|evaluation reliability|evaluation severity|evaluation tlp|evaluation ttl|hash|id|language|portalLink|size|updated|useful|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2020-02-02T13:52:01+03:00 | Big chunk of data | C3 | 50 | 50 | green | amber | 30 | a11f2354e52d5fa0a8697c8df0b4ed99cc956211 | a11f2354e52d5fa0a8697c8df0b4ed99cc956211 | java | <https://bt.group-ib.com/osi/public_leak?searchValue=id:a09f2354e52d5fa0a8697c8df0b4ed99cc956273> | 709 B | 2021-04-01T14:57:01+03:00 | 1 |

>### linkList table

>|dateDetected|datePublished|hash|itemSource|link|size|source|status|
>|---|---|---|---|---|---|---|---|
>| 2021-04-01T14:57:01+03:00 | 2021-04-01T14:50:45+03:00 | 5d9657dbdf59487a6031820add2cacbe54e86814 | api | <https://some.ru> | 709 | some.ru | 1 |


### gibtia-get-osi-vulnerability-info

***
Command performs Group IB event lookup in osi/vulnerability collection with provided ID.


#### Base Command

`gibtia-get-osi-vulnerability-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | GIB event id.<br/><br/>e.g.: CVE-2021-27152. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTIA.OSIVulnerability.affectedSoftware.name | String | Affected software name | 
| GIBTIA.OSIVulnerability.affectedSoftware.operator | String | Affected software version operator\( ex. le=less or equal\) | 
| GIBTIA.OSIVulnerability.affectedSoftware.version | String | Affected software version | 
| GIBTIA.OSIVulnerability.bulletinFamily | String | Bulletin family | 
| GIBTIA.OSIVulnerability.cvss.score | String | CVSS score | 
| GIBTIA.OSIVulnerability.cvss.vector | String | CVSS vector | 
| GIBTIA.OSIVulnerability.dateLastSeen | Date | Date last seen | 
| GIBTIA.OSIVulnerability.datePublished | Date | Date published | 
| GIBTIA.OSIVulnerability.description | String | Vulnerability description | 
| GIBTIA.OSIVulnerability.id | String | Vulnerability ID | 
| GIBTIA.OSIVulnerability.reporter | String | Vulnerability reporter | 
| GIBTIA.OSIVulnerability.title | String | Vulnerability title | 
| GIBTIA.OSIVulnerability.evaluation.severity | String | Event severity | 


#### Command Example

```!gibtia-get-osi-vulnerability-info id=CVE-2021-27152```

#### Context Example

```json
{
    "CVE": {
        "CVSS": 7.5,
        "Description": "Description",
        "ID": "CVE-2021-27152",
        "Modified": "2021-02-11T14:35:24+03:00",
        "Published": "2021-02-10T19:15:00+03:00"
    },
    "DBotScore": {
        "Indicator": "CVE-2021-27152",
        "Score": 0,
        "Type": "cve",
        "Vendor": null
    },
    "GIBTIA": {
        "OSIVulnerability": {
            "affectedSoftware": [],
            "bulletinFamily": "NVD",
            "cveList": [],
            "cvss": {
                "score": 7.5,
                "vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P"
            },
            "dateLastSeen": "2021-02-11T14:35:24+03:00",
            "dateModified": "2021-02-11T00:45:00+03:00",
            "datePublished": "2021-02-10T19:15:00+03:00",
            "description": "Description",
            "displayOptions": {
                "favouriteForCompanies": [],
                "hideForCompanies": [],
                "isFavourite": false,
                "isHidden": false
            },
            "evaluation": {
                "admiraltyCode": "A1",
                "credibility": 100,
                "reliability": 100,
                "severity": "red",
                "tlp": "green",
                "ttl": 30
            },
            "exploitCount": 0,
            "exploitList": [],
            "extCvss": {
                "base": 9.8,
                "environmental": 0,
                "exploitability": 3.9,
                "impact": 5.9,
                "mImpact": 0,
                "overall": 9.8,
                "temporal": 0,
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            },
            "extDescription": "Big description",
            "href": "https://some.ru",
            "id": "CVE-2021-27152",
            "lastseen": "2021-02-11T14:35:24+03:00",
            "modified": "2021-02-11T00:45:00+03:00",
            "portalLink": "https://bt.group-ib.com/osi/vulnerabilities?searchValue=id:CVE-2021-27152",
            "provider": "some.ru",
            "published": "2021-02-10T19:15:00+03:00",
            "references": [
                "https://pierrekim.github.io/blog/2021-01-12-fiberhome-ont-0day-vulnerabilities.html#httpd-hardcoded-credentials",
                "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2021-27152"
            ],
            "reporter": "some.ru",
            "softwareMixed": [
                {
                    "arch": [],
                    "hardware": "",
                    "hardwareVendor": "",
                    "hardwareVersion": "",
                    "os": "some_firmware",
                    "osVendor": "some",
                    "osVersion": "some",
                    "rel": [],
                    "softwareFileName": "",
                    "softwareName": [],
                    "softwareType": [],
                    "softwareVersion": [],
                    "softwareVersionString": "",
                    "vendor": "some",
                    "versionOperator": ""
                }
            ],
            "threats": [],
            "threatsList": [],
            "timeLineData": [],
            "title": "CVE-2021-27152",
            "type": "cve"
        }
    }
}
```

#### Human Readable Output

>### Feed from osi/vulnerability with ID CVE-2021-27152

>|bulletinFamily|cvss score|cvss vector|dateLastSeen|dateModified|datePublished|description|displayOptions isFavourite|displayOptions isHidden|evaluation admiraltyCode|evaluation credibility|evaluation reliability|evaluation severity|evaluation tlp|evaluation ttl|exploitCount|extCvss base|extCvss environmental|extCvss exploitability|extCvss impact|extCvss mImpact|extCvss overall|extCvss temporal|extCvss vector|extDescription|href|id|lastseen|modified|portalLink|provider|published|references|reporter|title|type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| NVD | 7.5 | AV:N/AC:L/Au:N/C:P/I:P/A:P | 2021-02-11T14:35:24+03:00 | 2021-02-11T00:45:00+03:00 | 2021-02-10T19:15:00+03:00 | Description | false | false | A1 | 100 | 100 | red | green | 30 | 0 | 9.8 | 0.0 | 3.9 | 5.9 | 0.0 | 9.8 | 0.0 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | Big description | <https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2021-27152> | CVE-2021-27152 | 2021-02-11T14:35:24+03:00 | 2021-02-11T00:45:00+03:00 | <https://bt.group-ib.com/osi/vulnerabilities?searchValue=id:CVE-2021-27152> | some.ru | 2021-02-10T19:15:00+03:00 | <https://pierrekim.github.io/blog/2021-01-12-fiberhome-ont-0day-vulnerabilities.html#httpd-hardcoded-credentials>,<br>https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2021-27152 | some.ru | CVE-2021-27152 | cve |

>### softwareMixed table

>|os|osVendor|osVersion|vendor|
>|---|---|---|---|
>| some_firmware | some | some | some |


### gibtia-get-phishing-kit-info

***
Command performs Group IB event lookup in bp/phishing_kit and attacks/phishing_kit collections with provided ID.


#### Base Command

`gibtia-get-phishing-kit-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | GIB event id.<br/>e.g.: 044f3f2cb599228c1882884eb77eb073f68a25f2. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTIA.PhishingKit.dateDetected | Date | Phishing kit detection date | 
| GIBTIA.PhishingKit.dateFirstSeen | Date | Phishing kit first seen date | 
| GIBTIA.PhishingKit.dateLastSeen | Date | Phishing kit last seen date | 
| GIBTIA.PhishingKit.downloadedFrom.fileName | String | Phishing kit filename | 
| GIBTIA.PhishingKit.downloadedFrom.domain | String | Phishing kit domain | 
| GIBTIA.PhishingKit.downloadedFrom.date | Date | Downloading date | 
| GIBTIA.PhishingKit.downloadedFrom.url | String | URL where phishing kit were downloaded from | 
| GIBTIA.PhishingKit.hash | String | MD5 phishing kit hash | 
| GIBTIA.PhishingKit.portalLink | String | Link to kit on GIB TI&amp;A | 
| GIBTIA.PhishingKit.targetBrand | String | Phishing kit target brand | 
| GIBTIA.PhishingKit.emails | String | Emails found in phishing kit | 
| GIBTIA.PhishingKit.id | String | GIB event ID | 
| GIBTIA.PhishingKit.evaluation.severity | String | Event severity | 


#### Command Example

```!gibtia-get-phishing-kit-info id=044f3f2cb599228c1882884eb77eb073f68a25f2```

#### Context Example

```json
{
    "GIBTIA": {
        "PhishingKit": {
            "company": [],
            "companyId": [
                -1
            ],
            "dateDetected": "2021-01-21T10:10:41+00:00",
            "dateFirstSeen": "2021-01-21T10:10:41+00:00",
            "dateLastSeen": "2021-01-21T10:12:17+00:00",
            "downloadedFrom": [
                {
                    "date": "2021-01-21 10:10:41",
                    "domain": "some.ru",
                    "fileName": "some.zip",
                    "url": "https://some.ru"
                }
            ],
            "emails": [],
            "evaluation": {
                "admiraltyCode": "B2",
                "credibility": 70,
                "reliability": 80,
                "severity": "orange",
                "tlp": "amber",
                "ttl": 30
            },
            "favouriteForCompanies": [],
            "hash": "8d7ea805fe20d6d77f57e2f0cadd17b1",
            "hideForCompanies": [],
            "id": "044f3f2cb599228c1882884eb77eb073f68a25f2",
            "login": "Some",
            "oldId": "396793696",
            "path": "https://tap.group-ib.com/api/api/v2/web/attacks/phishing_kit/044f3f2cb599228c1882884eb77eb073f68a25f2/file/95b61a1df152012abb79c3951ed98680e0bd917bbcf1d440e76b66a120292c76",
            "portalLink": "https://bt.group-ib.com/attacks/phishing_kit?searchValue=id:044f3f2cb599228c1882884eb77eb073f68a25f2",
            "source": [
                "some"
            ],
            "targetBrand": [],
            "tsFirstSeen": null,
            "tsLastSeen": null,
            "variables": [
                {
                    "filePath": "some.ru",
                    "type": "DB",
                    "value": "host: localhost"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Feed from attack/phishing_kit with ID 044f3f2cb599228c1882884eb77eb073f68a25f2

>|companyId|dateDetected|dateFirstSeen|dateLastSeen|evaluation admiraltyCode|evaluation credibility|evaluation reliability|evaluation severity|evaluation tlp|evaluation ttl|hash|id|login|oldId|path|portalLink|source|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| -1 | 2021-01-21T10:10:41+00:00 | 2021-01-21T10:10:41+00:00 | 2021-01-21T10:12:17+00:00 | B2 | 70 | 80 | orange | amber | 30 | 8d7ea805fe20d6d77f57e2f0cadd17b1 | 044f3f2cb599228c1882884eb77eb073f68a25f2 | some | 396793696 | <https://tap.group-ib.com/api/api/v2/web/attacks/phishing_kit/044f3f2cb599228c1882884eb77eb073f68a25f2/file/95b61a1df152012abb79c3951ed98680e0bd917bbcf1d440e76b66a120292c76> | <https://bt.group-ib.com/attacks/phishing_kit?searchValue=id:044f3f2cb599228c1882884eb77eb073f68a25f2> | some |

>### downloadedFrom table

>|date|domain|fileName|url|
>|---|---|---|---|
>| 2021-01-21 10:10:41 | some.ru | some.ru| <https://some.ru> |

>### variables table

>|filePath|type|value|
>|---|---|---|
>| some.ru | DB | host: localhost |



### gibtia-get-phishing-info

***
Command performs Group IB event lookup in bp/phishing and attacks/phishing collections with provided ID.


#### Base Command

`gibtia-get-phishing-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | GIB event id.<br/>e.g.: fce7f92d0b64946cf890842d083953649b259952. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTIA.Phishing.dateDetected | Date | Date of phishing detection | 
| GIBTIA.Phishing.dateBlocked | Unknown | Phishing resource block date | 
| GIBTIA.Phishing.id | String | GIB incident ID | 
| GIBTIA.Phishing.ipv4.asn | String | Phishing resource ASN | 
| GIBTIA.Phishing.ipv4.countryName | String | Phishing resource country name | 
| GIBTIA.Phishing.ipv4.ip | String | Phishing resource IP address | 
| GIBTIA.Phishing.ipv4.region | String | Phishing resource region name | 
| GIBTIA.Phishing.phishingDomain.domain | String | Phishing domain | 
| GIBTIA.Phishing.phishingDomain.dateRegistered | Date | Phishing domain creation date | 
| GIBTIA.Phishing.phishingDomain.registrar | String | Phishing domain registrar name | 
| GIBTIA.Phishing.phishingDomain.title | String | Phishing domain title | 
| GIBTIA.Phishing.targetBrand | String | Phishing target name | 
| GIBTIA.Phishing.targetCategory | String | Phishing target category \(financial, government, etc.\) | 
| GIBTIA.Phishing.targetDomain | String | Phishing target domain | 
| GIBTIA.Phishing.status | String | Current status of phishing incident \(blocked, in response, etc.\) | 
| GIBTIA.Phishing.url | String | Phishing URL | 
| GIBTIA.Phishing.evaluation.severity | String | Event severity | 


#### Command Example

```!gibtia-get-phishing-info id=fce7f92d0b64946cf890842d083953649b259952```

#### Context Example

```json
{
    "DBotScore": [
        {
            "Indicator": "https://some.ru",
            "Score": 3,
            "Type": "url",
            "Vendor": "GIB TI&A"
        },
        {
            "Indicator": "some.ru",
            "Score": 3,
            "Type": "domain",
            "Vendor": "GIB TI&A"
        },
        {
            "Indicator": "11.11.11.11",
            "Score": 3,
            "Type": "ip",
            "Vendor": "GIB TI&A"
        }
    ],
    "Domain": {
        "Malicious": {
            "Description": null,
            "Vendor": "GIB TI&A"
        },
        "Name": "some.ru",
        "Registrar": {
            "AbuseEmail": null,
            "AbusePhone": null,
            "Name": "Some"
        },
        "WHOIS": {
            "Registrar": {
                "AbuseEmail": null,
                "AbusePhone": null,
                "Name": "Some"
            }
        }
    },
    "GIBTIA": {
        "Phishing": {
            "company": [],
            "companyId": [
                2008
            ],
            "dateBlocked": "2021-01-25T22:58:10+00:00",
            "dateDetected": "2021-01-21T11:21:34+00:00",
            "evaluation": {
                "admiraltyCode": "A2",
                "credibility": 80,
                "reliability": 90,
                "severity": "red",
                "tlp": "amber",
                "ttl": 30
            },
            "favouriteForCompanies": [],
            "hideForCompanies": [],
            "history": [
                {
                    "date": "2021-01-21T11:20:50+00:00",
                    "field": "Detected",
                    "reason": "In response",
                    "reporter": "Group-IB Intelligence",
                    "value": "In response"
                }
            ],
            "id": "fce7f92d0b64946cf890842d083953649b259952",
            "ipv4": {
                "asn": null,
                "city": "Some",
                "countryCode": "CA",
                "countryName": "Canada",
                "ip": "11.11.11.11",
                "provider": "Some",
                "region": "NA"
            },
            "objective": "Login harvest",
            "oldId": "396798526",
            "phishingDomain": {
                "dateRegistered": "2021-01-20 13:41:30",
                "domain": "some.ru",
                "local": "some.ru",
                "registrar": "Some",
                "title": ""
            },
            "portalLink": "https://bt.group-ib.com/attacks/phishing?searchValue=id:fce7f92d0b64946cf890842d083953649b259952",
            "status": "Responding completed",
            "stixGuid": "4812358a-1de0-ab32-05e4-d91842d369e2",
            "targetBrand": "Some",
            "targetCategory": "Finance > Banking",
            "targetCountryName": null,
            "targetDomain": "some.ru",
            "type": "Phishing",
            "url": "https://some.ru"
        }
    },
    "IP": {
        "Address": "11.11.11.11",
        "Geo": {
            "Country": "Canada",
            "Description": "NA"
        },
        "Malicious": {
            "Description": null,
            "Vendor": "GIB TI&A"
        }
    },
    "URL": {
        "Data": "https://some.ru",
        "Malicious": {
            "Description": null,
            "Vendor": "GIB TI&A"
        }
    }
}
```

#### Human Readable Output

>### Feed from attacks/phishing with ID fce7f92d0b64946cf890842d083953649b259952

>|companyId|dateBlocked|dateDetected|evaluation admiraltyCode|evaluation credibility|evaluation reliability|evaluation severity|evaluation tlp|evaluation ttl|id|ipv4 city|ipv4 countryCode|ipv4 countryName|ipv4 ip|ipv4 provider|ipv4 region|objective|oldId|phishingDomain dateRegistered|phishingDomain domain|phishingDomain local|phishingDomain registrar|portalLink|status|stixGuid|targetBrand|targetCategory|targetDomain|type|url|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2008 | 2021-01-25T22:58:10+00:00 | 2021-01-21T11:21:34+00:00 | A2 | 80 | 90 | red | amber | 30 | fce7f92d0b64946cf890842d083953649b259952 | Some | CA | Canada | 11.11.11.11 | Some | NA | Login harvest | 396798526 | 2021-01-20 13:41:30 | some.ru | some.ru | Some | <https://bt.group-ib.com/attacks/phishing?searchValue=id:fce7f92d0b64946cf890842d083953649b259952> | Responding completed | 4812358a-1de0-ab32-05e4-d91842d369e2 | Some | Finance > Banking | some.ru | Phishing | <https://some.ru> |

>### history table

>|date|field|reason|reporter|value|
>|---|---|---|---|---|
>| 2021-01-21T11:20:50+00:00 | Detected | In response | Group-IB Intelligence | In response |

>### URL indicator

>|gibid|severity|value|
>|---|---|---|
>| fce7f92d0b64946cf890842d083953649b259952 | red | <https://some.ru> |

>### Domain indicator

>|creationdate|gibid|gibphishingtitle|gibtargetbrand|gibtargetcategory|gibtargetdomain|registrarname|severity|value|
>|---|---|---|---|---|---|---|---|---|
>| 2021-01-20T13:41:30Z | fce7f92d0b64946cf890842d083953649b259952 |  | Some | Finance > Banking | some.ru | Some | red | some.ru |

>### IP indicator

>|geocountry|geolocation|gibid|severity|value|
>|---|---|---|---|---|
>| Canada | NA | fce7f92d0b64946cf890842d083953649b259952 | red | 11.11.11.11 |


### gibtia-get-attacks-ddos-info

***
Command performs Group IB event lookup in attacks/ddos collection with provided ID.


#### Base Command

`gibtia-get-attacks-ddos-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | GIB event id.<br/>e.g.: 26a05baa4025edff367b058b13c6b43e820538a5. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTIA.AttacksDDoS.cnc.url | String | CNC URL | 
| GIBTIA.AttacksDDoS.cnc.domain | String | CNC domain | 
| GIBTIA.AttacksDDoS.cnc.ipv4.asn | String | CNC ASN | 
| GIBTIA.AttacksDDoS.cnc.ipv4.countryName | String | CNC IP country name | 
| GIBTIA.AttacksDDoS.cnc.ipv4.ip | String | CNC IP address | 
| GIBTIA.AttacksDDoS.cnc.ipv4.region | String | CNC region name | 
| GIBTIA.AttacksDDoS.target.ipv4.asn | String | DDoS target ASN | 
| GIBTIA.AttacksDDoS.target.ipv4.countryName | String | DDoS target country name | 
| GIBTIA.AttacksDDoS.target.ipv4.ip | String | DDoS target IP address | 
| GIBTIA.AttacksDDoS.target.ipv4.region | String | DDoS target region name | 
| GIBTIA.AttacksDDoS.target.category | String | DDoS target category | 
| GIBTIA.AttacksDDoS.target.domain | String | DDoS target domain | 
| GIBTIA.AttacksDDoS.threatActor.id | String | Associated threat actor ID | 
| GIBTIA.AttacksDDoS.threatActor.name | String | Associated threat actor | 
| GIBTIA.AttacksDdos.threatActor.isAPT | Boolean | Is threat actor APT | 
| GIBTIA.AttacksDDoS.id | String | GIB incident ID | 
| GIBTIA.AttacksDDoS.evaluation.severity | String | Event severity | 


#### Command Example

```!gibtia-get-attacks-ddos-info id=26a05baa4025edff367b058b13c6b43e820538a5```

#### Context Example

```json
{
    "DBotScore": [
        {
            "Indicator": "some.ru",
            "Score": 3,
            "Type": "domain",
            "Vendor": "GIB TI&A"
        },
        {
            "Indicator": "11.11.11.11",
            "Score": 3,
            "Type": "ip",
            "Vendor": "GIB TI&A"
        }
    ],
    "Domain": {
        "Malicious": {
            "Description": null,
            "Vendor": "GIB TI&A"
        },
        "Name": "some.ru"
    },
    "GIBTIA": {
        "AttacksDDoS": {
            "cnc": {
                "cnc": "some.ru",
                "domain": "some.ru",
                "ipv4": {
                    "asn": "AS11111",
                    "city": "Some",
                    "countryCode": "US",
                    "countryName": "United States",
                    "ip": "11.11.11.11",
                    "provider": "Some",
                    "region": "Some"
                },
                "ipv6": null,
                "url": null
            },
            "company": null,
            "companyId": -1,
            "dateBegin": "2021-01-16T02:58:53+00:00",
            "dateEnd": "2021-01-16T02:58:55+00:00",
            "dateReg": "2021-01-16",
            "evaluation": {
                "admiraltyCode": "A2",
                "credibility": 90,
                "reliability": 90,
                "severity": "red",
                "tlp": "green",
                "ttl": 30
            },
            "favouriteForCompanies": [],
            "hideForCompanies": [],
            "id": "26a05baa4025edff367b058b13c6b43e820538a5",
            "malware": null,
            "messageLink": null,
            "oldId": "394657345",
            "portalLink": "https://bt.group-ib.com/attacks/ddos?searchValue=id:26a05baa4025edff367b058b13c6b43e820538a5",
            "protocol": "udp",
            "source": "honeypot_logs:1",
            "stixGuid": "ea05c117-2cca-b3cd-f033-a8e16e5db3c2",
            "target": {
                "category": null,
                "domain": null,
                "domainsCount": 0,
                "ipv4": {
                    "asn": "AS11111",
                    "city": "Some",
                    "countryCode": "US",
                    "countryName": "United States",
                    "ip": "11.11.11.11",
                    "provider": "Some",
                    "region": "Some"
                },
                "port": 55843,
                "url": null
            },
            "threatActor": null,
            "type": "DNS Reflection"
        }
    },
    "IP": {
        "ASN": "AS11111",
        "Address": "11.11.11.11",
        "Geo": {
            "Country": "United States",
            "Description": "Some"
        },
        "Malicious": {
            "Description": null,
            "Vendor": "GIB TI&A"
        }
    }
}
```

#### Human Readable Output

>### Feed from attacks/ddos with ID 26a05baa4025edff367b058b13c6b43e820538a5

>|cnc cnc|cnc domain|cnc ipv4 asn|cnc ipv4 city|cnc ipv4 countryCode|cnc ipv4 countryName|cnc ipv4 ip|cnc ipv4 provider|cnc ipv4 region|companyId|dateBegin|dateEnd|dateReg|evaluation admiraltyCode|evaluation credibility|evaluation reliability|evaluation severity|evaluation tlp|evaluation ttl|id|oldId|portalLink|protocol|source|stixGuid|target domainsCount|target ipv4 asn|target ipv4 city|target ipv4 countryCode|target ipv4 countryName|target ipv4 ip|target ipv4 provider|target ipv4 region|target port|type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| some.ru | some.ru | AS11111 | Some | US | United States | 11.11.11.11 | Some | Some | -1 | 2021-01-16T02:58:53+00:00 | 2021-01-16T02:58:55+00:00 | 2021-01-16 | A2 | 90 | 90 | red | green | 30 | 26a05baa4025edff367b058b13c6b43e820538a5 | 394657345 | <https://bt.group-ib.com/attacks/ddos?searchValue=id:26a05baa4025edff367b058b13c6b43e820538a5> | udp | honeypot_logs:1 | ea05c117-2cca-b3cd-f033-a8e16e5db3c2 | 0 | AS11111 | Some | US | United States | 11.11.11.11 | Some | Some | 55843 | DNS Reflection |

>### Domain indicator

>|gibid|severity|value|
>|---|---|---|
>| 26a05baa4025edff367b058b13c6b43e820538a5 | red | some.ru |

>### IP indicator

>|asn|geocountry|geolocation|gibid|severity|value|
>|---|---|---|---|---|---|
>| AS11111 | United States | Some | 26a05baa4025edff367b058b13c6b43e820538a5 | red | 11.11.11.11 |


### gibtia-get-attacks-deface-info

***
Command performs Group IB event lookup in attacks/deface collection with provided ID.


#### Base Command

`gibtia-get-attacks-deface-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | GIB event id.<br/>e.g.: 6009637a1135cd001ef46e21. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTIA.AttacksDeface.date | Date | Date of deface | 
| GIBTIA.AttacksDeface.id | String | GIB incident ID | 
| GIBTIA.AttacksDeface.targetIp.asn | String | Victim ASN | 
| GIBTIA.AttacksDeface.targetIp.countryName | String | Victim country name | 
| GIBTIA.AttacksDeface.targetIp.region | String | Victim IP region name | 
| GIBTIA.AttacksDeface.threatActor.id | String | Associated threat actor ID | 
| GIBTIA.AttacksDeface.threatActor.name | String | Associated threat actor | 
| GIBTIA.AttacksDeface.threatActor.isAPT | Boolean | Is threat actor APT | 
| GIBTIA.AttacksDeface.url | String | URL of compromised resource | 
| GIBTIA.AttacksDeface.evaluation.severity | String | Event severity | 


#### Command Example

```!gibtia-get-attacks-deface-info id=6009637a1135cd001ef46e21```

#### Context Example

```json
{
    "DBotScore": [
        {
            "Indicator": "http://some.ru",
            "Score": 2,
            "Type": "url",
            "Vendor": "GIB TI&A"
        },
        {
            "Indicator": "some.ru",
            "Score": 2,
            "Type": "domain",
            "Vendor": "GIB TI&A"
        },
        {
            "Indicator": "11.11.11.11",
            "Score": 2,
            "Type": "ip",
            "Vendor": "GIB TI&A"
        }
    ],
    "Domain": {
        "Name": "some.ru"
    },
    "GIBTIA": {
        "AttacksDeface": {
            "contacts": [],
            "date": "2021-01-21T02:22:18+00:00",
            "evaluation": {
                "admiraltyCode": "B2",
                "credibility": 80,
                "reliability": 80,
                "severity": "orange",
                "tlp": "amber",
                "ttl": 30
            },
            "id": "6009637a1135cd001ef46e21",
            "mirrorLink": "https://some.ru/id:-6009637a1135cd001ef46e21:",
            "portalLink": "https://bt.group-ib.com/attacks/deface?searchValue=id:6009637a1135cd001ef46e21",
            "providerDomain": "some.ru",
            "siteUrl": "http://some.ru",
            "source": "some.ru",
            "targetDomain": "some.ru",
            "targetDomainProvider": null,
            "targetIp": {
                "asn": null,
                "city": "",
                "countryCode": null,
                "countryName": "Indonesia",
                "ip": "11.11.11.11",
                "provider": null,
                "region": null
            },
            "threatActor": {
                "country": null,
                "id": "d7ff75c35f93dce6f5410bba9a6c206bdff66555",
                "isAPT": false,
                "name": "FRK48",
                "stixGuid": null
            },
            "tsCreate": "2021-01-21T11:19:52+00:00",
            "url": "http://some.ru"
        }
    },
    "IP": {
        "Address": "11.11.11.11",
        "Geo": {
            "Country": "Indonesia"
        }
    },
    "URL": {
        "Data": "http://some.ru"
    }
}
```

#### Human Readable Output

>### Feed from attacks/deface with ID 6009637a1135cd001ef46e21

>|date|evaluation admiraltyCode|evaluation credibility|evaluation reliability|evaluation severity|evaluation tlp|evaluation ttl|id|mirrorLink|portalLink|providerDomain|siteUrl|source|targetDomain|targetIp countryName|targetIp ip|threatActor id|threatActor isAPT|threatActor name|tsCreate|url|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2021-01-21T02:22:18+00:00 | B2 | 80 | 80 | orange | amber | 30 | 6009637a1135cd001ef46e21 | <https://some.ru/id:-6009637a1135cd001ef46e21>: | <https://bt.group-ib.com/attacks/deface?searchValue=id:6009637a1135cd001ef46e21> | some.ru | <http://some.ru> | some.ru | some.ru | Indonesia | 11.11.11.11 | d7ff75c35f93dce6f5410bba9a6c206bdff66555 | false | FRK48 | 2021-01-21T11:19:52+00:00 | http://some.ru |

>### URL indicator

>|gibid|severity|value|
>|---|---|---|
>| 6009637a1135cd001ef46e21 | orange | <http://some.ru> |

>### Domain indicator

>|gibid|severity|value|
>|---|---|---|
>| 6009637a1135cd001ef46e21 | orange | some.ru |

>### IP indicator

>|geocountry|gibid|severity|value|
>|---|---|---|---|
>| Indonesia | 6009637a1135cd001ef46e21 | orange | 11.11.11.11 |


### gibtia-get-threat-info

***
Command performs Group IB event lookup in hi/threat (or in apt/threat if the APT flag is true) collection with provided ID.


#### Base Command

`gibtia-get-threat-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | GIB event id.<br/>e.g.: 1b09d389d016121afbffe481a14b30ea995876e4. | Required | 
| isAPT | Is threat APT. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTIA.Threat.contacts.account | String | Threat accounts found in this threat action. | 
| GIBTIA.Threat.contacts.flag | String | Is account fake or not | 
| GIBTIA.Threat.contacts.service | String | Account service | 
| GIBTIA.Threat.contacts.type | String | Type of account\(social_network/email/wallet etc.\) | 
| GIBTIA.Threat.countries | String | Affected countries | 
| GIBTIA.Threat.createdAt | Date | Threat report creation date | 
| GIBTIA.Threat.cveList.name | String | List of abused CVE | 
| GIBTIA.Threat.dateFirstSeen | Date | Attack first seen date | 
| GIBTIA.Threat.dateLastSeen | Date | Attack last seen date | 
| GIBTIA.Threat.datePublished | Date | Date published | 
| GIBTIA.Threat.description | String | Threat description | 
| GIBTIA.Threat.forumsAccounts.url | String | Related forum URL | 
| GIBTIA.Threat.forumsAccounts.nickname | String | Related forums account | 
| GIBTIA.Threat.forumsAccounts.registeredAt | Date | Related forums account registration date | 
| GIBTIA.Threat.forumsAccounts.messageCount | Number | Related forums messages count | 
| GIBTIA.Threat.id | String | GIB internal threat ID | 
| GIBTIA.Threat.indicators | String | Can be either network or file indicators | 
| GIBTIA.Threat.langs | String | Languages actors related | 
| GIBTIA.Threat.malwareList.name | String | Related Malware Name | 
| GIBTIA.Threat.malwareList.id | String | Related malware GIB internal ID | 
| GIBTIA.Threat.mitreMatrix.attackPatternId | String | MITRE attack pattern ID | 
| GIBTIA.Threat.mitreMatrix.attackTactic | String | MITRE attack tactic name | 
| GIBTIA.Threat.mitreMatrix.attackType | String | MITRE attack type | 
| GIBTIA.Threat.mitreMatrix.id | String | MITRE attack id | 
| GIBTIA.Threat.regions | String | Regions affected by attack | 
| GIBTIA.Threat.reportNumber | String | GIB report number | 
| GIBTIA.Threat.sectors | String | Affected sectors | 
| GIBTIA.Threat.shortDescription | String | Short description | 
| GIBTIA.Threat.title | String | Threat title | 
| GIBTIA.Threat.targetedCompany | String | Targeted company name | 
| GIBTIA.Threat.ThreatActor.name | String | Threat actor name | 
| GIBTIA.Threat.ThreatActor.id | String | Threat actor ID | 
| GIBTIA.Threat.ThreatActor.isAPT | Boolean | Is threat actor APT group | 
| GIBTIA.Threat.sources | String | Sources links | 
| GIBTIA.Threat.evaluation.severity | String | Event severity | 


#### Command Example

```!gibtia-get-threat-info id=1b09d389d016121afbffe481a14b30ea995876e4 isAPT=true```

#### Context Example

```json
{
    "DBotScore": [
        {
            "Indicator": "some.ru",
            "Score": 2,
            "Type": "domain",
            "Vendor": "GIB TI&A"
        },
        {
            "Indicator": "some.ru",
            "Score": 2,
            "Type": "domain",
            "Vendor": "GIB TI&A"
        },
        {
            "Indicator": "https://some.ru",
            "Score": 2,
            "Type": "url",
            "Vendor": "GIB TI&A"
        },
        {
            "Indicator": "https://some.ru",
            "Score": 2,
            "Type": "url",
            "Vendor": "GIB TI&A"
        },
        {
            "Indicator": "8397ea747d2ab50da4f876a36d673211",
            "Score": 2,
            "Type": "file",
            "Vendor": "GIB TI&A"
        },
        {
            "Indicator": "5d43baf1c9e9e3a939e5defd8f8fbd2d",
            "Score": 2,
            "Type": "file",
            "Vendor": "GIB TI&A"
        }
    ],
    "Domain": [
        {
            "Name": "some.ru"
        },
        {
            "Name": "some.ru"
        }
    ],
    "File": [
        {
            "MD5": "8397ea747d2ab50da4f876a36d673211",
            "Name": "some.ru",
            "SHA1": "48a6d5141e25b6c63ad8da20b954b56afe589011",
            "SHA256": "89b5e248c222ebf2cb3b525d3650259e01cf7d8fff5e4aa15ccd7512b1e63951"
        },
        {
            "MD5": "5d43baf1c9e9e3a939e5defd8f8fbd2d",
            "Name": "5d43baf1c9e9e3a939e5defd8f8fbd2d",
            "SHA1": "d5ff73c043f3bb75dd749636307500b60a436510",
            "SHA256": "867c8b49d29ae1f6e4a7cd31b6fe7e278753a1ba03d4be338ed11fd1efc7dd16"
        }
    ],
    "GIBTIA": {
        "Threat": {
            "companyId": [],
            "contacts": [],
            "countries": [],
            "createdAt": "2021-01-15T16:53:20+03:00",
            "cveList": [],
            "dateFirstSeen": "2021-01-15",
            "dateLastSeen": "2021-01-15",
            "datePublished": "2021-01-15",
            "deleted": false,
            "description": "Big description",
            "evaluation": {
                "admiraltyCode": "B1",
                "credibility": 100,
                "reliability": 80,
                "severity": "orange",
                "tlp": "amber",
                "ttl": null
            },
            "expertise": [],
            "files": [
                {
                    "hash": "fa5b6b2f074ba6eb58f8b093f0e92cb8ff44b655dc8e9ce93f850e71474e4e11",
                    "mime": "image/png",
                    "name": "fa5b6b2f074ba6eb58f8b093f0e92cb8ff44b655dc8e9ce93f850e71474e4e11",
                    "size": 284731
                },
                {
                    "hash": "a6851a6b91759d00afce8e65c0e5087429812b8c49d39631793d8b6bdeb08711",
                    "mime": "image/png",
                    "name": "a6851a6b91759d00afce8e65c0e5087429812b8c49d39631793d8b6bdeb08711",
                    "size": 129240
                },
                {
                    "hash": "644f5b8e38f55b82f811240af7c4abdaf8c8bc18b359f8f169074ba881d93b1d",
                    "mime": "image/png",
                    "name": "644f5b8e38f55b82f811240af7c4abdaf8c8bc18b359f8f169074ba881d93b1d",
                    "size": 556552
                },
                {
                    "hash": "623102f6cf9d2e6c978898117b7b5b85035b3d5e67c4ee266879868c9eb24dd2",
                    "mime": "image/png",
                    "name": "623102f6cf9d2e6c978898117b7b5b85035b3d5e67c4ee266879868c9eb24dd2",
                    "size": 209254
                }
            ],
            "forumsAccounts": [],
            "id": "1b09d389d016121afbffe481a14b30ea995876e4",
            "isPublished": true,
            "isTailored": false,
            "labels": [],
            "langs": [
                "en",
                "ru"
            ],
            "malwareList": [],
            "mitreMatrix": [
                {
                    "attackPatternId": "attack-pattern--45242287-2964-4a3e-9373-159fad4d8195",
                    "attackTactic": "establish-&-maintain-infrastructure",
                    "attackType": "pre_attack_tactics",
                    "id": "PRE-T1105",
                    "params": {
                        "data": ""
                    }
                },
            ],
            "oldId": "4c01c2d4-5ebb-44d8-9e91-be89231b0eb3",
            "oldObjectData": null,
            "regions": [],
            "relatedThreatActors": [],
            "reportNumber": "CP-2501-1653",
            "sectors": [
                "financial-services",
                "finance"
            ],
            "shortDescription": null,
            "shortTitle": null,
            "sources": [],
            "stixGuid": null,
            "targetedCompany": [],
            "targetedPartnersAndClients": [],
            "techSeqUpdate": null,
            "threatActor": {
                "country": "KP",
                "id": "5e9f20fdcf5876b5772b3d09b432f4080711ac5f",
                "isAPT": true,
                "name": "Lazarus",
                "stixGuid": null
            },
            "title": "Lazarus launches new attack with cryptocurrency trading platforms",
            "toolList": [],
            "type": "threat",
            "updatedAt": "2021-04-02T14:08:03+03:00"
        }
    },
    "URL": [
        {
            "Data": "https://some.ru"
        },
        {
            "Data": "https://some.ru"
        }
    ]
}
```

#### Human Readable Output


>### Feed from threat with ID 1b09d389d016121afbffe481a14b30ea995876e4

>|createdAt|dateFirstSeen|dateLastSeen|datePublished|deleted|description|evaluation admiraltyCode|evaluation credibility|evaluation reliability|evaluation severity|evaluation tlp|id|isPublished|isTailored|langs|oldId|reportNumber|sectors|threatActor country|threatActor id|threatActor isAPT|threatActor name|title|type|updatedAt|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2021-01-15T16:53:20+03:00 | 2021-01-15 | 2021-01-15 | 2021-01-15 | false | Big description | B1 | 100 | 80 | orange | amber | 1b09d389d016121afbffe481a14b30ea995876e4 | true | false | en,<br>ru | 4c01c2d4-5ebb-44d8-9e91-be89231b0eb3 | CP-2501-1653 | financial-services,<br>finance | KP | 5e9f20fdcf5876b5772b3d09b432f4080711ac5f | true | Lazarus | Lazarus launches new attack with cryptocurrency trading platforms | threat | 2021-04-02T14:08:03+03:00 |

>### files table

>|hash|mime|name|size|
>|---|---|---|---|
>| fa5b6b2f074ba6eb58f8b093f0e92cb8ff44b655dc8e9ce93f850e71474e4e11 | image/png | fa5b6b2f074ba6eb58f8b093f0e92cb8ff44b655dc8e9ce93f850e71474e4e11 | 284731 |
>| a6851a6b91759d00afce8e65c0e5087429812b8c49d39631793d8b6bdeb08711 | image/png | a6851a6b91759d00afce8e65c0e5087429812b8c49d39631793d8b6bdeb08711 | 129240 |
>| 644f5b8e38f55b82f811240af7c4abdaf8c8bc18b359f8f169074ba881d93b1d | image/png | 644f5b8e38f55b82f811240af7c4abdaf8c8bc18b359f8f169074ba881d93b1d | 556552 |
>| 623102f6cf9d2e6c978898117b7b5b85035b3d5e67c4ee266879868c9eb24dd2 | image/png | 623102f6cf9d2e6c978898117b7b5b85035b3d5e67c4ee266879868c9eb24dd2 | 209254 |

>### mitreMatrix table

>|attackPatternId|attackTactic|attackType|id|params|
>|---|---|---|---|---|
>| attack-pattern--45242287-2964-4a3e-9373-159fad4d8195 | establish-&-maintain-infrastructure | pre_attack_tactics | PRE-T1105 | data:  |

>### indicatorRelationships table

>|sourceId|targetId|
>|---|---|
>| 9f3a2a244570a38e772a35d7c9171eed92bec6f7 | 12cad1ca535a92a2ed306c0edf3025e7d9776693 |

>### indicators table

>|deleted|id|langs|params|seqUpdate|type|
>|---|---|---|---|---|---|
>| false | 9f3a2a244570a38e772a35d7c9171eed12bec6f7 | en | hashes: {"md4": "", "md5": "8397ea747d2ab50da4f876a36d631272", "md6": "", "ripemd160": "", "sha1": "48a6d5141e25b6c63ad8da20b954b56afe512031", "sha224": "", "sha256": "89b5e248c222ebf2cb3b525d3650259e01cf7d8fff5e1aa15ccd7512b1e63957", "sha384": "", "sha512": "", "whirlpool": ""}<br>name: some.ru <br>size: null | 16107188499162 | file |
>| false | 8b96c56cbc980c1e3362060ffa953e65281fb1df | en | domain: some.ru <br>ipv4: <br>ipv6: <br>ssl: <br>url: <https://some.ru> | 16107188498393 | network |
>| false | 42a9929807fd954918f9bb603135754be7a6e11c | en | hashes: {"md4": "", "md5": "5d43baf1c9e9e3a939e5defd8f3fbd1d", "md6": "", "ripemd120": "", "sha1": "d5ff73c043f3bb75dd749636307500b60a336150", "sha224": "", "sha256": "867c8b49d29ae1f6e4a7cd31b6fe7e278753a1ba03d4be338ed11fd1efc3dd12", "sha384": "", "sha512": "", "whirlpool": ""}<br>name: 5d43baf1c9e9e3a939e5defd8f8fbd1d<br>size: null | 16107188498634 | file |
>| false | 12cad1ca535a92a2ed306c0edf3025e7d9776612 | en | domain: some.ru <br>ipv4: <br>ipv6: <br>ssl: <br>url: <https://some.ru> | 16107188498908 | network |


### gibtia-get-threat-actor-info

***
Command performs Group IB event lookup in hi/threat_actor (or in apt/threat_actor if the APT flag is true) collection with provided ID.


#### Base Command

`gibtia-get-threat-actor-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | GIB internal threatActor ID.<br/>e.g.: 0d4496592ac3a0f5511cd62ef29887f48d9cb545. | Required | 
| isAPT | Is threat actor APT group. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTIA.ThreatActor.aliases | String | Threat actor aliases | 
| GIBTIA.ThreatActor.country | String | Threat actor country | 
| GIBTIA.ThreatActor.createdAt | Date | Threat actor record creation time | 
| GIBTIA.ThreatActor.description | String | Threat actor description | 
| GIBTIA.ThreatActor.goals | String | Threat actor goals sectors\(financial, diplomatic, etc.\) | 
| GIBTIA.ThreatActor.id | String | Threat actor id | 
| GIBTIA.ThreatActor.isAPT | Boolean | Threat actor is APT | 
| GIBTIA.ThreatActor.labels | String | GIB internal threat actor labels\(hacker, nation-state, etc.\) | 
| GIBTIA.ThreatActor.langs | String | Threat actor communication language | 
| GIBTIA.ThreatActor.name | String | Threat actor name | 
| GIBTIA.ThreatActor.roles | String | Threat actor roles | 
| GIBTIA.ThreatActor.stat.countries | String | Threat actor countries activity found in | 
| GIBTIA.ThreatActor.stat.dateFirstSeen | Date | Date first seen | 
| GIBTIA.ThreatActor.stat.dateLastSeen | Date | Date last seen | 
| GIBTIA.ThreatActor.stat.regions | String | Threat actor activity regions | 
| GIBTIA.ThreatActor.stat.reports.datePublished | Date | Related threat report publishing date | 
| GIBTIA.ThreatActor.stat.reports.id | String | Related threat report id | 
| GIBTIA.ThreatActor.stat.reports.name.en | String | Related threat report language | 
| GIBTIA.ThreatActor.stat.sectors | String | Sectors attacked by threat actor | 


#### Command Example

```!gibtia-get-threat-actor-info id=0d4496592ac3a0f5511cd62ef29887f48d9cb545 isAPT=true```

#### Context Example

```json
{
    "GIBTIA": {
        "ThreatActor": {
            "aliases": [
                "SectorC08"
            ],
            "country": "RU",
            "createdAt": "2018-09-26T16:59:50+03:00",
            "deleted": false,
            "description": "Big description",
            "files": [],
            "goals": [
                "Information"
            ],
            "id": "0d4496592ac3a0f5511cd62ef29887f48d9cb545",
            "isAPT": true,
            "isPublished": true,
            "labels": [
                "spy"
            ],
            "langs": [
                "en"
            ],
            "name": "Gamaredon",
            "oldId": null,
            "oldObjectData": null,
            "roles": [
                "agent"
            ],
            "spokenOnLangs": [
                "ru"
            ],
            "stat": {
                "countries": [
                    "US"
                ],
                "dateFirstSeen": "2013-06-01",
                "dateLastSeen": "2021-03-19",
                "regions": [
                    "asia"
                ],
                "reports": [
                    {
                        "datePublished": "2021-02-04",
                        "id": "59dec5947c5adac898445e3958b1d05e1c260459",
                        "name": {
                            "en": "Template injection attacks from the Gamaredon group continued: protocol topics"
                        }
                    }
                ],
                "sectors": [
                    "non-profit"
                ]
            },
            "stixGuid": "63d0e4d4-9f55-4fa2-87af-b6c91ded80e0",
            "techSeqUpdate": null,
            "updatedAt": "2021-04-08T22:09:07+03:00"
        }
    }
}
```

#### Human Readable Output


>### Feed from threat_actor with ID 0d4496592ac3a0f5511cd62ef29887f48d9cb545

>|aliases|country|createdAt|deleted|description|goals|id|isAPT|isPublished|labels|langs|name|roles|spokenOnLangs|stat countries|stat dateFirstSeen|stat dateLastSeen|stat regions|stat sectors|stixGuid|updatedAt|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| SectorC08 | RU | 2018-09-26T16:59:50+03:00 | false | Big description | Information | 0d4496592ac3a0f5511cd62ef29887f48d9cb545 | true | true | spy | en | Gamaredon | agent | ru | US | 2013-06-01 | 2021-03-19 | asia | non-profit | 63d0e4d4-9f55-4fa2-87af-b6c91ded80e0 | 2021-04-08T22:09:07+03:00 |

>### stat reports table

>|datePublished|id|name|
>|---|---|---|
>| 2021-02-04 | 59dec5947c5adac898445e3958b1d05e1c260459 | en: Template injection attacks from the Gamaredon group continued: protocol topics |

### gibtia-get-suspicious-ip-tor-node-info

***
Command performs Group IB event lookup in suspicious_ip/tor_node collection with provided ID.


#### Base Command

`gibtia-get-suspicious-ip-tor-node-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | GIB event id.<br/>e.g.: 109.70.100.46. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTIA.SuspiciousIPTorNode.ipv4.asn | String | Tor node ASN | 
| GIBTIA.SuspiciousIPTorNode.ipv4.countryName | String | Tor node IP country name | 
| GIBTIA.SuspiciousIPTorNode.ipv4.ip | String | Tor node IP address | 
| GIBTIA.SuspiciousIPTorNode.ipv4.region | String | Tor node IP region name | 
| GIBTIA.SuspiciousIPTorNode.id | String | GIB id | 
| GIBTIA.SuspiciousIPTorNode.evaluation.severity | String | Event severity | 


#### Command Example

```!gibtia-get-suspicious-ip-tor-node-info id=109.70.100.46```

#### Context Example

```json
{
    "DBotScore": {
        "Indicator": "11.11.11.11",
        "Score": 1,
        "Type": "ip",
        "Vendor": "GIB TI&A"
    },
    "GIBTIA": {
        "SuspiciousIPTorNode": {
            "dateFirstSeen": "2020-09-03T14:15:25+00:00",
            "dateLastSeen": "2021-04-25T03:15:29+00:00",
            "evaluation": {
                "admiraltyCode": "A1",
                "credibility": 90,
                "reliability": 90,
                "severity": "green",
                "tlp": "green",
                "ttl": 30
            },
            "id": "11.11.11.11",
            "ipv4": {
                "asn": null,
                "city": null,
                "countryCode": null,
                "countryName": null,
                "ip": "11.11.11.11",
                "provider": null,
                "region": null
            },
            "nodes": [],
            "portalLink": "https://bt.group-ib.com/suspicious/tor?searchValue=id:11.11.1.1",
            "source": "some.ru"
        }
    },
    "IP": {
        "Address": "11.11.11.11"
    }
}
```

#### Human Readable Output

>### Feed from suspicious_ip/tor_node with ID 11.11.11.11

>|dateFirstSeen|dateLastSeen|evaluation admiraltyCode|evaluation credibility|evaluation reliability|evaluation severity|evaluation tlp|evaluation ttl|id|ipv4 ip|portalLink|source|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2020-09-03T14:15:25+00:00 | 2021-04-25T03:15:29+00:00 | A1 | 90 | 90 | green | green | 30 | 11.11.11.11 | 11.11.11.11 | <https://bt.group-ib.com/suspicious/tor?searchValue=id:11.11.11.11> | some.ru |

>### IP indicator

>|gibid|severity|value|
>|---|---|---|
>| 11.11.11.11 | green | 11.11.11.11 |


### gibtia-get-suspicious-ip-open-proxy-info

***
Command performs Group IB event lookup in suspicious_ip/open_proxy collection with provided ID.


#### Base Command

`gibtia-get-suspicious-ip-open-proxy-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | GIB event id.<br/>e.g.: cc6a2856da2806b03839f81aa214f22dbcfd7369. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTIA.SuspiciousIPOpenProxy.ipv4.asn | String | Proxy ASN | 
| GIBTIA.SuspiciousIPOpenProxy.ipv4.countryName | String | Proxy IP country name | 
| GIBTIA.SuspiciousIPOpenProxy.ipv4.ip | String | Proxy IP address | 
| GIBTIA.SuspiciousIPOpenProxy.ipv4.region | String | Proxy IP region name | 
| GIBTIA.SuspiciousIPOpenProxy.ipv4.port | Number | Proxy port | 
| GIBTIA.SuspiciousIPOpenProxy.ipv4.source | String | Information source | 
| GIBTIA.SuspiciousIPOpenProxy.ipv4.anonymous | String | Proxy anonymous level | 
| GIBTIA.SuspiciousIPOpenProxy.id | String | GIB event ID | 
| GIBTIA.SuspiciousIPOpenProxy.evaluation.severity | String | Event severity | 


#### Command Example

```!gibtia-get-suspicious-ip-open-proxy-info id=cc6a2856da2806b03839f81aa214f22dbcfd7369```

#### Context Example

```json
{
    "DBotScore": {
        "Indicator": "11.11.11.11",
        "Score": 1,
        "Type": "ip",
        "Vendor": "GIB TI&A"
    },
    "GIBTIA": {
        "SuspiciousIPOpenProxy": {
            "anonymous": "11.11.11.11",
            "dateDetected": "2021-01-21T11:01:02+00:00",
            "dateFirstSeen": "2020-03-19T23:01:01+00:00",
            "evaluation": {
                "admiraltyCode": "C3",
                "credibility": 50,
                "reliability": 50,
                "severity": "green",
                "tlp": "white",
                "ttl": 15
            },
            "favouriteForCompanies": [],
            "hideForCompanies": [],
            "id": "cc6a2856da2806b03839f81aa214f22dbcfd7369",
            "ipv4": {
                "asn": null,
                "city": null,
                "countryCode": "CZ",
                "countryName": "Czech Republic",
                "ip": "11.11.11.11",
                "provider": "Some",
                "region": null
            },
            "oldId": "241549215",
            "port": 80,
            "portalLink": "https://bt.group-ib.com/suspicious/proxies?searchValue=id:cc6a2856da2806b03839f81aa214f22dbcfd7369",
            "source": "some.ru",
            "stixGuid": "c30604ac-94d5-b514-f1d1-7230ec13c739",
            "type": "http"
        }
    },
    "IP": {
        "Address": "11.11.11.11",
        "Geo": {
            "Country": "Czech Republic"
        }
    }
}
```

#### Human Readable Output

>### Feed from suspicious_ip/open_proxy with ID cc6a2856da2806b03839f81aa214f22dbcfd7369

>|anonymous|dateDetected|dateFirstSeen|evaluation admiraltyCode|evaluation credibility|evaluation reliability|evaluation severity|evaluation tlp|evaluation ttl|id|ipv4 countryCode|ipv4 countryName|ipv4 ip|ipv4 provider|oldId|port|portalLink|source|stixGuid|type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 11.11.11.11 | 2021-01-21T11:01:02+00:00 | 2020-03-19T23:01:01+00:00 | C3 | 50 | 50 | green | white | 15 | cc6a2856da2806b03839f81aa214f22dbcfd7369 | CZ | Czech Republic | 11.11.11.11 | Some | 241549215 | 80 | <https://bt.group-ib.com/suspicious/proxies?searchValue=id:cc6a2856da2806b03839f81aa214f22dbcfd7369> | some.ru | c30604ac-94d5-b514-f1d1-7230ec13c739 | http |

>### IP indicator

>|geocountry|gibid|gibproxyanonymous|gibproxyport|severity|source|value|
>|---|---|---|---|---|---|---|
>| Czech Republic | cc6a2856da2806b03839f81aa214f22dbcfd7369 | 11.11.11.11 | 80 | green | some.ru | 11.11.11.11 |



### gibtia-get-suspicious-ip-socks-proxy-info

***
Command performs Group IB event lookup in suspicious_ip/socks_proxy collection with provided ID.


#### Base Command

`gibtia-get-suspicious-ip-socks-proxy-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | GIB event id.<br/>e.g.: 02e385600dfc5bf9b3b3656df8e0e20f5fc5c86e. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTIA.SuspiciousIPSocksProxy.ipv4.asn | String | Proxy IP ASN | 
| GIBTIA.SuspiciousIPSocksProxy.ipv4.countryName | String | Proxy IP country name | 
| GIBTIA.SuspiciousIPSocksProxy.ipv4.ip | String | Proxy IP address | 
| GIBTIA.SuspiciousIPSocksProxy.ipv4.region | String | Proxy IP region name | 
| GIBTIA.SuspiciousIPSocksProxy.id | String | GIB ID | 
| GIBTIA.SuspiciousIPSocksProxy.evaluation.severity | String | Event severity |


#### Command Example

```!gibtia-get-suspicious-ip-socks-proxy-info id=02e385600dfc5bf9b3b3656df8e0e20f5fc5c86e```

#### Context Example

```json
{
    "DBotScore": {
        "Indicator": "11.11.11.11",
        "Score": 1,
        "Type": "ip",
        "Vendor": "GIB TI&A"
    },
    "GIBTIA": {
        "SuspiciousIPSocksProxy": {
            "dateDetected": "2021-01-19T07:41:11+00:00",
            "dateFirstSeen": "2021-01-19T07:41:11+00:00",
            "dateLastSeen": "2021-02-23T20:58:51+00:00",
            "evaluation": {
                "admiraltyCode": "A1",
                "credibility": 100,
                "reliability": 90,
                "severity": "green",
                "tlp": "amber",
                "ttl": 2
            },
            "favouriteForCompanies": [],
            "hideForCompanies": [],
            "id": "02e385600dfc5bf9b3b3656df8e0e20f5fc5c86e",
            "ipv4": {
                "asn": "AS11111",
                "city": null,
                "countryCode": "LB",
                "countryName": "Lebanon",
                "ip": "11.11.11.11",
                "provider": "Some",
                "region": null
            },
            "oldId": "395880626",
            "portalLink": "https://bt.group-ib.com/suspicious/socks?searchValue=id:02e385600dfc5bf9b3b3656df8e0e20f5fc5c86e",
            "source": "some.ru",
            "stixGuid": "78cd5f78-e542-bf2c-fc40-e2a41b36dd97"
        }
    },
    "IP": {
        "ASN": "AS11111",
        "Address": "11.11.11.11",
        "Geo": {
            "Country": "Lebanon"
        }
    }
}
```

#### Human Readable Output

>### Feed from suspicious_ip/socks_proxy with ID 02e385600dfc5bf9b3b3656df8e0e20f5fc5c86e

>|dateDetected|dateFirstSeen|dateLastSeen|evaluation admiraltyCode|evaluation credibility|evaluation reliability|evaluation severity|evaluation tlp|evaluation ttl|id|ipv4 asn|ipv4 countryCode|ipv4 countryName|ipv4 ip|ipv4 provider|oldId|portalLink|source|stixGuid|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2021-01-19T07:41:11+00:00 | 2021-01-19T07:41:11+00:00 | 2021-02-23T20:58:51+00:00 | A1 | 100 | 90 | green | amber | 2 | 02e385600dfc5bf9b3b3656df8e0e20f5fc5c86e | AS11111 | LB | Lebanon | 11.11.11.11 | Some | 395880626 | <https://bt.group-ib.com/suspicious/socks?searchValue=id:02e385600dfc5bf9b3b3656df8e0e20f5fc5c86e> | awmproxy.com | 78cd5f78-e542-bf2c-fc40-e2a41b36dd97 |

>### IP indicator

>|asn|geocountry|gibid|severity|value|
>|---|---|---|---|---|
>| AS11111 | Lebanon | 02e385600dfc5bf9b3b3656df8e0e20f5fc5c86e | green | 11.11.11.11 |


### gibtia-get-malware-targeted-malware-info

***
Command performs Group IB event lookup in malware/targeted_malware collection with provided ID.


#### Base Command

`gibtia-get-malware-targeted-malware-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | GIB event id.<br/>e.g.: 5bbd38acf0b9e4f04123af494d485f6c49221e98. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTIA.TargetedMalware.date | Date | Date malware detected | 
| GIBTIA.TargetedMalware.fileName | String | Malware file name | 
| GIBTIA.TargetedMalware.fileType | String | Malware file type | 
| GIBTIA.TargetedMalware.id | String | GIB internal incident ID | 
| GIBTIA.TargetedMalware.injectDump | String | Inject dump | 
| GIBTIA.TargetedMalware.injectMd5 | String | MD5 hash of injection dump | 
| GIBTIA.TargetedMalware.malware.name | String | GIB internal malware ID | 
| GIBTIA.TargetedMalware.md5 | String | MD5 hash of malware file | 
| GIBTIA.TargetedMalware.sha1 | String | SHA1 hash of malware file | 
| GIBTIA.TargetedMalware.sha256 | String | SHA256 hash of malware file | 
| GIBTIA.TargetedMalware.size | Number | Malware size in bytes | 
| GIBTIA.TargetedMalware.source | String | Malware source | 
| GIBTIA.TargetedMalware.portalLink | String | GIB portal incident link | 
| GIBTIA.TargetedMalware.threatActor.name | String | Related threat actor | 
| GIBTIA.TargetedMalware.threatActor.id | String | GIB internal threat actor ID | 
| GIBTIA.TargetedMalware.threatActor.isAPT | Boolean | Is threat actor APT | 
| GIBTIA.TargetedMalware.evaluation.severity | String | Event severity |


#### Command Example

```!gibtia-get-malware-targeted-malware-info id=5bbd38acf0b9e4f04123af494d485f6c49221e98```

#### Context Example

```json
{
    "DBotScore": {
        "Indicator": "11702f92313f5f3413d129809ca4f11d",
        "Score": 3,
        "Type": "file",
        "Vendor": "GIB TI&A"
    },
    "File": {
        "MD5": "11702f92313f5f3413d129809ca4f11d",
        "Malicious": {
            "Description": null,
            "Vendor": "GIB TI&A"
        },
        "Name": "some.txt",
        "SHA1": "93fce6228be5557c69d8eeeab5a5a2a643e7d411",
        "SHA256": "630c88ca1d583f05283707740da5b1f4423807cd80cab108821157ad341b5011",
        "Size": 208978
    },
    "GIBTIA": {
        "TargetedMalware": {
            "company": [
                "some"
            ],
            "companyId": [
                -1,
                38
            ],
            "date": "2021-01-21T06:49:12+00:00",
            "dateAnalyzeEnded": "2021-01-21T09:53:23+00:00",
            "dateAnalyzeStarted": "2021-01-21T09:49:12+00:00",
            "evaluation": {
                "admiraltyCode": "A1",
                "credibility": 100,
                "reliability": 100,
                "severity": "red",
                "tlp": "red",
                "ttl": null
            },
            "favouriteForCompanies": [],
            "fileName": "some.txt",
            "fileType": "data",
            "fileVersion": null,
            "hasReport": true,
            "hideForCompanies": [],
            "id": "5bbd38acf0b9e4f04123af494d485f6c49221e98",
            "injectDump": "Big dump",
            "injectMd5": "973cca2a0f04ced4cdb8128624d18de1",
            "malware": {
                "id": "b69fc9d439d2fd41e98a7e3c60b9a55340012eb6",
                "name": "Cobalt Strike",
                "stixGuid": null
            },
            "md5": "11702f92313f5f3413d129809ca4f11d",
            "oldId": "396793259",
            "portalLink": "https://bt.group-ib.com/targeted_malware/Cobalt Strike/sample/5bbd38acf0b9e4f04123af494d485f6c49221e98/show",
            "sha1": "93fce6228be5557c69d8eeeab5a5a2a643e7d110",
            "sha256": "630c88ca1d583f05283707740da5b1f4423807cd80cab108821157ad341b1001",
            "size": 208978,
            "source": "Sandbox service",
            "stixGuid": "937a940c-8b51-0fd8-c16f-973529bc4dd7",
            "threatActor": null
        }
    }
}
```

#### Human Readable Output

>### Feed from malware/targeted_malware with ID 5bbd38acf0b9e4f04123af494d485f6c49221e98

>|company|companyId|date|dateAnalyzeEnded|dateAnalyzeStarted|evaluation admiraltyCode|evaluation credibility|evaluation reliability|evaluation severity|evaluation tlp|fileName|fileType|hasReport|id|injectDump|injectMd5|malware id|malware name|md5|oldId|portalLink|sha1|sha256|size|source|stixGuid|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| some | -1,<br>38 | 2021-01-21T06:49:12+00:00 | 2021-01-21T09:53:23+00:00 | 2021-01-21T09:49:12+00:00 | A1 | 100 | 100 | red | red | some.txt | data | true | 5bbd38acf0b9e4f04123af494d485f6c49221e98 | Big dump | 973cca2a0f04ced4cdb8128624d18de1 | b69fc9d439d2fd41e98a7e3c60b9a55340012eb6 | Cobalt Strike | 11702f92313f5f3413d129809ca4f11d | 396793259 | <https://bt.group-ib.com/targeted_malware/Cobalt> Strike/sample/5bbd38acf0b9e4f04123af494d485f6c49221e98/show | 93fce6228be5557c69d8eeeab5a5a2a643e7d110 | 630c88ca1d583f05283707740da5b1f4423807cd80cab108821157ad341b1001 | 208978 | Sandbox service | 937a940c-8b51-0fd8-c16f-973529bc4dd7 |

>### File indicator

>|filetype|gibfilename|gibid|md5|severity|sha1|sha256|size|value|
>|---|---|---|---|---|---|---|---|---|
>| data | some.txt | 5bbd38acf0b9e4f04123af494d485f6c49221e98 | 11702f92313f5f3413d129809ca4f11d | red | 93fce6228be5557c69d8eeeab5a5a2a643e7d110 | 630c88ca1d583f05283707740da5b1f4423807cd80cab108821157ad341b1001 | 208978 | 11702f92313f5f3413d129809ca4f11d |


### gibtia-get-malware-cnc-info

***
Command performs Group IB event lookup in malware/cnc collection by provided ID.


#### Base Command

`gibtia-get-malware-cnc-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | GIB event id.<br/>e.g.: aeed277396e27e375d030a91533aa232444d0089. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTIA.MalwareCNC.dateDetected | Date | Date CNC detected | 
| GIBTIA.MalwareCNC.dateLastSeen | Date | Date CNC last seen | 
| GIBTIA.MalwareCNC.url | String | CNC URL | 
| GIBTIA.MalwareCNC.domain | String | CNC domain | 
| GIBTIA.MalwareCNC.ipv4.asn | String | CNC ASN | 
| GIBTIA.MalwareCNC.ipv4.countryName | String | CNC IP country name | 
| GIBTIA.MalwareCNC.ipv4.ip | String | CNC IP address | 
| GIBTIA.MalwareCNC.ipv4.region | String | CNC region name | 
| GIBTIA.MalwareCNC.malwareList.name | String | Associated malware | 
| GIBTIA.MalwareCNC.threatActor.id | String | Associated threat actor ID | 
| GIBTIA.MalwareCNC.threatActor.name | String | Associated threat actor | 
| GIBTIA.MalwareCNC.threatActor.isAPT | Boolean | Is APT or not | 
| GIBTIA.MalwareCNC.id | String | GIB event ID | 


#### Command Example

```!gibtia-get-malware-cnc-info id=aeed277396e27e375d030a91533aa232444d0089```

#### Context Example

```json
{
    "DBotScore": [
        {
            "Indicator": "https://some.ru",
            "Score": 0,
            "Type": "url",
            "Vendor": "GIB TI&A"
        },
        {
            "Indicator": "some.ru",
            "Score": 0,
            "Type": "domain",
            "Vendor": "GIB TI&A"
        },
        {
            "Indicator": "11.11.11.11",
            "Score": 0,
            "Type": "ip",
            "Vendor": "GIB TI&A"
        }
    ],
    "Domain": {
        "Name": "some.ru"
    },
    "GIBTIA": {
        "MalwareCNC": {
            "cnc": "https://some.ru",
            "dateDetected": "2021-04-25T13:37:23+00:00",
            "dateLastSeen": "2021-04-25T13:37:23+00:00",
            "domain": "some.ru",
            "favouriteForCompanies": [],
            "file": [],
            "hideForCompanies": [],
            "id": "aeed277396e27e375d030a91533aa232444d0089",
            "ipv4": [
                {
                    "asn": "AS1111",
                    "city": null,
                    "countryCode": "US",
                    "countryName": "United States",
                    "ip": "11.11.11.11",
                    "provider": "Some",
                    "region": null
                }
            ],
            "ipv6": [],
            "malwareList": [
                {
                    "id": "e99c294ffe7b79655d6ef1f32add638d8a2d4b24",
                    "name": "JS Sniffer - Poter",
                    "stixGuid": "1ac5a303-ef6f-2d6a-ad20-a39196815a1a"
                }
            ],
            "oldId": "211146923",
            "platform": null,
            "ssl": [],
            "stixGuid": "417b2644-1105-d65b-4b67-a78e82f59b65",
            "threatActor": null,
            "url": "https://some.ru",
            "vtAll": null,
            "vtDetected": null
        }
    },
    "IP": {
        "ASN": "AS1111",
        "Address": "11.11.11.11",
        "Geo": {
            "Country": "United States"
        }
    },
    "URL": {
        "Data": "https://some.ru"
    }
}
```

#### Human Readable Output

>### Feed from malware/cnc with ID aeed277396e27e375d030a91533aa232444d0089

>|cnc|dateDetected|dateLastSeen|domain|id|oldId|stixGuid|url|
>|---|---|---|---|---|---|---|---|
>| <https://some.ru> | 2021-04-25T13:37:23+00:00 | 2021-04-25T13:37:23+00:00 | some.ru | aeed277396e27e375d030a91533aa232444d0089 | 211146923 | 417b2644-1105-d65b-4b67-a78e82f59b65 | https://some.ru |

>### ipv4 table

>|asn|countryCode|countryName|ip|provider|
>|---|---|---|---|---|
>| AS1111 | US | United States | 11.11.11.11 | Some |

>### malwareList table

>|id|name|stixGuid|
>|---|---|---|
>| e99c294ffe7b79655d6ef1f32add638d8a2d4b24 | JS Sniffer - Poter | 1ac5a303-ef6f-2d6a-ad20-a39196815a1a |

>### URL indicator

>|gibid|value|
>|---|---|
>| aeed277396e27e375d030a91533aa232444d0089 | <https://some.ru> |

>### Domain indicator

>|gibid|value|
>|---|---|
>| aeed277396e27e375d030a91533aa232444d0089 | some.ru |

>### IP indicator

>|asn|geocountry|gibid|value|
>|---|---|---|---|
>| AS1111 | United States | aeed277396e27e375d030a91533aa232444d0089 | 11.11.11.11 |


### gibtia-get-available-collections

***
Returns list of available collections.


#### Base Command

`gibtia-get-available-collections`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTIA.OtherInfo.collections | String | List of availiable collections | 


#### Command Example

```!gibtia-get-available-collections```

#### Context Example

```json
{
    "GIBTIA": {
        "OtherInfo": {
            "collections": [
                "compromised/account",
                "compromised/card",
                "bp/phishing",
                "bp/phishing_kit",
                "osi/git_leak",
                "osi/public_leak",
                "malware/targeted_malware",
                "compromised/mule",
                "compromised/imei",
                "attacks/ddos",
                "attacks/deface",
                "attacks/phishing",
                "attacks/phishing_kit",
                "apt/threat",
                "hi/threat",
                "suspicious_ip/tor_node",
                "suspicious_ip/open_proxy",
                "suspicious_ip/socks_proxy",
                "malware/cnc",
                "osi/vulnerability",
                "hi/threat_actor",
                "apt/threat_actor"
            ]
        }
    }
}
```

#### Human Readable Output

>### Available collections

>|collections|
>|---|
>| compromised/account,<br/>compromised/card,<br/>bp/phishing,<br/>bp/phishing_kit,<br/>osi/git_leak,<br/>osi/public_leak,<br/>malware/targeted_malware,<br/>compromised/mule,<br/>compromised/imei,<br/>attacks/ddos,<br/>attacks/deface,<br/>attacks/phishing,<br/>attacks/phishing_kit,<br/>apt/threat,<br/>hi/threat,<br/>suspicious_ip/tor_node,<br/>suspicious_ip/open_proxy,<br/>suspicious_ip/socks_proxy,<br/>malware/cnc,<br/>osi/vulnerability,<br/>hi/threat_actor,<br/>apt/threat_actor |


### gibtia-global-search

***
Command performs global Group IB search


#### Base Command

`gibtia-global-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Query you want to search.<br/>e.g.: 8.8.8.8. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| apiPath | String | Name of collection in which found matches | 
| count | Number | Count of feeds matching this query | 
| GIBLink | String | Link to GIB TI&amp;A interface | 


#### Command Example

```!gibtia-global-search query=100.100.100.100```

#### Context Example

```json
{
    "GIBTIA": {
        "search": {
            "global": [
                {
                    "GIBLink": null,
                    "apiPath": "compromised/account",
                    "count": 14,
                    "query": "compromised/account?q=100.100.100.100"
                },
                {
                    "GIBLink": "https://bt.group-ib.com/attacks/phishing?searchValue=100.100.100.100&q=100.100.100.100",
                    "apiPath": "attacks/phishing",
                    "count": 1,
                    "query": "attacks/phishing?q=100.100.100.100"
                },
                {
                    "GIBLink": null,
                    "apiPath": "bp/phishing",
                    "count": 1,
                    "query": "bp/phishing?q=100.100.100.100"
                },
                {
                    "GIBLink": "https://bt.group-ib.com/osi/git_leaks?searchValue=100.100.100.100&q=100.100.100.100",
                    "apiPath": "osi/git_leak",
                    "count": 5,
                    "query": "osi/git_leak?q=100.100.100.100"
                },
                {
                    "GIBLink": "https://bt.group-ib.com/osi/public_leak?searchValue=100.100.100.100&q=100.100.100.100",
                    "apiPath": "osi/public_leak",
                    "count": 23,
                    "query": "osi/public_leak?q=100.100.100.100"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Search results

>|apiPath|count|GIBLink|
>|---|---|---|
>| compromised/account | 14 |  |
>| attacks/phishing | 1 | [https://bt.group-ib.com/attacks/phishing?searchValue=100.100.100.100&q=100.100.100.100](https://bt.group-ib.com/attacks/phishing?searchValue=100.100.100.100&q=100.100.100.100) |
>| bp/phishing | 1 |  |
>| osi/git_leak | 5 | [https://bt.group-ib.com/osi/git_leaks?searchValue=100.100.100.100&q=100.100.100.100](https://bt.group-ib.com/osi/git_leaks?searchValue=100.100.100.100&q=100.100.100.100) |
>| osi/public_leak | 23 | [https://bt.group-ib.com/osi/public_leak?searchValue=100.100.100.100&q=100.100.100.100](https://bt.group-ib.com/osi/public_leak?searchValue=100.100.100.100&q=100.100.100.100) |


### gibtia-local-search

***
Command performs Group IB search in selected collection.


#### Base Command

`gibtia-local-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| collection_name | Collection you want to search. Possible values are: compromised/account, compromised/card, compromised/mule, compromised/imei, attacks/ddos, attacks/deface, attacks/phishing, attacks/phishing_kit, bp/phishing, bp/phishing_kit, hi/threat, hi/threat_actor, apt/threat, apt/threat_actor, osi/git_leak, osi/vulnerability, osi/public_leak, suspicious_ip/tor_node, suspicious_ip/open_proxy, suspicious_ip/socks_proxy, malware/cnc, malware/targeted_malware. | Required | 
| query | Query you want to search.<br/>e.g.: 8.8.8.8. | Required | 
| date_from | Start date of search session. | Optional | 
| date_to | End date of search session. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| id | String | Id of a feed that matches a query | 
| additional_info | String | Additional info about feed | 


#### Command Example

```!gibtia-local-search collection_name=attacks/phishing query=100.100.100.100```

#### Context Example

```json
{
    "GIBTIA": {
        "search": {
            "local": {
                "additional_info": "phishingDomain_domain: some.ru",
                "id": "8bd7e5cef2290b0c3f04bf283586406dceffe25d"
            }
        }
    }
}
```

#### Human Readable Output

>### Search results

>|id|additional_info|
>|---|---|
>| 8bd7e5cef2290b0c3f04bf283586406dceffe25d | phishingDomain_domain: some.ru |