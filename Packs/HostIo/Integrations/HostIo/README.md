Use the HostIo integration to enrich domains using the Host.io API.
This integration was integrated and tested with version 1.0 of HostIo
## Configure HostIo in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL (e.g. https://host.io) | True |
| API Key | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### hostio-domain-search
***
Returns a list of domains associated with a specific field, and the total number of these domains.


#### Base Command

`hostio-domain-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| field | Field name by which to search for a domain. Possible values are: ip, ns, mx, asn, backlinks, redirects, adsense, facebook, twitter, instagram, gtm, googleanalytics, email. | Required | 
| value | The value of the given field. | Required | 
| limit | The maximum number of domains to display. Possible values are 0, 1, 5, 10, 25, 100, 250, or 1000. Default is 25. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HostIo.Search.Field | String | The field to look up. | 
| HostIo.Search.Value | String | The value of the given field. | 
| HostIo.Search.Domains | Unknown | List of domains associated with the given field. | 
| HostIo.Search.Total | Number | The total number of domains associated with the given field. | 


#### Command Example
```!hostio-domain-search field="twitter" value="elonmusk"```

#### Context Example
```json
{
    "HostIo": {
        "Search": {
            "Domains": [
                "dogedoor.net",
                "ridesharehouston.org",
                "a2ch.ru",
                "elon-airdrop.org",
                "selenianboondocks.com",
                "e-musk.org",
                "emusk4.com",
                "chaskor.ru",
                "elonbest.club",
                "muskfree.uk"
            ],
            "Field": "twitter",
            "Total": 356,
            "Value": "elonmusk"
        }
    }
}
```

#### Human Readable Output

>### Domains associated with twitter: elonmusk
>|domains|total|twitter|
>|---|---|---|
>| dogedoor.net,<br/>ridesharehouston.org,<br/>a2ch.ru,<br/>elon-airdrop.org,<br/>selenianboondocks.com | 356 | elonmusk |


### domain
***
Returns Domain information.


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | List of domains. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HostIo.Domain.web.rank | Number | A rank that's based on popularity. | 
| HostIo.Domain.web.server | String | Name of the server where the domain exists. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| Domain.Name | String | The domain name. | 
| Domain.Registrant.Name | String | The name of the registrant. | 
| Domain.Registrant.Country | String | The country of the registrant. | 
| Domain.UpdatedDate | Date | The date when the domain was last updated in ISO8601 format \(i.e. '2020-04-30T10:35:00.000Z'\). | 
| Domain.NameServers | String | Name of the server where the domain exist. | 


#### Command Example
```!domain domain="twitter.com"```

#### Context Example
```json
{
    "DBotScore": [
        {
            "Indicator": "twitter.com",
            "Score": 0,
            "Type": "domain",
            "Vendor": "HostIo"
        },
        {
            "Indicator": "twitter.com",
            "Score": 1,
            "Type": "domain",
            "Vendor": "VirusTotal"
        }
    ],
    "Domain": {
        "DNS": {
            "a": [
                "104.244.42.1",
                "104.244.42.193"
            ],
            "domain": "twitter.com",
            "mx": [
                "10 aspmx.l.google.com.",
                "20 alt1.aspmx.l.google.com.",
                "20 alt2.aspmx.l.google.com.",
                "30 aspmx2.googlemail.com.",
                "30 aspmx3.googlemail.com."
            ],
            "ns": [
                "a.r06.twtrdns.net.",
                "b.r06.twtrdns.net.",
                "c.r06.twtrdns.net.",
                "d.r06.twtrdns.net.",
                "d01-01.ns.twtrdns.net.",
                "d01-02.ns.twtrdns.net.",
                "ns1.p34.dynect.net.",
                "ns2.p34.dynect.net.",
                "ns3.p34.dynect.net.",
                "ns4.p34.dynect.net."
            ]
        },
        "Name": "twitter.com",
        "NameServers": "tsa_a",
        "Registrant": {
            "Country": null,
            "Email": null,
            "Name": "Twitter",
            "Phone": null
        },
        "UpdatedDate": "2020-11-25T20:10:08Z",
        "VirusTotal": {
            "CommunicatingHashes": [
                {
                    "date": "2021-02-27 14:49:35",
                    "positives": 63,
                    "sha256": "fa6a67bcd4d22c2dc03db54dda286b7e4f638ca69e363568c21b8b15b036b00e",
                    "total": 76
                },
                {
                    "date": "2021-02-28 02:49:35",
                    "positives": 57,
                    "sha256": "39ef7a7aa200c6c32922e0fb618b0991c4bb60563b2fd1db2e447da78f809320",
                    "total": 75
                },
                {
                    "date": "2021-02-28 02:49:35",
                    "positives": 58,
                    "sha256": "deacc09cf48dd009311f5ec24430e3528ec2cd269fe7db433701c9d6a0d97688",
                    "total": 76
                },
                {
                    "date": "2021-02-28 02:38:26",
                    "positives": 62,
                    "sha256": "25f6e207ac602c214a4781edc7f309a282cd011d821f8b4f96a4511bb38e75b1",
                    "total": 76
                },
                {
                    "date": "2021-02-28 02:38:28",
                    "positives": 62,
                    "sha256": "741fa4ed1debdef50cb3d8735f0ecff07b49bd73ca2d3b2a61ba6a0c3ab60b8b",
                    "total": 76
                }
            ],
            "DetectedURLs": [
                {
                    "positives": 2,
                    "scan_date": "2021-02-25 15:58:00",
                    "total": 84,
                    "url": "https://twitter.com/henya290"
                },
                {
                    "positives": 1,
                    "scan_date": "2021-02-08 22:53:14",
                    "total": 83,
                    "url": "http://twitter.com/pidoras6"
                },
                {
                    "positives": 1,
                    "scan_date": "2021-02-05 23:19:08",
                    "total": 83,
                    "url": "https://twitter.com/todayinsyria"
                },
                {
                    "positives": 2,
                    "scan_date": "2021-02-04 11:37:20",
                    "total": 83,
                    "url": "https://twitter.com/z0x55g"
                },
                {
                    "positives": 1,
                    "scan_date": "2021-01-31 01:53:21",
                    "total": 83,
                    "url": "https://twitter.com/todayinsyria/status/832256656176214016"
                },
                {
                    "positives": 1,
                    "scan_date": "2020-12-29 10:08:17",
                    "total": 83,
                    "url": "http://twitter.com/nygul/index.php?r=gate&ac=08a69f4b&group=rk15&debug=0"
                }
            ],
            "DownloadedHashes": [
                {
                    "date": "2019-06-16 11:01:29",
                    "positives": 1,
                    "sha256": "30296f30c8b7b7f09589c11112e52019c7bf1eb6eb8d47a6d90431952a219669",
                    "total": 54
                },
                {
                    "date": "2019-06-16 08:28:34",
                    "positives": 1,
                    "sha256": "cfa510cf95e7ac67c59165d91c1289b7e159286ae8a4b9f85f2f972edb2d102d",
                    "total": 57
                },
                {
                    "date": "2019-06-15 07:59:28",
                    "positives": 1,
                    "sha256": "e61cb7d49ac864201297a847eee19ce379bd510d99f6620c224b6ce4e43aa00f",
                    "total": 54
                },
                {
                    "date": "2019-06-14 08:57:22",
                    "positives": 1,
                    "sha256": "103c8bf188d1edc9b3e91bd2220d6e131758e48edcb99f5e946e61ab3f0535e5",
                    "total": 57
                },
                {
                    "date": "2019-06-12 22:30:11",
                    "positives": 1,
                    "sha256": "f33a3c8df022dfae87a6fed3b884193cc0b5350fceccbc0913f2f185999139d2",
                    "total": 57
                },
                {
                    "date": "2019-03-12 08:27:26",
                    "positives": 1,
                    "sha256": "af9d4e7768247a760d7fc072f5ceafc08569334e2ce60276a855078956f43fb4",
                    "total": 54
                },
                {
                    "date": "2018-12-07 04:42:50",
                    "positives": 1,
                    "sha256": "dbad7591474091ddb4613cd08234bd2712b8e3b6360e7428b6dfe89d268ddd21",
                    "total": 58
                }
            ],
            "ReferrerHashes": [
                {
                    "date": "2021-02-28 09:50:11",
                    "positives": 10,
                    "sha256": "f5d9460942a8650d15063b8e9e44e67c3e143ff309d823c9307085142f8c909e",
                    "total": 75
                },
                {
                    "date": "2018-07-06 07:51:17",
                    "positives": 24,
                    "sha256": "07c848a7afb8fb7f1a38959bcc30d0114ff3bb63d070083f89eb4a9cd9ae1d1c",
                    "total": 65
                },
                {
                    "date": "2021-02-28 11:42:44",
                    "positives": 15,
                    "sha256": "638e8fcc7e51ffd7992d7fc1a2d23e69f016e73fccc3e5c4d34926584148e9c4",
                    "total": 76
                },
                {
                    "date": "2021-02-28 11:39:11",
                    "positives": 5,
                    "sha256": "ae320e121cf7557d40792e58eb5ef8b003a589d77990e92370d543065ab5010d",
                    "total": 76
                },
                {
                    "date": "2021-02-28 11:15:41",
                    "positives": 1,
                    "sha256": "0db4943d759d5e2e9baa2fcc4973876d881ad7ea30471de4f775d8ae0bc2b04f",
                    "total": 75
                },
                {
                    "date": "2021-02-28 11:11:31",
                    "positives": 48,
                    "sha256": "7c676b665815c2168c6706ce5b646f20f5784408e223027b229c27877ab53873",
                    "total": 76
                },
                {
                    "date": "2021-02-28 11:07:47",
                    "positives": 1,
                    "sha256": "21f2cb257a9859643463b5ce8ce4008a6a90ed758b5b171e5986adbac7632603",
                    "total": 74
                }
            ],
            "Resolutions": [
                {
                    "ip_address": "103.200.30.143",
                    "last_resolved": "2020-09-16 00:05:41"
                },
                {
                    "ip_address": "103.200.30.245",
                    "last_resolved": "2020-11-18 21:44:30"
                },
                {
                    "ip_address": "103.200.31.172",
                    "last_resolved": "2020-09-05 14:51:17"
                },
                {
                    "ip_address": "103.214.168.106",
                    "last_resolved": "2020-09-08 05:58:51"
                },
                {
                    "ip_address": "103.223.122.178",
                    "last_resolved": "2020-09-14 11:54:10"
                },
                {
                    "ip_address": "103.226.246.99",
                    "last_resolved": "2020-09-14 11:03:25"
                },
                {
                    "ip_address": "103.226.246.99",
                    "last_resolved": "2020-09-20 00:39:09"
                },
                {
                    "ip_address": "103.226.246.99",
                    "last_resolved": "2020-09-08 05:52:46"
                },
                {
                    "ip_address": "103.226.246.99",
                    "last_resolved": "2020-09-21 13:58:33"
                },
                {
                    "ip_address": "103.226.246.99",
                    "last_resolved": "2020-09-21 00:22:12"
                }
            ],
            "Subdomains": [],
            "UnAVDetectedCommunicatingHashes": [
                {
                    "date": "2021-02-28 12:25:53",
                    "positives": 0,
                    "sha256": "21f2cb257a9859643463b5ce8ce4008a6a90ed758b5b171e5986adbac7632603",
                    "total": 0
                },
                {
                    "date": "2021-02-28 12:01:21",
                    "positives": 0,
                    "sha256": "32d3c2ce01e83048eccd44eb1a9b73ecca3a6f49928225cebe059aa50759b68d",
                    "total": 74
                },
                {
                    "date": "2021-02-28 10:28:22",
                    "positives": 0,
                    "sha256": "ef2a4e04983550da57ef5bd4a859b55378fe51592cd891575af6d6c51e5aad53",
                    "total": 74
                },
                {
                    "date": "2021-02-28 09:50:24",
                    "positives": 0,
                    "sha256": "9517273fbfceccef7d84c0be5f0009e37c12afb0eafcd0dee6318e6391fb3a75",
                    "total": 75
                },
                {
                    "date": "2021-02-28 07:45:34",
                    "positives": 0,
                    "sha256": "142860eba99f69c118b60ca4bc439a7baf43b163526461a13d6cf6a49f1612b8",
                    "total": 0
                },
                {
                    "date": "2021-02-28 07:04:49",
                    "positives": 0,
                    "sha256": "21f2cb257a9859643463b5ce8ce4008a6a90ed758b5b171e5986adbac7632603",
                    "total": 75
                }
            ],
            "UnAVDetectedDownloadedHashes": [
                {
                    "date": "2019-11-20 12:52:58",
                    "positives": 0,
                    "sha256": "660ebd3eefa3b703a00851e6bd3ca2065fabfbf50f577359983b71c8fde81598",
                    "total": 59
                },
                {
                    "date": "2019-11-20 12:43:18",
                    "positives": 0,
                    "sha256": "fa57890063727eee4e6567b539e5cbc0206b9b66d9f57a8d93e73d005e873c8f",
                    "total": 58
                },
                {
                    "date": "2019-11-20 12:42:49",
                    "positives": 0,
                    "sha256": "04551111aee334cdfbcdc5a034fe90943481244836b94655ad0e9a0798e8624f",
                    "total": 58
                },
                {
                    "date": "2019-11-20 12:40:13",
                    "positives": 0,
                    "sha256": "21f2cb257a9859643463b5ce8ce4008a6a90ed758b5b171e5986adbac7632603",
                    "total": 59
                },
                {
                    "date": "2019-11-20 12:38:08",
                    "positives": 0,
                    "sha256": "1702a0035d58b1c7649c8eac1dad1ec351752fe36d1180a91a61cc1dbc5df2d2",
                    "total": 58
                },
                {
                    "date": "2019-11-20 12:37:22",
                    "positives": 0,
                    "sha256": "17cd55867e2f808779de1469d243678502737f03fea1147c8d23d2bdee72e4ef",
                    "total": 59
                },
                {
                    "date": "2019-11-20 12:36:42",
                    "positives": 0,
                    "sha256": "eef2f30908fc3f0d9bd2eefce479345f77d707c539645ba79a8f7b725ca4f6f1",
                    "total": 59
                }
            ],
            "UnAVDetectedReferrerHashes": [
                {
                    "date": "2021-02-28 16:10:37",
                    "positives": 0,
                    "sha256": "3bb3df74115cc237a27176e6294e2d90379c2e5f2f47a0c2cf9013fed8e2efbc",
                    "total": 75
                },
                {
                    "date": "2021-02-28 15:48:13",
                    "positives": 0,
                    "sha256": "1e548758aa06e048ee8940728dd8940b185f6630b55e3fa918d373d45fb1104c",
                    "total": 75
                },
                {
                    "date": "2021-02-28 16:00:46",
                    "positives": 0,
                    "sha256": "1d5a75b2ef7a91bf8d3367b4762480d20dd80d3dc0d9f0c29bc70e3772bc8502",
                    "total": 75
                },
                {
                    "date": "2021-02-28 16:00:22",
                    "positives": 0,
                    "sha256": "74270156af11073823bf4dea8482e6fa38d5f342e0790e65475780ea3102ffe0",
                    "total": 74
                },
                {
                    "date": "2021-02-28 16:02:29",
                    "positives": 0,
                    "sha256": "cd91163c9a459233f77dee2f24f876e6fe13c92cedae4a9e681f39b8e6450aaa",
                    "total": 75
                },
                {
                    "date": "2021-02-28 16:01:56",
                    "positives": 0,
                    "sha256": "99d2edce9a0e53bc9cd168ad8a28b9ecf2abf55d28c9b9eb0cf3ee6fb5684744",
                    "total": 75
                },
                {
                    "date": "2021-02-28 15:57:15",
                    "positives": 0,
                    "sha256": "20922195ff3bdf9efbb35a7e6224f35869fb23c4dc1dc3aa3738dff6ed446bd4",
                    "total": 75
                },
                {
                    "date": "2021-02-28 16:00:21",
                    "positives": 0,
                    "sha256": "8976da5015dbe5e78fe6ddd2da260b0bffbe98eb3cb22108de21d2936315deb1",
                    "total": 74
                },
                {
                    "date": "2021-02-28 15:56:47",
                    "positives": 0,
                    "sha256": "3e5f7fbb78f7ecf64e4584e0eef4e0dbe30eb18657bf54a2fe47628da755ab15",
                    "total": 75
                }
            ],
            "Whois": "Admin City: San Francisco\nAdmin Country: US\nAdmin Email: c215fc66323f439as@twitter.com\nAdmin Organization: Twitter, Inc.\nAdmin Postal Code: 94103\nAdmin State/Province: CA\nCreation Date: 2000-01-21T11:28:17Z\nCreation Date: 2000-01-21T16:28:17Z\nDNSSEC: unsigned\nDomain Name: TWITTER.COM\nDomain Name: twitter.com\nDomain Status: clientTransferProhibited http://www.icann.org/epp#clientTransferProhibited\nDomain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\nDomain Status: serverDeleteProhibited http://www.icann.org/epp#serverDeleteProhibited\nDomain Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited\nDomain Status: serverTransferProhibited http://www.icann.org/epp#serverTransferProhibited\nDomain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited\nDomain Status: serverUpdateProhibited http://www.icann.org/epp#serverUpdateProhibited\nDomain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited\nName Server: A.R06.TWTRDNS.NET\nName Server: B.R06.TWTRDNS.NET\nName Server: C.R06.TWTRDNS.NET\nName Server: D.R06.TWTRDNS.NET\nName Server: D01-01.NS.TWTRDNS.NET\nName Server: D01-02.NS.TWTRDNS.NET\nName Server: NS3.P34.DYNECT.NET\nName Server: NS4.P34.DYNECT.NET\nName Server: a.r06.twtrdns.net\nName Server: b.r06.twtrdns.net\nName Server: c.r06.twtrdns.net\nName Server: d.r06.twtrdns.net\nName Server: d01-01.ns.twtrdns.net\nName Server: d01-02.ns.twtrdns.net\nRegistrant City: bf539c4f17ec5f2d\nRegistrant Country: US\nRegistrant Email: c215fc66323f439as@twitter.com\nRegistrant Fax Ext: 3432650ec337c945\nRegistrant Fax: e4f6fd8e0923f595\nRegistrant Name: 8705a223dfbc887b\nRegistrant Organization: 8705a223dfbc887b\nRegistrant Phone Ext: 3432650ec337c945\nRegistrant Phone: b05a54c5d3fb7f78\nRegistrant Postal Code: eff1ab11fdc42fcb\nRegistrant State/Province: b1952dfc047df18a\nRegistrant Street: 9bd06cf373eeb0ad \nRegistrar Abuse Contact Email: domainabuse@cscglobal.com\nRegistrar Abuse Contact Phone: 123 Abuse Contact Phone: 765\nRegistrar IANA ID: 299\nRegistrar Registration Expiration Date: 2022-01-21T16:28:17Z\nRegistrar URL: url\nRegistrar URL: www.cscprotectsbrands.com\nRegistrar WHOIS Server: whois.corporatedomains.com\nRegistrar: CSC CORPORATE DOMAINS, INC.\nRegistrar: CSC Corporate Domains, Inc.\nRegistry Domain ID: 18195971_DOMAIN_COM-VRSN\nRegistry Expiry Date: 2022-01-21T16:28:17Z\nSponsoring Registrar IANA ID: 299\nTech City: San Francisco\nTech Country: US\nTech Email: f378bdbc7d62cfa5s@twitter.com\nTech Organization: Twitter, Inc.\nTech Postal Code: 94103\nTech State/Province: CA\nUpdated Date: 2021-01-17T01:10:16Z\nUpdated Date: 2021-01-17T06:10:16Z"
        },
        "WHOIS": {
            "NameServers": "tsa_a",
            "Registrant": {
                "Country": null,
                "Email": null,
                "Name": "Twitter",
                "Phone": null
            },
            "UpdatedDate": "2020-11-25T20:10:08Z"
        }
    },
    "HostIo": {
        "Domain": {
            "dns": {
                "a": [
                    "103.200.30.245",
                    "103.200.30.245"
                ],
                "domain": "twitter.com",
                "mx": [
                    "10 aspmx.l.google.com.",
                    "20 alt1.aspmx.l.google.com.",
                    "20 alt2.aspmx.l.google.com.",
                    "30 aspmx2.googlemail.com.",
                    "30 aspmx3.googlemail.com."
                ],
                "ns": [
                    "a.r06.twtrdns.net.",
                    "b.r06.twtrdns.net.",
                    "c.r06.twtrdns.net.",
                    "d.r06.twtrdns.net.",
                    "d01-01.ns.twtrdns.net.",
                    "d01-02.ns.twtrdns.net.",
                    "ns1.p34.dynect.net.",
                    "ns2.p34.dynect.net.",
                    "ns3.p34.dynect.net.",
                    "ns4.p34.dynect.net."
                ]
            },
            "domain": "twitter.com",
            "ipinfo": {
                "103.200.30.245": {
                    "asn": {
                        "asn": "AS13414",
                        "domain": "twitter.com",
                        "name": "Twitter Inc.",
                        "route": "103.200.30.245",
                        "type": "business"
                    },
                    "city": "San Francisco",
                    "country": "US",
                    "loc": "37.7749,-122.4194",
                    "postal": "94103",
                    "region": "California",
                    "timezone": "America/Los_Angeles"
                },
                "103.200.30.245": {
                    "asn": {
                        "asn": "AS13414",
                        "domain": "twitter.com",
                        "name": "Twitter Inc.",
                        "route": "103.214.168.106",
                        "type": "business"
                    },
                    "city": "San Francisco",
                    "country": "US",
                    "loc": "37.7749,-122.4194",
                    "postal": "94103",
                    "region": "California",
                    "timezone": "America/Los_Angeles"
                },
                "103.200.30.245": {
                    "asn": {
                        "asn": "AS13414",
                        "domain": "twitter.com",
                        "name": "Twitter Inc.",
                        "route": "103.200.30.245",
                        "type": "business"
                    },
                    "city": "San Francisco",
                    "country": "US",
                    "loc": "37.7749,-122.4194",
                    "postal": "94103",
                    "region": "California",
                    "timezone": "America/Los_Angeles"
                }
            },
            "related": {
                "asn": [
                    {
                        "count": 392693,
                        "value": "AS13414"
                    }
                ],
                "backlinks": [
                    {
                        "count": 18707958,
                        "value": "twitter.com"
                    }
                ],
                "ip": [
                    {
                        "count": 92624,
                        "value": "103.200.30.245"
                    },
                    {
                        "count": 51,
                        "value": "103.200.30.245"
                    },
                    {
                        "count": 52,
                        "value": "103.200.30.245"
                    }
                ],
                "mx": [
                    {
                        "count": 13977803,
                        "value": "google.com"
                    },
                    {
                        "count": 5288687,
                        "value": "googlemail.com"
                    }
                ],
                "ns": [
                    {
                        "count": 118,
                        "value": "twtrdns.net"
                    },
                    {
                        "count": 181297,
                        "value": "dynect.net"
                    }
                ],
                "redirects": [
                    {
                        "count": 389612,
                        "value": "twitter.com"
                    }
                ]
            },
            "updated_date": "2020-11-25T20:10:08Z",
            "web": {
                "date": "2020-11-25T20:10:08.708Z",
                "domain": "twitter.com",
                "encoding": "utf8",
                "ip": "103.200.30.245",
                "length": 4170,
                "links": [],
                "rank": 5,
                "server": "tsa_a",
                "title": "Twitter",
                "twitter": "signup",
                "url": "https://mobile.twitter.com/signup"
            }
        }
    }
}
```

#### Human Readable Output

>### Domain
>|dns|domain|ipinfo|related|updated_date|web|
>|---|---|---|---|---|---|
>| domain: twitter.com<br/>a: 104.244.42.1,<br/>104.244.42.193<br/>mx: 10 aspmx.l.google.com.,<br/>20 alt1.aspmx.l.google.com.,<br/>20 alt2.aspmx.l.google.com.,<br/>30 aspmx2.googlemail.com.,<br/>30 aspmx3.googlemail.com.<br/>ns: a.r06.twtrdns.net.,<br/>b.r06.twtrdns.net.,<br/>c.r06.twtrdns.net.,<br/>d.r06.twtrdns.net.,<br/>d01-01.ns.twtrdns.net.,<br/>d01-02.ns.twtrdns.net.,<br/>ns1.p34.dynect.net.,<br/>ns2.p34.dynect.net.,<br/>ns3.p34.dynect.net.,<br/>ns4.p34.dynect.net. | twitter.com | 104.244.42.6: {"city": "San Francisco", "region": "California", "country": "US", "loc": "37.7749,-122.4194", "postal": "94103", "timezone": "America/Los_Angeles", "asn": {"asn": "AS13414", "name": "Twitter Inc.", "domain": "twitter.com", "route": "104.244.42.0/24", "type": "business"}}<br/>104.244.42.1: {"city": "San Francisco", "region": "California", "country": "US", "loc": "37.7749,-122.4194", "postal": "94103", "timezone": "America/Los_Angeles", "asn": {"asn": "AS13414", "name": "Twitter Inc.", "domain": "twitter.com", "route": "104.244.42.0/24", "type": "business"}}<br/>104.244.42.193: {"city": "San Francisco", "region": "California", "country": "US", "loc": "37.7749,-122.4194", "postal": "94103", "timezone": "America/Los_Angeles", "asn": {"asn": "AS13414", "name": "Twitter Inc.", "domain": "twitter.com", "route": "104.244.42.0/24", "type": "business"}} | ip: {'value': '104.244.42.6', 'count': 92624},<br/>{'value': '104.244.42.1', 'count': 51},<br/>{'value': '104.244.42.193', 'count': 52}<br/>asn: {'value': 'AS13414', 'count': 392693}<br/>ns: {'value': 'twtrdns.net', 'count': 118},<br/>{'value': 'dynect.net', 'count': 181297}<br/>mx: {'value': 'google.com', 'count': 13977803},<br/>{'value': 'googlemail.com', 'count': 5288687}<br/>backlinks: {'value': 'twitter.com', 'count': 18707958}<br/>redirects: {'value': 'twitter.com', 'count': 389612} | 2020-11-25T20:10:08Z | domain: twitter.com<br/>rank: 5<br/>url: https://mobile.twitter.com/signup<br/>ip: 104.244.42.6<br/>date: 2020-11-25T20:10:08.708Z<br/>length: 4170<br/>server: tsa_a<br/>encoding: utf8<br/>twitter: signup<br/>title: Twitter<br/>links:  |