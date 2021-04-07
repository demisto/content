Enhancement script to enrich SSL information for Email, File SHA-1 and RiskIQSerialNumber type of indicators.
It can be set by following these steps:
 - Settings > ADVANCED > Indicator Type
 - Edit Email, File SHA-1 and RiskIQSerialNumber Indicator one by one 
 - Add this script into Enhancement Scripts

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | enhancement |
| Demisto Version | 5.0.0 |

## Dependencies
---
This script uses the following commands and scripts.
* pt-ssl-cert-search

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| indicator_value | Email, File SHA-1 and RiskIQSerialNumber indicator value that need to enrich |

## Outputs
---
There are no outputs for this script.

## Script Example
```!RiskIQPassiveTotalSSLScript indicator_value=61135c80f8ed28d2```

## Context Example
```
{
    "PassiveTotal": {
        "SSL": [
            {
                "expirationDate": "Apr 09 13:15:00 2019 GMT",
                "fingerprint": "88:48:e8:68:b1:90:d0:fd:cb:6f:39:c3:7b:53:82:c8:7e:09:76:b0",
                "firstSeen": 1547559631314,
                "issueDate": "Jan 15 13:15:00 2019 GMT",
                "issuerCommonName": "Google Internet Authority G3",
                "issuerCountry": "US",
                "issuerOrganizationName": "Google Trust Services",
                "lastSeen": 1547607634446,
                "serialNumber": "6995036355238373586",
                "sha1": "8848e868b190d0fdcb6f39c37b5382c87e0976b0",
                "sslVersion": "3",
                "subjectAlternativeNames": [
                    "www.google.com"
                ],
                "subjectCommonName": "www.google.com",
                "subjectCountry": "US",
                "subjectLocalityName": "Mountain View",
                "subjectOrganizationName": "Google LLC",
                "subjectProvince": "California",
                "subjectStateOrProvinceName": "California"
            },
            {
                "expirationDate": "Apr 09 13:15:00 2019 GMT",
                "fingerprint": "99:5b:00:5f:44:be:53:bf:3e:59:21:90:1d:79:a9:8e:54:af:d3:29",
                "firstSeen": 1548455641692,
                "issueDate": "Jan 15 13:15:00 2019 GMT",
                "issuerCommonName": "Google Internet Authority G3",
                "issuerCountry": "US",
                "issuerOrganizationName": "Google Trust Services",
                "lastSeen": 1549571983939,
                "serialNumber": "6995036355238373586",
                "sha1": "995b005f44be53bf3e5921901d79a98e54afd329",
                "sslVersion": "3",
                "subjectAlternativeNames": [
                    "www.google.com"
                ],
                "subjectCommonName": "www.google.com",
                "subjectCountry": "US",
                "subjectLocalityName": "Mountain View",
                "subjectOrganizationName": "Google LLC",
                "subjectProvince": "California",
                "subjectStateOrProvinceName": "California"
            }
        ]
    }
}
```

## Human Readable Output

>### Total Retrieved Record(s): 2
>### SSL certificate(s)
>|Sha1|Serial Number|Issued (GMT)|Expires (GMT)|SSL Version|First Seen (GMT)|Last Seen (GMT)|Issuer Common Name|Subject Common Name|Subject Alternative Names|Issuer Organization Name|Subject Organization Name|Subject Locality Name|Subject State/Province Name|Issuer Country|Subject Country|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 8848e868b190d0fdcb6f39c37b5382c87e0976b0 | 6995036355238373586 | Jan 15 13:15:00 2019 GMT | Apr 09 13:15:00 2019 GMT | 3 | 2019-01-15 13:40:31 | 2019-01-16 03:00:34 | Google Internet Authority G3 | www.google.com | www.google.com | Google Trust Services | Google LLC | Mountain View | California | US | US |
>| 995b005f44be53bf3e5921901d79a98e54afd329 | 6995036355238373586 | Jan 15 13:15:00 2019 GMT | Apr 09 13:15:00 2019 GMT | 3 | 2019-01-25 22:34:01 | 2019-02-07 20:39:43 | Google Internet Authority G3 | www.google.com | www.google.com | Google Trust Services | Google LLC | Mountain View | California | US | US |
