Enhancement script to enrich web trackers information for Domain and IP type of indicators.
It can be set by following these steps:
 - Settings > ADVANCED > Indicator Type
 - Edit Domain and IP Indicator one by one 
 - Add this script into Enhancement Scripts
 
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | enhancement |
| Cortex XSOAR Version | 5.0.0 |

## Dependencies
---
This script uses the following commands and scripts.
* pt-get-trackers

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| indicator_value | Domain or IP indicator value that need to enrich |

## Outputs
---
There are no outputs for this script.


## Script Example
```!RiskIQPassiveTotalTrackersScript indicator_value=filmesonlinegratis.net```

## Context Example
```
{
    "DBotScore": [
        {
            "Indicator": "filmesonlinegratis.net",
            "Score": 0,
            "Type": "domain",
            "Vendor": "PassiveTotal"
        },
        {
            "Indicator": "www.filmesonlinegratis.net",
            "Score": 0,
            "Type": "domain",
            "Vendor": "PassiveTotal"
        }
    ],
    "Domain": [
        {
            "Name": "filmesonlinegratis.net"
        },
        {
            "Name": "www.filmesonlinegratis.net"
        }
    ],
    "PassiveTotal": {
        "Tracker": [
            {
                "attributeType": "GoogleAnalyticsTrackingId",
                "attributeValue": "ua-70630818-3",
                "firstSeen": "2016-10-14 10:16:38",
                "hostname": "filmesonlinegratis.net",
                "lastSeen": "2020-06-14 19:43:28"
            },
            {
                "attributeType": "GoogleAnalyticsAccountNumber",
                "attributeValue": "ua-70630818",
                "firstSeen": "2016-10-14 10:16:38",
                "hostname": "filmesonlinegratis.net",
                "lastSeen": "2020-06-14 19:43:28"
            },
            {
                "attributeType": "GoogleAnalyticsAccountNumber",
                "attributeValue": "ua-11598035",
                "firstSeen": "2012-03-07 05:53:50",
                "hostname": "www.filmesonlinegratis.net",
                "lastSeen": "2016-10-13 15:38:35"
            },
            {
                "attributeType": "GoogleAnalyticsTrackingId",
                "attributeValue": "ua-11598035-1",
                "firstSeen": "2012-03-07 05:53:50",
                "hostname": "www.filmesonlinegratis.net",
                "lastSeen": "2016-10-13 15:38:35"
            },
            {
                "attributeType": "GoogleAnalyticsTrackingId",
                "attributeValue": "ua-11598035-1",
                "firstSeen": "2014-02-11 01:30:40",
                "hostname": "filmesonlinegratis.net",
                "lastSeen": "2016-09-13 03:54:34"
            },
            {
                "attributeType": "GoogleAnalyticsAccountNumber",
                "attributeValue": "ua-11598035",
                "firstSeen": "2014-02-11 01:30:40",
                "hostname": "filmesonlinegratis.net",
                "lastSeen": "2016-09-13 03:54:34"
            },
            {
                "attributeType": "TumblrId",
                "attributeValue": "25.media",
                "firstSeen": "2016-07-02 00:46:33",
                "hostname": "www.filmesonlinegratis.net",
                "lastSeen": "2016-09-02 11:09:30"
            },
            {
                "attributeType": "FacebookId",
                "attributeValue": "filmesog",
                "firstSeen": "2012-11-27 06:06:44",
                "hostname": "www.filmesonlinegratis.net",
                "lastSeen": "2015-09-26 05:52:23"
            },
            {
                "attributeType": "FacebookId",
                "attributeValue": "filmesog",
                "firstSeen": "2014-02-11 01:30:40",
                "hostname": "filmesonlinegratis.net",
                "lastSeen": "2015-09-24 05:12:39"
            },
            {
                "attributeType": "WhosAmungUsId",
                "attributeValue": "6cdg",
                "firstSeen": "2012-03-07 05:53:50",
                "hostname": "www.filmesonlinegratis.net",
                "lastSeen": "2012-03-07 16:00:45"
            }
        ]
    }
}
```

## Human Readable Output

>### Total Retrieved Record(s): 10
>### TRACKERS
>|Hostname|First (GMT)|Last (GMT)|Type|Value|
>|---|---|---|---|---|
>| filmesonlinegratis.net | 2016-10-14 10:16:38 | 2020-06-14 19:43:28 | GoogleAnalyticsTrackingId | ua-70630818-3 |
>| filmesonlinegratis.net | 2016-10-14 10:16:38 | 2020-06-14 19:43:28 | GoogleAnalyticsAccountNumber | ua-70630818 |
>| www.filmesonlinegratis.net | 2012-03-07 05:53:50 | 2016-10-13 15:38:35 | GoogleAnalyticsAccountNumber | ua-11598035 |
>| www.filmesonlinegratis.net | 2012-03-07 05:53:50 | 2016-10-13 15:38:35 | GoogleAnalyticsTrackingId | ua-11598035-1 |
>| filmesonlinegratis.net | 2014-02-11 01:30:40 | 2016-09-13 03:54:34 | GoogleAnalyticsTrackingId | ua-11598035-1 |
>| filmesonlinegratis.net | 2014-02-11 01:30:40 | 2016-09-13 03:54:34 | GoogleAnalyticsAccountNumber | ua-11598035 |
>| www.filmesonlinegratis.net | 2016-07-02 00:46:33 | 2016-09-02 11:09:30 | TumblrId | 25.media |
>| www.filmesonlinegratis.net | 2012-11-27 06:06:44 | 2015-09-26 05:52:23 | FacebookId | filmesog |
>| filmesonlinegratis.net | 2014-02-11 01:30:40 | 2015-09-24 05:12:39 | FacebookId | filmesog |
>| www.filmesonlinegratis.net | 2012-03-07 05:53:50 | 2012-03-07 16:00:45 | WhosAmungUsId | 6cdg |
