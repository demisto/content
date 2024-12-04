Proactively Prevent Fraud
This integration was integrated and tested with version 1.0 of IPQualityScore
## Configure IPQualityScore in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API Key | See guide below for getting an API key. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| IP Suspicious Score Threshold | Threshold for fraud score from IP lookup to be marked as suspicious | False |
| IP Malicious Score Threshold | Threshold for fraud score from IP lookup to be marked as malicious | False |
| Email Suspicious Score Threshold | Threshold for fraud score from Email lookup to be marked as suspicious | False |
| Email Malicious Score Threshold | Threshold for fraud score from Email lookup to be marked as malicious | False |
| Url Suspicious Score Threshold | Threshold for fraud score from Url lookup to be marked as suspicious | False |
| Url Malicious Score Threshold | Threshold for fraud score from Url lookup to be marked as malicious | False |
| Source Reliability | Reliability of the source providing the intelligence data | True |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ip
***
Runs reputation on IPs.

#### Aquiring an API key

1. Go to https://www.ipqualityscore.com/create-account and register for an account. Accounts are free and come with 5,000 API lookups each month. Additional lookups can be purchased one time or on a monthly basis.
2. Once you've registered, login then go to https://www.ipqualityscore.com/documentation/proxy-detection/overview and your API key will be listed under the "Private Key" subheading.


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP address to check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IPQualityScore.IP.success | Boolean | Was the request successful? | 
| IPQualityScore.IP.message | String | A generic status message, either success or some form of an error notice. | 
| IPQualityScore.IP.fraud_score | Number | The overall fraud score of the user based on the IP, user agent, language, and any other optionally passed variables. Fraud Scores &gt;= 75 are suspicious, but not necessarily fraudulent. We recommend flagging or blocking traffic with Fraud Scores &gt;= 85, but you may find it beneficial to use a higher or lower threshold. | 
| IPQualityScore.IP.country_code | String | Two character country code of IP address or "N/A" if unknown. | 
| IPQualityScore.IP.region | String | Region \(state\) of IP address if available or "N/A" if unknown. | 
| IPQualityScore.IP.city | String | City of IP address if available or "N/A" if unknown. | 
| IPQualityScore.IP.ISP | String | ISP if one is known. Otherwise "N/A". | 
| IPQualityScore.IP.ASN | Number | Autonomous System Number if one is known. Null if nonexistent. | 
| IPQualityScore.IP.organization | String | Organization if one is known. Can be parent company or sub company of the listed ISP. Otherwise "N/A". | 
| IPQualityScore.IP.latitude | Number | Latitude of IP address if available or "N/A" if unknown. | 
| IPQualityScore.IP.longitude | Number | Longitude of IP address if available or "N/A" if unknown. | 
| IPQualityScore.IP.is_crawler | Boolean | Is this IP associated with being a confirmed crawler from a mainstream search engine such as Googlebot, Bingbot, Yandex, etc. based on hostname or IP address verification. | 
| IPQualityScore.IP.timezone | String | Timezone of IP address if available or "N/A" if unknown. | 
| IPQualityScore.IP.mobile | Boolean | Is this user agent a mobile browser? \(will always be false if the user agent is not passed in the API request\) | 
| IPQualityScore.IP.host | String | Hostname of the IP address if one is available. | 
| IPQualityScore.IP.proxy | Boolean | Is this IP address suspected to be a proxy? \(SOCKS, Elite, Anonymous, VPN, Tor, etc.\) | 
| IPQualityScore.IP.vpn | Boolean | Is this IP suspected of being a VPN connection? This can include data center ranges which can become active VPNs at any time. The "proxy" status will always be true when this value is true. | 
| IPQualityScore.IP.tor | Boolean | Is this IP suspected of being a TOR connection? This can include previously active TOR nodes and exits which can become active TOR exits at any time. The "proxy" status will always be true when this value is true. | 
| IPQualityScore.IP.active_vpn | Boolean | Premium Account Feature - Identifies active VPN connections used by popular VPN services and private VPN servers. | 
| IPQualityScore.IP.active_tor | Boolean | Premium Account Feature - Identifies active TOR exits on the TOR network. | 
| IPQualityScore.IP.recent_abuse | Boolean | This value will indicate if there has been any recently verified abuse across our network for this IP address. Abuse could be a confirmed chargeback, compromised device, fake app install, or similar malicious behavior within the past few days. | 
| IPQualityScore.IP.bot_status | Boolean | Premium Account Feature - Indicates if bots or non-human traffic has recently used this IP address to engage in automated fraudulent behavior. Provides stronger confidence that the IP address is suspicious. | 
| IPQualityScore.IP.connection_type | String | Classification of the IP address connection type as "Residential", "Corporate", "Education", "Mobile", or "Data Center". | 
| IPQualityScore.IP.abuse_velocity | String | Premium Account Feature - How frequently the IP address is engaging in abuse across the IPQS threat network. Values can be "high", "medium", "low", or "none". Can be used in combination with the Fraud Score to identify bad behavior. | 
| IPQualityScore.IP.request_id | String | A unique identifier for this request that can be used to lookup the request details or send a postback conversion notice. | 
| IPQualityScore.IP.address | String | The IP address that was queried. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| IP.Address | string | IP address | 
| IP.ASN | string | The autonomous system name for the IP address, for example: "AS8948". | 
| IP.Hostname | string | The hostname that is mapped to this IP address. | 
| IP.Geo.Country | string | The country in which the IP address is located. | 
| IP.Geo.Description | string | Additional information about the location. | 
| IP.Malicious.Vendor | string | The vendor reporting the IP address as malicious. | 
| IP.Malicious.Description | string | A description explaining why the IP address was reported as malicious. | 


#### Command Example
```!ip ip="8.8.8.8"```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "8.8.8.8",
        "Reliability": "A - Completely reliable",
        "Score": 3,
        "Type": "ip",
        "Vendor": "IPQualityScore"
    },
    "IP": {
        "ASN": 15169,
        "Address": "8.8.8.8",
        "Geo": {
            "Country": "US",
            "Location": "37.39:-122.07"
        },
        "Hostname": "dns.google",
        "Malicious": {
            "Description": null,
            "Vendor": "IPQualityScore"
        }
    },
    "IPQualityScore": {
        "IP": {
            "ASN": 15169,
            "ISP": "Google",
            "Malicious": {
                "Vendor": "IPQualityScore"
            },
            "abuse_velocity": "high",
            "active_tor": false,
            "active_vpn": false,
            "address": "8.8.8.8",
            "bot_status": true,
            "city": "Mountain View",
            "connection_type": "Data Center",
            "country_code": "US",
            "fraud_score": 100,
            "host": "dns.google",
            "is_crawler": false,
            "latitude": 37.39,
            "longitude": -122.07,
            "message": "Success",
            "mobile": false,
            "organization": "Google",
            "proxy": true,
            "recent_abuse": true,
            "region": "California",
            "request_id": "4DpK9WpOZGPFSPg",
            "success": true,
            "timezone": "America/Los_Angeles",
            "tor": false,
            "vpn": true
        }
    }
}
```

#### Human Readable Output

>### IPQualityScore Results for 8.8.8.8
>|success|message|fraud_score|country_code|region|city|ISP|ASN|organization|latitude|longitude|is_crawler|timezone|mobile|host|proxy|vpn|tor|active_vpn|active_tor|recent_abuse|bot_status|connection_type|abuse_velocity|request_id|address|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| true | Success | 100 | US | California | Mountain View | Google | 15169 | Google | 37.39 | -122.07 | false | America/Los_Angeles | false | dns.google | true | true | false | false | false | true | true | Data Center | high | 4DpK9WpOZGPFSPg | 8.8.8.8 |


### email
***
Runs reputation on email addresses.


#### Base Command

`email`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | Email address to check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IPQualityScore.Email.message | String | A generic status message, either success or some form of an error notice. | 
| IPQualityScore.Email.success | Boolean | Was the request successful? | 
| IPQualityScore.Email.valid | Boolean | Does this email address appear valid? | 
| IPQualityScore.Email.disposable | Boolean | Is this email suspected of belonging to a temporary or disposable mail service? Usually associated with fraudsters and scammers. | 
| IPQualityScore.Email.smtp_score | Number | Validity score of email server's SMTP setup. Range: "-1" - "3". Scores above "-1" can be associated with a valid email. -1 = invalid email address 0 = mail server exists, but is rejecting all mail 1 = mail server exists, but is showing a temporary error 2 = mail server exists, but accepts all email 3 = mail server exists and has verified the email address | 
| IPQualityScore.Email.overall_score | Number | Overall email validity score. Range: "0" - "4". Scores above "1" can be associated with a valid email. 0 = invalid email address 1 = dns valid, unreachable mail server 2 = dns valid, temporary mail rejection error 3 = dns valid, accepts all mail 4 = dns valid, verified email exists | 
| IPQualityScore.Email.first_name | String | Suspected first name based on email. Returns "CORPORATE" if the email is suspected of being a generic company email. Returns "UNKNOWN" if the first name was not determinable. | 
| IPQualityScore.Email.generic | Boolean | Is this email suspected as being a catch all or shared email for a domain? \("admin@", "webmaster@", "newsletter@", "sales@", "contact@", etc.\) | 
| IPQualityScore.Email.common | Boolean | Is this email from a common email provider? \("gmail.com", "yahoo.com", "hotmail.com", etc.\) | 
| IPQualityScore.Email.dns_valid | Boolean | Does the email's hostname have valid DNS entries? Partial indication of a valid email. | 
| IPQualityScore.Email.honeypot | Boolean | Is this email believed to be a "honeypot" or "SPAM trap"? Bulk mail sent to these emails increases your risk of being added to block lists by large ISPs &amp; ending up in the spam folder. | 
| IPQualityScore.Email.deliverability | String | How likely is this email to be delivered to the user and land in their mailbox. Values can be "high", "medium", or "low".	 | 
| IPQualityScore.Email.frequent_complainer | Boolean | Indicates if this email frequently unsubscribes from marketing lists or reports email as SPAM. | 
| IPQualityScore.Email.spam_trap_score | String | Confidence level of the email address being an active SPAM trap. Values can be "high", "medium", "low", or "none". We recommend scrubbing emails with "high" or "medium" statuses. Avoid "low" emails whenever possible for any promotional mailings. | 
| IPQualityScore.Email.catch_all | Boolean | Is this email likely to be a "catch all" where the mail server verifies all emails tested against it as valid? It is difficult to determine if the address is truly valid in these scenarios, since the email's server will not confirm the account's status. | 
| IPQualityScore.Email.timed_out | Boolean | Did the connection to the mail service provider timeout during the verification? If so, we recommend increasing the "timeout" variable above the default 7 second value. Lookups that timeout with a "valid" result as false are most likely false and should be not be trusted. | 
| IPQualityScore.Email.suspect | Boolean | This value indicates if the mail server is currently replying with a temporary error and unable to verify the email address. This status will also be true for "catch all" email addresses as defined below. If this value is true, then we suspect the "valid" result may be tainted and there is not a guarantee that the email address is truly valid. | 
| IPQualityScore.Email.recent_abuse | Boolean | This value will indicate if there has been any recently verified abuse across our network for this email address. Abuse could be a confirmed chargeback, fake signup, compromised device, fake app install, or similar malicious behavior within the past few days. | 
| IPQualityScore.Email.fraud_score | Number | The overall Fraud Score of the user based on the email's reputation and recent behavior across the IPQS threat network. Fraud Scores &gt;= 75 are suspicious, but not necessarily fraudulent. | 
| IPQualityScore.Email.suggested_domain | String | Default value is "N/A". Indicates if this email's domain should in fact be corrected to a popular mail service. This field is useful for catching user typos. For example, an email address with "gmai.com", would display a suggested domain of "gmail.com". This feature supports all major mail service providers. | 
| IPQualityScore.Email.leaked | Boolean | Was this email address associated with a recent database leak from a third party? Leaked accounts pose a risk as they may have become compromised during a database breach.	 | 
| IPQualityScore.Email.domain_age.human | Date | A human description of when this domain was registered. \(Ex: 3 months ago\) | 
| IPQualityScore.Email.domain_age.timestamp | Number | The unix time since epoch when this domain was first registered. \(Ex: 1568061634\) | 
| IPQualityScore.Email.domain_age.iso | Date | The time this domain was registered in ISO8601 format \(Ex: 2019-09-09T16:40:34-04:00\) | 
| IPQualityScore.Email.first_seen.human | Date | A human description of the email address age, using an estimation of the email creation date when IPQS first discovered this email address. \(Ex: 3 months ago\) | 
| IPQualityScore.Email.first_seen.timestamp | Number | The unix time since epoch when this email was first analyzed by IPQS. \(Ex: 1568061634\) | 
| IPQualityScore.Email.first_seen.iso | Date | The time this email was first analyzed by IPQS in ISO8601 format \(Ex: 2019-09-09T16:40:34-04:00\) | 
| IPQualityScore.Email.sanitized_email | String | Sanitized email address with all aliases and masking removed, such as multiple periods for Gmail.com. | 
| IPQualityScore.Email.request_id | String | A unique identifier for this request that can be used to lookup the request details or send a postback conversion notice. | 
| IPQualityScore.Email.address | String | The email address that was queried | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 


#### Command Example
```!email email="noreply@ipqualityscore.com"```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "noreply@ipqualityscore.com",
        "Reliability": "A - Completely reliable",
        "Score": 3,
        "Type": "email",
        "Vendor": "IPQualityScore"
    },
    "Email": {
        "Address": "noreply@ipqualityscore.com",
        "Domain": "ipqualityscore.com"
    },
    "IPQualityScore": {
        "Email": {
            "Malicious": {
                "Vendor": "IPQualityScore"
            },
            "address": "noreply@ipqualityscore.com",
            "catch_all": true,
            "common": false,
            "deliverability": "low",
            "disposable": false,
            "dns_valid": true,
            "domain_age": {
                "human": "10 years ago",
                "iso": "2011-04-14T23:26:37-04:00",
                "timestamp": 1302837997
            },
            "first_name": "Corporate",
            "first_seen": {
                "human": "2 years ago",
                "iso": "2019-05-06T02:09:06-04:00",
                "timestamp": 1557122946
            },
            "fraud_score": 95,
            "frequent_complainer": false,
            "generic": true,
            "honeypot": true,
            "leaked": false,
            "message": "Success.",
            "overall_score": 3,
            "recent_abuse": true,
            "request_id": "4DpK9WpOZGQDnr7",
            "sanitized_email": "noreply@ipqualityscore.com",
            "smtp_score": 2,
            "spam_trap_score": "medium",
            "success": true,
            "suggested_domain": "N/A",
            "suspect": true,
            "timed_out": false,
            "valid": true
        }
    }
}
```

#### Human Readable Output

>### IPQualityScore Results for noreply@ipqualityscore.com
>|message|success|valid|disposable|smtp_score|overall_score|first_name|generic|common|dns_valid|honeypot|deliverability|frequent_complainer|spam_trap_score|catch_all|timed_out|suspect|recent_abuse|fraud_score|suggested_domain|leaked|domain_age|first_seen|sanitized_email|request_id|address|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Success. | true | true | false | 2 | 3 | Corporate | true | false | true | true | low | false | medium | true | false | true | true | 95 | N/A | false | human: 10 years ago<br/>timestamp: 1302837997<br/>iso: 2011-04-14T23:26:37-04:00 | human: 2 years ago<br/>timestamp: 1557122946<br/>iso: 2019-05-06T02:09:06-04:00 | noreply@ipqualityscore.com | 4DpK9WpOZGQDnr7 | noreply@ipqualityscore.com |


### url
***
Runs reputation on URLs.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | Url address to check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IPQualityScore.Url.message | String | A generic status message, either success or some form of an error notice. | 
| IPQualityScore.Url.success | Boolean | Was the request successful? | 
| IPQualityScore.Url.unsafe | Boolean | Is this domain suspected of being unsafe due to phishing, malware, spamming, or abusive behavior? View the confidence level by analyzing the "risk_score". | 
| IPQualityScore.Url.domain | String | Domain name of the final destination URL of the scanned link, after following all redirects. | 
| IPQualityScore.Url.ip_address | String | The IP address corresponding to the server of the domain name. | 
| IPQualityScore.Url.server | String | The server banner of the domain's IP address. For example: "nginx/1.16.0". Value will be "N/A" if unavailable. | 
| IPQualityScore.Url.content_type | String | MIME type of URL's content. For example "text/html; charset=UTF-8". Value will be "N/A" if unavailable. | 
| IPQualityScore.Url.status_code | Number | HTTP Status Code of the URL's response. This value should be "200" for a valid website. Value is "0" if URL is unreachable. | 
| IPQualityScore.Url.page_size | Number | Total number of bytes to download the URL's content. Value is "0" if URL is unreachable. | 
| IPQualityScore.Url.domain_rank | Number | Estimated popularity rank of website globally. Value is "0" if the domain is unranked or has low traffic. | 
| IPQualityScore.Url.dns_valid | Boolean | The domain of the URL has valid DNS records. | 
| IPQualityScore.Url.parking | Boolean | Is the domain of this URL currently parked with a for sale notice? | 
| IPQualityScore.Url.spamming | Boolean | Is the domain of this URL associated with email SPAM or abusive email addresses? | 
| IPQualityScore.Url.malware | Boolean | Is this URL associated with malware or viruses? | 
| IPQualityScore.Url.phishing | Boolean | Is this URL associated with malicious phishing behavior? | 
| IPQualityScore.Url.suspicious | Boolean | Is this URL suspected of being malicious or used for phishing or abuse? Use in conjunction with the "risk_score" as a confidence level. | 
| IPQualityScore.Url.risk_score | Number | The IPQS risk score which estimates the confidence level for malicious URL detection. Risk Scores 85\+ are high risk, while Risk Scores = 100 are confirmed as accurate. | 
| IPQualityScore.Url.request_id | String | A unique identifier for this request that can be used to lookup the request details or send a postback conversion notice. | 
| IPQualityScore.Url.url | String | The URL being queried. | 
| IPQualityScore.Url.adult | Boolean | Is this URL or domain hosting dating or adult content? | 
| IPQualityScore.Url.domain_age.human | Date | A human description of when this domain was registered. \(Ex: 3 months ago\) | 
| IPQualityScore.Url.domain_age.timestamp | Number | The unix time since epoch when this domain was first registered. \(Ex: 1568061634\) | 
| IPQualityScore.Url.domain_age.iso | Date | The time this domain was registered in ISO8601 format \(Ex: 2019-09-09T16:40:34-04:00\) | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| URL.Data | String | The URL | 
| URL.Malicious.Vendor | String | The vendor reporting the URL as malicious. | 


#### Command Example
```!url url="https://google.com"```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "https://google.com",
        "Reliability": "A - Completely reliable",
        "Score": 0,
        "Type": "url",
        "Vendor": "IPQualityScore"
    },
    "IPQualityScore": {
        "Url": {
            "adult": false,
            "content_type": "text/html; charset=UTF-8",
            "dns_valid": true,
            "domain": "google.com",
            "domain_age": {
                "human": "24 years ago",
                "iso": "1997-09-15T00:00:00-04:00",
                "timestamp": 874296000
            },
            "domain_rank": 1,
            "ip_address": "172.217.11.142",
            "malware": false,
            "message": "Success.",
            "page_size": 39242,
            "parking": false,
            "phishing": false,
            "request_id": "4DpK9WpOZGQFSPi",
            "risk_score": 0,
            "server": " gws\r\n",
            "spamming": false,
            "status_code": 200,
            "success": true,
            "suspicious": false,
            "unsafe": false,
            "url": "https://google.com"
        }
    },
    "URL": {
        "Data": "https://google.com"
    }
}
```

#### Human Readable Output

>### IPQualityScore Results for https://google.com
>|message|success|unsafe|domain|ip_address|server|content_type|status_code|page_size|domain_rank|dns_valid|parking|spamming|malware|phishing|suspicious|adult|risk_score|domain_age|request_id|url|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Success. | true | false | google.com | 172.217.11.142 |  gws<br/> | text/html; charset=UTF-8 | 200 | 39242 | 1 | true | false | false | false | false | false | false | 0 | human: 24 years ago<br/>timestamp: 874296000<br/>iso: 1997-09-15T00:00:00-04:00 | 4DpK9WpOZGQFSPi | https://google.com |
