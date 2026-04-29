## Overview

IPQualityScore (IPQS) provides enterprise-grade real-time threat intelligence for IP addresses, email addresses, URLs, phone numbers, and files. Detect fraud, phishing, malware, leaked credentials, and abusive behavior using IPQS's global threat network.

This integration was integrated and tested with version 1.0 of IPQualityScore.

## Getting an API Key

1. Register for a free account at <https://www.ipqualityscore.com/create-account>. Free accounts include 5,000 API lookups per month.
2. After registering, log in and visit <https://www.ipqualityscore.com/documentation/proxy-detection/overview>. Your API key is listed under the **Private Key** subheading.

## Configure IPQualityScore in Cortex

| **Parameter**                        | **Description**                                                                                  | **Required** |
| ------------------------------------ | ------------------------------------------------------------------------------------------------ | ------------ |
| API Key                              | Your IPQS private API key.                                                                       | True         |
| Trust any certificate (not secure)   | Skip SSL certificate verification.                                                               | False        |
| Use system proxy settings            | Route requests through the system proxy.                                                         | False        |
| IP Suspicious Score Threshold        | Fraud score at or above which an IP is marked suspicious (default: 75).                          | False        |
| IP Malicious Score Threshold         | Fraud score at or above which an IP is marked malicious (default: 90).                           | False        |
| Email Suspicious Score Threshold     | Fraud score at or above which an email is marked suspicious (default: 75).                       | False        |
| Email Malicious Score Threshold      | Fraud score at or above which an email is marked malicious (default: 90).                        | False        |
| Url Suspicious Score Threshold       | Risk score at or above which a URL is marked suspicious (default: 75).                           | False        |
| Url Malicious Score Threshold        | Risk score at or above which a URL is marked malicious (default: 90).                            | False        |
| Phone Suspicious Score Threshold     | Fraud score at or above which a phone number is marked suspicious (default: 75).                 | False        |
| Phone Malicious Score Threshold      | Fraud score at or above which a phone number is marked malicious (default: 90).                  | False        |
| File Suspicious Detections Threshold | Number of engine detections at or above which a file/URL scan is marked suspicious (default: 1). | False        |
| File Malicious Detections Threshold  | Number of engine detections at or above which a file/URL scan is marked malicious (default: 5).  | False        |
| Source Reliability                   | Reliability of the source providing the intelligence data.                                       | True         |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### ip

---

Runs reputation check on one or more IP addresses.

#### Base Command

`ipqs-ip-reputation`

#### Input

| **Argument Name** | **Description**                                         | **Required** |
| ----------------- | ------------------------------------------------------- | ------------ |
| ip                | IP address(es) to check. Supports comma-separated list. | Required     |

#### Context Output

| **Path**                          | **Type** | **Description**                                                                                                                                                                                                                                                                                                                      |
| --------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| IPQualityScore.IP.success         | Boolean  | Was the request successful?                                                                                                                                                                                                                                                                                                          |
| IPQualityScore.IP.message         | String   | A generic status message, either success or some form of an error notice.                                                                                                                                                                                                                                                            |
| IPQualityScore.IP.fraud_score     | Number   | The overall fraud score of the user based on the IP, user agent, language, and any other optionally passed variables. Fraud Scores &gt;= 75 are suspicious, but not necessarily fraudulent. We recommend flagging or blocking traffic with Fraud Scores &gt;= 85, but you may find it beneficial to use a higher or lower threshold. |
| IPQualityScore.IP.country_code    | String   | Two character country code of IP address or "N/A" if unknown.                                                                                                                                                                                                                                                                        |
| IPQualityScore.IP.region          | String   | Region \(state\) of IP address if available or "N/A" if unknown.                                                                                                                                                                                                                                                                     |
| IPQualityScore.IP.city            | String   | City of IP address if available or "N/A" if unknown.                                                                                                                                                                                                                                                                                 |
| IPQualityScore.IP.ISP             | String   | ISP if one is known. Otherwise "N/A".                                                                                                                                                                                                                                                                                                |
| IPQualityScore.IP.ASN             | Number   | Autonomous System Number if one is known. Null if nonexistent.                                                                                                                                                                                                                                                                       |
| IPQualityScore.IP.organization    | String   | Organization if one is known. Can be parent company or sub company of the listed ISP. Otherwise "N/A".                                                                                                                                                                                                                               |
| IPQualityScore.IP.latitude        | Number   | Latitude of IP address if available or "N/A" if unknown.                                                                                                                                                                                                                                                                             |
| IPQualityScore.IP.longitude       | Number   | Longitude of IP address if available or "N/A" if unknown.                                                                                                                                                                                                                                                                            |
| IPQualityScore.IP.is_crawler      | Boolean  | Is this IP associated with being a confirmed crawler from a mainstream search engine such as Googlebot, Bingbot, Yandex, etc. based on hostname or IP address verification.                                                                                                                                                          |
| IPQualityScore.IP.timezone        | String   | Timezone of IP address if available or "N/A" if unknown.                                                                                                                                                                                                                                                                             |
| IPQualityScore.IP.mobile          | Boolean  | Is this user agent a mobile browser? \(will always be false if the user agent is not passed in the API request\)                                                                                                                                                                                                                     |
| IPQualityScore.IP.host            | String   | Hostname of the IP address if one is available.                                                                                                                                                                                                                                                                                      |
| IPQualityScore.IP.proxy           | Boolean  | Is this IP address suspected to be a proxy? \(SOCKS, Elite, Anonymous, VPN, Tor, etc.\)                                                                                                                                                                                                                                              |
| IPQualityScore.IP.vpn             | Boolean  | Is this IP suspected of being a VPN connection? This can include data center ranges which can become active VPNs at any time. The "proxy" status will always be true when this value is true.                                                                                                                                        |
| IPQualityScore.IP.tor             | Boolean  | Is this IP suspected of being a TOR connection? This can include previously active TOR nodes and exits which can become active TOR exits at any time. The "proxy" status will always be true when this value is true.                                                                                                                |
| IPQualityScore.IP.active_vpn      | Boolean  | Premium Account Feature - Identifies active VPN connections used by popular VPN services and private VPN servers.                                                                                                                                                                                                                    |
| IPQualityScore.IP.active_tor      | Boolean  | Premium Account Feature - Identifies active TOR exits on the TOR network.                                                                                                                                                                                                                                                            |
| IPQualityScore.IP.recent_abuse    | Boolean  | This value will indicate if there has been any recently verified abuse across our network for this IP address. Abuse could be a confirmed chargeback, compromised device, fake app install, or similar malicious behavior within the past few days.                                                                                  |
| IPQualityScore.IP.bot_status      | Boolean  | Premium Account Feature - Indicates if bots or non-human traffic has recently used this IP address to engage in automated fraudulent behavior. Provides stronger confidence that the IP address is suspicious.                                                                                                                       |
| IPQualityScore.IP.connection_type | String   | Classification of the IP address connection type as "Residential", "Corporate", "Education", "Mobile", or "Data Center".                                                                                                                                                                                                             |
| IPQualityScore.IP.abuse_velocity  | String   | Premium Account Feature - How frequently the IP address is engaging in abuse across the IPQS threat network. Values can be "high", "medium", "low", or "none". Can be used in combination with the Fraud Score to identify bad behavior.                                                                                             |
| IPQualityScore.IP.request_id      | String   | A unique identifier for this request that can be used to lookup the request details or send a postback conversion notice.                                                                                                                                                                                                            |
| IPQualityScore.IP.address         | String   | The IP address that was queried.                                                                                                                                                                                                                                                                                                     |
| DBotScore.Indicator               | String   | The indicator that was tested.                                                                                                                                                                                                                                                                                                       |
| DBotScore.Score                   | Number   | The actual score.                                                                                                                                                                                                                                                                                                                    |
| DBotScore.Type                    | String   | The indicator type.                                                                                                                                                                                                                                                                                                                  |
| DBotScore.Vendor                  | String   | The vendor used to calculate the score.                                                                                                                                                                                                                                                                                              |
| IP.Address                        | string   | IP address                                                                                                                                                                                                                                                                                                                           |
| IP.ASN                            | string   | The autonomous system name for the IP address, for example: "AS8948".                                                                                                                                                                                                                                                                |
| IP.Hostname                       | string   | The hostname that is mapped to this IP address.                                                                                                                                                                                                                                                                                      |
| IP.Geo.Country                    | string   | The country in which the IP address is located.                                                                                                                                                                                                                                                                                      |
| IP.Geo.Description                | string   | Additional information about the location.                                                                                                                                                                                                                                                                                           |
| IP.Malicious.Vendor               | string   | The vendor reporting the IP address as malicious.                                                                                                                                                                                                                                                                                    |
| IP.Malicious.Description          | string   | A description explaining why the IP address was reported as malicious.                                                                                                                                                                                                                                                               |

#### Command Example

`!ipqs-ip-reputation ip="8.8.8.8"`

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

> ### IPQualityScore Results for 8.8.8.8
>
> | success | message | fraud_score | country_code | region     | city          | ISP    | ASN   | organization | latitude | longitude | is_crawler | timezone            | mobile | host       | proxy | vpn  | tor   | active_vpn | active_tor | recent_abuse | bot_status | connection_type | abuse_velocity | request_id      | address |
> | ------- | ------- | ----------- | ------------ | ---------- | ------------- | ------ | ----- | ------------ | -------- | --------- | ---------- | ------------------- | ------ | ---------- | ----- | ---- | ----- | ---------- | ---------- | ------------ | ---------- | --------------- | -------------- | --------------- | ------- |
> | true    | Success | 100         | US           | California | Mountain View | Google | 15169 | Google       | 37.39    | -122.07   | false      | America/Los_Angeles | false  | dns.google | true  | true | false | false      | false      | true         | true       | Data Center     | high           | 4DpK9WpOZGPFSPg | 8.8.8.8 |

### email

---

Runs reputation check on one or more email addresses.

#### Base Command

`ipqs-email-reputation`

#### Input

| **Argument Name** | **Description**                                            | **Required** |
| ----------------- | ---------------------------------------------------------- | ------------ |
| email             | Email address(es) to check. Supports comma-separated list. | Required     |

#### Context Output

| **Path**                                  | **Type** | **Description**                                                                                                                                                                                                                                                                                                                                                       |
| ----------------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| IPQualityScore.Email.message              | String   | A generic status message, either success or some form of an error notice.                                                                                                                                                                                                                                                                                             |
| IPQualityScore.Email.success              | Boolean  | Was the request successful?                                                                                                                                                                                                                                                                                                                                           |
| IPQualityScore.Email.valid                | Boolean  | Does this email address appear valid?                                                                                                                                                                                                                                                                                                                                 |
| IPQualityScore.Email.disposable           | Boolean  | Is this email suspected of belonging to a temporary or disposable mail service? Usually associated with fraudsters and scammers.                                                                                                                                                                                                                                      |
| IPQualityScore.Email.smtp_score           | Number   | Validity score of email server's SMTP setup. Range: "-1" - "3". Scores above "-1" can be associated with a valid email. -1 = invalid email address 0 = mail server exists, but is rejecting all mail 1 = mail server exists, but is showing a temporary error 2 = mail server exists, but accepts all email 3 = mail server exists and has verified the email address |
| IPQualityScore.Email.overall_score        | Number   | Overall email validity score. Range: "0" - "4". Scores above "1" can be associated with a valid email. 0 = invalid email address 1 = dns valid, unreachable mail server 2 = dns valid, temporary mail rejection error 3 = dns valid, accepts all mail 4 = dns valid, verified email exists                                                                            |
| IPQualityScore.Email.first_name           | String   | Suspected first name based on email. Returns "CORPORATE" if the email is suspected of being a generic company email. Returns "UNKNOWN" if the first name was not determinable.                                                                                                                                                                                        |
| IPQualityScore.Email.generic              | Boolean  | Is this email suspected as being a catch all or shared email for a domain? \("admin@", "webmaster@", "newsletter@", "sales@", "contact@", etc.\)                                                                                                                                                                                                                      |
| IPQualityScore.Email.common               | Boolean  | Is this email from a common email provider? \("gmail.com", "yahoo.com", "hotmail.com", etc.\)                                                                                                                                                                                                                                                                         |
| IPQualityScore.Email.dns_valid            | Boolean  | Does the email's hostname have valid DNS entries? Partial indication of a valid email.                                                                                                                                                                                                                                                                                |
| IPQualityScore.Email.honeypot             | Boolean  | Is this email believed to be a "honeypot" or "SPAM trap"? Bulk mail sent to these emails increases your risk of being added to block lists by large ISPs &amp; ending up in the spam folder.                                                                                                                                                                          |
| IPQualityScore.Email.deliverability       | String   | How likely is this email to be delivered to the user and land in their mailbox. Values can be "high", "medium", or "low".                                                                                                                                                                                                                                             |
| IPQualityScore.Email.frequent_complainer  | Boolean  | Indicates if this email frequently unsubscribes from marketing lists or reports email as SPAM.                                                                                                                                                                                                                                                                        |
| IPQualityScore.Email.spam_trap_score      | String   | Confidence level of the email address being an active SPAM trap. Values can be "high", "medium", "low", or "none". We recommend scrubbing emails with "high" or "medium" statuses. Avoid "low" emails whenever possible for any promotional mailings.                                                                                                                 |
| IPQualityScore.Email.catch_all            | Boolean  | Is this email likely to be a "catch all" where the mail server verifies all emails tested against it as valid? It is difficult to determine if the address is truly valid in these scenarios, since the email's server will not confirm the account's status.                                                                                                         |
| IPQualityScore.Email.timed_out            | Boolean  | Did the connection to the mail service provider timeout during the verification? If so, we recommend increasing the "timeout" variable above the default 7 second value. Lookups that timeout with a "valid" result as false are most likely false and should be not be trusted.                                                                                      |
| IPQualityScore.Email.suspect              | Boolean  | This value indicates if the mail server is currently replying with a temporary error and unable to verify the email address. This status will also be true for "catch all" email addresses as defined below. If this value is true, then we suspect the "valid" result may be tainted and there is not a guarantee that the email address is truly valid.             |
| IPQualityScore.Email.recent_abuse         | Boolean  | This value will indicate if there has been any recently verified abuse across our network for this email address. Abuse could be a confirmed chargeback, fake signup, compromised device, fake app install, or similar malicious behavior within the past few days.                                                                                                   |
| IPQualityScore.Email.fraud_score          | Number   | The overall Fraud Score of the user based on the email's reputation and recent behavior across the IPQS threat network. Fraud Scores &gt;= 75 are suspicious, but not necessarily fraudulent.                                                                                                                                                                         |
| IPQualityScore.Email.suggested_domain     | String   | Default value is "N/A". Indicates if this email's domain should in fact be corrected to a popular mail service. This field is useful for catching user typos. For example, an email address with "gmai.com", would display a suggested domain of "gmail.com". This feature supports all major mail service providers.                                                 |
| IPQualityScore.Email.leaked               | Boolean  | Was this email address associated with a recent database leak from a third party? Leaked accounts pose a risk as they may have become compromised during a database breach.                                                                                                                                                                                           |
| IPQualityScore.Email.domain_age.human     | Date     | A human description of when this domain was registered. \(Ex: 3 months ago\)                                                                                                                                                                                                                                                                                          |
| IPQualityScore.Email.domain_age.timestamp | Number   | The unix time since epoch when this domain was first registered. \(Ex: 1568061634\)                                                                                                                                                                                                                                                                                   |
| IPQualityScore.Email.domain_age.iso       | Date     | The time this domain was registered in ISO8601 format \(Ex: 2019-09-09T16:40:34-04:00\)                                                                                                                                                                                                                                                                               |
| IPQualityScore.Email.first_seen.human     | Date     | A human description of the email address age, using an estimation of the email creation date when IPQS first discovered this email address. \(Ex: 3 months ago\)                                                                                                                                                                                                      |
| IPQualityScore.Email.first_seen.timestamp | Number   | The unix time since epoch when this email was first analyzed by IPQS. \(Ex: 1568061634\)                                                                                                                                                                                                                                                                              |
| IPQualityScore.Email.first_seen.iso       | Date     | The time this email was first analyzed by IPQS in ISO8601 format \(Ex: 2019-09-09T16:40:34-04:00\)                                                                                                                                                                                                                                                                    |
| IPQualityScore.Email.sanitized_email      | String   | Sanitized email address with all aliases and masking removed, such as multiple periods for Gmail.com.                                                                                                                                                                                                                                                                 |
| IPQualityScore.Email.request_id           | String   | A unique identifier for this request that can be used to lookup the request details or send a postback conversion notice.                                                                                                                                                                                                                                             |
| IPQualityScore.Email.address              | String   | The email address that was queried                                                                                                                                                                                                                                                                                                                                    |
| DBotScore.Indicator                       | String   | The indicator that was tested.                                                                                                                                                                                                                                                                                                                                        |
| DBotScore.Score                           | Number   | The actual score.                                                                                                                                                                                                                                                                                                                                                     |
| DBotScore.Type                            | String   | The indicator type.                                                                                                                                                                                                                                                                                                                                                   |
| DBotScore.Vendor                          | String   | The vendor used to calculate the score.                                                                                                                                                                                                                                                                                                                               |

#### Command Example

`!ipqs-email-reputation email="noreply@ipqualityscore.com"`

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

> ### IPQualityScore Results for noreply@ipqualityscore.com
>
> | message  | success | valid | disposable | smtp_score | overall_score | first_name | generic | common | dns_valid | honeypot | deliverability | frequent_complainer | spam_trap_score | catch_all | timed_out | suspect | recent_abuse | fraud_score | suggested_domain | leaked | domain_age                                                                       | first_seen                                                                      | sanitized_email            | request_id      | address                    |
> | -------- | ------- | ----- | ---------- | ---------- | ------------- | ---------- | ------- | ------ | --------- | -------- | -------------- | ------------------- | --------------- | --------- | --------- | ------- | ------------ | ----------- | ---------------- | ------ | -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- | -------------------------- | --------------- | -------------------------- |
> | Success. | true    | true  | false      | 2          | 3             | Corporate  | true    | false  | true      | true     | low            | false               | medium          | true      | false     | true    | true         | 95          | N/A              | false  | human: 10 years ago<br/>timestamp: 1302837997<br/>iso: 2011-04-14T23:26:37-04:00 | human: 2 years ago<br/>timestamp: 1557122946<br/>iso: 2019-05-06T02:09:06-04:00 | noreply@ipqualityscore.com | 4DpK9WpOZGQDnr7 | noreply@ipqualityscore.com |

### url

---

Runs reputation check on one or more URLs.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.

#### Base Command

`ipqs-url-reputation`

#### Input

| **Argument Name** | **Description**                                 | **Required** |
| ----------------- | ----------------------------------------------- | ------------ |
| url               | URL(s) to check. Supports comma-separated list. | Required     |

#### Context Output

| **Path**                                | **Type** | **Description**                                                                                                                                                          |
| --------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| IPQualityScore.Url.message              | String   | A generic status message, either success or some form of an error notice.                                                                                                |
| IPQualityScore.Url.success              | Boolean  | Was the request successful?                                                                                                                                              |
| IPQualityScore.Url.unsafe               | Boolean  | Is this domain suspected of being unsafe due to phishing, malware, spamming, or abusive behavior? View the confidence level by analyzing the "risk_score".               |
| IPQualityScore.Url.domain               | String   | Domain name of the final destination URL of the scanned link, after following all redirects.                                                                             |
| IPQualityScore.Url.ip_address           | String   | The IP address corresponding to the server of the domain name.                                                                                                           |
| IPQualityScore.Url.server               | String   | The server banner of the domain's IP address. For example: "nginx/1.16.0". Value will be "N/A" if unavailable.                                                           |
| IPQualityScore.Url.content_type         | String   | MIME type of URL's content. For example "text/html; charset=UTF-8". Value will be "N/A" if unavailable.                                                                  |
| IPQualityScore.Url.status_code          | Number   | HTTP Status Code of the URL's response. This value should be "200" for a valid website. Value is "0" if URL is unreachable.                                              |
| IPQualityScore.Url.page_size            | Number   | Total number of bytes to download the URL's content. Value is "0" if URL is unreachable.                                                                                 |
| IPQualityScore.Url.domain_rank          | Number   | Estimated popularity rank of website globally. Value is "0" if the domain is unranked or has low traffic.                                                                |
| IPQualityScore.Url.dns_valid            | Boolean  | The domain of the URL has valid DNS records.                                                                                                                             |
| IPQualityScore.Url.parking              | Boolean  | Is the domain of this URL currently parked with a for sale notice?                                                                                                       |
| IPQualityScore.Url.spamming             | Boolean  | Is the domain of this URL associated with email SPAM or abusive email addresses?                                                                                         |
| IPQualityScore.Url.malware              | Boolean  | Is this URL associated with malware or viruses?                                                                                                                          |
| IPQualityScore.Url.phishing             | Boolean  | Is this URL associated with malicious phishing behavior?                                                                                                                 |
| IPQualityScore.Url.suspicious           | Boolean  | Is this URL suspected of being malicious or used for phishing or abuse? Use in conjunction with the "risk_score" as a confidence level.                                  |
| IPQualityScore.Url.risk_score           | Number   | The IPQS risk score which estimates the confidence level for malicious URL detection. Risk Scores 85\+ are high risk, while Risk Scores = 100 are confirmed as accurate. |
| IPQualityScore.Url.request_id           | String   | A unique identifier for this request that can be used to lookup the request details or send a postback conversion notice.                                                |
| IPQualityScore.Url.url                  | String   | The URL being queried.                                                                                                                                                   |
| IPQualityScore.Url.adult                | Boolean  | Is this URL or domain hosting dating or adult content?                                                                                                                   |
| IPQualityScore.Url.domain_age.human     | Date     | A human description of when this domain was registered. \(Ex: 3 months ago\)                                                                                             |
| IPQualityScore.Url.domain_age.timestamp | Number   | The unix time since epoch when this domain was first registered. \(Ex: 1568061634\)                                                                                      |
| IPQualityScore.Url.domain_age.iso       | Date     | The time this domain was registered in ISO8601 format \(Ex: 2019-09-09T16:40:34-04:00\)                                                                                  |
| DBotScore.Indicator                     | String   | The indicator that was tested.                                                                                                                                           |
| DBotScore.Score                         | Number   | The actual score.                                                                                                                                                        |
| DBotScore.Type                          | String   | The indicator type.                                                                                                                                                      |
| DBotScore.Vendor                        | String   | The vendor used to calculate the score.                                                                                                                                  |
| URL.Data                                | String   | The URL                                                                                                                                                                  |
| URL.Malicious.Vendor                    | String   | The vendor reporting the URL as malicious.                                                                                                                               |

#### Command Example

`!ipqs-url-reputation url="https://google.com"`

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

> ### IPQualityScore Results for https://google.com
>
> | message  | success | unsafe | domain     | ip_address     | server   | content_type             | status_code | page_size | domain_rank | dns_valid | parking | spamming | malware | phishing | suspicious | adult | risk_score | domain_age                                                                      | request_id      | url                |
> | -------- | ------- | ------ | ---------- | -------------- | -------- | ------------------------ | ----------- | --------- | ----------- | --------- | ------- | -------- | ------- | -------- | ---------- | ----- | ---------- | ------------------------------------------------------------------------------- | --------------- | ------------------ |
> | Success. | true    | false  | google.com | 172.217.11.142 | gws<br/> | text/html; charset=UTF-8 | 200         | 39242     | 1           | true      | false   | false    | false   | false    | false      | false | 0          | human: 24 years ago<br/>timestamp: 874296000<br/>iso: 1997-09-15T00:00:00-04:00 | 4DpK9WpOZGQFSPi | https://google.com |

---

### phone

---

Runs reputation check on one or more phone numbers.

#### Base Command

`ipqs-phone-reputation`

#### Input

| **Argument Name** | **Description**                                                                                      | **Required** |
| ----------------- | ---------------------------------------------------------------------------------------------------- | ------------ |
| phone             | Phone number(s) to check in international format (e.g. +14155552671). Supports comma-separated list. | Required     |

#### Context Output

| **Path**                                               | **Type** | **Description**                                       |
| ------------------------------------------------------ | -------- | ----------------------------------------------------- |
| IPQualityScore.Phone.success                           | Boolean  | Was the request successful?                           |
| IPQualityScore.Phone.message                           | String   | A generic status message.                             |
| IPQualityScore.Phone.formatted                         | String   | Internationally formatted phone number.               |
| IPQualityScore.Phone.local_format                      | String   | Local format of the phone number.                     |
| IPQualityScore.Phone.valid                             | Boolean  | Is the phone number valid?                            |
| IPQualityScore.Phone.fraud_score                       | Number   | Overall fraud score (0–100).                          |
| IPQualityScore.Phone.recent_abuse                      | Boolean  | Has there been recent abuse reported for this number? |
| IPQualityScore.Phone.VOIP                              | Boolean  | Is the number a VOIP number?                          |
| IPQualityScore.Phone.prepaid                           | Boolean  | Is this a prepaid phone number?                       |
| IPQualityScore.Phone.risky                             | Boolean  | Is this number considered risky?                      |
| IPQualityScore.Phone.active                            | Boolean  | Is this number currently active?                      |
| IPQualityScore.Phone.carrier                           | String   | Carrier name.                                         |
| IPQualityScore.Phone.line_type                         | String   | Type of phone line (e.g., Landline, Mobile).          |
| IPQualityScore.Phone.country                           | String   | Country code or name associated with the number.      |
| IPQualityScore.Phone.city                              | String   | City associated with the number.                      |
| IPQualityScore.Phone.zip_code                          | String   | Zip code associated with the number.                  |
| IPQualityScore.Phone.region                            | String   | Region associated with the number.                    |
| IPQualityScore.Phone.dialing_code                      | Number   | Country dialing code.                                 |
| IPQualityScore.Phone.active_status                     | String   | Active status description.                            |
| IPQualityScore.Phone.sms_domain                        | String   | SMS domain for the number.                            |
| IPQualityScore.Phone.associated_email_addresses.status | String   | Status of associated email addresses.                 |
| IPQualityScore.Phone.associated_email_addresses.emails | Unknown  | List of email addresses associated with the number.   |
| IPQualityScore.Phone.user_activity                     | String   | User activity status.                                 |
| IPQualityScore.Phone.mnc                               | String   | Mobile Network Code.                                  |
| IPQualityScore.Phone.mcc                               | String   | Mobile Country Code.                                  |
| IPQualityScore.Phone.leaked                            | Boolean  | Was this number found in a known data leak?           |
| IPQualityScore.Phone.spammer                           | Boolean  | Is this number a known spammer?                       |
| IPQualityScore.Phone.do_not_call                       | Boolean  | Is this number on a do-not-call list?                 |
| IPQualityScore.Phone.name                              | String   | Name associated with the number.                      |
| IPQualityScore.Phone.timezone                          | String   | Timezone for the number.                              |
| IPQualityScore.Phone.request_id                        | String   | Unique request identifier.                            |
| IPQualityScore.Phone.phone                             | String   | The phone number that was queried.                    |
| DBotScore.Indicator                                    | String   | The indicator that was tested.                        |
| DBotScore.Score                                        | Number   | The actual DBot score.                                |
| DBotScore.Type                                         | String   | The indicator type.                                   |
| DBotScore.Vendor                                       | String   | The vendor used to calculate the score.               |

#### Command Example

`!ipqs-phone-reputation phone="+91 9000000000"`

#### Context Example

```json
{
  "DBotScore": {
    "Indicator": "+916300445124",
    "Reliability": "A - Completely reliable",
    "Score": 0,
    "Type": "phone",
    "Vendor": "IPQualityScore"
  },
  "IPQualityScore": {
    "Phone": {
      "message": "Phone is valid.",
      "success": true,
      "formatted": "+916300445124",
      "local_format": "063004 45124",
      "valid": true,
      "fraud_score": 0,
      "recent_abuse": false,
      "VOIP": false,
      "prepaid": false,
      "risky": false,
      "active": true,
      "carrier": "Reliance (JIO)",
      "line_type": "Wireless",
      "country": "IN",
      "city": "N/A",
      "zip_code": "N/A",
      "region": "India",
      "dialing_code": 91,
      "active_status": "N/A",
      "sms_domain": "N/A",
      "associated_email_addresses": {
        "status": "No associated emails found.",
        "emails": []
      },
      "user_activity": "high",
      "mnc": "854",
      "mcc": "405",
      "leaked": true,
      "spammer": false,
      "request_id": "gOODapX9Cj",
      "name": "CHETHAN SWAROOP",
      "timezone": "Asia/Kolkata",
      "do_not_call": false,
      "tcpa_blacklist": false,
      "accurate_country_code": false,
      "sms_email": "N/A",
      "number_recycling": {
        "message": "Number recycling feature disabled. Please contact support to activate.",
        "recently_recycled": null,
        "last_ported_date": null,
        "ported": null
      },
      "identity_data": [
        {
          "names": [
            {
              "first_name": "CHETHAN",
              "last_name": "SWAROOP",
              "middle_name": ""
            }
          ],
          "addresses": [],
          "email_addresses": [],
          "phone_numbers": [
            {
              "formatted_phone_number": "+916300445124",
              "country": "IN"
            }
          ],
          "age": [],
          "source": "marketing_databases"
        }
      ]
    }
  },
  "Phone": {
    "Number": "+916300445124"
  }
}
```

#### Human Readable Output

> ### IPQualityScore Results for +14155552671
>
> | fraud_score | valid | active | VOIP  | prepaid | risky | carrier | line_type | country | phone        |
> | ----------- | ----- | ------ | ----- | ------- | ----- | ------- | --------- | ------- | ------------ |
> | 20          | true  | true   | false | false   | false | AT&T    | Mobile    | US      | +14155552671 |

---

### leaked-username

---

Checks if a username has been exposed in known data breaches.

#### Base Command

`ipqs-username-leaked`

#### Input

| **Argument Name** | **Description**                                                | **Required** |
| ----------------- | -------------------------------------------------------------- | ------------ |
| username          | Username(s) to check for leaks. Supports comma-separated list. | Required     |

#### Context Output

| **Path**                                     | **Type** | **Description**                                   |
| -------------------------------------------- | -------- | ------------------------------------------------- |
| IPQualityScore.Username.success              | Boolean  | Was the request successful?                       |
| IPQualityScore.Username.message              | String   | Status message.                                   |
| IPQualityScore.Username.request_hash         | String   | Unique hash for the request.                      |
| IPQualityScore.Username.source               | Unknown  | List of sources where the username was found.     |
| IPQualityScore.Username.exposed              | Boolean  | Was the username found in a known leak?           |
| IPQualityScore.Username.first_seen.human     | String   | Human-readable time when the leak was first seen. |
| IPQualityScore.Username.first_seen.timestamp | Number   | Unix epoch when the leak was first seen.          |
| IPQualityScore.Username.first_seen.iso       | String   | ISO8601 timestamp when the leak was first seen.   |
| IPQualityScore.Username.request_id           | String   | Unique request identifier.                        |
| IPQualityScore.Username.username             | String   | The username that was queried.                    |
| DBotScore.Indicator                          | String   | The indicator that was tested.                    |
| DBotScore.Score                              | Number   | The actual DBot score.                            |
| DBotScore.Type                               | String   | The indicator type.                               |
| DBotScore.Vendor                             | String   | The vendor used to calculate the score.           |

#### Command Example

`!!ipqs-username-leaked username="user@123"`

#### Context Example

```json
{
  "DBotScore": {
    "Indicator": "testuser123",
    "Reliability": "A - Completely reliable",
    "Score": 0,
    "Type": "username",
    "Vendor": "IPQualityScore"
  },
  "IPQualityScore": {
    "Username": {
      "success": true,
      "message": "Success",
      "request_hash": "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
      "source": [],
      "exposed": false,
      "first_seen": {
        "human": "just now",
        "timestamp": 1776841128,
        "iso": "2026-04-22T02:58:48-04:00"
      },
      "request_id": "gOOSmfym49"
    }
  },
  "Account": {
    "Username": "testuser123"
  }
}
```

#### Human Readable Output

> ### IPQualityScore Results for johndoe
>
> | success | exposed | source | request_id | username |
> | ------- | ------- | ------ | ---------- | -------- |
> | true    | false   |        | abc123     | johndoe  |

---

### leaked-password

---

Checks if a password has been exposed in known data breaches.

#### Base Command

`ipqs-password-leaked`

#### Input

| **Argument Name** | **Description**                                                | **Required** |
| ----------------- | -------------------------------------------------------------- | ------------ |
| password          | Password(s) to check for leaks. Supports comma-separated list. | Required     |

#### Context Output

| **Path**                                     | **Type** | **Description**                                   |
| -------------------------------------------- | -------- | ------------------------------------------------- |
| IPQualityScore.Password.success              | Boolean  | Was the request successful?                       |
| IPQualityScore.Password.message              | String   | Status message.                                   |
| IPQualityScore.Password.request_hash         | String   | Unique hash for the request.                      |
| IPQualityScore.Password.source               | Unknown  | List of sources where the password was found.     |
| IPQualityScore.Password.exposed              | Boolean  | Was the password found in a known leak?           |
| IPQualityScore.Password.first_seen.human     | String   | Human-readable time when the leak was first seen. |
| IPQualityScore.Password.first_seen.timestamp | Number   | Unix epoch when the leak was first seen.          |
| IPQualityScore.Password.first_seen.iso       | String   | ISO8601 timestamp when the leak was first seen.   |
| IPQualityScore.Password.request_id           | String   | Unique request identifier.                        |
| IPQualityScore.Password.password             | String   | The password that was queried.                    |
| DBotScore.Indicator                          | String   | The indicator that was tested.                    |
| DBotScore.Score                              | Number   | The actual DBot score.                            |
| DBotScore.Type                               | String   | The indicator type.                               |
| DBotScore.Vendor                             | String   | The vendor used to calculate the score.           |

#### Command Example

`!ipqs-password-leaked password="user123"`

#### Context Example

```json
{
  "DBotScore": {
    "Indicator": "abc@123",
    "Reliability": "A - Completely reliable",
    "Score": 3,
    "Type": "password",
    "Vendor": "IPQualityScore"
  },
  "IPQualityScore": {
    "Leak": {
      "Password": {
        "success": true,
        "message": "Success",
        "request_hash": "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
        "source": ["Exploit Antipublic", "Dark Web Leaks"],
        "exposed": true,
        "first_seen": {
          "human": "3 years ago",
          "timestamp": 1681115849,
          "iso": "2023-04-10T04:37:29-04:00"
        },
        "request_id": "gOOeuEg77u"
      }
    }
  },
  "Password": {
    "Data": "abc@123"
  }
}
```

#### Human Readable Output

> ### IPQualityScore Results for provided password
>
> | success | exposed | source      | request_id |
> | ------- | ------- | ----------- | ---------- |
> | true    | true    | breach_db_1 | xyz789     |

---

### leaked-email

---

Checks if an email address has been exposed in known data breaches.

#### Base Command

`ipqs-email-leaked`

#### Input

| **Argument Name** | **Description**                                                      | **Required** |
| ----------------- | -------------------------------------------------------------------- | ------------ |
| email             | Email address(es) to check for leaks. Supports comma-separated list. | Required     |

#### Context Output

| **Path**                                        | **Type** | **Description**                                   |
| ----------------------------------------------- | -------- | ------------------------------------------------- |
| IPQualityScore.LeakedEmail.success              | Boolean  | Was the request successful?                       |
| IPQualityScore.LeakedEmail.message              | String   | Status message.                                   |
| IPQualityScore.LeakedEmail.request_hash         | String   | Unique hash for the request.                      |
| IPQualityScore.LeakedEmail.source               | Unknown  | List of sources where the email was found.        |
| IPQualityScore.LeakedEmail.exposed              | Boolean  | Was the email found in a known leak?              |
| IPQualityScore.LeakedEmail.first_seen.human     | String   | Human-readable time when the leak was first seen. |
| IPQualityScore.LeakedEmail.first_seen.timestamp | Number   | Unix epoch when the leak was first seen.          |
| IPQualityScore.LeakedEmail.first_seen.iso       | String   | ISO8601 timestamp when the leak was first seen.   |
| IPQualityScore.LeakedEmail.plain_text_password  | String   | Plain text password if found in the leak.         |
| IPQualityScore.LeakedEmail.request_id           | String   | Unique request identifier.                        |
| IPQualityScore.LeakedEmail.email                | String   | The email address that was queried.               |
| DBotScore.Indicator                             | String   | The indicator that was tested.                    |
| DBotScore.Score                                 | Number   | The actual DBot score.                            |
| DBotScore.Type                                  | String   | The indicator type.                               |
| DBotScore.Vendor                                | String   | The vendor used to calculate the score.           |

#### Command Example

`!ipqs-email-leaked email="user@example.com"`

#### Context Example

```json
{
  "DBotScore": {
    "Indicator": "user@example.com",
    "Reliability": "A - Completely reliable",
    "Score": 3,
    "Type": "email",
    "Vendor": "IPQualityScore"
  },
  "IPQualityScore": {
    "Leak": {
      "Email": {
        "success": true,
        "message": "Success",
        "request_hash": "d2b6ff2e611edf5bb40014608a84d75a5b30773272248c28fa79db3bd5739677",
        "source": ["Dark Web Leaks"],
        "exposed": true,
        "first_seen": {
          "human": "6 years ago",
          "timestamp": 1591641120,
          "iso": "2020-06-08T14:32:00-04:00"
        },
        "plain_text_password": false,
        "request_id": "gOOsrUX4lK"
      }
    }
  },
  "Email": {
    "Address": "user@example.com"
  }
}
```

#### Human Readable Output

> ### IPQualityScore Results for user@example.com
>
> | success | exposed | plain_text_password | source      | request_id | email            |
> | ------- | ------- | ------------------- | ----------- | ---------- | ---------------- |
> | true    | true    | p@ssw0rd            | breach_db_2 | lmn456     | user@example.com |

---

### file-scan

---

Uploads a file and scans it using the IPQualityScore Malware File Scanner API. First attempts a cached lookup by file hash; if not cached, the file is submitted for scanning. Polls for results automatically if the scan is pending.

#### Base Command

`ipqs-file-scan`

#### Input

| **Argument Name** | **Description**                                    | **Required** |
| ----------------- | -------------------------------------------------- | ------------ |
| entry_id          | The entry id of the uploaded file in the War Room. | Required     |

#### Context Output

| **Path**                               | **Type** | **Description**                                        |
| -------------------------------------- | -------- | ------------------------------------------------------ |
| IPQualityScore.FileScan.success        | Boolean  | Was the request successful?                            |
| IPQualityScore.FileScan.message        | String   | Status message.                                        |
| IPQualityScore.FileScan.file_name      | String   | The file name that was scanned.                        |
| IPQualityScore.FileScan.file_hash      | String   | SHA256 hash of the file.                               |
| IPQualityScore.FileScan.type           | String   | Type of operation performed: "scan" or "lookup".       |
| IPQualityScore.FileScan.status         | String   | Scan status: "pending" or "complete".                  |
| IPQualityScore.FileScan.detected       | Boolean  | Was the file detected as malicious?                    |
| IPQualityScore.FileScan.detected_scans | Number   | Number of engines that detected the file as malicious. |
| IPQualityScore.FileScan.total_scans    | Number   | Total number of scan engines used.                     |
| IPQualityScore.FileScan.result         | String   | Detailed scan engine results.                          |
| IPQualityScore.FileScan.file_size      | Number   | File size in bytes.                                    |
| IPQualityScore.FileScan.file_type      | String   | MIME type of the file.                                 |
| IPQualityScore.FileScan.sha1           | String   | SHA1 hash of the file.                                 |
| IPQualityScore.FileScan.md5            | String   | MD5 hash of the file.                                  |
| IPQualityScore.FileScan.request_id     | String   | Unique request identifier.                             |
| File.SHA256                            | String   | SHA256 hash of the file.                               |
| File.SHA1                              | String   | SHA1 hash of the file.                                 |
| File.MD5                               | String   | MD5 hash of the file.                                  |
| File.Size                              | Number   | File size in bytes.                                    |
| File.Type                              | String   | File MIME type.                                        |
| File.Malicious.Count                   | Number   | Number of detections.                                  |
| DBotScore.Indicator                    | String   | The indicator that was tested.                         |
| DBotScore.Score                        | Number   | The actual DBot score.                                 |
| DBotScore.Type                         | String   | The indicator type (file).                             |
| DBotScore.Vendor                       | String   | The vendor used to calculate the score.                |

#### Command Example

`!ipqs-file-scan entry_id="212@_13"`

#### Human Readable Output

> ### IPQualityScore URL Scan Result
>
> | file_name | file_hash                                                        | detected | detected_scans | total_scans | status | file_type | file_size | sha1                                     | md5                              | request_id | IPQS_Internet_Security        | IPQS_Malicious_Code           | IPQS_Emerging_Threats         | IPQS_Threat_Defender          | IPQS_Network_Activity         | IPQS_Foreign_Entity           | IPQS_Byte_Checks              |
> | --------- | ---------------------------------------------------------------- | -------- | -------------- | ----------- | ------ | --------- | --------- | ---------------------------------------- | -------------------------------- | ---------- | ----------------------------- | ----------------------------- | ----------------------------- | ----------------------------- | ----------------------------- | ----------------------------- | ----------------------------- |
> | ipks.exe  | a35e17ca3d1c0d7363ad4a9c358260d1343033212299ac37cd43471aaa3478b9 | false    | 0              | 7           | done   | text/html | 61049     | 6751c12507d83f850edaceea8bd51031d27ee363 | 942af291e78ae29787c0069611ec58e3 | fmXlsRjJ4x | detected: false, error: false | detected: false, error: false | detected: false, error: false | detected: false, error: false | detected: false, error: false | detected: false, error: false | detected: false, error: false |

---

### url-file-scan

---

Submits a URL to the IPQualityScore Malware File Scanner API. First attempts a cached lookup; if not cached, the URL is submitted for scanning. Polls for results automatically if the scan is pending.

#### Base Command

`ipqs-url-file-scan`

#### Input

| **Argument Name** | **Description**                                            | **Required** |
| ----------------- | ---------------------------------------------------------- | ------------ |
| url               | URL(s) to scan for malware. Supports comma-separated list. | Required     |

#### Context Output

| **Path**                                  | **Type** | **Description**                                       |
| ----------------------------------------- | -------- | ----------------------------------------------------- |
| IPQualityScore.URLFileScan.success        | Boolean  | Was the request successful?                           |
| IPQualityScore.URLFileScan.message        | String   | Status message.                                       |
| IPQualityScore.URLFileScan.file_name      | String   | The URL that was scanned.                             |
| IPQualityScore.URLFileScan.file_hash      | String   | SHA256 hash of the scanned content.                   |
| IPQualityScore.URLFileScan.type           | String   | Type of operation performed: "scan" or "lookup".      |
| IPQualityScore.URLFileScan.status         | String   | Scan status: "pending" or "complete".                 |
| IPQualityScore.URLFileScan.detected       | Boolean  | Was the URL detected as malicious?                    |
| IPQualityScore.URLFileScan.detected_scans | Number   | Number of engines that detected the URL as malicious. |
| IPQualityScore.URLFileScan.total_scans    | Number   | Total number of scan engines used.                    |
| IPQualityScore.URLFileScan.result         | String   | Detailed scan engine results.                         |
| IPQualityScore.URLFileScan.file_size      | Number   | Size of the scanned content in bytes.                 |
| IPQualityScore.URLFileScan.file_type      | String   | MIME type of the scanned content.                     |
| IPQualityScore.URLFileScan.sha1           | String   | SHA1 hash of the scanned content.                     |
| IPQualityScore.URLFileScan.md5            | String   | MD5 hash of the scanned content.                      |
| IPQualityScore.URLFileScan.scan_date      | Unknown  | Date and time when the scan was performed.            |
| IPQualityScore.URLFileScan.request_id     | String   | Unique request identifier.                            |
| URL.Data                                  | String   | The URL that was scanned.                             |
| URL.Malicious.Description                 | String   | Description of why the URL was flagged as malicious.  |
| URL.Malicious.Vendor                      | String   | The vendor that identified the URL as malicious.      |
| DBotScore.Indicator                       | String   | The indicator that was tested.                        |
| DBotScore.Score                           | Number   | The actual DBot score.                                |
| DBotScore.Type                            | String   | The indicator type (URL).                             |
| DBotScore.Vendor                          | String   | The vendor used to calculate the score.               |

#### Command Example

`!ipqs-url-file-scan url="http://www.example.com/"`

#### Human Readable Output

> ### IPQualityScore URL Scan Result
>
> | file_name   | file_hash                                                        | detected | detected_scans | total_scans | status | file_type | file_size | sha1                                     | md5                              | request_id | IPQS_Internet_Security        | IPQS_Malicious_Code           | IPQS_Emerging_Threats         | IPQS_Threat_Defender          | IPQS_Network_Activity         | IPQS_Foreign_Entity           | IPQS_Byte_Checks              |
> | ----------- | ---------------------------------------------------------------- | -------- | -------------- | ----------- | ------ | --------- | --------- | ---------------------------------------- | -------------------------------- | ---------- | ----------------------------- | ----------------------------- | ----------------------------- | ----------------------------- | ----------------------------- | ----------------------------- | ----------------------------- |
> | M94scZj.exe | a35e17ca3d1c0d7363ad4a9c358260d1343033212299ac37cd43471aaa3478b9 | false    | 0              | 7           | done   | text/html | 61049     | 6751c12507d83f850edaceea8bd51031d27ee363 | 942af291e78ae29787c0069611ec58e3 | fmXlsRjJ4x | detected: false, error: false | detected: false, error: false | detected: false, error: false | detected: false, error: false | detected: false, error: false | detected: false, error: false | detected: false, error: false |

---

## Scoring Thresholds

| **Indicator Type**  | **Suspicious (default)** | **Malicious (default)** | **Score Field**  |
| ------------------- | ------------------------ | ----------------------- | ---------------- |
| IP                  | 75                       | 90                      | `fraud_score`    |
| Email               | 75                       | 90                      | `fraud_score`    |
| URL (reputation)    | 75                       | 90                      | `risk_score`     |
| Phone               | 75                       | 90                      | `fraud_score`    |
| File (malware scan) | 1 detection              | 5 detections            | `detected_scans` |
| URL (malware scan)  | 1 detection              | 5 detections            | `detected_scans` |
