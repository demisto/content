Netcraft takedown, submission and screenshot management.

## Use Cases

1. Verify the incident image of the reported URL.
2. Authorize takedowns.
3. Escalate takedowns.
4. Track takedowns.
5. Submit a report - email, file, URL.
6. Take a screenshot of the email, file or URL.
7. Fetch incidents from attacks.

## Configure Netcraft on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Netcraft.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Takedown Server URL | The URL to use for the Takedown Service. | True |
    | Submission Server URL | The URL to use for the Submission Service. | True |
    | API Key | The API key associated with the Netcraft account. | True |
    | Region | The default region to use with the Takedown Service. | True |
    | Fetch incidents |  | False |
    | Incident type |  | False |
    | Maximum number of incidents per fetch |  | False |
    | First fetch time |  | True |
    | Incidents Fetch Interval |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, API Key, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### netcraft-attack-report

***
Report a new attack or authorize an existing attack in the Takedown Service.
If a takedown for the attack already exists in the Netcraft system it will be authorized, otherwise, a new takedown will be added and authorized.


#### Base Command

`netcraft-attack-report`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| attack | The digital location of the attack to take down, e.g., a phishing URL, or a fraudulent email address. | Required | 
| comment | The reason for the report, such as a description of the attack. | Required | 
| brand | The brand to report the takedown under. If no brand is specified, the brand of the provided "region" will be used. | Optional | 
| attack_type | The type of attack being reported.<br/>Run the command "netcraft-attack-type-list" to get the list of available types, use the "Name" field of the type for this argument.<br/>. Default is phishing_url. | Optional | 
| inactive | Set to "true" if the attack is not currently active.<br/>This will place the takedown directly into the "Inactive (Monitoring)" status, which can be used to monitor suspicious sites.<br/>. Possible values are: true, false. Default is false. | Optional | 
| force_auth | If set to true, Netcraft will be authorized to start the takedown as soon as the report has been processed.<br/>If set to false, the takedown will only be authorized if you have automatic authorization enabled for the given attack type, or if the takedown is manually authorized later through the web interface.<br/>. Possible values are: true, false. Default is true. | Optional | 
| malware | Should be set to true if the reported content contains or is related to a computer virus.<br/>This is used to determine the correct attack type in the case where the attack_type argument has not been provided.<br/>. Possible values are: true, false. | Optional | 
| suspected_fraud_domain | Should be set to true if you believe that the domain name has been registered as part of the fraud.<br/>This will ensure that the registrar is contacted to seek suspension of the domain name.<br/>. Possible values are: true, false. Default is false. | Optional | 
| password | The password to extract any archived evidence provided via the evidence argument, if necessary. | Optional | 
| entry_id | Entry ID of the evidence file uploaded to Cortex XSOAR. If a password is needed for the file, it can be provided with the "password" argument. | Optional | 
| phishkit_fetch_url | The URL where the phishkit archive was found.<br/>This parameter is required for attacks of type "phishkit_email".<br/>. | Optional | 
| phishkit_phish_url | The URL of the phishing attack which uses the referenced phishkit.<br/>This parameter is required for attacks of type "phishkit_email" and/or "phishkit_archive".<br/>. | Optional | 
| customer_label | A free-text field which can be used to keep track of particular attacks. | Optional | 
| tags | A comma-separated list of tags to apply to the attack. | Optional | 
| region | The name of the region to create a takedown under.<br/>If not provided, the region specified in the instance configuration will be used.<br/>. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netcraft.Takedown.id | String | The ID of the takedown. (this key will only appear if the takedown has been created and verified). | 

#### Command example
```!netcraft-attack-report attack="https://www.example.com/" comment="Very malicious" attack_type="phishing_url" inactive="true" customer_label="Test Playbook run" tags="coronavirus"```
#### Context Example
```json
{
    "Netcraft": {
        "Takedown": {
            "id": "45492113"
        }
    }
}
```

#### Human Readable Output

>### Netcraft attack reported
>|Report status|Takedown ID|Response code|
>|---|---|---|
>| The attack was submitted to Netcraft successfully. | 45492113 | TD_OK |


### netcraft-takedown-list

***
Get a list of takedown objects.
Netcraft has a limit of 1,000,000 objects returned within a 24 hour period (moving time window) per email address.


#### Base Command

`netcraft-takedown-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Filter to the takedown with the specified ID. | Optional | 
| statuses | Filter to takedowns that are currently in the given status. Multiple values may be provided as a comma-separated list. Possible values are: unverified, inactive_monitoring, verified, contacted_hosting, contacted_police, contacted_upstream, resolved_monitoring, resolved, stale, invalid. | Optional | 
| url | Filter by URL, email, hostname, domain or IP. | Optional | 
| false_positive | Whether to filter to takedowns which have been incorrectly marked as malicious. Possible values are: true, false. | Optional | 
| ip | Filter to attacks that are hosted on the given IPv4 address, or within the given IPv4 CIDR range. Note that partial IP addresses will not be matched. | Optional | 
| id_before | Filter to takedowns that were submitted before the specified takedown ID. | Optional | 
| id_after | Filter to takedowns that were submitted after the specified takedown<br/>ID. When using this argument we recommend that you also set the "sort" argument<br/>to Id to ensure that no results are missed.<br/>. | Optional | 
| date_from | Filter to takedowns that were submitted on or after the date/time<br/>provided. Values should be supplied as "YYYY-MM-DD HH:MM:SS" in UTC format. If no time<br/>information is provided, the system will default to YYYY-MM-DD 00:00:00. Relative<br/>date/time formats are also supported, for example "5 days ago"",\_and "monday<br/>this week". | Optional | 
| date_to | Filter to takedowns that were submitted on or before the date/time<br/>provided. Values should be supplied as "YYYY-MM-DD HH:MM:SS" in UTC format. If no time<br/>information is provided, the system will default to "YYYY-MM-DD 00:00:00". Relative<br/>date/time formats are also supported, for example "5 days ago", and "monday this week". | Optional | 
| reporter_email | Filter to takedowns that were reported by the given user. | Optional | 
| report_source | Filter to takedowns that were reported through the given mechanism. Possible values are: Interface, Phishing Feed, Referer, Forensic, Api, Email Feed, Fraud Detection. | Optional | 
| attack_types | Filter to takedowns of the given attack type. Multiple values may be provided as a comma-separated list.<br/>Run the command "netcraft-attack-type-list" to get the list of available types, use the "Name" field of the type for this argument.<br/>. | Optional | 
| auth_given | Filter based on whether and by who the takedown has been authorized. Possible values are: Yes, Yes Customer, Yes Netcraft, No. | Optional | 
| escalated | Filter based on whether and by who the takedown has been escalated. Possible values are: Yes, Yes Customer, Yes Netcraft, No. | Optional | 
| sort | The key that the list of takedowns should be sorted by. Possible values are: Auth Given, Customer Label, Date Submitted, Hoster, Id, Ip, Language, Last Updated, Registrar, Status. Default is Status. | Optional | 
| sort_direction | The direction to sort takedowns in with the key specified in the "sort" argument. Possible values are: asc, desc. Default is asc. | Optional | 
| limit | The maximum number of takedowns to return. The max value is 100,000. Default is 50. | Optional | 
| all_results | Whether to retrieve all takedowns that match the filters.<br/>If true, the "limit" argument will be ignored. The maximum takedowns returned in one call is 100,000.<br/>. Possible values are: false, true. Default is false. | Optional | 
| region | The name of the region for which to list takedowns.<br/>If not provided, the region specified in the instance configuration will be used.<br/>. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netcraft.Takedown.id | String | The ID of the takedown. | 
| Netcraft.Takedown.group_id | String | The ID of the group that the takedown belongs to. Can potentially be the same ID, or empty if there is no group. | 
| Netcraft.Takedown.attack_url | String | The location of the attack being taken down. This field contains a canonicalized value. See the reported_url field for the exact location that was reported to takedown. | 
| Netcraft.Takedown.reported_url | String | The location of the attack as reported to takedown. See the attack_url field for the formatted location of the attack being taken down. | 
| Netcraft.Takedown.ip | String | The IPv4 address of the attack. | 
| Netcraft.Takedown.country_code | String | ISO country code of the advertised hosting location. | 
| Netcraft.Takedown.date_submitted | Date | The date and time that the takedown was reported, in UTC format. | 
| Netcraft.Takedown.last_updated | Date | The date and time of the last action taken on the takedown, in UTC format. | 
| Netcraft.Takedown.region | String | The name of the area that the takedown resides in. | 
| Netcraft.Takedown.target_brand | String | The name of the brand being targeted by the attack. | 
| Netcraft.Takedown.authgiven | Boolean | Indicates whether the takedown has been authorized. | 
| Netcraft.Takedown.host | String | The name of the company responsible for the IP address. | 
| Netcraft.Takedown.registrar | String | The name of the registrar responsible for the domain name used in the attack. | 
| Netcraft.Takedown.customer_label | String | A custom field which may be provided along with the takedown report. | 
| Netcraft.Takedown.date_authed | Date | The date and time that the takedown was authorized, in UTC. | 
| Netcraft.Takedown.stop_monitoring_date | Date | The date and time that the takedown system stopped monitoring the attack, in UTC format. If the attack is still being monitored, an empty string is given.  | 
| Netcraft.Takedown.domain | String | The domain of the URL or email address being taken down. This will be blank for an attack with no domain name.  | 
| Netcraft.Takedown.language | String | The language used in the attack \(if it can be determined\). | 
| Netcraft.Takedown.date_first_actioned | Date | The date and time of the first action taken by Netcraft after the takedown was reported, in UTC format. This is calculated as the first time that the takedown was moved out of the "unverified" status.  | 
| Netcraft.Takedown.escalated | Boolean | Indicates whether the takedown has been escalated. | 
| Netcraft.Takedown.first_contact | Date | The date and time that the takedown first entered a contacted state, in UTC format. | 
| Netcraft.Takedown.first_inactive | Date | The date and time that the takedown first entered the inactive \(monitoring\) state in UTC format. | 
| Netcraft.Takedown.is_redirect | String | Whether or not the attack redirects to another location. Possible values: "final" - the attack is the final destination of another redirect.  "redirect" - the attack redirects to another location. "no_redirect" - the attack does not redirect.  | 
| Netcraft.Takedown.attack_type | String | The type of attack being taken down. | 
| Netcraft.Takedown.certificate | Unknown | HTTPS certificate details for the hostname. The structure of the returned data is the output of PHP's "openssl_x509_parse" function with the additional keys spki_sha256 and spki_sha1. \(See https://www.php.net/manual/en/function.openssl-x509-parse.php\).  | 
| Netcraft.Takedown.certificate.spki_sha256 | Unknown | The SHA-256 hash of the Subject Public Key Info structure in the certificate. | 
| Netcraft.Takedown.certificate.spki_sha1 | Unknown | The SHA-1 hash of the Subject Public Key Info structure in the certificate. | 
| Netcraft.Takedown.deceptive_domain_score | String | The deceptive domain score of the domain. E.g., for the URL https://l0gin.example.com/, this value will contain the deceptive domain score for example.com.  | 
| Netcraft.Takedown.domain_risk_rating | String | A score from 0 to 10 which represents the risk that the domain is hosting a malicious website. E.g., for the URL https://l0gin.example.com/, this value will contain the risk rating for "example.com". This score is distinct from the "deceptive domain score", and takes a range of factors into account, such as the reputation of the hosting provider, age of the domain name, search engine rankings and more.  | 
| Netcraft.Takedown.final_outage | String | The duration \(hh:mm:ss\) between when the takedown was authorized, and the final time that the attack went offline \(final_resolved - date_authed\).  | 
| Netcraft.Takedown.final_resolved | Date | The date and time that the attack went offline for the final time, in UTC format. | 
| Netcraft.Takedown.first_outage | Date | The duration \(hh:mm:ss\) between when the takedown was authorized, and the first time that the attack went offline \(first_resolved - date_authed\). | 
| Netcraft.Takedown.first_resolved | Date | The date and time that the attack first went offline, in UTC format. | 
| Netcraft.Takedown.fwd_owner | String | The owner of the forward DNS infrastructure. | 
| Netcraft.Takedown.has_phishing_kit | Boolean | Indicates whether the takedown has an associated phishing kit. | 
| Netcraft.Takedown.hostname | String | The full hostname of the URL or email address being taken down. This will be blank for attacks with no hostname. | 
| Netcraft.Takedown.hostname_ddss_score | String | The deceptive domain score of the hostname. E.g., For the URL https://l0gin.example.com/, this value will contain the deceptive domain score for l0gin.example.com.  | 
| Netcraft.Takedown.evidence_url | String | A URL for the public incident report for this attack. | 
| Netcraft.Takedown.domain_attack | String | Whether or not the domain name used in the attack is believed to be fraudulent. Possible values \(non exhaustive\): "all" - All attacks. "yes" - There is a high confidence that the domain name is fraudulent. The domain registrar will be contacted, and the webmaster will not be contacted. "yes_low_confidence" - The domain is likely fraudulent. The domain registrar will be contacted, and the webmaster will still be contacted. "no" - The domain name is not believed to be fraudulent. This is likely a compromised site.  | 
| Netcraft.Takedown.false_positive | Boolean | Indicates whether the reported content was incorrectly flagged as malicious. | 
| Netcraft.Takedown.hostname_attack | String | Whether or not the hostname used in the attack is believed to be fraudulent. Possible values \(non exhaustive\): "all" - All attacks. "yes" - There is a high confidence that the hostname is fraudulent. The certificate authority will be contacted. "yes_low_confidence" - The hostname is likely fraudulent. "no" - The hostname is not believed to be fraudulent. This is likely a compromised site.  | 
| Netcraft.Takedown.malware_category | String | The category of malware detected. Only set for malware attack types. May be empty if category cannot be determined. | 
| Netcraft.Takedown.malware_family | String | The family of malware detected. Only set for malware attack types. May be empty if family cannot be determined. | 
| Netcraft.Takedown.phishing_kit_hash | Unknown | The SHA-1 hashes of all phishing kits available for download that are related to this takedown. | 
| Netcraft.Takedown.report_source | String | The method through which the takedown was submitted. | 
| Netcraft.Takedown.reporter | String | Person/account that submitted the takedown. This will be the email address of the user, or "netcraft" for any reports made by Netcraft. | 
| Netcraft.Takedown.rev_owner | String | The owner of the reverse DNS infrastructure. | 
| Netcraft.Takedown.reverse_dns | String | The output of a reverse DNS lookup on the IP of the attack. | 
| Netcraft.Takedown.certificate_revoked | String | If the SSL certificate has been revoked, then the date this was detected \(in UTC format\) is returned, else "Not revoked" is returned. | 
| Netcraft.Takedown.screenshot_url | String | The URL\(s\) at which a screenshot of the attack can be found. When returning a single URL as a string \(the default behaviour\) the returned URL will be the best guess of the screenshot which displays the live attack. When returning multiple URLs, the list will be sorted by the time the screenshot was requested, with the earliest first. | 
| Netcraft.Takedown.status_change_uptime | String | The total duration \(hh:mm:ss\) that the attack was available for after authorization, as determined by the takedown status changes. i.e. the total amount of time since authorization that an attack was not in the resolved or resolved \(monitoring\) state.'. | 
| Netcraft.Takedown.status | String | The status of the takedown. Possible values: "Unverified" - The report has not yet been verified as fraudulent by Netcraft. "Inactive \(Monitoring\)" - The attack went offline before Netcraft was authorized to start the takedown process, and is being monitored in case it returns. "Verified" - The report has been verified as fraudulent, but no takedown notices have been sent. "Contacted Hosting" - Takedown notices have been sent to the hosting provider. "Contacted Police" - The takedown has been escalated to local law enforcement. "Contacted Upstream" - The takedown has been escalated to the organization providing connectivity to the hosting provider. "Monitoring" - The attack is offline, as it is being monitored in case it returns. "Resolved" - The attack has been offline for 7 consecutive days, and is no longer being monitored. "Stale" - The attack went offline before Netcraft was authorized to start the takedown process, and is no longer being monitored. "Invalid" - The report is not a valid takedown target. | 
| Netcraft.Takedown.tags | String | List of tags applied to the group. | 
| Netcraft.Takedown.targeted_url | String | The URL which this attack is masquerading as, e.g., the URL of the legitimate login form that a phishing attack is targeting. | 
| Netcraft.Takedown.site_risk_rating | String | A score from 0 to 10 which represents the risk that the hostname is hosting a malicious website. E.g., For the URL https://l0gin.example.com/, this value will contain the risk rating for l0gin.example.com. | 
| Netcraft.Takedown.whois_server | String | The WHOIS data for the takedown. | 
| Netcraft.Takedown.authorization_source | String | The source of authorization for the takedown. will be blank if the takedown has not been authorized. Possible values: "customer" "netcraft". | 
| Netcraft.Takedown.escalation_source | String | The source of escalation for the takedown. Will be blank if the takedown has not been escalated. Possible values: "customer" "netcraft". | 
| Netcraft.Takedown.restart_date | String | The latest date and time, in UTC format, that the takedown was restarted, i.e., went from the "resolved \(monitoring\)" status to a contacted status. Will be empty if the takedown had never been restarted. | 
| Netcraft.Takedown.gsb_block_status | Unknown | An array of objects containing the Google Safe Browsing block status on all platforms \(iOS, Android and Desktop\). Will be an empty array if the takedown is not a Phishing URL takedown, or if Netcraft hasn't tested the GSB block status for the takedown.  | 
| Netcraft.Takedown.gsb_first_blocked | Unknown | An array of objects containing the first time that the URL was seen blocked in Google Safe Browsing \(GSB\) by Netcraft. Will be an empty array if the URL was not seen blocked by GSB on any platform.  | 
| Netcraft.Takedown.managed | Boolean | Indicates whether the takedown is being performed under the managed service. | 
| Netcraft.Takedown.date_escalated | Date | The date and time that the takedown entered the managed state, in UTC format. | 
| Netcraft.Takedown.logged_credential_injections | String | An array of objects containing the type and value of each marked account injection associated with the takedown. | 
| Netcraft.Takedown.whois_data | String | The WHOIS data for the takedown. | 

#### Command example
```!netcraft-takedown-list attack_types="coronavirus" date_from="last week" date_to="yesterday" escalated="No" limit="3"```
#### Context Example
```json
{
    "Netcraft": {
        "Takedown": [
            {
                "attack_type": "survey_scam",
                "attack_url": "https://www.example.com",
                "authgiven": "0",
                "authorization_source": "",
                "certificate": {
                    "spki_sha1": "a1a15014c6b818bad729ee738a63e2ea9518a1a1",
                    "spki_sha256": "a1a12eaa37f2f3eb1046a195d73a1a112015967afa18948c431514f20671a1a1",
                },
                "certificate_revoked": "Not revoked",
                "country_code": "us",
                "customer_label": "",
                "customer_tag": "",
                "date_authed": "",
                "date_escalated": "",
                "date_first_actioned": "",
                "date_submitted": "2023-09-19 19:05:21 UTC",
                "deceptive_domain_score": "0.00",
                "domain": "dynamicelevate.com",
                "domain_attack": "yes",
                "domain_risk_rating": "1",
                "escalated": "0",
                "escalation_source": "",
                "evidence_url": "https://incident.netcraft.com/85e57bf4d933/",
                "false_positive": false,
                "final_outage": "",
                "final_resolved": "",
                "first_contact": "",
                "first_inactive": "",
                "first_outage": "",
                "first_resolved": "",
                "fwd_owner": "[unknown]",
                "group_id": "45535862",
                "gsb_block_status": [],
                "gsb_first_blocked": [],
                "has_phishing_kit": "0",
                "host": "Cloudflare",
                "hostname": "ganu.dynamicelevate.com",
                "hostname_attack": "no",
                "hostname_ddss_score": "0.00",
                "id": "45535866",
                "ip": "1.1.1.1",
                "is_redirect": "no_redirect",
                "language": "english",
                "last_updated": "2023-09-19 19:27:06 UTC",
                "malware_category": "",
                "malware_family": "",
                "managed": false,
                "phishing_kit_hash": [],
                "region": "paloalto-xsoar-test",
                "registrar": "Internet Domain Service BS Corp.",
                "report_source": "Phishing Feed",
                "reported_url": "http://www.example.com",
                "reporter": "netcraft",
                "restart_date": "",
                "rev_owner": "cloudflare.com",
                "reverse_dns": "",
                "screenshot_url": "https://screenshot.netcraft.com/images/archive/2023-09-19/sce6d3ba3f08df24091b33333771b8c6.png?url=1&title=1&proxy=1",
                "site_risk_rating": "1",
                "status": "Verified",
                "status_change_uptime": "",
                "stop_monitoring_date": "",
                "tags": [],
                "target_brand": "Cortex XSOAR",
                "targeted_url": "",
                "whois_server": "whois.internet.bs"
            },
            {
                "attack_type": "fake_shop",
                "attack_url": "https://www.example.com/",
                "authgiven": "0",
                "authorization_source": "",
                "certificate": {
                    "spki_sha1": "a1a15014c6b818bad729ee738a63e2ea9518a1a1",
                    "spki_sha256": "a1a12eaa37f2f3eb1046a195d73a1a112015967afa18948c431514f20671a1a1",
                },
                "certificate_revoked": "Not revoked",
                "country_code": "ca",
                "customer_label": "",
                "customer_tag": "",
                "date_authed": "",
                "date_escalated": "",
                "date_first_actioned": "",
                "date_submitted": "2023-09-19 04:34:18 UTC",
                "deceptive_domain_score": "0.00",
                "domain": "sawbladeonsale.com",
                "domain_attack": "yes",
                "domain_risk_rating": "10",
                "escalated": "0",
                "escalation_source": "",
                "evidence_url": "https://incident.netcraft.com/b440f677254f/",
                "false_positive": false,
                "final_outage": "",
                "final_resolved": "",
                "first_contact": "",
                "first_inactive": "2023-09-19 12:18:20 UTC",
                "first_outage": "",
                "first_resolved": "",
                "fwd_owner": "[unknown]",
                "group_id": "45510294",
                "gsb_block_status": [],
                "gsb_first_blocked": [],
                "has_phishing_kit": "0",
                "host": "net-minders.com",
                "hostname": "www.sawbladeonsale.com",
                "hostname_attack": "yes",
                "hostname_ddss_score": "0.00",
                "id": "45510294",
                "ip": "1.1.1.1",
                "is_redirect": "no_redirect",
                "language": "english",
                "last_updated": "2023-09-19 12:50:53 UTC",
                "malware_category": "",
                "malware_family": "",
                "managed": false,
                "phishing_kit_hash": [],
                "region": "paloalto-xsoar-test",
                "registrar": "Gname.com Pte. Ltd.",
                "report_source": "Phishing Feed",
                "reported_url": "https://www.example.com/",
                "reporter": "netcraft",
                "restart_date": "",
                "rev_owner": "net-minders.com",
                "reverse_dns": "",
                "screenshot_url": "https://screenshot.netcraft.com/images/archive/2023-09-19/sc58c54455971009699acdb235e4b8bd.png?url=1&title=1&proxy=1",
                "site_risk_rating": "10",
                "status": "Verified",
                "status_change_uptime": "",
                "stop_monitoring_date": "",
                "tags": [
                    "generic-fake-shop"
                ],
                "target_brand": "Cortex XSOAR",
                "targeted_url": "",
                "whois_server": "whois.gname.com"
            },
            {
                "attack_type": "fake_shop",
                "attack_url": "http://www.example.com/",
                "authgiven": "0",
                "authorization_source": "",
                "certificate": {
                    "spki_sha1": "a1a15014c6b818bad729ee738a63e2ea9518a1a1",
                    "spki_sha256": "a1a12eaa37f2f3eb1046a195d73a1a112015967afa18948c431514f20671a1a1",
                },
                "certificate_revoked": "Not revoked",
                "country_code": "za",
                "customer_label": "",
                "customer_tag": "",
                "date_authed": "",
                "date_escalated": "",
                "date_first_actioned": "",
                "date_submitted": "2023-09-19 00:36:25 UTC",
                "deceptive_domain_score": "0.00",
                "domain": "kitchesell.com",
                "domain_attack": "yes",
                "domain_risk_rating": "6",
                "escalated": "0",
                "escalation_source": "",
                "evidence_url": "https://incident.netcraft.com/6d7067101545/",
                "false_positive": false,
                "final_outage": "",
                "final_resolved": "",
                "first_contact": "",
                "first_inactive": "",
                "first_outage": "",
                "first_resolved": "",
                "fwd_owner": "cloudflare.com",
                "group_id": "45502344",
                "gsb_block_status": [],
                "gsb_first_blocked": [],
                "has_phishing_kit": "0",
                "host": "Fibergrid Group",
                "hostname": "www.kitchesell.com",
                "hostname_attack": "yes",
                "hostname_ddss_score": "0.00",
                "id": "45502434",
                "ip": "1.1.1.1",
                "is_redirect": "redirect",
                "language": "english",
                "last_updated": "2023-09-19 00:52:01 UTC",
                "malware_category": "",
                "malware_family": "",
                "managed": false,
                "phishing_kit_hash": [],
                "region": "paloalto-xsoar-test",
                "registrar": "Name.com, Inc.",
                "report_source": "Phishing Feed",
                "reported_url": "http://www.example.com/",
                "reporter": "netcraft",
                "restart_date": "",
                "rev_owner": "fibergrid.net",
                "reverse_dns": "",
                "screenshot_url": "https://screenshot.netcraft.com/images/archive/2023-09-19/sbf28d4700b79019c802dac611e9514c.png?url=1&title=1&proxy=1",
                "site_risk_rating": "6",
                "status": "Verified",
                "status_change_uptime": "",
                "stop_monitoring_date": "",
                "tags": [
                    "fake-shop-logo"
                ],
                "target_brand": "Cortex XSOAR",
                "targeted_url": "",
                "whois_server": "whois.name.com"
            }
        ]
    }
}
```

#### Human Readable Output

>### Netcraft Takedowns
>|ID|Auth|Brand|Attack Type|Status|Attack URL|Date Reported|Last Updated|Date Authorized|Date Escalated|First Inactive (Monitoring)|First Resolved|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 45535866 | false | Cortex XSOAR | survey_scam | Verified | https:<span>//</span>ganu.dynamicelevate.com/ze/xufawa/namu/index.php?rpclk=8wocgxnwZlVgWqCl4amyElWSdU%2B8SEBm6%2F1vWOh6CEpdwEcFOH6aEWZY8JIqG1yHriIwkvzBnonP07noIGpSFWVojTWPE%2FqBGCYHt2%2FxNJG7sMIb73v2Ba1AdgiFoBWGKZamryDq2xk8JtxfVtgUclt4PWFF3I1CWFqXAH%2FvbFg%2F1Mv%2F0EOWJS6dUJy2IWbtCJvNnuBcJWYF0bEosXgsnv5KmRQDEVAhJjIp4eyvMJr8yPmJWCYMKCH0QJS8kqmnp5AWegynT78OnZyPx1Gf7LS4wbWQ5lB3V3CYpBjgDXmH8UgS69M3RU1HXvQxMXTeHobGqoqBL1odDt5026Cvg014jKzORjPbPRX5O46z6siX%2B0%2BNqGkmwJj4NOmAp%2B%2Bcr07NFz2PRkTnzxhUOULhDux6dICLkRn0Yx30fsQWOznrGGF27ipnKVFY2Ipaa76vpNWzhrklt%2FZhTlWWsS0SsBR0yEKyQDyk6qVv%2BK8DMRA4lZf1XZfY2hNGLJ6nwMVApzIt5iMdgKL78roTKNR3lVSZ6w8rtIEB2NtiiOxFF9ikytLlIHQXSevd6fHvSuXeb3n6Omdyj3ONKIZY%2B3%2FjiIXuPplxffD9kv5dGR2QgXK93cMbhWi8uajt5pHQH3BEQcBAJO%2BcHmh6auGjLuzGCbaWVkueArhTPnw83%2FoI%2BVGEPa7VdwsBJiV55QBTO8%2BWoazxW70VZ4fpKeTA8xB2f3Tg9GQ%2FpdwwdT24f%2BUbnYPgzkIqSqU%2FZhf%2FFQCi2JP0wwE7ffh7T%2Bz0il%2Fkb4EaYEVIpAUdcG5q%2BxJt%2BrIn8Xrw83Hh%2Bci6gSbGwU1A1TWSresXSX01EJ8%2F3Guf2C%2FT0DM0CwpbAFJxz22bILkDOoFx6ICxFKNaKTZcjtKGjrgQfoxhWr%2FCH5%2BU%2B4FhBp6iz8tw6gSR5kxQZYiYTZtoJjJPsHIX5wGV2zYM%2B7LXp7f4EP0Wy%2FS1Pm1ryAiPaIbUUbbh4mWFzwFroDjNt43lD6VK3G3RbpWHI0Fo5k%2F6wlFhev%2Blq6qCeS02P3arwPrF0Qcv%2FGWeFI5Bq2H7LUs0ToCHYUa%2FJo4BA%2Bji0v6WlRN1DS7%2F7k%2F1Zw4ykzxgZN8f712rnKsKLCKIp0AidTPWuVm3DaSk5LRKnHpvMIXYFSus99BSuBqcMGl5J%2BAP9qwXVbtsvPxkr4E%2BhmWRPzaT7At5%2BZen%2B%2BE4f6TWqrDimFbMJoYyiqzxloGQYU%2Fm0FMZhRyicVPXHDg1Y2qWEk8Qh0WtjyQq2jBWuZTDlMixP4kpTU4EaXSXgJsWf5jfIQmZLICAuNWRU3ZJTXB0Q%2FoFOE0dWjKpZ%2BBqIj6ei6hivIUU8F0NblPo98zbIgl%2FKjcBVgq9s3thc%2B257QwNf3D9zKyU0%2FoIHDMAcCe4qIqfMZ6mQ2dTVNbfMe0GvjUHfX9qi2j0RCDLO9WZxCAsDM6eZF7c7TlBrn4DNmugpwRAkdJeUim52UcXOQyVpmtmv0UzOGttUS1SKVOBfhSUZaA5QZbWUHeKtqJnxlRepFBIr2NLtv3IUs1gV4aYpE9lrlbCLuunKuNxgfRhsJbxmt7yxfPnYJ0THmqM%2Fzi2ucbal91xCZN3pV35J8KV8BNt3dXtS38UazqPtnAIfI6W77OBItaQEQ5C5FtpWw2gPGqjEK2%2FscgRBTHWElB3FGGdyiYEE1ymLRJudGux4vdsbndaP6NRKgraYt83HkIWxukpvayoLGtzyAgGNS7mAuoPeILzGwSpz3Vu7lWjBHRbWUY5%2BdRVBsXUcWuj7T6sqGf8pQX7j80rPZ%2ByDHO5agY7ukNOKe7%2BcM1VHhZOEpDDnj5MBp8O%2BpQqxX7tgszsMG9s9YpmmIaztnf6hYo6dM4G3bKae%2FVgNWRPZQb692UHqLGoZqinMP3MqFDfxxpPFVJlsb2yFvqeQUhYOVZlqIASA9sN8nAyLXv%2BhymUTzdyx0lvgqk56M9%2FZGlOkoFibOsAfRp1at4nptRLJ3QZVMg7hI3%2BQs0HjuVRvgF%2Fu5%2BZ5KvytxfanXfdqaOstxSrq7Q1BPW1MRIZ0xIyal%2FYsdEKxMqCr20GOOaha4T1bsj9R7d6lUBJ1HNEXC3BFgPSz0x3%2BUBGBtI7tD%2F6Te5dJ2brm0NmOh%2Fpv1%2Bd%2Bg0RyJoYruyHA2LsMTYP54l2vC30ygGnl7o%2BRLwBMZCkFvKgdD1lP%2BYIqcdUE5xNe4YyJN7nAwPkfq5nro1WlOybHWpwnHmRBu9RSE2hEV4IfyQPLCuBAQbrxdW4sOvnqgxOA7fGqqurj%2BDdUDgcmtzY8tewKpBCBPUV%2BEKGlRTHlOSlilHWu3VPqJVkggviJ2QF8XDa5NISy1nJ6t%2F3D4bfC0y72r%2F%2FsK%2BdRqFvL%2FBcavzhqU1H8jVTvIDz%2Bq9ju2l6%2FVTl2zR1nPg2P2kOWr3u2EDnrwbymtGMEXf39JbldX8UII4JTKNfVuJIYzK8VWqDGaQbmT2vN3Cfh17DD%2B%2BNF%2FsMNl2KL1pgF%2BQtb%2FRGy4Dfs0vWy%2B0Q5HlTwbRVO1COe6QNvOvYtrKY7dlED1le6dn8joEZmptJMx%2BhRd08JARuxfsgOK917RlcAwAYxJh8qgRoJ9ZdtJ9BscTcAhTkclWUD%2Flr75io%3A%3Adeb2860c8e29b6c68bd296fe1cd42554&p=yyKy6P3Jm1mmQPoGQYvkuk6Ug3gYBg%3D%3D%3A%3Afb77cfae6566e293f1c681f8c6c33b5d&oho=t4.radiantascendhq.com&ptf=b932a9b8ce22aed66461b2591cbbb5ed | 2023-09-19 19:05:21 UTC | 2023-09-19 19:27:06 UTC | N/A | N/A | N/A | N/A |
>| 45510294 | false | Cortex XSOAR | fake_shop | Verified | https:<span>//</span>www.example.com/ | 2023-09-19 04:34:18 UTC | 2023-09-19 12:50:53 UTC | N/A | N/A | 2023-09-19 12:18:20 UTC | N/A |
>| 45502434 | false | Cortex XSOAR | fake_shop | Verified | http:<span>//</span>www.example2.com/ | 2023-09-19 00:36:25 UTC | 2023-09-19 00:52:01 UTC | N/A | N/A | N/A | N/A |


### netcraft-takedown-update

***
Update one or more fields related to a takedown.

#### Base Command

`netcraft-takedown-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| takedown_id | The ID of the takedown to update. | Required | 
| customer_label | A free-text field which can be used to keep track of particular attacks. | Optional | 
| description | The reason for the report, such as a description of the attack. | Optional | 
| brand | The brand to move the takedown under. | Optional | 
| suspected_fraud_domain | Should be set to true if it is believed that the domain name has been registered as part of the fraud. This will ensure that the registrar is contacted to seek suspension of the domain name. Possible values are: true, false. | Optional | 
| suspected_fraud_hostname | Should be set to true if it is believed that the hostname has been created as part of the fraud. This will ensure that the certificate issuer is contacted to seek revocation of any certificates for the hostname. Possible values are: true, false. | Optional | 
| add_tags | A comma-separated list of tags to add to the takedown group. | Optional | 
| remove_tags | A comma-separated list of tags to remove from the takedown group.<br/>Removing a tag from a group which already doesn't have that tag is permitted.<br/>However, including the same tag in both "add_tags" and "remove_tags" will return an error.<br/>. | Optional | 
| region | The name of the region to move the takedown under. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!netcraft-takedown-update add_tags="smishing,fake-shop-logo" remove_tags="coronavirus" takedown_id=45492113```
#### Human Readable Output

>### Takedown successfully updated.
>|Takedown ID|
>|---|
>| 45492113 |


### netcraft-takedown-escalate

***
Escalate an automated takedown to a managed takedown.
Only attacks that are in an authorized state can be escalated.
The minimum access level required to escalate is "Escalator".
**Note that escalating a takedown may cost one or more Netcraft managed credits.**


#### Base Command

`netcraft-takedown-escalate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| takedown_id | The ID of the automated takedown to escalate. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!netcraft-takedown-escalate takedown_id=45470682```
#### Human Readable Output

>### Takedown successfully escalated.
>|Takedown ID|
>|---|
>| 45470682 |


### netcraft-takedown-note-create

***
Add a new note to an existing takedown.

#### Base Command

`netcraft-takedown-note-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| takedown_id | The ID of the takedown to add the note to. | Required | 
| note_text | The contents of the new note. | Required | 
| notify | When set to true, the note will also be raised to Netcraft's operations team for further investigation.<br/>This should be set if you require a Netcraft staff member to read and respond to your note.<br/>. Possible values are: true, false. Default is true. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netcraft.TakedownNote.note_id | Number | The ID of the note added to the takedown. | 

#### Command example
```!netcraft-takedown-note-create note_text="important not" notify="false" takedown_id=45470682```
#### Context Example
```json
{
    "Netcraft": {
        "TakedownNote": {
            "note_id": 1394724283
        }
    }
}
```

#### Human Readable Output

>### Note successfully added to takedown.
>|Note ID|Takedown ID|
>|---|---|
>| 1394724283 | 45470682 |


### netcraft-takedown-note-list

***
Retrieve details of notes that have been added to takedowns.

#### Base Command

`netcraft-takedown-note-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| takedown_id | Filter to notes that have been added to the takedown with the given ID. | Optional | 
| author_mail | Filter to notes that were created by the user with the given username.<br/>Notes that were created by Netcraft can be found by filtering to "Netcraft".<br/>. | Optional | 
| all_results | Whether to retrieve all notes that match the filters. If set to false, only 50 will be returned. Possible values are: false, true. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netcraft.TakedownNote.note_id | Number | The unique identifier for the note. | 
| Netcraft.TakedownNote.takedown_id | String | The ID of the takedown that the note belongs to. | 
| Netcraft.TakedownNote.group_id | String | The ID of the takedown group that this note belongs to. This will only be set if the note has been attached to all takedowns in the group, otherwise this field will have a value of "0".  | 
| Netcraft.TakedownNote.time | Date | The date and time that the note was created. | 
| Netcraft.TakedownNote.author | String | The username of the account that created the note. Notes added by Netcraft will show as "Netcraft". | 
| Netcraft.TakedownNote.note | String | The contents of the note. | 

#### Command example
```!netcraft-takedown-note-list all_results="true" takedown_id=45470682```
#### Context Example
```json
{
    "Netcraft": {
        "TakedownNote": [
            {
                "author": "reporter@socteam.com",
                "group_id": 0,
                "note": "Takedown escalated from automated to managed",
                "note_id": 1394719264,
                "takedown_id": 45470682,
                "time": "2023-09-21 08:08:52"
            },
            {
                "author": "reporter@socteam.com",
                "group_id": 45470682,
                "note": "important not",
                "note_id": 1394724283,
                "takedown_id": 45470682,
                "time": "2023-09-21 08:23:56"
            }
        ]
    }
}
```

#### Human Readable Output

>### Takedown Notes
>|Note ID|Takedown ID|Group ID|Time|Author|Note|
>|---|---|---|---|---|---|
>| 1394719264 | 45470682 | 0 | 2023-09-21 08:08:52 | reporter@socteam.com | Takedown escalated from automated to managed |
>| 1394724283 | 45470682 | 45470682 | 2023-09-21 08:23:56 | reporter@socteam.com | important not |


### netcraft-attack-type-list

***
Get information on the attack types that are available under a given region.

#### Base Command

`netcraft-attack-type-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| automated | Filter to attack types where automated takedowns are available. Possible values are: true, false. | Optional | 
| auto_escalation | Filter to attack types which you have chosen to escalate to managed takedowns after the configured escalation period. Possible values are: true, false. | Optional | 
| auto_authorize | Filter to attack types which you have chosen to automatically authorize takedowns against. Possible values are: true, false. | Optional | 
| region | The name of the region to create a takedown under.<br/>If not provided, the region specified in the instance configuration will be used.<br/>. | Optional | 
| all_results | Whether to retrieve all attack types that match the filters. If set to false, only 50 will be returned. Possible values are: false, true. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netcraft.AttackType.name | String | The unique string identifier for the attack type. | 
| Netcraft.AttackType.display_name | String | The human-readable name of the attack type. | 
| Netcraft.AttackType.base_type | String | The unique string identifier for the top-level parent type of this attack type. | 
| Netcraft.AttackType.description | String | A short description of the attack type. | 
| Netcraft.AttackType.automated | Boolean | Indicates whether or not automated takedowns are available for this attack type. | 
| Netcraft.AttackType.auto_escalation | Boolean | Indicates whether or not you have chosen to automatically escalate takedowns under this type to managed takedowns after the configured escalation period. | 
| Netcraft.AttackType.auto_authorize | Boolean | Indicates whether or not you have chosen to automatically authorize takedowns under this type. | 

#### Command example
```!netcraft-attack-type-list all_results="false" automated=true```
#### Context Example
```json
{
    "Netcraft": {
        "AttackType": [
            {
                "auto_authorize": true,
                "auto_escalation": false,
                "automated": true,
                "base_type": "url",
                "description": "The URL for a webpage which impersonates your company in an attempt to trick users into submitting their login details. Usually the URL is linked to in an email sent to your users.",
                "display_name": "Phishing URL",
                "name": "phishing_url"
            },
            {
                "auto_authorize": true,
                "auto_escalation": false,
                "automated": true,
                "base_type": "url",
                "description": "The URL of a webpage which receives user's details from a HTML attachment sent to users via email.",
                "display_name": "Phishing Dropsite",
                "name": "dropsite"
            },
            {
                "auto_authorize": true,
                "auto_escalation": false,
                "automated": true,
                "base_type": "url",
                "description": "The URL for a fraudulent mobile application, found on a mobile application store, that is targeting your customers.",
                "display_name": "Fake Mobile App",
                "name": "fake_mobile_app"
            },
            {
                "auto_authorize": true,
                "auto_escalation": false,
                "automated": true,
                "base_type": "url",
                "description": "A URL from which a phishing kit archive can be downloaded. A phishing kit is an archive containing all the files necessary for a phishing attack, it is usually uploaded and extracted on a server by the phisher to launch an attack.",
                "display_name": "Phishkit Archive",
                "name": "phishkit_archive"
            },
            {
                "auto_authorize": true,
                "auto_escalation": false,
                "automated": true,
                "base_type": "url",
                "description": "",
                "display_name": "Malware Infrastructure URL",
                "name": "malware_c2"
            },
            {
                "auto_authorize": true,
                "auto_escalation": false,
                "automated": true,
                "base_type": "url",
                "description": "A URL used as the Command and Control Centre (C2) for a malware binary.",
                "display_name": "Malware Command and Control Centre",
                "name": "malware_c2_c2"
            },
            {
                "auto_authorize": true,
                "auto_escalation": false,
                "automated": true,
                "base_type": "url",
                "description": "A URL used to distribute a malicious binary.",
                "display_name": "Malware Distribution URL",
                "name": "malware_c2_distribution"
            },
            {
                "auto_authorize": true,
                "auto_escalation": false,
                "automated": true,
                "base_type": "url",
                "description": "A URL used to collect payments from victims of malware attacks, specifically ransomware.",
                "display_name": "Malware Payment URL",
                "name": "malware_c2_payment"
            },
            {
                "auto_authorize": true,
                "auto_escalation": false,
                "automated": true,
                "base_type": "url",
                "description": "A URL for a Facebook page which is maliciously infringing on your trademark.",
                "display_name": "Facebook Brand Infringement",
                "name": "facebook_brand_infringement"
            },
            {
                "auto_authorize": true,
                "auto_escalation": false,
                "automated": true,
                "base_type": "url",
                "description": "A URL for an Instagram profile which is maliciously infringing on your trademark.",
                "display_name": "Instagram Brand Infringement",
                "name": "instagram_brand_infringement"
            },
            {
                "auto_authorize": true,
                "auto_escalation": false,
                "automated": true,
                "base_type": "url",
                "description": "A URL to a LinkedIn company listing which is maliciously infringing on your trademark.",
                "display_name": "LinkedIn Brand Infringement",
                "name": "linkedin_brand_infringement"
            },
            {
                "auto_authorize": true,
                "auto_escalation": false,
                "automated": true,
                "base_type": "url",
                "description": "A URL to a Twitter account which is maliciously infringing on your trademark.",
                "display_name": "Twitter Brand Infringement",
                "name": "twitter_brand_infringement"
            },
            {
                "auto_authorize": true,
                "auto_escalation": false,
                "automated": true,
                "base_type": "url",
                "description": "A URL for a YouTube channel or video which is maliciously infringing on your trademark.",
                "display_name": "YouTube Brand Infringement",
                "name": "youtube"
            },
            {
                "auto_authorize": true,
                "auto_escalation": false,
                "automated": true,
                "base_type": "url",
                "description": "A URL to a Skype profile which is maliciously infringing on your trademark.",
                "display_name": "Skype Brand Infringement",
                "name": "skype_brand_infringement"
            },
            {
                "auto_authorize": true,
                "auto_escalation": false,
                "automated": true,
                "base_type": "url",
                "description": "A URL to a Telegram user or channel which is maliciously infringing on your trademark.",
                "display_name": "Telegram Brand Infringement",
                "name": "telegram_brand_infringement"
            },
            {
                "auto_authorize": true,
                "auto_escalation": false,
                "automated": true,
                "base_type": "url",
                "description": "A URL to a Weibo page which is maliciously infringing on your trademark.",
                "display_name": "Weibo Brand Infringement",
                "name": "weibo_brand_infringement"
            },
            {
                "auto_authorize": true,
                "auto_escalation": false,
                "automated": true,
                "base_type": "url",
                "description": "A URL to a Pinterest profile or pin which is maliciously infringing on your trademark.",
                "display_name": "Pinterest Brand Infringement",
                "name": "pinterest_brand_infringement"
            },
            {
                "auto_authorize": true,
                "auto_escalation": false,
                "automated": true,
                "base_type": "url",
                "description": "A URL for a TikTok account which is maliciously infringing on your trademark.",
                "display_name": "TikTok Brand Infringement",
                "name": "tiktok_brand_infringement"
            },
            {
                "auto_authorize": true,
                "auto_escalation": false,
                "automated": true,
                "base_type": "url",
                "description": "A URL for a WhatsApp phone number which is maliciously infringing on your trademark.",
                "display_name": "WhatsApp Brand Infringement",
                "name": "whatsapp_brand_infringement"
            },
            {
                "auto_authorize": true,
                "auto_escalation": false,
                "automated": true,
                "base_type": "url",
                "description": "A Google Adwords advert which redirects to a phishing webpage.",
                "display_name": "Google Adwords",
                "name": "adwords"
            },
            {
                "auto_authorize": true,
                "auto_escalation": false,
                "automated": true,
                "base_type": "url",
                "description": "A Bing advert which redirects to a phishing webpage.",
                "display_name": "Bing Ad",
                "name": "bing_ad"
            },
            {
                "auto_authorize": true,
                "auto_escalation": false,
                "automated": true,
                "base_type": "malware_c2_ip",
                "description": "An IP address and port being used to conduct a malware attack.",
                "display_name": "Malware C2 IP",
                "name": "malware_c2_ip"
            },
            {
                "auto_authorize": true,
                "auto_escalation": false,
                "automated": true,
                "base_type": "malware_c2_ip",
                "description": "A email server IP identified during the analysis of a malware binary. Possibly used for exfiltrating data.",
                "display_name": "Malware SMTP C2",
                "name": "malware_c2_mailserver"
            },
            {
                "auto_authorize": true,
                "auto_escalation": false,
                "automated": true,
                "base_type": "email",
                "description": "An email address involved in carrying out an Advance Fee Fraud scam. Advance fee fraud is when fraudsters target victims to make advance or upfront payments for goods, services and/or financial gains that do not materialise.",
                "display_name": "Advance Fee Fraud",
                "name": "advance_fee_fraud"
            },
            {
                "auto_authorize": true,
                "auto_escalation": false,
                "automated": true,
                "base_type": "server",
                "description": "The IP address of a email server which is sending phishing emails that contain a link to a phishing website.",
                "display_name": "Phishing URL Mail Server",
                "name": "sends_phishing_url"
            },
            {
                "auto_authorize": true,
                "auto_escalation": false,
                "automated": true,
                "base_type": "server",
                "description": "The IP address of a email server which is sending emails that contain a link to a website which is serving malware.",
                "display_name": "Malware URL Mail Server",
                "name": "sends_malware_url"
            },
            {
                "auto_authorize": true,
                "auto_escalation": false,
                "automated": true,
                "base_type": "server",
                "description": "The IP address of a email server which is sending emails that contain a malicious attachment which infects a victim's computer with malware.",
                "display_name": "Malware Attachment Mail Server",
                "name": "sends_malware_attachments"
            },
            {
                "auto_authorize": true,
                "auto_escalation": false,
                "automated": true,
                "base_type": "server",
                "description": "The IP address of a email server which is sending Advance Fee Fraud emails. Advance fee fraud is when fraudsters target victims to make advance or upfront payments for goods, services and/or financial gains that do not materialise.",
                "display_name": "Advance Fee Fraud Mail Server",
                "name": "sends_advance_fee_fraud"
            }
        ]
    }
}
```

#### Human Readable Output

>### Netcraft Attack Types
>|Name|Display Name|Base Type|Description|Automated|Auto Escalation|Auto Authorize|
>|---|---|---|---|---|---|---|
>| phishing_url | Phishing URL | url | The URL for a webpage which impersonates your company in an attempt to trick users into submitting their login details. Usually the URL is linked to in an email sent to your users. | true | false | true |
>| dropsite | Phishing Dropsite | url | The URL of a webpage which receives user's details from a HTML attachment sent to users via email. | true | false | true |
>| fake_mobile_app | Fake Mobile App | url | The URL for a fraudulent mobile application, found on a mobile application store, that is targeting your customers. | true | false | true |
>| phishkit_archive | Phishkit Archive | url | A URL from which a phishing kit archive can be downloaded. A phishing kit is an archive containing all the files necessary for a phishing attack, it is usually uploaded and extracted on a server by the phisher to launch an attack. | true | false | true |
>| malware_c2 | Malware Infrastructure URL | url |  | true | false | true |
>| malware_c2_c2 | Malware Command and Control Centre | url | A URL used as the Command and Control Centre (C2) for a malware binary. | true | false | true |
>| malware_c2_distribution | Malware Distribution URL | url | A URL used to distribute a malicious binary. | true | false | true |
>| malware_c2_payment | Malware Payment URL | url | A URL used to collect payments from victims of malware attacks, specifically ransomware. | true | false | true |
>| facebook_brand_infringement | Facebook Brand Infringement | url | A URL for a Facebook page which is maliciously infringing on your trademark. | true | false | true |
>| instagram_brand_infringement | Instagram Brand Infringement | url | A URL for an Instagram profile which is maliciously infringing on your trademark. | true | false | true |
>| linkedin_brand_infringement | LinkedIn Brand Infringement | url | A URL to a LinkedIn company listing which is maliciously infringing on your trademark. | true | false | true |
>| twitter_brand_infringement | Twitter Brand Infringement | url | A URL to a Twitter account which is maliciously infringing on your trademark. | true | false | true |
>| youtube | YouTube Brand Infringement | url | A URL for a YouTube channel or video which is maliciously infringing on your trademark. | true | false | true |
>| skype_brand_infringement | Skype Brand Infringement | url | A URL to a Skype profile which is maliciously infringing on your trademark. | true | false | true |
>| telegram_brand_infringement | Telegram Brand Infringement | url | A URL to a Telegram user or channel which is maliciously infringing on your trademark. | true | false | true |
>| weibo_brand_infringement | Weibo Brand Infringement | url | A URL to a Weibo page which is maliciously infringing on your trademark. | true | false | true |
>| pinterest_brand_infringement | Pinterest Brand Infringement | url | A URL to a Pinterest profile or pin which is maliciously infringing on your trademark. | true | false | true |
>| tiktok_brand_infringement | TikTok Brand Infringement | url | A URL for a TikTok account which is maliciously infringing on your trademark. | true | false | true |
>| whatsapp_brand_infringement | WhatsApp Brand Infringement | url | A URL for a WhatsApp phone number which is maliciously infringing on your trademark. | true | false | true |
>| adwords | Google Adwords | url | A Google Adwords advert which redirects to a phishing webpage. | true | false | true |
>| bing_ad | Bing Ad | url | A Bing advert which redirects to a phishing webpage. | true | false | true |
>| malware_c2_ip | Malware C2 IP | malware_c2_ip | An IP address and port being used to conduct a malware attack. | true | false | true |
>| malware_c2_mailserver | Malware SMTP C2 | malware_c2_ip | An email server IP identified during the analysis of a malware binary. Possibly used for exfiltrating data. | true | false | true |
>| advance_fee_fraud | Advance Fee Fraud | email | An email address involved in carrying out an Advance Fee Fraud scam. Advance fee fraud is when fraudsters target victims to make advance or upfront payments for goods, services and/or financial gains that do not materialise. | true | false | true |
>| sends_phishing_url | Phishing URL Mail Server | server | The IP address of an email server which is sending phishing emails that contain a link to a phishing website. | true | false | true |
>| sends_malware_url | Malware URL Mail Server | server | The IP address of an email server which is sending emails that contain a link to a website which is serving malware. | true | false | true |
>| sends_malware_attachments | Malware Attachment Mail Server | server | The IP address of an email server which is sending emails that contain a malicious attachment which infects a victim's computer with malware. | true | false | true |
>| sends_advance_fee_fraud | Advance Fee Fraud Mail Server | server | The IP address of an email server which is sending Advance Fee Fraud emails. Advance fee fraud is when fraudsters target victims to make advance or upfront payments for goods, services and/or financial gains that do not materialise. | true | false | true |


### netcraft-submission-list

***
Get basic information about a submissions.

#### Base Command

`netcraft-submission-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| submission_uuid | Get a specific submission. If provided, all the others arguments will be ignored and an extensive report will be returned. | Optional | 
| date_start | Filter submissions by start date. Use UTC format or plain English for example "5 days ago". | Optional | 
| date_end | Filter submissions by end date. Use UTC format or plain English for example "5 days ago". | Optional | 
| source_name | Filter the submissions by source. | Optional | 
| state | The state of the submissions. Note, in the case of a misclassification, a submission may be assigned a higher-severity state several days after its initial classification. Possible values are: Processing, No Threats, Suspicious, Malicious. | Optional | 
| submission_reason | Filter the submissions by words contained in the submission reason. | Optional | 
| submitter_email | Filter the submissions by submitter email. | Optional | 
| limit | The number of submissions to return. Default is 50. | Optional | 
| page_size | The number of submissions to return per page. The maximum is 1000. | Optional | 
| next_token | The UUID denoting the first submission to return, as given by the response of the previous run of this command under the context key "Netcraft.SubmissionNextToken". | Optional | 
| polling | Use Cortex XSOAR built-in polling to wait for the report to be processed. Default is false. | Optional | 
| interval_in_seconds | Indicates the time in seconds until the polling sequence times out. Default is 30. | Optional | 
| timeout | Indicates how long to wait between command executions (in seconds). Default is 600. | Optional | 
| hide_polling_output | whether to hide the output of the polling on each run, should always be "true". Default is True. | Optional | 
| ignore_404 | Whether to ignore 404 responses from the API. Used when creating a submission as Netcraft may not have updated the system yet. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netcraft.Submission.date | Number | The UNIX timestamp of the submission. | 
| Netcraft.Submission.source_name | String | The name of the source of this submission. | 
| Netcraft.Submission.state | String | The state of the submission. One of "processing", "no threats", "suspicious" or "malicious". Note, in the case of a misclassification, a submission may be assigned a higher-severity state several days after its initial classification. | 
| Netcraft.Submission.submitter_email | String | The email address of the reporter of the submission. | 
| Netcraft.Submission.uuid | String | The unique identifier of the submission. | 
| Netcraft.Submission.submitter_uuid | String | The unique identifier of the submitter. This key appears only if the "submission_uuid" argument is \*not\* provided. | 
| Netcraft.Submission.classification_log.date | Number | A UNIX timestamp of when this state change occurred. This key appears only if the "submission_uuid" argument is provided. | 
| Netcraft.Submission.classification_log.from_state | String | The state the submission moved out of. This key appears only if the "submission_uuid" argument is provided. | 
| Netcraft.Submission.classification_log.to_state | String | The state the submission moved into. This key appears only if the "submission_uuid" argument is provided. | 
| Netcraft.Submission.files | String | An API URL to get details about the files associated with this submission. This key appears only if the "submission_uuid" argument is provided. | 
| Netcraft.Submission.has_cryptocurrency_addresses | Boolean | Whether the submission contains cryptocurrency addresses. This key appears only if the "submission_uuid" argument is provided. | 
| Netcraft.Submission.has_files | Boolean | Whether the submission contains files. This key appears only if the "submission_uuid" argument is provided. | 
| Netcraft.Submission.has_issues | Boolean | Whether the submission contains issues. This key appears only if the "submission_uuid" argument is provided. | 
| Netcraft.Submission.has_mail | Boolean | Whether the submission has an email. This key appears only if the "submission_uuid" argument is provided. | 
| Netcraft.Submission.has_phone_numbers | Boolean | Whether the submission contains phone numbers. This key appears only if the "submission_uuid" argument is provided. | 
| Netcraft.Submission.has_urls | Boolean | Whether the submission contains URLs. This key appears only if the "submission_uuid" argument is provided. | 
| Netcraft.Submission.is_archived | Boolean | Whether the submission has been archived. This key appears only if the "submission_uuid" argument is provided. | 
| Netcraft.Submission.last_update | Number | A UNIX timestamp of when this submission was last updated. This key appears only if the "submission_uuid" argument is provided. | 
| Netcraft.Submission.mail | String | An API URL to get details about the email associated with this submission. This key appears only if the "submission_uuid" argument is provided. | 
| Netcraft.Submission.mail_state | String | The state of the email in the submission. This key appears only if the "submission_uuid" argument is provided. | 
| Netcraft.Submission.original_source.name | String | The name of the submission source. This key appears only if the "submission_uuid" argument is provided. | 
| Netcraft.Submission.original_source.type | String | The type of submission source. This key appears only if the "submission_uuid" argument is provided. | 
| Netcraft.Submission.pending | Boolean | Whether the submission is still pending. This key appears only if the "submission_uuid" argument is provided. | 
| Netcraft.Submission.reason | String | The optional reason for this submission. This key appears only if the "submission_uuid" argument is provided. | 
| Netcraft.Submission.source.type | String | The type of submission source. This key appears only if the "submission_uuid" argument is provided. | 
| Netcraft.Submission.source.uuid | String | The UUID of the source. This key appears only if the "submission_uuid" argument is provided. | 
| Netcraft.Submission.state_counts.files | Unknown | An object containing the amount of files in each state, where the key is the state and the value is the amount. This key appears only if the "submission_uuid" argument is provided. | 
| Netcraft.Submission.state_counts.urls | Unknown | An object containing the amount of URLs in each state, where the key is the state and the value is the amount. This key appears only if the "submission_uuid" argument is provided. | 
| Netcraft.Submission.tags.name | String | The name of the tag. This key appears only if the "submission_uuid" argument is provided. | 
| Netcraft.Submission.tags.description | String | The tag's description. This key appears only if the "submission_uuid" argument is provided. | 
| Netcraft.Submission.urls | String | An API URL to get details about the URLs associated with this submission. This key appears only if the "submission_uuid" argument is provided. | 
| Netcraft.Submission.warnings.link | String | A link to further information about the warning. This key appears only if the "submission_uuid" argument is provided. | 
| Netcraft.Submission.warnings.warning | String | The warning. This key appears only if the "submission_uuid" argument is provided. | 
| Netcraft.SubmissionNextToken | String | The submission UUID to provide as the "next_token" argument in a subsequent request for pagination. Will be null if the end of the submissions has been reached. This key appears only if the "submission_uuid" argument is \*not\* provided. | 

#### Command example
```!netcraft-submission-list submission_uuid=RUxOzbo2OGfEAaq5G3vsAsdUqDh7wa70```
#### Context Example
```json
{
    "Netcraft": {
        "Submission": {
            "classification_log": [
                {
                    "date": 1695130047,
                    "from_state": "processing",
                    "to_state": "no threats"
                }
            ],
            "date": 1695129915,
            "files": "https://report.netcraft.com/api/v3/submission/RUxOzbo2OGfEAaq5G3vsAsdUqDh7wa70/files",
            "has_cryptocurrency_addresses": false,
            "has_files": true,
            "has_issues": false,
            "has_mail": false,
            "has_phone_numbers": false,
            "has_urls": false,
            "is_archived": false,
            "last_update": 1695130047,
            "mail": "https://report.netcraft.com/api/v3/submission/RUxOzbo2OGfEAaq5G3vsAsdUqDh7wa70/mail",
            "mail_state": "processing",
            "original_source": {
                "name": "report.netcraft.com",
                "type": "web"
            },
            "pending": false,
            "reason": null,
            "source": {
                "type": "email"
            },
            "source_name": "Palo Alto Networks",
            "state": "no threats",
            "state_counts": {
                "files": {
                    "no threats": 1
                },
                "urls": {}
            },
            "submitter_email": "reporter@socteam.com",
            "tags": [],
            "urls": "https://report.netcraft.com/api/v3/submission/RUxOzbo2OGfEAaq5G3vsAsdUqDh7wa70/urls",
            "uuid": "RUxOzbo2OGfEAaq5G3vsAsdUqDh7wa70",
            "warnings": []
        }
    }
}
```

#### Human Readable Output

>### Netcraft Submissions
>|Submission UUID|Submission Date|Submitter Email|State|Source|
>|---|---|---|---|---|
>| RUxOzbo2OGfEAaq5G3vsAsdUqDh7wa70 | 2023-09-19 13:25:15+00:00 | reporter@socteam.com | no threats | Palo Alto Networks |


### netcraft-file-report-submit

***
Report files to Netcraft for analysis.

#### Base Command

`netcraft-file-report-submit`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| reporter_email | The reporter's email address, to which the result of Netcraft's analysis will be sent. | Required | 
| file_content | A base64 encoded string of the file. To report multiple files, upload the files to Cortex XSOAR and provide the file entry IDs in the "entry_id" argument. Max 10 files per submission, with a maximum combined file size of 20MiB. | Optional | 
| file_name | The name of the file. To report multiple files, upload the files to Cortex XSOAR and provide the file entry IDs in the "entry_id" argument.<br/>. | Optional | 
| entry_id | A comma-separated list of Cortex XSOAR file entry IDs to report. Max 10 files per submission, with a maximum combined file size of 20MiB. The arguments "file_content" and "file_name" can be used for reporting a single file. | Optional | 
| reason | The reason the file is considered malicious. Should be less than 1000 characters. | Optional | 
| polling | Use Cortex XSOAR built-in polling to wait for the report to be processed. Possible values are: true, false. Default is true. | Optional | 
| interval_in_seconds | Indicates how long to wait between command executions (in seconds) when the 'polling' argument is true. Minimum value is 10 seconds. Default is 30. | Optional | 
| timeout | Indicates the time in seconds until the polling sequence times out. Default is 600. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netcraft.Submission.date | Number | The UNIX timestamp of the submission. | 
| Netcraft.Submission.source_name | String | The name of the source of this submission. | 
| Netcraft.Submission.state | String | The state of the submission. One of "processing", "no threats", "suspicious" or "malicious". Note, in the case of a misclassification, a submission may be assigned a higher-severity state several days after its initial classification. | 
| Netcraft.Submission.submitter_email | String | The email address of the reporter of the submission. | 
| Netcraft.Submission.uuid | String | The unique identifier of the submission. | 
| Netcraft.Submission.classification_log.date | Number | A UNIX timestamp of when this state change occurred. | 
| Netcraft.Submission.classification_log.from_state | String | The state the submission moved out of. | 
| Netcraft.Submission.classification_log.to_state | String | The state the submission moved into. | 
| Netcraft.Submission.files | String | An API URL to get details about the files associated with this submission. | 
| Netcraft.Submission.has_cryptocurrency_addresses | Boolean | Whether the submission contains cryptocurrency addresses. | 
| Netcraft.Submission.has_files | Boolean | Whether the submission contains files. | 
| Netcraft.Submission.has_issues | Boolean | Whether the submission contains issues. | 
| Netcraft.Submission.has_mail | Boolean | Whether the submission has an email. | 
| Netcraft.Submission.has_phone_numbers | Boolean | Whether the submission contains phone numbers. | 
| Netcraft.Submission.has_urls | Boolean | Whether the submission contains URLs. | 
| Netcraft.Submission.is_archived | Boolean | Whether the submission has been archived. | 
| Netcraft.Submission.last_update | Number | A UNIX timestamp of when this submission was last updated. | 
| Netcraft.Submission.mail | String | An API URL to get details about the email associated with this submission. | 
| Netcraft.Submission.mail_state | String | The state of the email in the submission. | 
| Netcraft.Submission.original_source.name | String | The name of the submission source. | 
| Netcraft.Submission.original_source.type | String | The type of submission source. | 
| Netcraft.Submission.pending | Boolean | Whether the submission is still pending. | 
| Netcraft.Submission.reason | String | The optional reason for this submission. | 
| Netcraft.Submission.source.type | String | The type of submission source. | 
| Netcraft.Submission.source.uuid | String | The UUID of the source. | 
| Netcraft.Submission.state_counts.files | Unknown | An object containing the amount of files in each state, where the key is the state and the value is the amount. | 
| Netcraft.Submission.state_counts.urls | Unknown | An object containing the amount of URLs in each state, where the key is the state and the value is the amount. | 
| Netcraft.Submission.tags.name | String | The name of the tag. | 
| Netcraft.Submission.tags.description | String | The tag's description. | 
| Netcraft.Submission.urls | String | An API URL to get details about the URLs associated with this submission. | 
| Netcraft.Submission.warnings.link | String | A link to further information about the warning. | 
| Netcraft.Submission.warnings.warning | String | The warning. | 

#### Command example
```!netcraft-file-report-submit file_content="a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1" file_name="malicious.txt" interval_in_seconds="15" polling="true" reason="the file may be malicious" reporter_email="reporter@socteam.com"```

#### Context Example
```json
{
    "Netcraft": {
        "Submission": {
            "classification_log": [],
            "date": 1695129915,
            "files": "https://report.netcraft.com/api/v3/submission/RUxOzbo2OGfEAaq5G3vsAsdUqDh7wa70/files",
            "has_cryptocurrency_addresses": false,
            "has_files": true,
            "has_issues": false,
            "has_mail": false,
            "has_phone_numbers": false,
            "has_urls": false,
            "is_archived": false,
            "last_update": 1695130047,
            "mail": "https://report.netcraft.com/api/v3/submission/RUxOzbo2OGfEAaq5G3vsAsdUqDh7wa70/mail",
            "mail_state": "processing",
            "original_source": {
                "name": "report.netcraft.com",
                "type": "web"
            },
            "pending": false,
            "reason": null,
            "source": {
                "type": "email"
            },
            "source_name": "Palo Alto Networks",
            "state": "no threats",
            "state_counts": {
                "files": {
                    "no threats": 1
                },
                "urls": {}
            },
            "submitter_email": "reporter@socteam.com",
            "tags": [],
            "urls": "https://report.netcraft.com/api/v3/submission/RUxOzbo2OGfEAaq5G3vsAsdUqDh7wa70/urls",
            "uuid": "RUxOzbo2OGfEAaq5G3vsAsdUqDh7wa70",
            "warnings": []
        }
    }
}
```

#### Human Readable Output

>Submission pending:

>### Netcraft Submissions
>|Submission UUID|Submission Date|Submitter Email|State|Source|
>|---|---|---|---|---|
>| RUxOzbo2OGfEAaq5G3vsAsdUqDh7wa70 | 2023-09-19 13:25:15+00:00 | reporter@socteam.com | no threats | Palo Alto Networks |


### netcraft-submission-file-list

***
Get basic information about a submission's files.
When a submission is archived this command will return an error with the message "this submission has been archived".


#### Base Command

`netcraft-submission-file-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| submission_uuid | The submission's unique identifier. Submission UUIDs can be obtained by running the command "netcraft-submission-list". | Required | 
| page | The page number of file records to retrieve (used for pagination) starting from 1. The page size is defined by the "page_size" argument. | Optional | 
| page_size | The number of file records per page to retrieve (used for pagination). The page number is defined by the "page" argument. | Optional | 
| limit | The maximum number of file records to retrieve. If "page_size" is defined, this argument is ignored. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netcraft.SubmissionFile.file_state | String | The classification state of the file. One of "processing", "no threats" or "malicious.". | 
| Netcraft.SubmissionFile.filename | String | The name of the file. | 
| Netcraft.SubmissionFile.has_screenshot | Boolean | Whether the file has a screenshot associated with it. | 
| Netcraft.SubmissionFile.hash | String | The hash of the file. | 
| Netcraft.SubmissionFile.classification_log.date | Number | A UNIX timestamp of when this state change occurred. | 
| Netcraft.SubmissionFile.classification_log.from_state | String | The state the entity moved out of. | 
| Netcraft.SubmissionFile.classification_log.to_state | String | The state the entity moved into. | 

#### Command example
```!netcraft-submission-file-list limit="50" submission_uuid=RUxOzbo2OGfEAaq5G3vsAsdUqDh7wa70```
#### Context Example
```json
{
    "Netcraft": {
        "SubmissionFile": {
            "classification_log": [],
            "file_state": "no threats",
            "filename": "1695129341388_Netcraft.py",
            "has_screenshot": false,
            "hash": "77fb7e37d57adddf4071f946cbd2a3dc"
        }
    }
}
```

#### Human Readable Output

>### Submission Files
>|Filename|Hash|Classification|
>|---|---|---|
>| 1695129341388_Netcraft.py | 77fb7e37d57adddf4071f946cbd2a3dc | no threats |


### netcraft-file-screenshot-get

***
Get a screenshot for a file associated with a submission.

#### Base Command

`netcraft-file-screenshot-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| submission_uuid | The unique identifier of the submission from which to retrieve a file screenshot. Submission UUIDs can be obtained by running the command "netcraft-submission-list". | Required | 
| file_hash | The file's hash. Submission file hashes can be obtained by running the command "netcraft-submission-file-list". | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Size | number | The size of the screenshot in bytes. | 
| InfoFile.Name | string | The name of the screenshot. | 
| InfoFile.EntryID | string | The War Room entry ID of the screenshot. | 
| InfoFile.Info | string | The format and encoding of the screenshot. | 
| InfoFile.Type | string | The type of the screenshot. | 
| InfoFile.Extension | string | The file extension of the screenshot. | 

#### Command example
```!netcraft-file-screenshot-get file_hash=77fb7e37d57adddf4071f946cbd2a3dc submission_uuid=RUxOzbo2OGfEAaq5G3vsAsdUqDh7wa70```

#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "1743@9dfe60aa-7485-4813-822a-03de171d38cb",
        "Extension": "png",
        "Info": "image/png",
        "Name": "file_screenshot_77fb7e37d57adddf4071f946cbd2a3dc.png",
        "Size": 4584,
        "Type": "JPEG image data, JFIF standard 1.01"
    }
}
```

#### Human Readable Output

>Returned file: file_screenshot_77fb7e37d57adddf4071f946cbd2a3dc.png [Download](https://www.paloaltonetworks.com/cortex)

### netcraft-email-report-submit

***
Report email messages to Netcraft for analysis.
The email will be examined for malicious attachments and URLs.
Optionally, emails can be encrypted before upload. If an email is encrypted before upload, it should be encrypted with AES-256-CBC, for example using OpenSSL.
The email must be provided using either the "message" or "entry_id" arguments.


#### Base Command

`netcraft-email-report-submit`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| reporter_email | The reporter's email address, to which the result of Netcraft's analysis will be sent. | Required | 
| message | Either a plain text string of the malicious email in MIME format or if the "password" argument is provided, a base64 encoded AES-256-CBC encrypted email in MIME format. Max message size is 20MiB. | Optional | 
| entry_id | Entry ID of an EML file uploaded to Cortex XSOAR. Max message size is 20MiB. | Optional | 
| password | The password used to encrypt/decrypt the MIME email provided with the "message" argument. Should not be provided if the email is not encrypted. | Optional | 
| polling | Use Cortex XSOAR built-in polling to wait for the report to be processed. Possible values are: true, false. Default is true. | Optional | 
| interval_in_seconds | Indicates how long to wait between command executions (in seconds) when the 'polling' argument is true. Minimum value is 10 seconds. Default is 30. | Optional | 
| timeout | Indicates the time in seconds until the polling sequence times out. Default is 600. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netcraft.Submission.date | Number | The UNIX timestamp of the submission. | 
| Netcraft.Submission.source_name | String | The name of the source of this submission. | 
| Netcraft.Submission.state | String | The state of the submission. One of "processing", "no threats", "suspicious" or "malicious". Note, in the case of a misclassification, a submission may be assigned a higher-severity state several days after its initial classification. | 
| Netcraft.Submission.submitter_email | String | The email address of the reporter of the submission. | 
| Netcraft.Submission.uuid | String | The unique identifier of the submission. | 
| Netcraft.Submission.classification_log.date | Number | A UNIX timestamp of when this state change occurred. | 
| Netcraft.Submission.classification_log.from_state | String | The state the submission moved out of. | 
| Netcraft.Submission.classification_log.to_state | String | The state the submission moved into. | 
| Netcraft.Submission.files | String | An API URL to get details about the files associated with this submission. | 
| Netcraft.Submission.has_cryptocurrency_addresses | Boolean | Whether the submission contains cryptocurrency addresses. | 
| Netcraft.Submission.has_files | Boolean | Whether the submission contains files. | 
| Netcraft.Submission.has_issues | Boolean | Whether the submission contains issues. | 
| Netcraft.Submission.has_mail | Boolean | Whether the submission has an email. | 
| Netcraft.Submission.has_phone_numbers | Boolean | Whether the submission contains phone numbers. | 
| Netcraft.Submission.has_urls | Boolean | Whether the submission contains URLs. | 
| Netcraft.Submission.is_archived | Boolean | Whether the submission has been archived. | 
| Netcraft.Submission.last_update | Number | A UNIX timestamp of when this submission was last updated. | 
| Netcraft.Submission.mail | String | An API URL to get details about the email associated with this submission. | 
| Netcraft.Submission.mail_state | String | The state of the email in the submission. | 
| Netcraft.Submission.original_source.name | String | The name of the submission source. | 
| Netcraft.Submission.original_source.type | String | The type of submission source. | 
| Netcraft.Submission.pending | Boolean | Whether the submission is still pending. | 
| Netcraft.Submission.reason | String | The optional reason for this submission. | 
| Netcraft.Submission.source.type | String | The type of submission source. | 
| Netcraft.Submission.source.uuid | String | The UUID of the source. | 
| Netcraft.Submission.state_counts.files | Unknown | An object containing the amount of files in each state, where the key is the state and the value is the amount. | 
| Netcraft.Submission.state_counts.urls | Unknown | An object containing the amount of URLs in each state, where the key is the state and the value is the amount. | 
| Netcraft.Submission.tags.name | String | The name of the tag. | 
| Netcraft.Submission.tags.description | String | The tag's description. | 
| Netcraft.Submission.urls | String | An API URL to get details about the URLs associated with this submission. | 
| Netcraft.Submission.warnings.link | String | A link to further information about the warning. | 
| Netcraft.Submission.warnings.warning | String | The warning. | 

#### Command example
```
!netcraft-email-report-submit message="""From: fraudster@example.com
To: example@netcraft.com
Subject: Example email
Date: Tue, 01 Jan 2019 00:00:00 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF8"
Content-Transfer-Encoding: 8bit

Example email body with http://example.com URL.
""" reporter_email="reporter@socteam.com"
```

#### Context Example
```json
{
    "Netcraft": {
        "Submission": {
            "classification_log": [],
            "date": 1695129915,
            "files": "https://report.netcraft.com/api/v3/submission/RUxOzbo2OGfEAaq5G3vsAsdUqDh7wa70/files",
            "has_cryptocurrency_addresses": false,
            "has_files": true,
            "has_issues": false,
            "has_mail": true,
            "has_phone_numbers": false,
            "has_urls": true,
            "is_archived": false,
            "last_update": 1695130047,
            "mail": "https://report.netcraft.com/api/v3/submission/RUxOzbo2OGfEAaq5G3vsAsdUqDh7wa70/mail",
            "mail_state": "processing",
            "original_source": {
                "name": "report.netcraft.com",
                "type": "web"
            },
            "pending": false,
            "reason": null,
            "source": {
                "type": "email"
            },
            "source_name": "Palo Alto Networks",
            "state": "no threats",
            "state_counts": {
                "files": {
                    "no threats": 1
                },
                "urls": {}
            },
            "submitter_email": "reporter@socteam.com",
            "tags": [],
            "urls": "https://report.netcraft.com/api/v3/submission/RUxOzbo2OGfEAaq5G3vsAsdUqDh7wa70/urls",
            "uuid": "RUxOzbo2OGfEAaq5G3vsAsdUqDh7wa70",
            "warnings": []
        }
    }
}
```

#### Human Readable Output

>Submission pending:

>### Netcraft Submissions
>|Submission UUID|Submission Date|Submitter Email|State|Source|
>|---|---|---|---|---|
>| RUxOzbo2OGfEAaq5G3vsAsdUqDh7wa70 | 2023-09-19 13:25:15+00:00 | reporter@socteam.com | no threats | Palo Alto Networks |


### netcraft-submission-mail-get

***
Get basic information about a submission's email.
When a submission is archived this command will return an error with the message "this submission has been archived".


#### Base Command

`netcraft-submission-mail-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| submission_uuid | The submission's unique identifier. Submission UUIDs can be obtained by running the command "netcraft-submission-list". | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netcraft.SubmissionMail.classification_log.date | Number | A unix timestamp of when this state change occurred. | 
| Netcraft.SubmissionMail.classification_log.from_state | String | The state the entity moved out of. | 
| Netcraft.SubmissionMail.classification_log.to_state | String | The state the entity moved into. | 
| Netcraft.SubmissionMail.from | String | The email addresses of the email senders. | 
| Netcraft.SubmissionMail.hash | String | The MD5 hash of the email associated with this submission. | 
| Netcraft.SubmissionMail.reply_to | String | The email addresses that reply messages of the email were sent to. | 
| Netcraft.SubmissionMail.state | String | The classification state of the email. One of "processing", "no threats" or "malicious". | 
| Netcraft.SubmissionMail.subject | String | The subject of the email submitted. | 
| Netcraft.SubmissionMail.to | String | The email addresses of the email recipients. | 

#### Command example
```!netcraft-submission-mail-get submission_uuid=bavSyjpYf4HpO7KlYzu6Z32FkHcXbZpT```
#### Context Example
```json
{
    "Netcraft": {
        "SubmissionMail": {
            "classification_log": [
                {
                    "date": 1694095036,
                    "from_state": "processing",
                    "to_state": "no threats"
                }
            ],
            "from": [
                "fraudster@example.com"
            ],
            "has_screenshot": 1,
            "hash": "6fabfd92d854588b9f5295aacc561782",
            "reply_to": [],
            "state": "no threats",
            "subject": "Example email",
            "tags": [],
            "to": [
                "example@netcraft.com"
            ]
        }
    }
}
```

#### Human Readable Output

>### Submission Mails
>|Subject|From|To|Classification|
>|---|---|---|---|
>| Example email | fraudster@example.com | example@netcraft.com | no threats |


### netcraft-mail-screenshot-get

***
Get a screenshot for the email associated with a submission.

#### Base Command

`netcraft-mail-screenshot-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| submission_uuid | The unique identifier of the submission from which to retrieve an email screenshot. Submission UUIDs can be obtained by running the command "netcraft-submission-list". | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Size | number | The size of the screenshot in bytes. | 
| InfoFile.Name | string | The name of the screenshot. | 
| InfoFile.EntryID | string | The War Room entry ID of the screenshot. | 
| InfoFile.Info | string | The format and encoding of the screenshot. | 
| InfoFile.Type | string | The type of the screenshot. | 
| InfoFile.Extension | string | The file extension of the screenshot. | 

#### Command example
```!netcraft-mail-screenshot-get submission_uuid=bavSyjpYf4HpO7KlYzu6Z32FkHcXbZpT```
#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "1743@9dfe60aa-7485-4813-822a-03de171d38cb",
        "Extension": "png",
        "Info": "image/png",
        "Name": "mail_screenshot_bavSyjpYf4HpO7KlYzu6Z32FkHcXbZpT.png",
        "Size": 4584,
        "Type": "JPEG image data, JFIF standard 1.01"
    }
}
```

#### Human Readable Output

>Returned file: email_screenshot_bavSyjpYf4HpO7KlYzu6Z32FkHcXbZpT.png [Download](https://www.paloaltonetworks.com/cortex)

### netcraft-url-report-submit

***
Report URLs to Netcraft for analysis.

#### Base Command

`netcraft-url-report-submit`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| reporter_email | The reporter's email address, to which the result of Netcraft's analysis will be sent. | Required | 
| urls | A comma-separated list of URLs to report. Up to 1,000 URLs per submission are permitted. | Required | 
| reason | The reason the URLs are considered malicious. Should be less than 10,000 characters. | Optional | 
| polling | Use Cortex XSOAR built-in polling to wait for the report to be processed. Possible values are: true, false. Default is true. | Optional | 
| interval_in_seconds | Indicates how long to wait between command executions (in seconds) when the 'polling' argument is true. Minimum value is 10 seconds. Default is 30. | Optional | 
| timeout | Indicates the time in seconds until the polling sequence times out. Default is 600. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netcraft.Submission.date | Number | The UNIX timestamp of the submission. | 
| Netcraft.Submission.source_name | String | The name of the source of this submission. | 
| Netcraft.Submission.state | String | The state of the submission. One of "processing", "no threats", "suspicious" or "malicious". Note, in the case of a misclassification, a submission may be assigned a higher-severity state several days after its initial classification. | 
| Netcraft.Submission.submitter_email | String | The email address of the reporter of the submission. | 
| Netcraft.Submission.uuid | String | The unique identifier of the submission. | 
| Netcraft.Submission.classification_log.date | Number | A UNIX timestamp of when this state change occurred. | 
| Netcraft.Submission.classification_log.from_state | String | The state the submission moved out of. | 
| Netcraft.Submission.classification_log.to_state | String | The state the submission moved into. | 
| Netcraft.Submission.files | String | An API URL to get details about the files associated with this submission. | 
| Netcraft.Submission.has_cryptocurrency_addresses | Boolean | Whether the submission contains cryptocurrency addresses. | 
| Netcraft.Submission.has_files | Boolean | Whether the submission contains files. | 
| Netcraft.Submission.has_issues | Boolean | Whether the submission contains issues. | 
| Netcraft.Submission.has_mail | Boolean | Whether the submission has an email. | 
| Netcraft.Submission.has_phone_numbers | Boolean | Whether the submission contains phone numbers. | 
| Netcraft.Submission.has_urls | Boolean | Whether the submission contains URLs. | 
| Netcraft.Submission.is_archived | Boolean | Whether the submission has been archived. | 
| Netcraft.Submission.last_update | Number | A unix timestamp of when this submission was last updated. | 
| Netcraft.Submission.mail | String | An API URL to get details about the email associated with this submission. | 
| Netcraft.Submission.mail_state | String | The state of the email in the submission. | 
| Netcraft.Submission.original_source.name | String | The name of the submission source. | 
| Netcraft.Submission.original_source.type | String | The type of submission source. | 
| Netcraft.Submission.pending | Boolean | Whether the submission is still pending. | 
| Netcraft.Submission.reason | String | The optional reason for this submission. | 
| Netcraft.Submission.source.type | String | The type of submission source. | 
| Netcraft.Submission.source.uuid | String | The UUID of the source. | 
| Netcraft.Submission.state_counts.files | Unknown | An object containing the amount of files in each state, where the key is the state and the value is the amount. | 
| Netcraft.Submission.state_counts.urls | Unknown | An object containing the amount of URLs in each state, where the key is the state and the value is the amount. | 
| Netcraft.Submission.tags.name | String | The name of the tag. | 
| Netcraft.Submission.tags.description | String | The tag's description. | 
| Netcraft.Submission.urls | String | An API URL to get details about the URLs associated with this submission. | 
| Netcraft.Submission.warnings.link | String | A link to further information about the warning. | 
| Netcraft.Submission.warnings.warning | String | The warning. | 

#### Command example
```!netcraft-file-report-submit file_content="a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1" file_name="malicious.txt" interval_in_seconds="15" polling="true" reason="the file may be malicious" reporter_email="reporter@socteam.com"```

#### Context Example
```json
{
    "Netcraft": {
        "Submission": {
            "classification_log": [],
            "date": 1695129915,
            "files": "https://report.netcraft.com/api/v3/submission/RUxOzbo2OGfEAaq5G3vsAsdUqDh7wa70/files",
            "has_cryptocurrency_addresses": false,
            "has_files": true,
            "has_issues": false,
            "has_mail": false,
            "has_phone_numbers": false,
            "has_urls": false,
            "is_archived": false,
            "last_update": 1695130047,
            "mail": "https://report.netcraft.com/api/v3/submission/RUxOzbo2OGfEAaq5G3vsAsdUqDh7wa70/mail",
            "mail_state": "processing",
            "original_source": {
                "name": "report.netcraft.com",
                "type": "web"
            },
            "pending": false,
            "reason": null,
            "source": {
                "type": "email"
            },
            "source_name": "Palo Alto Networks",
            "state": "no threats",
            "state_counts": {
                "files": {
                    "no threats": 1
                },
                "urls": {}
            },
            "submitter_email": "reporter@socteam.com",
            "tags": [],
            "urls": "https://report.netcraft.com/api/v3/submission/RUxOzbo2OGfEAaq5G3vsAsdUqDh7wa70/urls",
            "uuid": "RUxOzbo2OGfEAaq5G3vsAsdUqDh7wa70",
            "warnings": []
        }
    }
}
```

#### Human Readable Output

>Submission pending:

>### Netcraft Submissions
>|Submission UUID|Submission Date|Submitter Email|State|Source|
>|---|---|---|---|---|
>| RUxOzbo2OGfEAaq5G3vsAsdUqDh7wa70 | 2023-09-19 13:25:15+00:00 | reporter@socteam.com | no threats | Palo Alto Networks |

### netcraft-submission-url-list

***
Get basic information about a submission's URLs.
When a submission is archived this command will return an error with the message "this submission has been archived".


#### Base Command

`netcraft-submission-url-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| submission_uuid | The submission's unique identifier. Submission UUIDs can be obtained by running the command "netcraft-submission-list". | Required | 
| page | The page number of URLs to retrieve (used for pagination). The page size is defined by the "page_size" argument. | Optional | 
| page_size | The number of URLs per page to retrieve (used for pagination). The page number is defined by the "page" argument. | Optional | 
| limit | The maximum number of URLs to retrieve. If "page_size" is defined, this argument is ignored. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netcraft.SubmissionURL.url | String | The URL reported. | 
| Netcraft.SubmissionURL.url_state | String | The state of the URL. One of "processing", "no threats", "unavailable", "malicious", "rejected", or "suspicious". | 
| Netcraft.SubmissionURL.classification_log.date | Number | A UNIX timestamp of when this state change occurred. | 
| Netcraft.SubmissionURL.classification_log.from_state | String | The state the entity moved out of. | 
| Netcraft.SubmissionURL.classification_log.to_state | String | The state the entity moved into. | 
| Netcraft.SubmissionURL.country_code | String | The country code this hostname resolved to. | 
| Netcraft.SubmissionURL.file_hash | String | If the URL was found in a file that was submitted or an email attachment, this field contains the MD5 hash of that file. | 
| Netcraft.SubmissionURL.hostname | String | The hostname of the URL. | 
| Netcraft.SubmissionURL.incident_report_url | String | A link to the incident report detailing the attack hosted by the URL. This will only exist if Netcraft is performing takedown action. | 
| Netcraft.SubmissionURL.ip | String | The IP address this hostname resolved to. | 
| Netcraft.SubmissionURL.reason | String | The reason this URL is believed to be malicious. | 
| Netcraft.SubmissionURL.screenshots.hash | String | A hash of the screenshot provided. | 
| Netcraft.SubmissionURL.screenshots.type | String | The type of screenshot. One of "gif" or "png". | 
| Netcraft.SubmissionURL.sources.file_hash | String | If this URL originated in a file, this is the hash of the file. | 
| Netcraft.SubmissionURL.sources.file_name | String | If this URL originated in a file, this is the filename. | 
| Netcraft.SubmissionURL.sources.source | String | The name of a source this URL was found in. | 
| Netcraft.SubmissionURL.sources.source_id | Number | The part of the email the URL was found in, if applicable. Either 1 for the body of the email, or 2 for an attachment to the email. | 
| Netcraft.SubmissionURL.tags.description | String | The tag's description. | 
| Netcraft.SubmissionURL.tags.name | String | The name of the tag. | 
| Netcraft.SubmissionURL.tags.submitter_tag | Number | The submitter of the tag, 1 is for user, 0 is for Netcraft. | 
| Netcraft.SubmissionURL.takedown_link | String | A link to the takedown associated with the URL. | 
| Netcraft.SubmissionURL.takedown_url_id | Number | The ID for the URL in takedown. | 
| Netcraft.SubmissionURL.url_classification_reason | String | The reason for a URL classification. | 
| Netcraft.SubmissionURL.url_takedown_state | String | The progress of Netcraft's takedown action against the URL. One of "not injected", "not started", "in progress" or "resolved". | 
| Netcraft.SubmissionURL.uuid | String | The UUID of the URL. | 

#### Command example
```!netcraft-submission-url-list limit="50" page="2" page_size="2" submission_uuid=bavSyjpYf4HpO7KlYzu6Z32FkHcXbZpT```
#### Human Readable Output

>### Submission URLs
>|UUID|URL|Hostname|Classification|URL Classification Log|
>|---|---|---|---|---|
>| 46b1921f9b4e4b34b547bdf20c0c0263 | http://example.com/ | example.com | string | - date: 1000000000<br>  from_state: processing<br>  to_state: no threats<br> |



### netcraft-url-screenshot-get

***
Download associated screenshots for a specified URL.

#### Base Command

`netcraft-url-screenshot-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| submission_uuid | The unique identifier of the submission from which to retrieve a URL screenshot. Submission UUIDs can be obtained by running the command "netcraft-submission-list". | Required | 
| url_uuid | The URL's UUID. Submission URL UUIDs can be obtained by running the command "netcraft-submission-url-list". | Required | 
| screenshot_hash | An MD5 hash of the URL's screenshot. Submission URL screenshot hashes can be obtained by running the command "netcraft-submission-url-list". | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Size | number | The size of the screenshot in bytes. | 
| InfoFile.Name | string | The name of the screenshot. | 
| InfoFile.EntryID | string | The War Room entry ID of the screenshot. | 
| InfoFile.Info | string | The format and encoding of the screenshot. | 
| InfoFile.Type | string | The type of the screenshot. | 
| InfoFile.Extension | string | The file extension of the screenshot. | 

#### Command example
```!netcraft-url-screenshot-get screenshot_hash="06f8715ba1b1ca5dee4af05e98bbc63a" submission_uuid="0qQt98P04o0qk46UXveNsCHhUN7zLopY" url_uuid="BZqSBm5i4KIoCq6TItXLWKZwGAm3nN08"```

#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "1743@9dfe60aa-7485-4813-822a-03de171d38cb",
        "Extension": "png",
        "Info": "image/png",
        "Name": "url_screenshot_06f8715ba1b1ca5dee4af05e98bbc63a.png",
        "Size": 4584,
        "Type": "JPEG image data, JFIF standard 1.01"
    }
}
```

#### Human Readable Output

>Returned file: url_screenshot_06f8715ba1b1ca5dee4af05e98bbc63a.png [Download](https://www.paloaltonetworks.com/cortex)