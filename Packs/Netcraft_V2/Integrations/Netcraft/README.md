Netcraft takedown, submission and screenshot management.

## Configure Netcraft on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Netcraft.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Takedown Server URL | True |
    | Submission Server URL | True |
    | API Key | True |
    | Netcraft_image | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |
    | Fetch incidents | False |
    | Incident type | False |
    | Maximum number of incidents per fetch | False |
    | First fetch time | True |
    | Incidents Fetch Interval | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### netcraft-attack-report

***
Report a new attack or authorise an existing attack in the Takedown service.
If a takedown for the attack already exists in the Netcraft system it will be authorised, otherwise, a new takedown will be added and authorised.


#### Base Command

`netcraft-attack-report`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| attack | The location of the attack to take down, e.g. a phishing URL, or a fraudulent email address. | Required | 
| comment | The reason for the report, such as a description of the attack. | Required | 
| brand | The brand to report the takedown under. If no brand is specified, the brand of the provided "region" will be used. | Optional | 
| attack_type | The type of attack being reported.<br/>Run the command "netcraft-attack-type-list" to get the list of available types, use the "Name" field of the type for this argument.<br/>. Default is phishing_url. | Optional | 
| inactive | Set to "true" if the attack is not currently active.<br/>This will place the takedown directly into the "Inactive (Monitoring)" status, which can be used to monitor suspicious sites.<br/>. Possible values are: true, false. Default is false. | Optional | 
| force_auth | If set to true, Netcraft will be authorised to start the takedown as soon as the report has been processed.<br/>If set to false, the takedown will only be authorised if you have automatic authorisation enabled for the given attack type, or if the takedown is manually authorised later through the web interface.<br/>. Possible values are: true, false. Default is true. | Optional | 
| malware | Should be set to true if the reported content contains or is related to a computer virus.<br/>This is used to determine the correct attack type in the case where the type parameter has not been provided.<br/>This argument is required for all malware attacks where the type parameter has not been provided.<br/>. Possible values are: true, false. | Optional | 
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
| Netcraft.Takedown.id | String | The ID of the takedown. \(this key will only appear if the takedown has been created and verified\). | 

#### Command example
```!netcraft-attack-report attack="https://www.amazon.com/phishing_rods" comment="Very malicious" attack_type="phishing_url" inactive="true" customer_label="Test Playbook run" tags="coronavirus"```
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

>### Netcraft Takedown
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
| false_positive | whether to filter to takedowns which have been incorrectly marked as malicious. Possible values are: true, false. | Optional | 
| ip | Filter to attacks that are hosted on the given IPv4 address, or within the given IPv4 CIDR range. Please note that partial IP addresses will not be matched. | Optional | 
| id_before | Filter to takedowns that were submitted before the specified takedown ID. | Optional | 
| id_after | Filter to takedowns that were submitted after the specified takedown<br/>ID. When using this argument we recommend that you also set the "sort" argument<br/>to id to ensure that no results are missed.<br/>. | Optional | 
| date_from | Filter to takedowns that were submitted on or after the date/time<br/>provided.Values should be supplied as YYYY-MM-DD HH:MM:SS\_in UTC. If no time<br/>information is provided, the system will default to YYYY-MM-DD 00:00:00. Relative<br/>date/time formats are also supported, for example\_5 days ago,\_and monday<br/>this week"<br/>. | Optional | 
| date_to | Filter to takedowns that were submitted on or before the date/time<br/>provided. Values should be supplied as "YYYY-MM-DD HH:MM:SS" in UTC. If no time<br/>information is provided, the system will default to "YYYY-MM-DD 00:00:00". Relative<br/>date/time formats are also supported, for example "5 days ago", and "monday this week"<br/>. | Optional | 
| reporter_email | Filter to takedowns that were reported by the given user. | Optional | 
| report_source | Filter to takedowns that were reported through the given mechanism. Possible values are: Interface, Phishing Feed, Referer, Forensic, Api, Email Feed, Fraud Detection. | Optional | 
| attack_types | Filter to takedowns of the given attack type. Multiple values may be provided as a comma-separated list.<br/>Run the command "netcraft-attack-type-list" to get the list of available types, use the "Name" field of the type for this argument.<br/>. | Optional | 
| auth_given | Filter based on whether and by who the takedown has been authorised. Possible values are: Yes, Yes Customer, Yes Netcraft, No. | Optional | 
| escalated | Filter based on whether and by who the takedown has been escalated. Possible values are: Yes, Yes Customer, Yes Netcraft, No. | Optional | 
| sort | The key that the list of takedowns should be sorted by. Possible values are: Auth Given, Customer Label, Date Submitted, Hoster, Id, Ip, Language, Last Updated, Registrar, Status. Default is Status. | Optional | 
| sort_direction | The direction to sort takedowns in with the key specified in the "sort" argument. Possible values are: asc, desc. Default is asc. | Optional | 
| limit | The maximum number of takedowns to return. The max value is 100,000. Default is 50. | Optional | 
| all_results | Whether to retrieve all takedowns that match the filters.<br/>If true, the "limit" argument will be ignored. The maximum takedowns returned in one call is 100,000.<br/>. Possible values are: false, true. Default is false. | Optional | 
| region | The name of the region of which to list takedowns.<br/>If not provided, the region specified in the instance configuration will be used.<br/>. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netcraft.Takedown.id | String | The ID of the takedown. | 
| Netcraft.Takedown.group_id | String | The ID of the group that the takedown belongs to. can potentially be the same a ID, or empty if there is no group. | 
| Netcraft.Takedown.attack_url | String | The location of the attack being taken down. This field contains a canonicalised value. see the reported_url field for the exact location that was reported to takedown. | 
| Netcraft.Takedown.reported_url | String | The location of the attack as reported to takedown. See the attack_url field for the formatted location of the attack being taken down. | 
| Netcraft.Takedown.ip | String | The IPv4 address of the attack. | 
| Netcraft.Takedown.country_code | String | ISO country code of the advertised hosting location. | 
| Netcraft.Takedown.date_submitted | Date | The date and time that the takedown was reported, in UTC. | 
| Netcraft.Takedown.last_updated | Date | The date and time of the last action taken on the takedown, in UTC. | 
| Netcraft.Takedown.region | String | The name of the area that the takedown resides in. | 
| Netcraft.Takedown.target_brand | String | The name of the brand being targeted by the attack. | 
| Netcraft.Takedown.authgiven | Boolean | Indicates whether the takedown has been authorised. | 
| Netcraft.Takedown.host | String | The name of the company responsible for the IP address. | 
| Netcraft.Takedown.registrar | String | The name of the registrar responsible for the domain name used in the attack. | 
| Netcraft.Takedown.customer_label | String | A custom field which may be provided along with the takedown report. | 
| Netcraft.Takedown.date_authed | Date | The date and time that the takedown was authorised, in UTC. | 
| Netcraft.Takedown.stop_monitoring_date | Date | The date and time that the takedown system stopped monitoring the attack, in UTC.
If the attack is still being monitored, an empty string is given.
 | 
| Netcraft.Takedown.domain | String | The domain of the url or email address being taken down.
This will be blank for an attack with no domain name.
 | 
| Netcraft.Takedown.language | String | The language used in the attack \(if it can be determined\). | 
| Netcraft.Takedown.date_first_actioned | Date | The date and time of the first action taken by netcraft
after the takedown was reported, in UTC. This is calculated as the first time
that the takedown was moved out of the "unverified" status.
 | 
| Netcraft.Takedown.escalated | Boolean | Indicates whether the takedown has been escalated. | 
| Netcraft.Takedown.first_contact | Date | The date and time that the takedown first entered a contacted state, in UTC. | 
| Netcraft.Takedown.first_inactive | Date | The date and time that the takedown first entered the inactive \(monitoring\) state. | 
| Netcraft.Takedown.is_redirect | String | Whether or not the attack redirects to another location.
Possible values:
  "final" - the attack is the final destination of another redirect.
  "redirect" - the attack redirects to another location.
  "no_redirect" - the attack does not redirect.
 | 
| Netcraft.Takedown.attack_type | String | The type of attack being taken down. | 
| Netcraft.Takedown.certificate | Unknown | HTTPS certificate details for the hostname.
The structure of the returned data is the output of PHP's "openssl_x509_parse" function with the additional keys spki_sha256 and spki_sha1, \(See https://www.php.net/manual/en/function.openssl-x509-parse.php\).
 | 
| Netcraft.Takedown.certificate.spki_sha256 | Unknown | The SHA-256 hash of the Subject Public Key Info structure in the certificate. | 
| Netcraft.Takedown.certificate.spki_sha1 | Unknown | The SHA-1 hash of the Subject Public Key Info structure in the certificate. | 
| Netcraft.Takedown.deceptive_domain_score | String | The deceptive domain score of the domain.
e.g. for the URL https://l0gin.example.com/, this value will contain the deceptive domain score for example.com.
 | 
| Netcraft.Takedown.domain_risk_rating | String | A score from 0 to 10 which represents the risk that the domain is hosting a malicious website.
e.g. for the url https://l0gin.example.com/, this value wil contain the risk rating for "example.com".
This score is distinct from the "deceptive domain score", and takes a range of factors into account,
such as the reputation of the hosting provider, age of the domain name, search engine rankings and more.
 | 
| Netcraft.Takedown.final_outage | String | The duration \(hh:mm:ss\) between when the takedown was
authorised, and the final time that the attack went offline \(final_resolved - date_authed\).
 | 
| Netcraft.Takedown.final_resolved | Date | The date and time that the attack went offline for the final time, in UTC. | 
| Netcraft.Takedown.first_outage | Date | The duration \(hh:mm:ss\) between when the takedown was authorised, and the first time that the attack went offline \(first_resolved - date_authed\). | 
| Netcraft.Takedown.first_resolved | Date | The date and time that the attack first went offline, in UTC. | 
| Netcraft.Takedown.fwd_owner | String | The owner of the forward DNS infrastructure. | 
| Netcraft.Takedown.has_phishing_kit | Boolean | Indicates whether the takedown has an associated phishing kit. | 
| Netcraft.Takedown.hostname | String | The full hostname of the URL or email address being taken down. this will be blank for attacks with no hostname. | 
| Netcraft.Takedown.hostname_ddss_score | String | The deceptive domain score of the hostname.
e.g. for the URL https://l0gin.example.com/, this value will contain the deceptive domain score for l0gin.example.com.
 | 
| Netcraft.Takedown.evidence_url | String | A url to the public incident report for this attack. | 
| Netcraft.Takedown.domain_attack | String | Whether or not the domain name used in the attack is believed to be fraudulent.
Possible values \(non exhaustive\):
  "all" - All attacks.
  "yes" - There is a high confidence that the domain name is fraudulent.
          the domain registrar will be contacted, and the webmaster will not be contacted.
  "yes_low_confidence" - The domain is likely fraudulent. The domain registrar
                        will be contacted, and the webmaster will still be contacted.
  "no" - The domain name is not believed to be fraudulent, this is likely compromised site.
 | 
| Netcraft.Takedown.false_positive | Boolean | Indicates whether the reported content was incorrectly flagged as malicious. | 
| Netcraft.Takedown.hostname_attack | String | Whether or not the hostname used in the attack is believed to be fraudulent.
Possible values \(non exhaustive\):
  "all" - All attacks.
  "yes" - There is a high confidence that the hostname is fraudulent. the certificate authority will be contacted.
  "yes_low_confidence" - The hostname is likely fraudulent.
  "no" - The hostname is not believed to be fraudulent, this is likely compromised site.
 | 
| Netcraft.Takedown.malware_category | String | The category of malware detected. Only set for malware attack types. May be empty if category cannot be determined. | 
| Netcraft.Takedown.malware_family | String | The family of malware detected. only set for malware attack types. may be empty if family cannot be determined. | 
| Netcraft.Takedown.phishing_kit_hash | Unknown | The sha1 hashes of all phishing kits available for download which are related to this takedown. | 
| Netcraft.Takedown.report_source | String | The method through which the takedown was submitted. | 
| Netcraft.Takedown.reporter | String | Person/account that submitted the takedown. This will be the email address of the user, or "netcraft" for any reports made by Netcraft. | 
| Netcraft.Takedown.rev_owner | String | The owner of the reverse DNS infrastructure. | 
| Netcraft.Takedown.reverse_dns | String | The output of a reverse DNS lookup on the IP of the attack. | 
| Netcraft.Takedown.certificate_revoked | String | If the SSL certificate has been revoked, then the date this was detected \(in UTC\) is returned, else "Not revoked" is returned. | 
| Netcraft.Takedown.screenshot_url | String | The URL\(s\) at which a screenshot of the attack can be found.
When returning a single URL as a string \(the default behaviour\) the returned URL will be the best guess of the screenshot which displays the live attack.
When returning multiple URLs, the list will be sorted by the time the screenshot was requested, with the earliest first.
 | 
| Netcraft.Takedown.status_change_uptime | String | The total duration \(hh:mm:ss\) that the attack was available for after authorisation, as determined by the takedown status changes.
i.e. the total amount of time since authorisation that an attack was not in the resolved or resolved \(monitoring\)  state.'
 | 
| Netcraft.Takedown.status | String | The status of the takedown.
Possible values:
  "Unverified" - The report has not yet been verified as fraudulent by Netcraft.
  "Inactive \(Monitoring\)" - The attack went offline before Netcraft was authorised to start the takedown process, and is being monitored in case it returns.
  "Verified" - The report has been verified as fraudulent, but no takedown notices have been sent.
  "Contacted Hosting" - Takedown notices have been sent to the hosting provider
  "Contacted Police" - The takedown has been escalated to local law enforcement.
  "Contacted Upstream" - The takedown has been escalated to the organisation providing connectivity to the hosting provider.
  "Monitoring" - The attack is offline, as is being monitored in case it returns.
  "Resolved" - The attack has been offline for 7 consecutive days, and is no longer being monitored.
  "Stale" - The attack went offline before Netcraft was authorised to start the takedown process, and is no longer being monitored.
  "Invalid" - The report is not a valid takedown target.
 | 
| Netcraft.Takedown.tags | String | List of tags applied to the group. | 
| Netcraft.Takedown.targeted_url | String | The URL which this attack is masquerading as, e.g. the URL of the legitimate login form that a phishing attack is targeting. | 
| Netcraft.Takedown.site_risk_rating | String | A score from 0 to 10 which represents the risk that the hostname is hosting a malicious website.
e.g. for the URL https://l0gin.example.com/, this value will contain the risk rating for l0gin.example.com.
 | 
| Netcraft.Takedown.whois_server | String | The WHOIS data for the takedown. | 
| Netcraft.Takedown.authorisation_source | String | The source of authorisation for the takedown. will be blank if the takedown has not bee authorised.  customer
Possible values: "customer" "netcraft"
 | 
| Netcraft.Takedown.escalation_source | String | The source of escalation for the takedown. will be blank if the takedown has not been escalated.
Possible values: "customer" "netcraft"
 | 
| Netcraft.Takedown.restart_date | String | The latest date and time, in UTC, that the takedown was restarted, i.e. went from the "resolved \(monitoring\)" status to a contacted status.
Will be empty if the takedown ha never been restarted.'
 | 
| Netcraft.Takedown.gsb_block_status | Unknown | An array of objects containing the Google Safe Browsing block status on all platforms \(iOS, Android and Desktop\).
Will be an empty array if the takedown is not a Phishing URL takedown, or if Netcraft hasn't tested the GSB block status for the takedown.
 | 
| Netcraft.Takedown.gsb_first_blocked | Unknown | An array of objects containing the first time that the URL was seen blocked in Google Safe Browsing \(GSB\) by Netcraft.
Will be an empty array if the URL was not seen blocked by GSB on any platform.
 | 
| Netcraft.Takedown.managed | Boolean | Indicates whether the takedown is being performed under the managed service. | 
| Netcraft.Takedown.date_escalated | Date | The date and time that the takedown entered the managed state, in UTC. | 
| Netcraft.Takedown.logged_credential_injections | String | An array of objects containing the type and value of each marked account injection associated with the takedown. | 
| Netcraft.Takedown.whois_data | String | The WHOIS data for the takedown. | 

#### Command example
```!netcraft-takedown-list date_from="last week" attack_types=phishing_url escalated="No" sort=id sort_direction=asc limit=2 all_results=false```
#### Human Readable Output

>### Netcraft Takedowns
>**No entries.**


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
| add_tags | A comma separated list tags to add to the takedown group. | Optional | 
| remove_tags | A comma separated list tags to remove from the takedown group.<br/>Removing a tag from a group which already doesn't have that tag is permitted.<br/>However, including the same tag in both "add_tags" and "remove_tags" will return an error.<br/>. | Optional | 
| region | The name of the region to move the takedown under. | Optional | 

#### Context Output

There is no context output for this command.
### netcraft-takedown-escalate

***
Escalate an automated takedown to a managed takedown.

#### Base Command

`netcraft-takedown-escalate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| takedown_id | The ID of the automated takedown to escalate. | Required | 

#### Context Output

There is no context output for this command.
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
| Netcraft.TakedownNote.group_id | String | The ID of the takedown group that this note belongs to.
This will only be set if the note has been attached to all takedowns in the group, otherwise this field will have a value of "0".
 | 
| Netcraft.TakedownNote.time | Date | The date and time that the note was created. | 
| Netcraft.TakedownNote.author | String | The username of the account that created the note. Notes added by Netcraft will show as "Netcraft". | 
| Netcraft.TakedownNote.note | String | The contents of the note. | 

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
| auto_authorise | Filter to attack types which you have chosen to automatically authorize takedowns against. Possible values are: true, false. | Optional | 
| region | The name of the region to create a takedown under.<br/>If not provided, the region specified in the instance configuration will be used.<br/>. | Optional | 
| all_results | Whether to retrieve all attack types that match the filters. If set to false, only 50 will be returned. Possible values are: false, true. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netcraft.AttackType.name | String | The unique string identifier for the attack type. | 
| Netcraft.AttackType.display_name | String | The human-readable name of the attack type. | 
| Netcraft.AttackType.base_type | String | The unique string identifier for the top-level parent type of this attack type. | 
| Netcraft.AttackType.description | String | A short description of the attack type | 
| Netcraft.AttackType.automated | Boolean | Indicates whether or not automated takedowns are available for this attack type. | 
| Netcraft.AttackType.auto_escalation | Boolean | Indicates whether or not you have chosen to automatically escalate takedowns under this type to managed takedowns after the configured escalation period. | 
| Netcraft.AttackType.auto_authorise | Boolean | Indicates whether or not you have chosen to automatically authorise takedowns under this type. | 

### netcraft-submission-list

***
Get basic information about a submissions.

#### Base Command

`netcraft-submission-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| submission_uuid | Get a specific submission. If provided, all the others arguments will be ignored and an extensive report will be returned. | Optional | 
| date_start | Filter submissions by start date. | Optional | 
| date_end | Filter submissions by end date. | Optional | 
| source_name | Filter the submissions by source. | Optional | 
| state | The state of the submissions. One of "processing", "no threats", "suspicious" or "malicious". Note, in the case of a misclassification, a submission may be assigned a higher-severity state several days after its initial classification. | Optional | 
| submission_reason | Filter the submissions by words contained in the submission reason. | Optional | 
| submitter_email | Filter the submissions by submitter email. | Optional | 
| limit | The number of submissions to return. Default is 50. | Optional | 
| page_size | The number of submissions to return per page. The maximum is 1000. | Optional | 
| next_token | The UUID denoting the first submission to return, as given by the response of the previous run of this command under the context key "Netcraft.SubmissionNextToken". | Optional | 
| polling | . Default is false. | Optional | 
| interval_in_seconds | . Default is 30. | Optional | 
| timeout | . Default is 600. | Optional | 
| hide_polling_output | . Default is True. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netcraft.Submission.date | Number | The unix timestamp of the submission. | 
| Netcraft.Submission.source_name | String | The name of the source of this submission. | 
| Netcraft.Submission.state | String | The state of the submission. One of "processing", "no threats", "suspicious" or "malicious". Note, in the case of a misclassification, a submission may be assigned a higher-severity state several days after its initial classification. | 
| Netcraft.Submission.submitter_email | String | The email address of the reporter of the submission. | 
| Netcraft.Submission.uuid | String | The unique identifier of the submission. | 
| Netcraft.Submission.submitter_uuid | String | The unique identifier of the submitter. This key appears only if the "submission_uuid" argument is \*not\* provided. | 
| Netcraft.Submission.classification_log.date | Number | A unix timestamp of when this state change occurred. This key appears only if the "submission_uuid" argument is provided. | 
| Netcraft.Submission.classification_log.from_state | String | The state the submission moved out of. This key appears only if the "submission_uuid" argument is provided. | 
| Netcraft.Submission.classification_log.to_state | String | The state the submission moved into. This key appears only if the "submission_uuid" argument is provided. | 
| Netcraft.Submission.files | String | An API URL to get details about the files associated with this submission. This key appears only if the "submission_uuid" argument is provided. | 
| Netcraft.Submission.has_cryptocurrency_addresses | Boolean | Whether the submission contains cryptocurrency addresses. This key appears only if the "submission_uuid" argument is provided. | 
| Netcraft.Submission.has_files | Boolean | Whether the submission contains files. This key appears only if the "submission_uuid" argument is provided. | 
| Netcraft.Submission.has_issues | Boolean | Whether the submission contains issues. This key appears only if the "submission_uuid" argument is provided. | 
| Netcraft.Submission.has_mail | Boolean | Whether the submission has a mail. This key appears only if the "submission_uuid" argument is provided. | 
| Netcraft.Submission.has_phone_numbers | Boolean | Whether the submission contains phone numbers. This key appears only if the "submission_uuid" argument is provided. | 
| Netcraft.Submission.has_urls | Boolean | Whether the submission contains URLs. This key appears only if the "submission_uuid" argument is provided. | 
| Netcraft.Submission.is_archived | Boolean | Whether the submission has been archived. This key appears only if the "submission_uuid" argument is provided. | 
| Netcraft.Submission.last_update | Number | A unix timestamp of when this submission was last updated. This key appears only if the "submission_uuid" argument is provided. | 
| Netcraft.Submission.mail | String | An API URL to get details about the mail associated with this submission. This key appears only if the "submission_uuid" argument is provided. | 
| Netcraft.Submission.mail_state | String | The state of the mail in the submission. This key appears only if the "submission_uuid" argument is provided. | 
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
| Netcraft.SubmissionNextToken | String | The submission UUID to provide as the "next_token" argument in a subsequent request for pagination. This key appears only if the "submission_uuid" argument is \*not\* provided. | 

### netcraft-file-report-submit

***
Report files to Netcraft for analysis.

#### Base Command

`netcraft-file-report-submit`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| reporter_email | The reporter's email address, to which the result of Netcraft's analysis will be sent. | Required | 
| file_content | A base64 encoded string of the file. To report multiple files, upload the files to XSOAR and provide the file entry IDs in the "entry_id" argument. Max 10 files per submission, with a maximum combined file size of 20MiB. | Optional | 
| file_name | The name of the file. To report multiple files, upload the files to XSOAR and provide the file entry IDs in the "entry_id" argument.<br/>. | Optional | 
| entry_id | A comma separated list of XSOAR file entry IDs to report. Max 10 files per submission, with a maximum combined file size of 20MiB. The arguments "file_content" and "file_name" can be used for reporting a single file. | Optional | 
| reason | The reason the file is considered malicious, should be less than 1000 characters. | Optional | 
| polling | Use Cortex XSOAR built-in polling to wait for the report to be processed. Possible values are: true, false. Default is true. | Optional | 
| interval_in_seconds | Indicates how long to wait between command executions (in seconds) when the 'polling' argument is true. Minimum value is 10 seconds. Default is 30. | Optional | 
| timeout | Indicates the time in seconds until the polling sequence times out. Default is 600. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netcraft.Submission.date | Number | The unix timestamp of the submission. | 
| Netcraft.Submission.source_name | String | The name of the source of this submission. | 
| Netcraft.Submission.state | String | The state of the submission. One of "processing", "no threats", "suspicious" or "malicious". Note, in the case of a misclassification, a submission may be assigned a higher-severity state several days after its initial classification. | 
| Netcraft.Submission.submitter_email | String | The email address of the reporter of the submission. | 
| Netcraft.Submission.uuid | String | The unique identifier of the submission. | 
| Netcraft.Submission.classification_log.date | Number | A unix timestamp of when this state change occurred. | 
| Netcraft.Submission.classification_log.from_state | String | The state the submission moved out of. | 
| Netcraft.Submission.classification_log.to_state | String | The state the submission moved into. | 
| Netcraft.Submission.files | String | An API URL to get details about the files associated with this submission. | 
| Netcraft.Submission.has_cryptocurrency_addresses | Boolean | Whether the submission contains cryptocurrency addresses. | 
| Netcraft.Submission.has_files | Boolean | Whether the submission contains files. | 
| Netcraft.Submission.has_issues | Boolean | Whether the submission contains issues. | 
| Netcraft.Submission.has_mail | Boolean | Whether the submission has a mail. | 
| Netcraft.Submission.has_phone_numbers | Boolean | Whether the submission contains phone numbers. | 
| Netcraft.Submission.has_urls | Boolean | Whether the submission contains URLs. | 
| Netcraft.Submission.is_archived | Boolean | Whether the submission has been archived. | 
| Netcraft.Submission.last_update | Number | A unix timestamp of when this submission was last updated. | 
| Netcraft.Submission.mail | String | An API URL to get details about the mail associated with this submission. | 
| Netcraft.Submission.mail_state | String | The state of the mail in the submission. | 
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
| Netcraft.SubmissionFile.file_state | String | The classification state of the file. One of "processing", "no threats" or "malicious." | 
| Netcraft.SubmissionFile.filename | String | The name of the file. | 
| Netcraft.SubmissionFile.has_screenshot | Boolean | Whether the file has a screenshot associated with it. | 
| Netcraft.SubmissionFile.hash | String | The hash of the file. | 
| Netcraft.SubmissionFile.classification_log.date | Number | A unix timestamp of when this state change occurred. | 
| Netcraft.SubmissionFile.classification_log.from_state | String | The state the entity moved out of. | 
| Netcraft.SubmissionFile.classification_log.to_state | String | The state the entity moved into. | 

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
| InfoFile.Extension | unknown | The file extension of the screenshot. | 

### netcraft-email-report-submit

***
Report email messages to Netcraft for analysis.
The mail will be examined for malicious attachments and URLs.
Optionally, mails can be encrypted before upload. If a mail is encrypted before upload, it should be encrypted with AES-256-CBC, for example using OpenSSL.


#### Base Command

`netcraft-email-report-submit`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| reporter_email | The reporter's email address, to which the result of Netcraft's analysis will be sent. | Required | 
| message | Either a plain text string of the malicious mail in MIME format or if the "password" argument is provided, a base64 encoded AES-256-CBC encrypted mail in MIME format. Max message size is 20MiB. | Required | 
| password | The password used to encrypt/decrypt the MIME mail. Should not be provided if the mail is not encrypted. | Optional | 
| polling | Use Cortex XSOAR built-in polling to wait for the report to be processed. Possible values are: true, false. Default is true. | Optional | 
| interval_in_seconds | Indicates how long to wait between command executions (in seconds) when the 'polling' argument is true. Minimum value is 10 seconds. Default is 30. | Optional | 
| timeout | Indicates the time in seconds until the polling sequence times out. Default is 600. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netcraft.Submission.date | Number | The unix timestamp of the submission. | 
| Netcraft.Submission.source_name | String | The name of the source of this submission. | 
| Netcraft.Submission.state | String | The state of the submission. One of "processing", "no threats", "suspicious" or "malicious". Note, in the case of a misclassification, a submission may be assigned a higher-severity state several days after its initial classification. | 
| Netcraft.Submission.submitter_email | String | The email address of the reporter of the submission. | 
| Netcraft.Submission.uuid | String | The unique identifier of the submission. | 
| Netcraft.Submission.classification_log.date | Number | A unix timestamp of when this state change occurred. | 
| Netcraft.Submission.classification_log.from_state | String | The state the submission moved out of. | 
| Netcraft.Submission.classification_log.to_state | String | The state the submission moved into. | 
| Netcraft.Submission.files | String | An API URL to get details about the files associated with this submission. | 
| Netcraft.Submission.has_cryptocurrency_addresses | Boolean | Whether the submission contains cryptocurrency addresses. | 
| Netcraft.Submission.has_files | Boolean | Whether the submission contains files. | 
| Netcraft.Submission.has_issues | Boolean | Whether the submission contains issues. | 
| Netcraft.Submission.has_mail | Boolean | Whether the submission has a mail. | 
| Netcraft.Submission.has_phone_numbers | Boolean | Whether the submission contains phone numbers. | 
| Netcraft.Submission.has_urls | Boolean | Whether the submission contains URLs. | 
| Netcraft.Submission.is_archived | Boolean | Whether the submission has been archived. | 
| Netcraft.Submission.last_update | Number | A unix timestamp of when this submission was last updated. | 
| Netcraft.Submission.mail | String | An API URL to get details about the mail associated with this submission. | 
| Netcraft.Submission.mail_state | String | The state of the mail in the submission. | 
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

### netcraft-submission-mail-get

***
Get basic information about a submission's mail.
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
| Netcraft.SubmissionMail.from | String | The email addresses of the mail senders. | 
| Netcraft.SubmissionMail.hash | String | The MD5 hash of the mail associated with this submission. | 
| Netcraft.SubmissionMail.reply_to | String | The email addresses that reply messages of the mail were sent to. | 
| Netcraft.SubmissionMail.state | String | The classification state of the mail. One of "processing", "no threats" or "malicious". | 
| Netcraft.SubmissionMail.subject | String | The subject of the mail submitted. | 
| Netcraft.SubmissionMail.to | String | The email addresses of the mail recipients. | 

### netcraft-mail-screenshot-get

***
Get a screenshot for the mail associated with a submission.

#### Base Command

`netcraft-mail-screenshot-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| submission_uuid | The unique identifier of the submission from which to retrieve a mail screenshot. Submission UUIDs can be obtained by running the command "netcraft-submission-list". | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Size | number | The size of the screenshot in bytes. | 
| InfoFile.Name | string | The name of the screenshot. | 
| InfoFile.EntryID | string | The War Room entry ID of the screenshot. | 
| InfoFile.Info | string | The format and encoding of the screenshot. | 
| InfoFile.Type | string | The type of the screenshot. | 
| InfoFile.Extension | unknown | The file extension of the screenshot. | 

### netcraft-url-report-submit

***
Report URLs to Netcraft for analysis.

#### Base Command

`netcraft-url-report-submit`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| reporter_email | The reporter's email address, to which the result of Netcraft's analysis will be sent. | Required | 
| urls | A comma separated list of URLs to report. Up to 1,000 URLs per submission are permitted. | Required | 
| reason | The reason the URLs are considered malicious. Should be less than 10,000 characters. | Optional | 
| polling | Use Cortex XSOAR built-in polling to wait for the report to be processed. Possible values are: true, false. Default is true. | Optional | 
| interval_in_seconds | Indicates how long to wait between command executions (in seconds) when the 'polling' argument is true. Minimum value is 10 seconds. Default is 30. | Optional | 
| timeout | Indicates the time in seconds until the polling sequence times out. Default is 600. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netcraft.Submission.date | Number | The unix timestamp of the submission. | 
| Netcraft.Submission.source_name | String | The name of the source of this submission. | 
| Netcraft.Submission.state | String | The state of the submission. One of "processing", "no threats", "suspicious" or "malicious". Note, in the case of a misclassification, a submission may be assigned a higher-severity state several days after its initial classification. | 
| Netcraft.Submission.submitter_email | String | The email address of the reporter of the submission. | 
| Netcraft.Submission.uuid | String | The unique identifier of the submission. | 
| Netcraft.Submission.classification_log.date | Number | A unix timestamp of when this state change occurred. | 
| Netcraft.Submission.classification_log.from_state | String | The state the submission moved out of. | 
| Netcraft.Submission.classification_log.to_state | String | The state the submission moved into. | 
| Netcraft.Submission.files | String | An API URL to get details about the files associated with this submission. | 
| Netcraft.Submission.has_cryptocurrency_addresses | Boolean | Whether the submission contains cryptocurrency addresses. | 
| Netcraft.Submission.has_files | Boolean | Whether the submission contains files. | 
| Netcraft.Submission.has_issues | Boolean | Whether the submission contains issues. | 
| Netcraft.Submission.has_mail | Boolean | Whether the submission has a mail. | 
| Netcraft.Submission.has_phone_numbers | Boolean | Whether the submission contains phone numbers. | 
| Netcraft.Submission.has_urls | Boolean | Whether the submission contains URLs. | 
| Netcraft.Submission.is_archived | Boolean | Whether the submission has been archived. | 
| Netcraft.Submission.last_update | Number | A unix timestamp of when this submission was last updated. | 
| Netcraft.Submission.mail | String | An API URL to get details about the mail associated with this submission. | 
| Netcraft.Submission.mail_state | String | The state of the mail in the submission. | 
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
| Netcraft.SubmissionURL.url_state | String | The state of the url. One of "processing", "no threats", "unavailable", "malicious", "rejected", or "suspicious". | 
| Netcraft.SubmissionURL.classification_log.date | Number | A unix timestamp of when this state change occurred. | 
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
| Netcraft.SubmissionURL.sources.file_name | String | f this URL originated in a file, this is the filename. | 
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
| InfoFile.Extension | unknown | The file extension of the screenshot. | 
