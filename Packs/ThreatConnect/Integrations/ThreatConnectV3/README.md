ThreatConnect's integration is a intelligence-driven security operations solution with intelligence, automation, analytics, and workflows.
This integration was integrated and tested with version 3 of ThreatConnect v3 REST API

## ThreatConnect v3 HMAC credentials
1. On the top navigation bar, hover the cursor over the Settings icon and select Org Settings from the dropdown menu.
2. Click the Create API User button on the Membership tab of the Organization Settings screen, and the API User Administration window will be displayed.
3. Enter the following information:
    - First Name: Enter the API user’s first name.
    - Last Name: Enter the API user’s last name.
    - Organization Role: Use the dropdown menu to select an Organization role for the user.
    - Include in Observations and False Positives: Check this box to allow data provided by the API user to be included in observation and false-positive counts.
    - Disabled: Click the checkbox to disable an API user’s account in the event that the Administrator wants to retain log integrity when the API user no longer requires ThreatConnect access.
4. Record the Secret Key, as it will not be accessible after the window is closed.
5. Click **SAVE** to create the API user account.

For more information - click [here](https://training.threatconnect.com/learn/article/creating-user-accounts-kb-article) (Section - Creating an API User).

## Configure ThreatConnect v3 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ThreatConnect v3.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | -- | --- | --- |
    | Base Url | The base URL for the API| True |
    | Access ID | The API credentials | True |
    | Secret key | The API secret key| True |
    | Default Organization | The default owner for the integration | False |
    | Tags filter for the fetch | Free text box to add comma-separated tags to filter the fetched incidents by. | False |
    | Group Type filter for the fetch | The group type to filter the fetched incidents by. | False |
    | Status filter for the fetch | The status to filter the fetched incidents by \(if not field will fetch all statuses\). | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, for example, 12 hours, 7 days, 3 months, 1 year) | | True |
    | Incident Metadata | The metadata to collect. | False |
    | Source Reliability | Reliability of the source providing the intelligence data. | True |
    | Rating Threshold for Malicious Indicators (needed for reputation calculation) | Rating Threshold for Malicious Indicators. This is necessary to calculate reputation. | False |
    | Confidence Threshold for Malicious Indicators (needed for reputation calculation) | Confidence Threshold for Malicious Indicators. This is necessary to calculate reputation. | False |
    | Indicator Reputation Freshness in days (needed for reputation calculation) | Indicator Reputation Freshness.This is necessary to calculate reputation. | False |
    | Trust any certificate (not secure) | Whether or not to trust any certificate| False |
    | Use system proxy settings | Whether or not to use proxy | False |
    | Maximum number of incidents to fetch | The maximum amount of incident to fetch per run | 200 |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### ip

***
Searches for an indicator of type IP address.

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | A comma-separated list of IPv4 or IPv6 addresses. | Required | 
| owners | A comma-separated list of a client's organizations, sources, or communities to which a user has permissions. For example, users with admin permissions can search for indicators belonging to all owners. | Optional | 
| ratingThreshold | A comma-separated list of results filtered by indicators whose threat rating is greater than the specified value. Can be "0" - "Unknown", "1" - "Suspicious", "2" - "Low", "3" - Moderate, "4" - High, or "5" - "Critical". | Optional | 
| confidenceThreshold | A comma-separated list of results filtered by indicators whose confidence rating is greater than the specified value. Can be "0%" - "Unknown," "1% " - "Discredited", "2-29%" - "Improbable," "30-49%" - "Doubtful," "50-69%" - "Possible", "70-89%" - "Probable," or "90-100%" - "Confirmed". | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Indicator.Name | string | The name of the indicator. | 
| TC.Indicator.Type | string | The type of the indicator. | 
| TC.Indicator.ID | string | The ID of the indicator. | 
| TC.Indicator.Description | string | The description of the indicator. | 
| TC.Indicator.Owner | string | The owner of the indicator. | 
| TC.Indicator.CreateDate | date | The date the indicator was created. | 
| TC.Indicator.LastModified | date | The date the indicator was last modified. | 
| TC.Indicator.Rating | number | The threat rating of the indicator. | 
| TC.Indicator.Confidence | number | The confidence rating of the indicator. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| IP.Address | string | The IP address of the indicator. | 
| IP.Malicious.Vendor | string | For malicious IP addresses, the vendor that made the decision. | 
| IP.Malicious.Description | string | For malicious IP addresses, the full description. | 
| TC.Indicator.WebLink | string | The web link of the indicator. | 

### url

***
Searches for an indicator of type URL.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.

#### Base Command

`url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | A comma-separated list of URLs for which to search. For example, "www.demisto.com". | Required | 
| owners | A comma-separated list of a client's organizations, sources, or communities to which a client’s API user has been granted permission. For example, "owner1", "owner2", or "owner3". | Optional | 
| ratingThreshold | A comma-separated list of results filtered by indicators whose threat rating is greater than the specified value. Can be "0" - "Unknown", "1" - "Suspicious", "2" - "Low", "3" - Moderate, "4" - High, or "5" - "Critical". | Optional | 
| confidenceThreshold | A comma-separated list of results filtered by indicators whose confidence rating is greater than the specified value. Can be "0%" - "Unknown," "1% " - "Discredited", "2-29%" - "Improbable," "30-49%" - "Doubtful," "50-69%" - "Possible", "70-89%" - "Probable," or "90-100%" - "Confirmed". | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Indicator.Name | string | The name of the indicator. | 
| TC.Indicator.Type | string | The type of the indicator. | 
| TC.Indicator.ID | string | The ID of the indicator. | 
| TC.Indicator.Description | string | The description of the indicator. | 
| TC.Indicator.Owner | string | The owner of the indicator. | 
| TC.Indicator.CreateDate | date | The date the indicator was created. | 
| TC.Indicator.LastModified | date | The date the indicator was last modified. | 
| TC.Indicator.Rating | number | The threat rating of the indicator. | 
| TC.Indicator.Confidence | number | The confidence rating of the indicator. | 
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | string | Reliability of the source providing the intelligence data. | 
| URL.Data | string | The data of the URL indicator. | 
| URL.Malicious.Vendor | string | For malicious URLs, the vendor that made the decision. | 
| URL.Malicious.Description | string | For malicious URLs, the full description. | 
| TC.Indicator.WebLink | string | The web link of the indicator. | 

### file

***
Searches for an indicator of type file.

#### Base Command

`file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | A comma-separated list of the hashes of the files. Can be "MD5", "SHA-1", or "SHA-256". | Required | 
| owners | A comma-separated list of a client's organizations, sources, or communities to which a user has permissions. For example, users with admin permissions can search for indicators belonging to all owners. | Optional | 
| ratingThreshold | A comma-separated list of results filtered by indicators whose threat rating is greater than the specified value. Can be "0" - "Unknown", "1" - "Suspicious", "2" - "Low", "3" - Moderate, "4" - High, or "5" - "Critical". | Optional | 
| confidenceThreshold | A comma-separated list of results filtered by indicators whose confidence rating is greater than the specified value. Can be "0%" - "Unknown," "1% " - "Discredited", "2-29%" - "Improbable," "30-49%" - "Doubtful," "50-69%" - "Possible", "70-89%" - "Probable," or "90-100%" - "Confirmed". | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Indicator.Name | string | The name of the indicator. | 
| TC.Indicator.Type | string | The type of the indicator. | 
| TC.Indicator.ID | string | The ID of the indicator. | 
| TC.Indicator.Description | string | The description of the indicator. | 
| TC.Indicator.Owner | string | The owner of the indicator. | 
| TC.Indicator.CreateDate | date | The date the indicator was created. | 
| TC.Indicator.LastModified | date | The date the indicator was last modified. | 
| TC.Indicator.Rating | number | The threat rating of the indicator. | 
| TC.Indicator.Confidence | number | The confidence rating of the indicator. | 
| TC.Indicator.File.MD5 | string | The MD5 hash of the indicator. | 
| TC.Indicator.File.SHA1 | string | The SHA1 hash of the indicator. | 
| TC.Indicator.File.SHA256 | string | The SHA256 hash of the indicator. | 
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | string | Reliability of the source providing the intelligence data. | 
| File.MD5 | string | The MD5 hash of the indicator. | 
| File.SHA1 | string | The SHA1 hash of the indicator. | 
| File.SHA256 | string | The SHA256 hash of the indicator. | 
| File.Malicious.Vendor | string | For malicious files, the vendor that made the decision. | 
| File.Malicious.Description | string | For malicious files, the full description. | 
| TC.Indicator.WebLink | string | The web link of the indicator. | 

### tc-owners

***
Retrieves all owners for the current account.

#### Base Command

`tc-owners`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Owner.Name | string | The name of the owner. | 
| TC.Owner.ID | string | The ID of the owner. | 
| TC.Owner.Type | string | The type of the owner. | 

### tc-indicators

***
Retrieves a list of all indicators.

#### Base Command

`tc-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| owner | A comma-separated list of results filtered by the owner of the indicator. | Optional | 
| page | The page to take the results from. | Optional | 
| limit | The maximum number of results that can be returned. The default is 500. | Optional | 
| fields_to_return | Comma separated list of additional fields to return as part of the result indicator metadata. Possible values are: associatedGroups, associatedIndicators, observations, tags, and attributes. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Indicator.Name | string | The name of the indicator. | 
| TC.Indicator.Type | string | The type of the indicator. | 
| TC.Indicator.ID | string | The ID of the indicator. | 
| TC.Indicator.Description | string | The description of the indicator. | 
| TC.Indicator.Owner | string | The owner of the indicator. | 
| TC.Indicator.CreateDate | date | The date the indicator was created. | 
| TC.Indicator.LastModified | date | The date the indicator was last modified. | 
| TC.Indicator.Rating | number | The threat rating of the indicator. | 
| TC.Indicator.Confidence | number | The confidence rating of the indicator. | 
| TC.Indicator.WhoisActive | string | The active indicator \(for domains only\). | 
| TC.Indicator.File.MD5 | string | The MD5 hash of the indicator of the file. | 
| TC.Indicator.File.SHA1 | string | The SHA1 hash of the indicator of the file. | 
| TC.Indicator.File.SHA256 | string | The SHA256 hash of the indicator of the file. | 
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | string | Reliability of the source providing the intelligence data. | 
| IP.Address | string | The IP address of the indicator. | 
| IP.Malicious.Vendor | string | For malicious IP addresses, the vendor that made the decision. | 
| IP.Malicious.Description | string | For malicious IP addresses, the full description. | 
| URL.Data | string | The data of the URL of the indicator. | 
| URL.Malicious.Vendor | string | For malicious URLs, the vendor that made the decision. | 
| URL.Malicious.Description | string | For malicious URLs, the full description. | 
| Domain.Name | string | The name of the domain. | 
| Domain.Malicious.Vendor | string | For malicious domains, the vendor that made the decision. | 
| Domain.Malicious.Description | string | For malicious domains, the full description. | 
| File.MD5 | string | The MD5 hash of the file. | 
| File.SHA1 | string | The SHA1 hash of the file. | 
| File.SHA256 | string | The SHA256 hash of the file. | 
| File.Malicious.Vendor | string | For malicious files, the vendor that made the decision. | 
| File.Malicious.Description | string | For malicious files, the full description. | 
| TC.Indicator.WebLink | string | The web link of the indicator. | 

### tc-get-tags

***
Returns a list of all ThreatConnect tags.

#### Base Command

`tc-get-tags`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The page to take the results from. | Optional | 
| limit | The maximum number of results that can be returned. The default is 500. | Optional | 
| name | The name of the tag to get. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Tags | Unknown | A list of tags. | 

### tc-tag-indicator

***
Adds a tag to an existing indicator.

#### Base Command

`tc-tag-indicator`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag | The name of the tag. | Required | 
| indicator | The indicator to tag. For example, for an IP indicator, "8.8.8.8". | Required | 

#### Context Output

There is no context output for this command.
### tc-get-indicator

***
Retrieves information about an indicator.

#### Base Command

`tc-get-indicator`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the indicator by which to search. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Indicator.Name | string | The name of the indicator. | 
| TC.Indicator.Type | string | The type of the indicator. | 
| TC.Indicator.ID | string | The ID of the indicator. | 
| TC.Indicator.Description | string | The description of the indicator. | 
| TC.Indicator.Owner | string | The owner of the indicator. | 
| TC.Indicator.CreateDate | date | The date the indicator was created. | 
| TC.Indicator.LastModified | date | The date the indicator was last modified. | 
| TC.Indicator.Rating | number | The threat rating of the indicator. | 
| TC.Indicator.Confidence | number | The confidence rating of the indicator. | 
| TC.Indicator.WhoisActive | string | The active indicator \(for domains only\). | 
| TC.Indicator.File.MD5 | string | The MD5 hash of the indicator of the file. | 
| TC.Indicator.File.SHA1 | string | The SHA1 hash of the indicator of the file. | 
| TC.Indicator.File.SHA256 | string | The SHA256 hash of the indicator of the file. | 
| TC.Indicator.IndicatorAttributes.dateAdded | date | The date the indicator attribute was added. | 
| TC.Indicator.IndicatorAttributes.displayed | boolean | Whether to display the indicator attributes on ThreatConnect. | 
| TC.Indicator.IndicatorAttributes.id | number | The ID of the attribute. | 
| TC.Indicator.IndicatorAttributes.lastModified | date | The date the indicator attribute was last modified. | 
| TC.Indicator.IndicatorAttributes.type | string | The name of the attribute. | 
| TC.Indicator.IndicatorAttributes.value | string | The contents of the attribute. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| IP.Address | string | The IP address of the indicator. | 
| IP.Malicious.Vendor | string | For malicious IP addresses, the vendor that made the decision. | 
| IP.Malicious.Description | string | For malicious IP addresses, the full description. | 
| URL.Data | string | The data of the indicator of the URL. | 
| URL.Malicious.Vendor | string | For malicious URLs, the vendor that made the decision. | 
| URL.Malicious.Description | string | For malicious URLs, the full description. | 
| Domain.Name | string | The domain name of the indicator. | 
| Domain.Malicious.Vendor | string | For malicious domains, the vendor that made the decision. | 
| Domain.Malicious.Description | string | For malicious domains, the full description. | 
| File.MD5 | string | The MD5 hash of the file. | 
| File.SHA1 | string | The SHA1 hash of the file. | 
| File.SHA256 | string | The SHA256 hash of the file. | 
| File.Malicious.Vendor | string | For malicious files, the vendor that made the decision. | 
| File.Malicious.Description | string | For malicious files, the full description. | 
| TC.Indicator.WebLink | string | The web link of the indicator. | 

### tc-get-indicators-by-tag

***
Fetches all indicators that have a tag.

#### Base Command

`tc-get-indicators-by-tag`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag | The name of the tag by which to filter the results. | Required | 
| owner | A comma-separated list of indicators filtered by the owner. | Optional | 
| page | The page to take the results from. | Optional | 
| limit | The maximum number of results that can be returned. The default is 500. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Indicator.Name | string | The name of the tagged indicator. | 
| TC.Indicator.Type | string | The type of the tagged indicator. | 
| TC.Indicator.ID | string | The ID of the tagged indicator. | 
| TC.Indicator.Description | string | The description of the tagged indicator. | 
| TC.Indicator.Owner | string | The owner of the tagged indicator. | 
| TC.Indicator.CreateDate | date | The date the tagged indicator was created. | 
| TC.Indicator.LastModified | date | The date the tagged indicator was last modified. | 
| TC.Indicator.Rating | number | The threat rating of the tagged indicator. | 
| TC.Indicator.Confidence | number | The confidence rating of the tagged indicator. | 
| TC.Indicator.WhoisActive | string | The active indicator \(for domains only\). | 
| TC.Indicator.File.MD5 | string | The MD5 hash of the indicator of the file. | 
| TC.Indicator.File.SHA1 | string | The SHA1 hash of the indicator of the file. | 
| TC.Indicator.File.SHA256 | string | The SHA256 hash of the indicator of the file. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| IP.Address | string | The IP address of the tagged indicator. | 
| IP.Malicious.Vendor | string | For malicious IP addresses, the vendor that made the decision. | 
| IP.Malicious.Description | string | For malicious IP addresses, the full description. | 
| URL.Data | string | The data of the URL of the tagged indicator. | 
| URL.Malicious.Vendor | string | For malicious URLs, the vendor that made the decision. | 
| URL.Malicious.Description | string | For malicious URLs, the full description. | 
| Domain.Name | string | The domain name of the tagged indicator. | 
| Domain.Malicious.Vendor | string | For malicious domains, the vendor that made the decision. | 
| Domain.Malicious.Description | string | For malicious domains, the full description. | 
| File.MD5 | string | The MD5 hash of the file. | 
| File.SHA1 | string | The SHA1 hash of the file. | 
| File.SHA256 | string | The SHA256 hash of the file. | 
| File.Malicious.Vendor | string | For malicious files, the vendor that made the decision. | 
| File.Malicious.Description | string | For malicious files, the full description. | 
| TC.Indicator.WebLink | string | The web link of the indicator. | 

### tc-add-indicator

***
Adds a new indicator to ThreatConnect.

#### Base Command

`tc-add-indicator`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator | The indicator to add. | Required | 
| indicatorType | The type of the indicator. Possible values are: Address, Agent, User, Registry Key, Mutex, Hashtag, Email Subject, Subject, Email, CIDR, Host, URL, ASN, File, EmailAddress. | Required | 
| hashType | The type of hash for the file indicator. Possible values are: md5, sha1, sha256. | Optional | 
| rating | The threat rating of the indicator. Can be "0" - "Unknown", "1" - "Suspicious", "2" - "Low", "3" - Moderate, "4" - High, or "5" - "Critical". | Optional | 
| confidence | The confidence rating of the indicator. Can be "0%" - "Unknown," "1% " - "Discredited", "2-29%" - "Improbable," "30-49%" - "Doubtful," "50-69%" - "Possible", "70-89%" - "Probable," or "90-100%" - "Confirmed". | Optional | 
| tags | A comma-separated list of the tags to apply to the campaign. | Optional | 
| description | The description of the indicator. | Optional | 
| owner | The name of the owner to which the Indicator belongs. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Indicator.Name | string | The name of the indicator. | 
| TC.Indicator.Type | string | The type of indicator. | 
| TC.Indicator.ID | string | The ID of the indicator. | 
| TC.Indicator.Description | string | The description of the indicator. | 
| TC.Indicator.Owner | string | The owner of the indicator. | 
| TC.Indicator.CreateDate | date | The date the added indicator was created. | 
| TC.Indicator.LastModified | date | The date the added indicator was last modified. | 
| TC.Indicator.Rating | number | The threat rating of the indicator. | 
| TC.Indicator.Confidence | number | The confidence rating of the indicator. | 
| TC.Indicator.WhoisActive | string | The active indicator \(for domains only\). | 
| TC.Indicator.File.MD5 | string | The MD5 hash of the indicator of the file. | 
| TC.Indicator.File.SHA1 | string | The SHA1 hash of the indicator of the file. | 
| TC.Indicator.File.SHA256 | string | The SHA256 hash of the indicator of the file. | 
| IP.Address | string | The IP address of the indicator. | 
| IP.Malicious.Vendor | string | For malicious IP addresses, the vendor that made the decision. | 
| IP.Malicious.Description | string | For malicious IP addresses, the full description. | 
| URL.Data | string | The data of the URL of the indicator. | 
| URL.Malicious.Vendor | string | For malicious URLs, the vendor that made the decision. | 
| URL.Malicious.Description | string | For malicious URLs, the full description. | 
| Domain.Name | string | The name of the added indicator of the domain. | 
| Domain.Malicious.Vendor | string | For malicious domains, the vendor that made the decision. | 
| Domain.Malicious.Description | string | For malicious domains, the full description. | 
| File.MD5 | string | The MD5 hash of the file. | 
| File.SHA1 | string | The SHA1 hash of the file. | 
| File.SHA256 | string | The SHA256 hash of the file. | 
| File.Malicious.Vendor | string | For malicious files, the vendor that made the decision. | 
| File.Malicious.Description | string | For malicious files, the full description. | 
| TC.Indicator.WebLink | string | The web link of the indicator. | 

### tc-create-incident

***
Creates a new incident group.

#### Base Command

`tc-create-incident`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incidentName | The name of the incident group. | Required | 
| eventDate | The creation time of an incident in the "2017-03-21T00:00:00Z" format. | Optional | 
| tag | A comma-separated list of the tags applied to the incident. | Optional | 
| securityLabel | The security label applied to the incident. Possible values are: TLP:RED, TLP:GREEN, TLP:AMBER, TLP:WHITE. | Optional | 
| description | The description of the incident. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Incident.Name | string | The name of the new incident group. | 
| TC.Incident.Owner | string | The owner of the new incident. | 
| TC.Incident.EventDate | date | The date on which the event that indicates an incident occurred. | 
| TC.Incident.Tag | string | The name of the tag of the new incident. | 
| TC.Incident.SecurityLabel | string | The security label of the new incident. | 
| TC.Incident.ID | Unknown | The ID of the new incident. | 

### tc-incident-associate-indicator

***
Associates an indicator with an existing incident. The indicator must exist before running this command. To add an indicator, run the tc-add-indicator command.

#### Base Command

`tc-incident-associate-indicator`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incidentId | The ID of the incident to which the indicator is associated. | Required | 
| indicator | The ID of the indicator. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Indicator.Name | string | The name of the indicator. | 
| TC.Indicator.Type | string | The type of the indicator. | 
| TC.Indicator.ID | string | The ID of the indicator. | 
| TC.Indicator.Description | string | The description of the indicator. | 
| TC.Indicator.Owner | string | The owner of the indicator. | 
| TC.Indicator.CreateDate | date | The date the associated indicator was created. | 
| TC.Indicator.LastModified | date | The date the associated indicator was last modified. | 
| TC.Indicator.Rating | number | The threat rating of the indicator. | 
| TC.Indicator.Confidence | number | The confidence rating of the indicator. | 
| TC.Indicator.WhoisActive | string | The active indicator \(for domains only\). | 
| TC.Indicator.File.MD5 | string | The MD5 hash of the indicator of the file. | 
| TC.Indicator.File.SHA1 | string | The SHA1 hash of the indicator of the file. | 
| TC.Indicator.File.SHA256 | string | The SHA256 hash of the indicator of the file. | 
| IP.Address | string | IP address of the associated indicator of the file. | 
| IP.Malicious.Vendor | string | For malicious IP addresses, the vendor that made the decision. | 
| IP.Malicious.Description | string | For malicious IP addresses, the full description. | 
| URL.Data | string | The data of the URL of the associated indicator of the file. | 
| URL.Malicious.Vendor | string | For malicious URLs, the vendor that made the decision. | 
| URL.Malicious.Description | string | For malicious URLs, the full description. | 
| Domain.Name | string | The name of the indicator of the domain. | 
| Domain.Malicious.Vendor | string | For malicious domains, the vendor that made the decision. | 
| Domain.Malicious.Description | string | For malicious domains, the full description. | 
| File.MD5 | string | The MD5 hash of the file. | 
| File.SHA1 | string | The SHA1 hash of the file. | 
| File.SHA256 | string | The SHA256 hash of the file. | 
| File.Malicious.Vendor | string | For malicious files, the vendor that made the decision. | 
| File.Malicious.Description | string | For malicious files, the full description. | 
| TC.Indicator.WebLink | string | The web link of the indicator. | 

### domain

***
Searches for an indicator of type domain.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.

#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | A comma-separated list of names of the domain. | Required | 
| owners | A comma-separated list of a client's organizations, sources, or communities to which a user has permissions. For example, users with admin permissions can search for indicators belonging to all owners. | Optional | 
| ratingThreshold | A comma-separated list of results filtered by indicators whose threat rating is greater than the specified value. Can be "0" - "Unknown", "1" - "Suspicious", "2" - "Low", "3" - Moderate, "4" - High, or "5" - "Critical". | Optional | 
| confidenceThreshold | A comma-separated list of results filtered by indicators whose confidence rating is greater than the specified value. Can be "0%" - "Unknown," "1% " - "Discredited", "2-29%" - "Improbable," "30-49%" - "Doubtful," "50-69%" - "Possible", "70-89%" - "Probable," or "90-100%" - "Confirmed". | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Indicator.Name | string | The name of the indicator. | 
| TC.Indicator.Type | string | The type of the domain. | 
| TC.Indicator.ID | string | The ID of the domain. | 
| TC.Indicator.Description | string | The description of the domain. | 
| TC.Indicator.Owner | string | The owner of the domain. | 
| TC.Indicator.CreateDate | date | The date the indicator of the domain was created. | 
| TC.Indicator.LastModified | date | The date the indicator of the domain was last modified. | 
| TC.Indicator.Rating | number | The threat rating of the domain. | 
| TC.Indicator.Confidence | number | The confidence rating of the domain. | 
| TC.Indicator.WhoisActive | string | The active indicator \(for domains only\). | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| Domain.Name | string | The name of the domain. | 
| Domain.Malicious.Vendor | string | For malicious domains, the vendor that made the decision. | 
| Domain.Malicious.Description | string | For malicious domains, the full description. | 
| TC.Indicator.WebLink | string | The web link of the indicator. | 

### tc-get-incident-associate-indicators

***
Returns indicators that are related to a specific incident.

#### Base Command

`tc-get-incident-associate-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incidentId | The ID of the incident. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Indicator.Name | string | The name of the returned indicator. | 
| TC.Indicator.Type | string | The type of the returned indicator. | 
| TC.Indicator.ID | string | The ID of the returned indicator. | 
| TC.Indicator.Description | string | The description of the returned indicator. | 
| TC.Indicator.Owner | string | The owner of the returned indicator. | 
| TC.Indicator.CreateDate | date | The date the returned indicator was created. | 
| TC.Indicator.LastModified | date | The date the returned indicator was last modified. | 
| TC.Indicator.Rating | number | The threat rating of the returned indicator. | 
| TC.Indicator.Confidence | number | The confidence rating of the returned indicator. | 
| TC.Indicator.WhoisActive | string | The active indicator \(for domains only\). | 
| TC.Indicator.File.MD5 | string | The MD5 hash of the indicator of the file. | 
| TC.Indicator.File.SHA1 | string | The SHA1 hash of the indicator of the file. | 
| TC.Indicator.File.SHA256 | string | The SHA256 hash of the indicator of the file. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| IP.Address | string | The IP address of the returned indicator. | 
| IP.Malicious.Vendor | string | For malicious IP addresses, the vendor that made the decision. | 
| IP.Malicious.Description | string | For malicious IP addresses, the full description. | 
| URL.Data | string | The data of the URL of the returned indicator. | 
| URL.Malicious.Vendor | string | For malicious URLs, the vendor that made the decision. | 
| URL.Malicious.Description | string | For malicious URLs, the full description. | 
| Domain.Name | string | The name of the domain. | 
| Domain.Malicious.Vendor | string | For malicious domains, the vendor that made the decision. | 
| Domain.Malicious.Description | string | For malicious domains, the full description. | 
| File.MD5 | string | The MD5 hash of the file. | 
| File.SHA1 | string | The SHA1 hash of the file. | 
| File.SHA256 | string | The SHA256 hash of the file. | 
| File.Malicious.Vendor | string | For malicious files, the vendor that made the decision. | 
| File.Malicious.Description | string | For malicious files, the full description. | 

### tc-update-indicator

***
Updates the indicator in ThreatConnect.

#### Base Command

`tc-update-indicator`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator | The name of the updated indicator. | Required | 
| rating | The threat rating of the updated indicator. | Optional | 
| confidence | The confidence rating of the updated indicator. | Optional | 
| size | The size of the file of the updated indicator. | Optional | 
| dnsActive | Whether the DNS indicator is active (only for hosts). Possible values are: True, False. | Optional | 
| whoisActive | Whether the indicator is active (only for hosts). Possible values are: True, False. | Optional | 
| securityLabel | The security label applied to the incident. Possible values are: TLP:RED, TLP:GREEN, TLP:AMBER, TLP:WHITE. | Optional | 
| tags | A comma-separated list of tags. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Indicator.Name | string | The name of the indicator. | 
| TC.Indicator.Type | string | The type of the indicator. | 
| TC.Indicator.ID | string | The ID of the indicator. | 
| TC.Indicator.Description | string | The description of the indicator. | 
| TC.Indicator.Owner | string | The owner of the indicator. | 
| TC.Indicator.CreateDate | date | The date the indicator was created. | 
| TC.Indicator.LastModified | date | The date the indicator was last modified. | 
| TC.Indicator.Rating | number | The threat rating of the indicator. | 
| TC.Indicator.Confidence | number | The confidence rating of the indicator. | 
| TC.Indicator.WhoisActive | string | The active indicator \(for domains only\). | 
| TC.Indicator.File.MD5 | string | The MD5 hash of the indicator of the file. | 
| TC.Indicator.File.SHA1 | string | The SHA1 hash of the indicator of the file. | 
| TC.Indicator.File.SHA256 | string | The SHA256 hash of the indicator of the file. | 
| IP.Address | string | The IP address of the indicator. | 
| IP.Malicious.Vendor | string | For malicious IP addresses, the vendor that made the decision. | 
| IP.Malicious.Description | string | For malicious IP addresses, the full description. | 
| URL.Data | string | The data of the URL of the indicator. | 
| URL.Malicious.Vendor | string | For malicious URLs, the vendor that made the decision. | 
| URL.Malicious.Description | string | For malicious URLs, the full description. | 
| Domain.Name | string | The domain name of the indicator. | 
| Domain.Malicious.Vendor | string | For malicious domains, the vendor that made the decision. | 
| Domain.Malicious.Description | string | For malicious domains, the full description. | 
| File.MD5 | string | The MD5 hash of the file. | 
| File.SHA1 | string | The SHA1 hash of the file. | 
| File.SHA256 | string | The SHA256 hash of the file. | 
| File.Malicious.Vendor | string | For malicious files, the vendor that made the decision. | 
| File.Malicious.Description | string | For malicious files, the full description. | 
| TC.Indicator.WebLink | string | The web link of the indicator. | 

### tc-delete-indicator-tag

***
Removes a tag from a specified indicator.

#### Base Command

`tc-delete-indicator-tag`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator | The ID of the indicator from which to remove a tag. | Required | 
| tag | The name of the tag to remove from the indicator. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Indicator.Name | string | The name of the indicator. | 
| TC.Indicator.Type | string | The type of the indicator. | 
| TC.Indicator.ID | string | The ID of the indicator. | 
| TC.Indicator.Description | string | The description of the indicator. | 
| TC.Indicator.Owner | string | The owner of the indicator. | 
| TC.Indicator.CreateDate | date | The date the indicator was created. | 
| TC.Indicator.LastModified | date | The date the indicator was last modified. | 
| TC.Indicator.Rating | number | The threat rating of the indicator. | 
| TC.Indicator.Confidence | number | The confidence rating of the indicator. | 
| TC.Indicator.WhoisActive | string | The active indicator \(for domains only\). | 
| TC.Indicator.File.MD5 | string | The MD5 hash of the indicator of the file. | 
| TC.Indicator.File.SHA1 | string | The SHA1 hash of the indicator of the file. | 
| TC.Indicator.File.SHA256 | string | The SHA256 hash of the indicator of the file. | 
| IP.Address | string | The IP address of the indicator. | 
| IP.Malicious.Vendor | string | For malicious IP addresses, the vendor that made the decision. | 
| IP.Malicious.Description | string | For malicious IP addresses, the full description. | 
| URL.Data | string | The data of the URL of the indicator. | 
| URL.Malicious.Vendor | string | For malicious URLs, the vendor that made the decision. | 
| URL.Malicious.Description | string | For malicious URLs, the full description. | 
| Domain.Name | string | The domain name of the indicator. | 
| Domain.Malicious.Vendor | string | For malicious domains, the vendor that made the decision. | 
| Domain.Malicious.Description | string | For malicious domains, the full description. | 
| File.MD5 | string | The MD5 hash of the file. | 
| File.SHA1 | string | The SHA1 hash of the file. | 
| File.SHA256 | string | The SHA256 hash of the file. | 
| File.Malicious.Vendor | string | For malicious files, the vendor that made the decision. | 
| File.Malicious.Description | string | For malicious files, the full description. | 
| TC.Indicator.WebLink | string | The web link of the indicator. | 

### tc-delete-indicator

***
Deletes an indicator from ThreatConnect.

#### Base Command

`tc-delete-indicator`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator | The ID of the indicator to delete. | Required | 

#### Context Output

There is no context output for this command.
### tc-create-campaign

***
Creates a group based on the Campaign type.

#### Base Command

`tc-create-campaign`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the campaign group. | Required | 
| firstSeen | The date the campaign was first seen. | Optional | 
| description | The description of the campaign. | Optional | 
| tag | Comma-separated list of the tags to apply to the campaign. | Optional | 
| securityLabel | The security label applied to the incident. Possible values are: TLP:RED, TLP:GREEN, TLP:AMBER, TLP:WHITE. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Campaign.Name | string | The name of the campaign. | 
| TC.Campaign.Owner | string | The owner of the campaign. | 
| TC.Campaign.FirstSeen | date | The date the campaign was first seen. | 
| TC.Campaign.Tag | string | The tag of the campaign. | 
| TC.Campaign.SecurityLevel | string | The security label of the campaign. | 
| TC.Campaign.ID | string | The ID of the campaign. | 

### tc-create-event

***
Creates a group based on the Event type.

#### Base Command

`tc-create-event`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the event group. | Required | 
| eventDate | The date the event occurred. If the date is not specified, the current date is used. | Optional | 
| status | The status of the event. Possible values are: Needs Review, False Positive, No Further Action, Escalated. | Optional |
| tag | A comma-separated list of the tags of the event. | Optional | 
| owner_name | The name of the owner to which the group belongs. By default, events will be created in the organization in which the API user account resides. | Optional | 



#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Event.Name | string | The name of the event. | 
| TC.Event.Date | date | The date of the event. | 
| TC.Event.Status | string | The status of the event. | 
| TC.Event.Owner | string | The owner of the event. | 
| TC.Event.Tag | string | The tag of the event. | 
| TC.Event.ID | string | The ID of the event. | 
| TC.Event.Type | string | The type of the event. | 

### tc-create-threat

***
Creates a group based on the "Threats" type.

#### Base Command

`tc-create-threat`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the threat group. | Required | 
| eventDate | The creation time of a threat in the "2017-03-21T00:00:00Z" format. | Optional | 
| tags | A comma-separated list of the tags applied to the threat. | Optional | 
| securityLabel | The security label applied to the threat. Possible values are: TLP:RED, TLP:GREEN, TLP:AMBER, TLP:WHITE. | Optional | 
| description | The description of the threat. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Threat.Name | string | The name of the threat. | 
| TC.Threat.ID | string | The ID of the threat. | 

### tc-delete-group

***
Deletes a group.

#### Base Command

`tc-delete-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| groupID | A comma-separated list of the IDs of the groups to delete. | Required | 

#### Context Output

There is no context output for this command.
### tc-get-events

***
Returns a list of events.

#### Base Command

`tc-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fromDate | The date to retrieve groups from in the yyyy-mm-dd format, e.g., 1111-11-11. | Optional | 
| tag | The tag to retrieve groups by. | Optional | 
| page | The page to take the results from. | Optional | 
| limit | The maximum number of results that can be returned. The default is 500. | Optional | 
| id | A comma-separated list of IDs to filter the groups by. | Optional | 
| filter | A free text TQL filter. Refer to https://knowledge.threatconnect.com/docs/threatconnect-query-language-tql for a basic TQL guide. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Event.DateAdded | Date | The date the event was added. | 
| TC.Event.EventDate | Date | The date the event occurred. | 
| TC.Event.ID | Number | The ID of the event. | 
| TC.Event.OwnerName | String | The name of the owner of the event. | 
| TC.Event.Status | String | The status of the event. | 
| TC.Event.AssociatedGroups | String | The associated groups for the event. | 
| TC.Event.AssociatedIndicators | String | The associated indicators for the event. | 
| TC.Event.Tags | String | The tags of the event. | 

### tc-list-groups

***
Returns all groups.

#### Base Command

`tc-list-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_type | The type of the group. Possible values are: Adversary, Attack Pattern, Campaign, Course of Action, Document, E-mail, Event, Incident, Intrusion Set, Malware, Report, Signature, Tactic, Task, Threat, Tool, Vulnerability. | Optional | 
| fromDate | The date to retrieve groups from in the yyyy-mm-dd format, e.g., 1111-11-11. | Optional | 
| tag | The tag to retrieve groups by. | Optional | 
| page | The page to take the results from. | Optional | 
| limit | The maximum number of results that can be returned. The default is 500. | Optional | 
| id | A comma-separated list of IDs to filter the groups by. | Optional | 
| filter | A free text TQL filter. Refer to https://knowledge.threatconnect.com/docs/threatconnect-query-language-tql for a basic TQL guide. | Optional | 
| include_tags | Add group tags metadata to the results. | Optional | 
| include_security_labels | Add group security labels metadata to the results. | Optional | 
| include_attributes | Add group attributes metadata to the results. | Optional | 
| include_associated_groups | Add group associated groups metadata to the results. | Optional | 
| include_associated_indicators | Add group associated indicators metadata to the results. | Optional | 
| include_all_metaData | Add all group metadata to the results. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Group.DateAdded | Date | The date the group was added. | 
| TC.Group.EventDate | Date | The date the event occurred. | 
| TC.Group.Name | String | The name of the group. | 
| TC.Group.OwnerName | String | The name of the owner of the group. | 
| TC.Group.Status | String | The status of the group. | 
| TC.Group.ID | Number | The ID of the group. | 

### tc-add-group-tag

***
Adds tags to a specified group.

#### Base Command

`tc-add-group-tag`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | The ID of the group to which to add the tag. To get the ID, run the tc-list-groups command. | Required | 
| tag_name | The name of the tag to add to the group. | Required | 

#### Context Output

There is no context output for this command.
### tc-get-indicator-types

***
Returns all indicator types available.

#### Base Command

`tc-get-indicator-types`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.IndicatorType.ApiBranch | String | The branch of the API. | 
| TC.IndicatorType.ApiEntity | String | The entity of the API. | 
| TC.IndicatorType.CasePreference | String | The case preference of the indicator. For example, "sensitive", "upper", or "lower". | 
| TC.IndicatorType.Custom | Boolean | Whether the indicator is a custom indicator. | 
| TC.IndicatorType.Parsable | Boolean | Whether the indicator can be parsed. | 
| TC.IndicatorType.Value1Type | String | The value type of the indicator. | 
| TC.IndicatorType.Value1Label | String | The value label of the indicator. | 

### tc-create-document-group

***
Creates a document group.

#### Base Command

`tc-create-document-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_name | The name of the file to display in the UI. | Required | 
| name | The name of the group. | Required | 
| malware | Whether the file is malware. If "true", ThreatConnect creates a password-protected ZIP file on your local machine that contains the sample and uploads the ZIP file. Possible values are: true, false. | Optional | 
| password | The password of the ZIP file. | Optional | 
| security_label | The security label applied to the document. Possible values are: TLP:RED, TLP:GREEN, TLP:AMBER, TLP:WHITE. | Optional | 
| description | A description of the group. | Optional | 
| entry_id | The ID of the entry, as displayed in the War Room. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Group.Name | String | The name of the group. | 
| TC.Group.Owner | String | The owner of the group. | 
| TC.Group.EventDate | Date | The date the group was created. | 
| TC.Group.Description | String | The description of the group. | 
| TC.Group.SecurityLabel | String | The security label of the group. | 
| TC.Group.ID | Number | The ID of the group to which the attribute was added. | 

### tc-download-document

***
Downloads the contents of a document.

#### Base Command

`tc-download-document`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| document_id | The ID of the document. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | Number | The size of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.Name | String | The name of the file. | 
| File.SSDeep | String | The ssdeep hash of the file \(same as displayed in file entries\). | 
| File.EntryID | String | The entry ID of the file. | 
| File.Info | String | The information of the file. | 
| File.Type | String | The type of the file. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.Extension | String | The extension of the file. | 

### tc-get-associated-groups

***
Returns groups associated with a specified group.

#### Base Command

`tc-get-associated-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | The ID of the group. To get the ID, run the tc-list-groups command. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Group.AssociatedGroup.DateAdded | Date | The date the group was added. | 
| TC.Group.AssociatedGroup.GroupID | Number | The ID of the group. | 
| TC.Group.AssociatedGroup.Name | String | The name of the group. | 
| TC.Group.AssociatedGroup.OwnerName | String | The name of the owner of the group. | 
| TC.Group.AssociatedGroup.Type | String | The type of the group. | 

### tc-get-indicator-owners

***
Get the owner for an indicator.

#### Base Command

`tc-get-indicator-owners`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator | Indicator ID. | Required | 

#### Context Output

There is no context output for this command.
### tc-download-report

***
The group report to download in PDF format.

#### Base Command

`tc-download-report`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | The ID of the group. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | Number | The size of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.Name | String | The name of the file. | 
| File.SSDeep | String | The ssdeep hash of the file. | 
| File.EntryID | String | The entry ID of the file. | 
| File.Info | String | The information of the file. | 
| File.Type | String | The type of the file. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.Extension | String | The extension of the file. | 

### tc-update-group

***
Updates a group.

#### Base Command

`tc-update-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the group. | Required | 
| custom_field | Custom fields for the group. | Optional | 
| tags | A comma-separated list of The tags applied to the threat. | Optional | 
| security_label | The security label applied to the threat. Possible values are: TLP:RED, TLP:GREEN, TLP:AMBER, TLP:WHITE. | Optional | 
| associated_group_id | An ID to associate a group by. | Optional | 
| associated_indicator_id | An ID to associate an indicator by. | Optional | 
| mode | The type of update to the group metadata(associated indicators, attributes,tags etc.). Possible values are: append, delete, replace. | Optional | 
| attribute_value | The value of the attribute to associate. | Optional | 
| attribute_type | The type of the attribute to associate. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Group.Name | string | The name of the group. | 
| TC.Group.Owner | string | The owner of the group. | 
| TC.Group.Tag | string | The tag of the group. | 
| TC.Group.SecurityLevel | string | The security label of the group. | 
| TC.Group.ID | string | The ID of the group. | 

### Redundant Arguments
The following arguments were removed in this version:

In the *tc-tag-indicator* command:
* *owner* - this argument was redundant.

In the *tc-get-indicator* command:
* *indicator_type* - this argument was redundant.
* *owners* - this argument was redundant.
* *ratingThreshold* - this argument was redundant.
* *confidenceThreshold* - this argument was redundant.
* *group_associations* - this argument was redundant.
* *indicator_associations* - this argument was redundant.
* *indicator_observations* - this argument was redundant.
* *indicator_tags* - this argument was redundant.
* *indicator_attributes* - this argument was redundant.

In the *tc-add-indicator* command:
* *owner* - this argument was redundant.

In the *tc-create-incident* command:
* *owner* - this argument was redundant.

In the *tc-fetch-incidents* command:
* *incidentName* - this argument was redundant.

In the *tc-incident-associate-indicator* command:
* *indicatorType* - this argument was redundant.
* *owner* - this argument was redundant.

In the *tc-get-incident-associate-indicators* command:
* *owner* - this argument was redundant.

In the *tc-update-indicator* command:
* *observations* - this argument was redundant.
* *threatAssessConfidence* - this argument was redundant.
* *threatAssessRating* - this argument was redundant.
* *owner* - this argument was redundant.

In the *tc-create-campaign* command:
* *owner* - this argument was redundant.

In the *tc-create-event* command:
* *owner* - this argument was redundant.

In the *tc-delete-group* command:
* *type* - this argument was redundant.

In the *tc-add-group-attribute* command:
* *group_type* - this argument was redundant.

In the *tc-add-group-security-label* command:
* *group_type* - this argument was redundant.

In the *tc-add-group-tag* command:
* *group_type* - this argument was redundant.

In the *tc-group-associate-indicator* command:
* *indicator_type* - this argument was redundant.
* *group_type* - this argument was redundant.

In the *tc-get-group* command:
* *group_type* - this argument was redundant.

In the *tc-get-group-attributes* command:
* *group_type* - this argument was redundant.

In the *tc-get-group-security-labels* command:
* *group_type* - this argument was redundant.

In the *tc-get-group-tags* command:
* *group_type* - this argument was redundant.

In the *tc-get-group-indicators* command:
* *group_type* - this argument was redundant.

In the *tc-get-associated-groups* command:
* *group_type* - this argument was redundant.

In the *tc-associate-group-to-group* command:
* *group_type* - this argument was redundant.
* *associated_group_type* - this argument was redundant.

In the *tc-download-report* command:
* *group_type* - this argument was redundant.


## Additional Considerations for this version
API version 3 [documentation](https://docs.threatconnect.com/en/latest/rest_api/rest_api.html#v3-api)
Use the new REST v3 API instead of the old python module.
### tc-create-victim-attribute

***
Creates a victim attribute.

#### Base Command

`tc-create-victim-attribute`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| victim_id | The ID of the victim. | Required | 
| security_labels | A comma-separated list of the security labels to apply to the victim attribute. Possible values are: TLP:RED, TLP:GREEN, TLP:AMBER, TLP:WHITE, TLP:AMBER+STRICT, TLP:CLEAR. | Optional | 
| attribute_type | The attribute type. Possible values are: Additional Analysis and Context, Description, External ID, Impact Description, Impact Score, Physical Address, Response Team &amp; Staff involved, Source, Takedown Requests, Targeted Industry Sector, Title. | Required | 
| attribute_value | The attribute value. | Required | 
| source | The attribute source. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.VictimAttribute.dateAdded | string | The date that the victim attribute was added. | 
| TC.VictimAttribute.default | string | Whether the attribute is the default attribute of its type for the victim to which it is added. | 
| TC.VictimAttribute.id | string | The ID of the victim attribute. | 
| TC.VictimAttribute.lastModified | string | The date that the victim attribute was last modified. | 
| TC.VictimAttribute.pinned | string | Whether the victim attribute is pinned. | 
| TC.VictimAttribute.type | string | The type of the victim attribute. | 
| TC.VictimAttribute.value | string | The value of the victim attribute. | 
| TC.VictimAttribute.createdBy.firstName | string | The first name of the user who created the victim attribute. | 
| TC.VictimAttribute.createdBy.id | string | The ID of the victim the attribute associated to. | 
| TC.VictimAttribute.createdBy.lastName | string | The last name of the user who created the victim attribute. | 
| TC.VictimAttribute.createdBy.owner | string | The owner of the user who created the victim attribute. | 
| TC.VictimAttribute.createdBy.pseudonym | string | The pseudonym of the user who created the victim attribute. | 
| TC.VictimAttribute.createdBy.userName | string | The user name of the user who created the victim attribute. | 

#### Command example
```!tc-create-victim-attribute attribute_type="Takedown Requests" victim_id=668 attribute_value="test"```
#### Context Example
```json
{
    "TC": {
        "VictimAttribute": {
            "createdBy": {
                "firstName": "Demisto API",
                "id": 615,
                "lastName": "Demisto API",
                "owner": "Palo Alto Cortex XSOAR",
                "pseudonym": "APIUsersTest",
                "userName": "test"
            },
            "dateAdded": "2024-01-04T13:24:53Z",
            "default": false,
            "id": 133,
            "lastModified": "2024-01-04T13:24:53Z",
            "pinned": false,
            "type": "Takedown Requests",
            "value": "test"
        }
    }
}
```

#### Human Readable Output

>Victim Attribute 133 created successfully for victim id: 668
### tc-create-victim

***
Creates a victim.

#### Base Command

`tc-create-victim`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the victim. | Required | 
| nationality | The nationality of the victim. | Optional | 
| org | The organization of the victim. | Optional | 
| sub_org | The sub-organization of the victim. | Optional | 
| security_labels | A comma-separated list of the security labels to apply to the victim. Possible values are: TLP:RED, TLP:GREEN, TLP:AMBER, TLP:WHITE, TLP:AMBER+STRICT, TLP:CLEAR. | Optional | 
| tags | A comma-separated list of tags. | Optional | 
| work_location | The work location of the victim. | Optional | 
| asset_type | The asset type of the victim. Possible values are: EmailAddress, NetworkAccount, Phone, SocialNetwork, WebSite. | Optional | 
| asset_value | The asset value of the victim. | Optional | 
| asset_address_type | The asset address type. Relevant only when the asset_type is EmailAddress. | Optional | 
| asset_network_type | The asset network type. Relevant only when the asset_type is NetworkAccount. | Optional | 
| asset_social_network | The asset social network. Required only when the asset_type is SocialNetwork. | Optional | 
| associated_groups_ids | A comma-separated list of group IDs to associate to the victim. | Optional | 
| attribute_type | The attribute type to associate to the victim. Possible values are: Additional Analysis and Context, Description, External ID, Impact Description, Impact Score, Physical Address, Response Team &amp; Staff involved, Source, Takedown Requests, Targeted Industry Sector, Title. | Optional | 
| attribute_value | The attribute value to associate to the victim. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Victim.Name | string | The name of the victim. | 
| TC.Victim.ownerId | string | The owner ID of the victim. | 
| TC.Victim.id | string | The ID of the victim. | 
| TC.Victim.ownerName | string | The owner name of the victim. | 
| TC.Victim.webLink | string | The web link of the victim. | 
| TC.Victim.description | string | The description of the victim. | 
| TC.Victim.org | string | The organization of the victim. | 
| TC.Victim.suborg | string | The sub-organization of the victim. | 
| TC.Victim.workLocation | string | The work location of the victim. | 
| TC.Victim.nationality | string | The nationality of the victim. | 

#### Command example
```!tc-create-victim name="test" org="test" asset_type="EmailAddress" asset_value="test@test.com" attribute_type="Description" attribute_value="test"```
#### Context Example
```json
{
    "TC": {
        "Victim": {
            "id": 671,
            "name": "test",
            "org": "test",
            "ownerId": 271,
            "ownerName": "Palo Alto Cortex XSOAR",
            "webLink": "https://threatconnect.com/auth/victim/victim.xhtml?victim=671"
        }
    }
}
```

#### Human Readable Output

>Victim test created successfully with id: 671 
### tc-create-victim-asset

***
Creates a victim asset.

#### Base Command

`tc-create-victim-asset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| victim_id | The ID of the victim. | Required | 
| asset_type | The asset type. Possible values are: EmailAddress, NetworkAccount, Phone, SocialNetwork, WebSite. | Required | 
| asset_value | The asset value. | Required | 
| asset_address_type | The asset address type. Relevant only when the asset_type is EmailAddress. | Optional | 
| asset_network_type | The asset network type. Relevant only when the asset_type is NetworkAccount. | Optional | 
| asset_social_network | The asset social network. Required only when the asset_type is SocialNetwork. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.VictimAsset.id | string | The ID of the victim asset. | 
| TC.VictimAsset.type | string | The type of the victim asset. | 
| TC.VictimAsset.victimId | string | The ID of the victim. | 
| TC.VictimAsset.webLink | string | The web link of the victim asset. | 
| TC.VictimAsset.phone | string | The phone number of the victim asset. | 
| TC.VictimAsset.address | string | The address of the victim asset. | 
| TC.VictimAsset.accountName | string | The account name of the victim asset. | 
| TC.VictimAsset.addressType | string | The address type of the victim asset. | 
| TC.VictimAsset.networkType | string | The network type of the victim asset. | 
| TC.VictimAsset.socialNetwork | string | The social network of the victim asset. | 
| TC.VictimAsset.website | string | The website of the victim asset. | 

#### Command example
```!tc-create-victim-asset victim_id=668 asset_type=SocialNetwork asset_value=test asset_social_network=test```
#### Context Example
```json
{
    "TC": {
        "VictimAsset": {
            "accountName": "test",
            "id": 753,
            "socialNetwork": "test",
            "type": "SocialNetwork",
            "victimId": 668,
            "webLink": "https://threatconnect.com/auth/victim/victim.xhtml?victim=668"
        }
    }
}
```

#### Human Readable Output

>Victim Asset 753 created successfully for victim id: 668

### tc-list-victim-assets

***
Retrieves victim assets.

#### Base Command

`tc-list-victim-assets`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| victim_asset_id | The ID of a specific victim asset to retrieve. If not specified, all victim assets will be retrieved. | Optional | 
| filter | A free text TQL filter. Refer to https://knowledge.threatconnect.com/docs/threatconnect-query-language-tql for a basic TQL guide. | Optional | 
| page | The page to take the results from. The first is 0. Default is 0. | Optional | 
| limit | The maximum number of results that can be returned. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.VictimAsset.id | string | The ID of the victim asset. | 
| TC.VictimAsset.type | string | The type of the victim asset. | 
| TC.VictimAsset.victimId | string | The ID of the victim. | 
| TC.VictimAsset.webLink | string | The web link of the victim asset. | 
| TC.VictimAsset.phone | string | The phone number of the victim asset. | 
| TC.VictimAsset.address | string | The address of the victim asset. | 
| TC.VictimAsset.accountName | string | The account name of the victim asset. | 
| TC.VictimAsset.addressType | string | The address type of the victim asset. | 
| TC.VictimAsset.networkType | string | The network type of the victim asset. | 
| TC.VictimAsset.socialNetwork | string | The social network of the victim asset. | 
| TC.VictimAsset.website | string | The website of the victim asset. | 

#### Command example
```!tc-list-victim-assets limit=1```
#### Context Example
```json
{
    "TC": {
        "VictimAsset": {
            "id": 740,
            "phone": "111111",
            "type": "Phone",
            "victimId": 660,
            "webLink": "https://threatconnect.com/auth/victim/victim.xhtml?victim=660"
        }
    }
}
```

#### Human Readable Output

>### Victim assets
>|id|type|victimId|asset|
>|---|---|---|---|
>| 740 | Phone | 660 | 111111 |

### tc-list-victim-attributes

***
Retrieves victim attributes.

#### Base Command

`tc-list-victim-attributes`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| victim_attribute_id | The ID of a specific victim attribute to retrieve. If not specified, all victim attributes will be retrieved. | Optional | 
| victim_id | The ID of a specific victim to retrieve its attributes. | Optional | 
| filter | A free text TQL filter. Refer to https://knowledge.threatconnect.com/docs/threatconnect-query-language-tql for a basic TQL guide. | Optional | 
| page | The page to take the results from. The first is 0. Default is 0. | Optional | 
| limit | The maximum number of results that can be returned. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.VictimAttribute.dateAdded | string | The date that the victim attribute was added. | 
| TC.VictimAttribute.default | string | Whether the attribute is the default attribute of its type for the victim to which it is added. | 
| TC.VictimAttribute.id | string | The ID of the victim attribute. | 
| TC.VictimAttribute.lastModified | string | The date that the victim attribute was last modified. | 
| TC.VictimAttribute.pinned | string | Whether the victim attribute is pinned. | 
| TC.VictimAttribute.type | string | The type of the victim attribute. | 
| TC.VictimAttribute.value | string | The value of the victim attribute. | 
| TC.VictimAttribute.createdBy.firstName | string | The first name of the user who created the victim attribute. | 
| TC.VictimAttribute.createdBy.id | string | The ID of the victim the attribute associated to. | 
| TC.VictimAttribute.createdBy.lastName | string | The last name of the user who created the victim attribute. | 
| TC.VictimAttribute.createdBy.owner | string | The owner of the user who created the victim attribute. | 
| TC.VictimAttribute.createdBy.pseudonym | string | The pseudonym of the user who created the victim attribute. | 
| TC.VictimAttribute.createdBy.userName | string | The user name of the user who created the victim attribute. | 

#### Command example
```!tc-list-victim-attributes limit=1```
#### Context Example
```json
{
    "TC": {
        "VictimAttribute": {
            "createdBy": {
                "firstName": "Demisto API",
                "id": 615,
                "lastName": "Demisto API",
                "owner": "Palo Alto Cortex XSOAR",
                "pseudonym": "APIUsersTest",
                "userName": "08265138623174323158"
            },
            "dateAdded": "2024-01-04T13:24:57Z",
            "default": false,
            "id": 134,
            "lastModified": "2024-01-04T13:24:57Z",
            "pinned": false,
            "type": "Description",
            "value": "test"
        }
    }
}
```

#### Human Readable Output

>### Victim attributes
>|id|type|value|dateAdded|
>|---|---|---|---|
>| 134 | Description | test | 2024-01-04T13:24:57Z |

### tc-list-victims

***
Retrieves victims.

#### Base Command

`tc-list-victims`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| victim_id | The ID of a specific victim to retrieve. If not specified, all victims will be retrieved. | Optional | 
| filter | A free text TQL filter. Refer to https://knowledge.threatconnect.com/docs/threatconnect-query-language-tql for a basic TQL guide. | Optional | 
| include_assets | Whether to add victim's assets metadata to the result. Possible values are: true, false. Default is false. | Optional | 
| include_associated_groups | Whether to add victim's associated groups metadata to the result. Possible values are: true, false. Default is false. | Optional | 
| include_attributes | Whether to add victim's attributes metadata to the result. Possible values are: true, false. Default is false. | Optional | 
| include_security_labels | Whether to add victim's security labels metadata to the result. Possible values are: true, false. Default is false. | Optional | 
| include_all_metaData | Whether to add all victim metadata to the results. Possible values are: true, false. Default is false. | Optional | 
| page | The page to take the results from. The first is 0. Default is 0. | Optional | 
| limit | The maximum number of results that can be returned. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Victim.id | Number | The victim's ID. | 
| TC.Victim.securityLabels.data.id | Number | The security label ID. | 
| TC.Victim.securityLabels.data.name | String | The security label name. | 
| TC.Victim.securityLabels.data.description | String | The security label description. | 
| TC.Victim.securityLabels.data.color | String | The security label color. | 
| TC.Victim.securityLabels.data.owner | String | The security label owner. | 
| TC.Victim.securityLabels.data.dateAdded | Date | The security label date added. | 
| TC.Victim.ownerId | Number | The victim's owner ID. | 
| TC.Victim.ownerName | String | The victim's owner name. | 
| TC.Victim.webLink | String | The victim's web link. | 
| TC.Victim.tags.data.id | Number | The victim's tag ID. | 
| TC.Victim.tags.data.name | String | The victim's tag name. | 
| TC.Victim.tags.data.lastUsed | Date | The victim's tag last use. | 
| TC.Victim.name | String | The victim's name. | 
| TC.Victim.description | String | The victim's description. | 
| TC.Victim.org | String | The victim's organization. | 
| TC.Victim.workLocation | String | The victim's work location. | 
| TC.Victim.nationality | String | The victim's nationality. | 
| TC.Victim.suborg | String | The victim's sub-organization. | 
| TC.Victim.assets.data.id | Number | The victim asset ID. | 
| TC.Victim.assets.data.type | String | The victim asset type. | 
| TC.Victim.assets.data.victimId | Number | The victim asset victim ID. | 
| TC.Victim.assets.data.phone | String | The victim asset phone number. | 
| TC.Victim.assets.data.webLink | String | The victim asset web link. | 
| TC.Victim.assets.data.website | String | The victim asset website. | 
| TC.Victim.assets.data.accountName | String | The victim asset account name. | 
| TC.Victim.assets.data.networkType | String | The victim asset network type. | 
| TC.Victim.assets.data.address | String | The victim asset address. | 
| TC.Victim.assets.data.addressType | String | The victim asset address type. | 
| TC.Victim.assets.data.socialNetwork | String | The victim asset social network. | 
| TC.Victim.associatedGroups.id | Unknown | The victim's associated group ID. | 
| TC.Victim.attributes.data.id | Number | The victim attribute ID. | 
| TC.Victim.attributes.data.dateAdded | Date | The victim attribute date added. | 
| TC.Victim.attributes.data.type | String | The victim attribute type. | 
| TC.Victim.attributes.data.value | String | The victim attribute value. | 
| TC.Victim.attributes.data.source | String | The victim attribute source. | 
| TC.Victim.attributes.data.createdBy.id | Number | The victim attribute creator ID. | 
| TC.Victim.attributes.data.createdBy.userName | String | The victim attribute creator user name. | 
| TC.Victim.attributes.data.createdBy.firstName | String | The victim attribute creator first name. | 
| TC.Victim.attributes.data.createdBy.lastName | String | The victim attribute creator last name. | 
| TC.Victim.attributes.data.createdBy.pseudonym | String | The victim attribute creator pseudonym. | 
| TC.Victim.attributes.data.createdBy.owner | String | The victim attribute creator owner. | 
| TC.Victim.attributes.data.lastModified | Date | The victim attribute last modified time. | 
| TC.Victim.attributes.data.pinned | String | Whether the victim attribute is pinned. | 
| TC.Victim.attributes.data.default | String | Whether the victim attribute is default. | 

#### Command example
```!tc-list-victims limit=1```
#### Context Example
```json
{
    "TC": {
        "Victim": {
            "id": 663,
            "name": "nat",
            "ownerId": 271,
            "ownerName": "Palo Alto Cortex XSOAR",
            "webLink": "https://threatconnect.com/auth/victim/victim.xhtml?victim=663"
        }
    }
}
```

#### Human Readable Output

>### Victims
>|id|name|ownerName|description|org|
>|---|---|---|---|---|
>| 663 | nat | Palo Alto Cortex XSOAR |  |  |

### tc-update-victim

***
Updates a victim.

#### Base Command

`tc-update-victim`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| victim_id | The ID of the victim. | Required | 
| name | The name of the victim. | Optional | 
| nationality | The nationality of the victim. | Optional | 
| org | The organization of the victim. | Optional | 
| sub_org | The sub-organization of the victim. | Optional | 
| security_labels | A comma-separated list of the security labels to apply to the victim. Possible values are: TLP:RED, TLP:GREEN, TLP:AMBER, TLP:WHITE, TLP:AMBER+STRICT, TLP:CLEAR. | Optional | 
| tags | A comma-separated list of tags. | Optional | 
| work_location | The work location of the victim. | Optional | 
| asset_type | The asset type of the victim. Possible values are: EmailAddress, NetworkAccount, Phone, SocialNetwork, WebSite. | Optional | 
| asset_value | The asset value of the victim. | Optional | 
| asset_address_type | The asset address type. Relevant only when the asset_type is EmailAddress. | Optional | 
| asset_network_type | The asset network type. Relevant only when the asset_type is NetworkAccount. | Optional | 
| asset_social_network | The asset social network. Relevant only when the asset_type is SocialNetwork. | Optional | 
| associated_groups_ids | A comma-separated list of group IDs to associate to the victim. | Optional | 
| attribute_type | The attribute type to associate to the victim. Possible values are: Additional Analysis and Context, Description, External ID, Impact Description, Impact Score, Physical Address, Response Team &amp; Staff involved, Source, Takedown Requests, Targeted Industry Sector, Title. | Optional | 
| attribute_value | The attribute value to associate to the victim. | Optional | 
| mode | The mode of the update operation. Relevant for associated groups, attributes, security labels and tags. Possible values are: append, delete, replace. Default is append. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Victim.Name | string | The name of the victim. | 
| TC.Victim.ownerId | string | The owner ID of the victim. | 
| TC.Victim.id | string | The ID of the victim. | 
| TC.Victim.ownerName | string | The owner name of the victim. | 
| TC.Victim.webLink | string | The web link of the victim. | 
| TC.Victim.description | string | The description of the victim. | 
| TC.Victim.org | string | The organization of the victim. | 
| TC.Victim.suborg | string | The sub-organization of the victim. | 
| TC.Victim.workLocation | string | The work location of the victim. | 
| TC.Victim.nationality | string | The nationality of the victim. | 

#### Command example
```!tc-update-victim victim_id=668 mode=append attribute_type="Source" attribute_value="test"```
#### Context Example
```json
{
    "TC": {
        "Victim": {
            "id": 668,
            "name": "nat",
            "ownerId": 271,
            "ownerName": "Palo Alto Cortex XSOAR",
            "webLink": "https://threatconnect.com/auth/victim/victim.xhtml?victim=668"
        }
    }
}
```

#### Human Readable Output

>Victim 668 was successfully updated.
### tc-update-victim-asset

***
Updates a victim asset.

#### Base Command

`tc-update-victim-asset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| victim_asset_id | The ID of the victim asset. | Required | 
| asset_value | The asset value. | Required | 
| asset_address_type | The asset address type. Relevant only when the asset_type is EmailAddress. | Optional | 
| asset_network_type | The asset network type. Relevant only when the asset_type is NetworkAccount. | Optional | 
| asset_social_network | The asset social network. Required only when the asset_type is SocialNetwork. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.VictimAsset.id | string | The ID of the victim asset. | 
| TC.VictimAsset.type | string | The type of the victim asset. | 
| TC.VictimAsset.victimId | string | The ID of the victim. | 
| TC.VictimAsset.webLink | string | The web link of the victim asset. | 
| TC.VictimAsset.phone | string | The phone number of the victim asset. | 
| TC.VictimAsset.address | string | The address of the victim asset. | 
| TC.VictimAsset.accountName | string | The account name of the victim asset. | 
| TC.VictimAsset.addressType | string | The address type of the victim asset. | 
| TC.VictimAsset.networkType | string | The network type of the victim asset. | 
| TC.VictimAsset.socialNetwork | string | The social network of the victim asset. | 
| TC.VictimAsset.website | string | The website of the victim asset. | 

#### Command example
```!tc-update-victim-asset victim_asset_id=750 asset_value="11111"```
#### Context Example
```json
{
    "TC": {
        "VictimAsset": {
            "id": 750,
            "phone": "11111",
            "type": "Phone",
            "victimId": 669,
            "webLink": "https://threatconnect.com/auth/victim/victim.xhtml?victim=669"
        }
    }
}
```

#### Human Readable Output

>Victim Asset 750 updated successfully for victim id: 669
### tc-update-victim-attribute

***
Updates a victim attribute.

#### Base Command

`tc-update-victim-attribute`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| victim_attribute_id | The ID of the victim attribute. | Required | 
| security_labels | A comma-separated list of the security labels to apply to the victim attribute. Possible values are: TLP:RED, TLP:GREEN, TLP:AMBER, TLP:WHITE, TLP:AMBER+STRICT, TLP:CLEAR. | Optional | 
| attribute_value | The attribute value. | Required | 
| source | The attribute source. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.VictimAttribute.dateAdded | string | The date that the victim attribute was added. | 
| TC.VictimAttribute.default | string | Whether the attribute is the default attribute of its type for the victim to which it is added. | 
| TC.VictimAttribute.id | string | The ID of the victim attribute. | 
| TC.VictimAttribute.lastModified | string | The date that the victim attribute was last modified. | 
| TC.VictimAttribute.pinned | string | Whether the victim attribute is pinned. | 
| TC.VictimAttribute.type | string | The type of the victim attribute. | 
| TC.VictimAttribute.value | string | The value of the victim attribute. | 
| TC.VictimAttribute.createdBy.firstName | string | The first name of the user who created the victim attribute. | 
| TC.VictimAttribute.createdBy.id | string | The ID of the victim the attribute associated to. | 
| TC.VictimAttribute.createdBy.lastName | string | The last name of the user who created the victim attribute. | 
| TC.VictimAttribute.createdBy.owner | string | The owner of the user who created the victim attribute. | 
| TC.VictimAttribute.createdBy.pseudonym | string | The pseudonym of the user who created the victim attribute. | 
| TC.VictimAttribute.createdBy.userName | string | The user name of the user who created the victim attribute. | 

#### Command example
```!tc-update-victim-attribute victim_attribute_id="132" attribute_value="test2"```
#### Context Example
```json
{
    "TC": {
        "VictimAttribute": {
            "createdBy": {
                "firstName": "Demisto API",
                "id": 615,
                "lastName": "Demisto API",
                "owner": "Palo Alto Cortex XSOAR",
                "pseudonym": "APIUsersTest",
                "userName": "test"
            },
            "dateAdded": "2024-01-04T09:14:16Z",
            "default": false,
            "id": 132,
            "lastModified": "2024-01-04T13:25:19Z",
            "pinned": false,
            "type": "Source",
            "value": "test2"
        }
    }
}
```

#### Human Readable Output

>Victim attribute 132 was successfully updated.
### tc-delete-victim-asset

***
Deletes a victim asset.

#### Base Command

`tc-delete-victim-asset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| victim_asset_id | The ID of the victim asset. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!tc-delete-victim-asset victim_asset_id=738```
#### Human Readable Output

>Victim asset 738 was successfully deleted.
### tc-delete-victim-attribute

***
Deletes a victim attribute.

#### Base Command

`tc-delete-victim-attribute`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| victim_attribute_id | The ID of the victim attribute. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!tc-delete-victim-attribute victim_attribute_id=110```
#### Human Readable Output

>Victim attribute 110 was successfully deleted.
### tc-list-attribute-type

***
Retrieved all attribute types

#### Base Command

`tc-list-attribute-type`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| attribute_type_id | A specific attribute type to retrieve. If not specified, all attribute types will be retrieved. | Optional | 
| page | The page to take the results from. The first is 0. Default is 0. | Optional | 
| limit | The maximum number of results that can be returned. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.AttributeType.allowMarkdown | string | Whether the attribute type markdown allowed. | 
| TC.AttributeType.description | string | The attribute type description. | 
| TC.AttributeType.name | string | The attribute type name. | 
| TC.AttributeType.errorMessage | string | The attribute type error message. | 
| TC.AttributeType.id | string | The attribute type ID. | 
| TC.AttributeType.maxSize | string | The attribute type maximum size. | 
| TC.AttributeType.TC.AttributeType.validationRule.description | string | The attribute type validation rule description. | 
| TC.AttributeType.TC.AttributeType.validationRule.id | string | The attribute type validation rule ID. | 
| TC.AttributeType.TC.AttributeType.validationRule.name | string | The attribute type validation rule name. | 
| TC.AttributeType.TC.AttributeType.validationRule.text | string | The attribute type validation rule text. | 
| TC.AttributeType.TC.AttributeType.validationRule.type | string | The attribute type validation rule type. | 
| TC.AttributeType.TC.AttributeType.validationRule.version | string | The attribute type validation rule version. | 

#### Command example
```!tc-list-attribute-type limit=1```
#### Context Example
```json
{
    "TC": {
        "AttributeType": {
            "allowMarkdown": true,
            "description": "Describe the Course of Action Taken.",
            "errorMessage": "Please enter a valid Course of Action.",
            "id": 1,
            "maxSize": 500,
            "name": "Course of Action Taken"
        }
    }
}
```

#### Human Readable Output

>### Attribute types
>|id|name|description|
>|---|---|---|
>| 1 | Course of Action Taken | Describe the Course of Action Taken. |


### tc-delete-victim

***
Deletes a victim.

#### Base Command

`tc-delete-victim`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| victim_id | The ID of the victim. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!tc-delete-victim victim_id=660```
#### Human Readable Output

>Victim 660 was successfully deleted.
