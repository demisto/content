ThreatConnect's intelligence-driven security operations solution with intelligence, automation, analytics, and workflows.
This integration was integrated and tested with version xx of ThreatConnect v3

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration-threatconnect-v3).

## Configure ThreatConnect v3 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ThreatConnect v3.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Base Url |  | True |
    | Access ID |  | True |
    | Secret key |  | True |
    | Default Organization |  | False |
    | Source Reliability | Reliability of the source providing the intelligence data. | True |
    | Rating threshold for Malicious Indicators |  | False |
    | Confidence threshold for Malicious Indicators |  | False |
    | Indicator Reputation Freshness (in days) |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

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
| ips | A comma-separated list of IPv4 or IPv6 address. | Required | 
| owners | A comma-separated list of a client's organizations, sources, or communities to which a user has permissions. For example, users with admin permissions can search for indicators belonging to all owners. | Optional | 
| ratingThreshold | A list of results filtered by indicators whose threat rating is greater than the specified value. Can be "0" - "Unknown", "1" - "Suspicious", "2" - "Low", "3" - Moderate, "4" - High, or "5" - "Critical". | Optional | 
| confidenceThreshold | A list of results filtered by indicators whose confidence rating is greater than the specified value. Can be "0%" - "Unknown," "1% " - "Discredited", "2-29%" - "Improbable," "30-49%" - "Doubtful," "50-69%" - "Possible", "70-89%" - "Probable," or "90-100%" - "Confirmed". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Indicator.Name | string | The name of the indicator. | 
| TC.Indicator.Type | string | The type of the indicator. | 
| TC.Indicator.ID | string | The ID of the indicator. | 
| TC.Indicator.Description | string | The description of the indicator. | 
| TC.Indicator.Owner | string | The owner of the indicator. | 
| TC.Indicator.CreateDate | date | The date on which the indicator was created. | 
| TC.Indicator.LastModified | date | The date on which the indicator was modified. | 
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


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| urls | A comma-separated list of URLs for which to search. For example, "www.demisto.com". | Required | 
| owners | A comma-separated list of a client's organizations, sources, or communities to which a client’s API user has been granted permission. For example, "owner1", "owner2", or "owner3". | Optional | 
| ratingThreshold | A list of results filtered by indicators whose threat rating is greater than the specified value. Can be "0" - "Unknown", "1" - "Suspicious", "2" - "Low", "3" - Moderate, "4" - High, or "5" - "Critical". | Optional | 
| confidenceThreshold | A list of results filtered by indicators whose confidence rating is greater than the specified value. Can be "0%" - "Unknown," "1% " - "Discredited", "2-29%" - "Improbable," "30-49%" - "Doubtful," "50-69%" - "Possible", "70-89%" - "Probable," or "90-100%" - "Confirmed". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Indicator.Name | string | The name of the indicator. | 
| TC.Indicator.Type | string | The type of the indicator. | 
| TC.Indicator.ID | string | The ID of the indicator. | 
| TC.Indicator.Description | string | The description of the indicator. | 
| TC.Indicator.Owner | string | The owner of the indicator. | 
| TC.Indicator.CreateDate | date | The date on which the indicator was created. | 
| TC.Indicator.LastModified | date | The date on which the indicator was last modified. | 
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
| files | A comma-separated list of the hash of the files. Can be "MD5", "SHA-1", or "SHA-256". | Required | 
| owners | A comma-separated list of a client's organizations, sources, or communities to which a user has permissions. For example, users with admin permissions can search for indicators belonging to all owners. | Optional | 
| ratingThreshold | A list of results filtered by indicators whose threat rating is greater than the specified value. Can be "0" - "Unknown", "1" - "Suspicious", "2" - "Low", "3" - Moderate, "4" - High, or "5" - "Critical". | Optional | 
| confidenceThreshold | A list of results filtered by indicators whose confidence rating is greater than the specified value. Can be "0%" - "Unknown," "1% " - "Discredited", "2-29%" - "Improbable," "30-49%" - "Doubtful," "50-69%" - "Possible", "70-89%" - "Probable," or "90-100%" - "Confirmed". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Indicator.Name | string | The name of the indicator. | 
| TC.Indicator.Type | string | The type of the indicator. | 
| TC.Indicator.ID | string | The ID of the indicator. | 
| TC.Indicator.Description | string | The description of the indicator. | 
| TC.Indicator.Owner | string | The owner of the indicator. | 
| TC.Indicator.CreateDate | date | The date on which the indicator was created. | 
| TC.Indicator.LastModified | date | The last date on which the indicator was modified. | 
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
| owner | A list of results filtered by the owner of the indicator. | Optional | 
| page | The page to take the results from. | Optional | 
| limit | The maximum number of results that can be returned. The default is 500. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Indicator.Name | string | The name of the indicator. | 
| TC.Indicator.Type | string | The type of the indicator. | 
| TC.Indicator.ID | string | The ID of the indicator. | 
| TC.Indicator.Description | string | The description of the indicator. | 
| TC.Indicator.Owner | string | The owner of the indicator. | 
| TC.Indicator.CreateDate | date | The date on which the indicator was created. | 
| TC.Indicator.LastModified | date | The last date on which the indicator was modified. | 
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
| tags | The name of the tag. | Required | 
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
| id | The id of the indicator by which to search. | Required | 
| indicator_type | Only for custom. Leave empty for standard ones. | Optional | 
| owners | Indicator Owner(s). | Required | 
| ratingThreshold | A list of results filtered by indicators whose threat rating is greater than the specified value. Can be "0" - "Unknown", "1" - "Suspicious", "2" - "Low", "3" - Moderate, "4" - High, or "5" - "Critical". | Optional | 
| confidenceThreshold | A list of results filtered by indicators whose confidence rating is greater than the specified value. Can be "0%" - "Unknown," "1% " - "Discredited", "2-29%" - "Improbable," "30-49%" - "Doubtful," "50-69%" - "Possible", "70-89%" - "Probable," or "90-100%" - "Confirmed". | Optional | 
| group_associations | Retrieve Indicator Group Associations. Possible values are: true, false. Default is false. | Optional | 
| indicator_associations | Retrieve Indicator Associations. Possible values are: true, false. Default is false. | Optional | 
| indicator_observations | Retrieve Indicator Observations. Possible values are: true, false. Default is false. | Optional | 
| indicator_tags | Retrieve Indicator Tags. Possible values are: true, false. Default is false. | Optional | 
| indicator_attributes | Retrieve Indicator Attributes. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Indicator.Name | string | The name of the indicator. | 
| TC.Indicator.Type | string | The type of the indicator. | 
| TC.Indicator.ID | string | The ID of the indicator. | 
| TC.Indicator.Description | string | The description of the indicator. | 
| TC.Indicator.Owner | string | The owner of the indicator. | 
| TC.Indicator.CreateDate | date | The date on which the indicator was created. | 
| TC.Indicator.LastModified | date | The last date on which the indicator was modified. | 
| TC.Indicator.Rating | number | The threat rating of the indicator. | 
| TC.Indicator.Confidence | number | The confidence rating of the indicator. | 
| TC.Indicator.WhoisActive | string | The active indicator \(for domains only\). | 
| TC.Indicator.File.MD5 | string | The MD5 hash of the indicator of the file. | 
| TC.Indicator.File.SHA1 | string | The SHA1 hash of the indicator of the file. | 
| TC.Indicator.File.SHA256 | string | The SHA256 hash of the indicator of the file. | 
| TC.Indicator.IndicatorAttributes.dateAdded | date | The SHA256 hash of the indicator of the file. | 
| TC.Indicator.IndicatorAttributes.displayed | boolean | A boolean flag to show on ThreatConnect. | 
| TC.Indicator.IndicatorAttributes.id | number | The ID of the attribute. | 
| TC.Indicator.IndicatorAttributes.lastModified | date | The date on which the indicator attribute was last modified. | 
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
| tag | The name of the tag by which to filter. | Required | 
| owner | A list of indicators filtered by the owner. | Optional | 
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
| TC.Indicator.CreateDate | date | The date on which the tagged indicator was created. | 
| TC.Indicator.LastModified | date | The last date on which the tagged indicator was modified. | 
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
| indicatorType | The type of the indicator. Can be "ADDRESSES", "EMAIL_ADDRESSES", "URLS", "HOSTS", "FILES", or "CUSTOM_INDICATORS". Possible values are: Address, EmailAddress, URL, Host, File. | Required | 
| hashType | The type of hash for file indicator. Possible values are: md5, sha1, sha256. | Optional | 
| rating | The threat rating of the indicator. Can be "0" - "Unknown", "1" - "Suspicious", "2" - "Low", "3" - Moderate, "4" - High, or "5" - "Critical". | Optional | 
| confidence | The confidence rating of the indicator. Can be "0%" - "Unknown," "1% " - "Discredited", "2-29%" - "Improbable," "30-49%" - "Doubtful," "50-69%" - "Possible", "70-89%" - "Probable," or "90-100%" - "Confirmed". | Optional | 
| description | The description of the indicator. | Optional | 
| tags | Comma-seperated list of the tags to apply to the campaign. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Indicator.Name | string | The name the indicator. | 
| TC.Indicator.Type | string | The type of indicator. | 
| TC.Indicator.ID | string | The ID of the indicator. | 
| TC.Indicator.Description | string | The description of the indicator. | 
| TC.Indicator.Owner | string | The owner of the indicator. | 
| TC.Indicator.CreateDate | date | The date on which the added indicator was created. | 
| TC.Indicator.LastModified | date | The last date on which the added indicator was modified. | 
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
| name | The name of the incident group. | Required | 
| eventDate | The creation time of an incident in the "2017-03-21T00:00:00Z" format. | Optional | 
| tags | A comma-separated list of The tags applied to the incident. | Optional | 
| securityLabel | The security label applied to the incident. Can be "TLP:RED", "TLP:GREEN", "TLP:AMBER", or "TLP:WHITE". Possible values are: TLP:RED, TLP:GREEN, TLP:AMBER, TLP:WHITE. | Optional | 
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
| indicator | The name of the indicator. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Indicator.Name | string | The name of the indicator. | 
| TC.Indicator.Type | string | The type of the indicator. | 
| TC.Indicator.ID | string | The ID of the indicator. | 
| TC.Indicator.Description | string | The description of the indicator. | 
| TC.Indicator.Owner | string | The owner of the indicator. | 
| TC.Indicator.CreateDate | date | The date on which the indicator associated was created. | 
| TC.Indicator.LastModified | date | The last date on which the indicator associated was modified. | 
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


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domains | A comma-separated list of names of the domain. | Required | 
| owners | A comma-separated list of a client's organizations, sources, or communities to which a user has permissions. For example, users with admin permissions can search for indicators belonging to all owners. | Optional | 
| ratingThreshold | A list of results filtered by indicators whose threat rating is greater than the specified value. Can be "0" - "Unknown", "1" - "Suspicious", "2" - "Low", "3" - Moderate, "4" - High, or "5" - "Critical". | Optional | 
| confidenceThreshold | A list of results filtered by indicators whose confidence rating is greater than the specified value. Can be "0%" - "Unknown," "1% " - "Discredited", "2-29%" - "Improbable," "30-49%" - "Doubtful," "50-69%" - "Possible", "70-89%" - "Probable," or "90-100%" - "Confirmed". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Indicator.Name | string | The name of the of the indicator. | 
| TC.Indicator.Type | string | The type of the domain. | 
| TC.Indicator.ID | string | The ID of the domain. | 
| TC.Indicator.Description | string | The description of the domain. | 
| TC.Indicator.Owner | string | The owner of the domain. | 
| TC.Indicator.CreateDate | date | The date on which the indicator of the domain was created. | 
| TC.Indicator.LastModified | date | The last date on which the indicator of the domain was modified. | 
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
| id | The ID of the incident. | Required | 
| owner | A list of indicators filtered by the owner. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Indicator.Name | string | The name of the returned indicator. | 
| TC.Indicator.Type | string | The type of the returned indicator. | 
| TC.Indicator.ID | string | The ID of the returned indicator. | 
| TC.Indicator.Description | string | The description of the returned indicator. | 
| TC.Indicator.Owner | string | The owner of the returned indicator. | 
| TC.Indicator.CreateDate | date | The date on which the returned indicator was created. | 
| TC.Indicator.LastModified | date | The last date on which the returned indicator was modified. | 
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
| dnsActive | The active DNS indicator (only for hosts). Possible values are: True, False. | Optional | 
| whoisActive | The active indicator (only for hosts). Possible values are: True, False. | Optional | 
| falsePositive | The updated indicator set as a false positive. Can be "True" or "False". Possible values are: True, False. | Optional | 
| securityLabel | The security label applied to the incident. Can be "TLP:RED", "TLP:GREEN", "TLP:AMBER", or "TLP:WHITE". Possible values are: TLP:RED, TLP:GREEN, TLP:AMBER, TLP:WHITE. | Optional | 
| tags | A comma-seperated list of tags. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Indicator.Name | string | The name of the indicator. | 
| TC.Indicator.Type | string | The type of the indicator. | 
| TC.Indicator.ID | string | The ID of the indicator. | 
| TC.Indicator.Description | string | The description of the indicator. | 
| TC.Indicator.Owner | string | The owner of the indicator. | 
| TC.Indicator.CreateDate | date | The date on which the indicator was created. | 
| TC.Indicator.LastModified | date | The last date on which the indicator was modified. | 
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
| indicator | The name of the indicator from which to remove a tag. | Required | 
| tags | The name of the tag to remove from the indicator. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Indicator.Name | string | The name of the indicator. | 
| TC.Indicator.Type | string | The type of the indicator. | 
| TC.Indicator.ID | string | The ID of the indicator. | 
| TC.Indicator.Description | string | The description of the indicator. | 
| TC.Indicator.Owner | string | The owner of the indicator. | 
| TC.Indicator.CreateDate | date | The date on which the indicator was created. | 
| TC.Indicator.LastModified | date | The last date on which the indicator was modified. | 
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
| indicatorId | The id of the indicator to delete. | Required | 


#### Context Output

There is no context output for this command.
### tc-create-campaign
***
Creates a group based on the "Campaign" type.


#### Base Command

`tc-create-campaign`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the campaign group. | Required | 
| firstSeen | The earliest date on which the campaign was seen. | Optional | 
| description | The description of the campaign. | Optional | 
| tags | Comma-seperated list of the tags to apply to the campaign. | Optional | 
| securityLabel | The security label applied to the incident. Can be "TLP:RED", "TLP:GREEN", "TLP:AMBER", or "TLP:WHITE". Possible values are: TLP:RED, TLP:GREEN, TLP:AMBER, TLP:WHITE. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Campaign.Name | string | The name of the campaign. | 
| TC.Campaign.Owner | string | The owner of the campaign. | 
| TC.Campaign.FirstSeen | date | The earliest date on which the campaign was seen. | 
| TC.Campaign.Tag | string | The tag of the campaign. | 
| TC.Campaign.SecurityLevel | string | The security label of the campaign. | 
| TC.Campaign.ID | strin | The ID of the campaign. | 

### tc-create-event
***
Creates a group based on the "Event" type.


#### Base Command

`tc-create-event`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the event group. | Required | 
| eventDate | The date on which the event occurred. If the date is not specified, the current date is used. | Optional | 
| status | The status of the event. Can be "Needs Review", "False Positive", "No Further Action", or "Escalated". Possible values are: Needs Review, False Positive, No Further Action, Escalated. | Optional | 
| description | The description of the event. | Optional | 
| tag | A comma-separated list of a The tags of the event. | Optional | 


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
| eventDate | The creation time of an threat in the "2017-03-21T00:00:00Z" format. | Optional | 
| tags | A comma-separated list of The tags applied to the threat. | Optional | 
| securityLabel | The security label applied to the threat. Can be "TLP:RED", "TLP:GREEN", "TLP:AMBER", or "TLP:WHITE". Possible values are: TLP:RED, TLP:GREEN, TLP:AMBER, TLP:WHITE. | Optional | 
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
| groupID | A comma seprated list of the IDs of the groups we want to to delete. | Required | 


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
| fromDate | The Date to fetrieve groups from, should be in format yyyy-mm-dd, e.g. 1111-11-11. | Optional | 
| tag | The tag to fetrieve groups by. | Optional | 
| page | The page to take the results from. | Optional | 
| limit | The maximum number of results that can be returned. The default is 500. | Optional | 
| id | A comma-separated list of IDs to filter the groups by. | Optional | 
| filter | A free text tql filter(reffer to the readme for a basic tql guide). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Event.DateAdded | Date | The date on which the event was added. | 
| TC.Event.EventDate | Date | The date on which the event occurred. | 
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
| fromDate | The Date to fetrieve groups from, should be in format yyyy-mm-dd, e.g. 1111-11-11. | Optional | 
| tag | The tag to fetrieve groups by. | Optional | 
| page | The page to take the results from. | Optional | 
| limit | The maximum number of results that can be returned. The default is 500. | Optional | 
| id | A comma-separated list of IDs to filter the groups by. | Optional | 
| filter | A free text tql filter(reffer to the readme for a basic tql guide). | Optional | 
| includeTags | Add group tags metadata to the results. | Optional | 
| includeSecurityLabels | Add group security labels metadata to the results. | Optional | 
| includeAttributes | Add group attributes metadata to the results. | Optional | 
| includeAssociatedGroups | Add group associated groups metadata to the results. | Optional | 
| includeAssociatedIndicators | Add group associated indicators metadata to the results. | Optional | 
| includeAllMetaData | Add all group metadata to the results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Group.DateAdded | Date | The date on which the group was added. | 
| TC.Group.EventDate | Date | The date on which the event occurred. | 
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
| id | The ID of the group to which to add the tag. To get the ID, run the tc-get-groups command. | Required | 
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
| TC.IndicatorType.Value1Type | String | The name of the indicator. | 
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
| name | The name of the file. | Required | 
| malware | Whether the file is malware. If "true", ThreatConnect creates a password-protected ZIP file on your local machine that contains the sample and uploads the ZIP file. Possible values are: true, false. | Optional | 
| password | The password of the ZIP file. | Optional | 
| securityLabel | The security label applied to the document. Can be "TLP:RED", "TLP:GREEN", "TLP:AMBER", or "TLP:WHITE". Possible values are: TLP:RED, TLP:GREEN, TLP:AMBER, TLP:WHITE. | Optional | 
| description | A description of the group. | Optional | 
| entry_id | The file of the ID of the entry, as displayed in the War Room. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Group.Name | String | The name of the group. | 
| TC.Group.Owner | String | The owner of the group. | 
| TC.Group.EventDate | Date | The date on which the group was created. | 
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
| id | The ID of the group. To get the ID, run the tc-list-groups command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TC.Group.AssociatedGroup.DateAdded | Date | The date on which group was added. | 
| TC.Group.AssociatedGroup.GroupID | Number | The ID of the group. | 
| TC.Group.AssociatedGroup.Name | String | The name of the group. | 
| TC.Group.AssociatedGroup.OwnerName | String | The name of the owner of the group. | 
| TC.Group.AssociatedGroup.Type | String | The type of the group. | 

### tc-get-indicator-owners
***
Get Owner for Indicator


#### Base Command

`tc-get-indicator-owners`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator | Indicator Value. | Required | 
| indicatorType | The type of the indicator. Can be "ADDRESSES", "EMAIL_ADDRESSES", "URLS", "HOSTS", "FILES", or "CUSTOM_INDICATORS". Possible values are: addresses, email_addresses, urls, hosts, files, custom_indicators. | Required | 


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
| File.SSDeep | String | The SSDeep hash of the file. | 
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
| id | The id of the group. | Required | 
| custom_field | Custom fields for the group. | Optional | 
| tags | A comma-separated list of The tags applied to the threat. | Optional | 
| security_label | The security label applied to the threat. Can be "TLP:RED", "TLP:GREEN", "TLP:AMBER", or "TLP:WHITE". Possible values are: TLP:RED, TLP:GREEN, TLP:AMBER, TLP:WHITE. | Optional | 
| associated_group_id | An ID to accosiate a group by. | Optional | 
| associated_indicator_id | An ID to accosiate an indicator by. | Optional | 
| security_label | The type of update to the group metadata(associated indicators, attributes,tags etc...). Possible values are: append, delete, replace. | Optional | 
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

## Breaking changes from the previous version of this integration - ThreatConnect v3
%%FILL HERE%%
The following sections list the changes in this version.

### Commands
#### The following commands were removed in this version:
* *commandName* - this command was replaced by XXX.
* *commandName* - this command was replaced by XXX.

### Arguments
#### The following arguments were removed in this version:

In the *commandName* command:
* *argumentName* - this argument was replaced by XXX.
* *argumentName* - this argument was replaced by XXX.

#### The behavior of the following arguments was changed:

In the *commandName* command:
* *argumentName* - is now required.
* *argumentName* - supports now comma separated values.

### Outputs
#### The following outputs were removed in this version:

In the *commandName* command:
* *outputPath* - this output was replaced by XXX.
* *outputPath* - this output was replaced by XXX.

In the *commandName* command:
* *outputPath* - this output was replaced by XXX.
* *outputPath* - this output was replaced by XXX.

## Additional Considerations for this version
%%FILL HERE%%
* Insert any API changes, any behavioral changes, limitations, or restrictions that would be new to this version.
