Malware information sharing platform and threat sharing.

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous version of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration-misp-v3).

## Configure MISP v3 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for MISP v3.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | MISP server URL (e.g., https://192.168.0.1) |  | True |
    | API Key |  | False |
    | Use system proxy settings |  | False |
    | Trust any certificate (not secure) |  | False |
    | Malicious tag IDs | Comma-separated list of event's or attribute's malicious tag IDs. Malicious tags are stronger than suspicious tags. | False |
    | Suspicious tag IDs | Comma-separated list of event's or attribute's suspicious tag IDs. Malicious tags are stronger than suspicious tags. | False |
    | Source Reliability | Reliability of the source providing the intelligence data. | True |
    | Maximum attributes to be returned | This field limits the number of attributes that will be written to the context for every reputation command. Raising the number of attributes may result in high memory and disk usage. | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### misp-search-events

***
Search for events in MISP. This search command will return only information about the matched events. To get information about attributes, use the misp-search-attributes command.

#### Base Command

`misp-search-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | Search for events that include the specified attribute type. Use any valid MISP attribute type. For example: "md5", "sha1", "email", "url". | Optional | 
| value | Search for events that include the specified attribute value. For example: "1.2.3.4" (and other IP addresses), "google.com" (and other domains), "www.example.com" (and other URLs). | Optional | 
| category | Search for events that include the specified attribute category. Use any valid MISP attribute category. For example: "Other", "Person", "Attribution", "Payload type". | Optional | 
| org | Search by creator organization by supplying the organization ID. | Optional | 
| tags | A comma-separated list of tags to include in the results. To exclude a tag, prefix the tag name with "!". Can be: "AND", "OR", and "NOT" followed by ":". To chain logical operators use ";". For example, "AND:tag1,tag2;OR:tag3". | Optional | 
| from | Event search start date in the format yyyy-mm-dd. For example, 2015-02-15. This date refers to the event creation date. | Optional | 
| to | Event search end date in the format yyyy-mm-dd. For example, 2015-02-15. This date refers to the event creation date. | Optional | 
| last | Events published within the last "x" amount of time. Valid time values are days, hours, and minutes. For example, "5d", "12h", "30m". This filter uses the published timestamp of the event. | Optional | 
| event_id | A comma-separated list of event IDs to be returned by the search. | Optional | 
| uuid | The event UUID to be returned by the search. For example, 59523300-4be8-4fa6-8867-0037ac110002. | Optional | 
| page | If a limit is set, sets the page to be returned. For example, page 3, limit 100 will return records 201-&gt;300. Default is 1. | Optional | 
| limit | Limit the number of events returned. Default is 50. | Optional | 
| include_feed_correlations | Whether to return the event related feeds. Possible values are "true" and "false". Note, Only if this argument set to "true" the response will include attributes' feed hits values. Possible values are: true, false. | Optional | 
| eventinfo | Search for events that include match the searchstring in the events info field. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MISP.Event.ID | string | MISP event ID. | 
| MISP.Event.Distribution | string | MISP event distribution. | 
| MISP.Event.ThreatLevelID | string | Threat level of the MISP event \(1 High, 2 Medium, 3 Low, 4 Undefined\). | 
| MISP.Event.PublishTimestamp | number | Timestamp of the publish time \(if published\). | 
| MISP.Event.EventCreatorEmail | string | Email address of the event creator. | 
| MISP.Event.Info | string | Event name. | 
| MISP.Event.AttributeCount | string | Number of attributes of the event. | 
| MISP.Event.OrganizationID | string | Event organization ID. | 
| MISP.Event.CreationDate | date | Event creation date. | 
| MISP.Event.Locked | boolean | Is the event locked. | 
| MISP.Event.Organization.ID | number | Organization ID. | 
| MISP.Event.Organization.Name | string | Organization name. | 
| MISP.Event.Organization.UUID | string | Organization UUID. | 
| MISP.Event.Organization.local | boolean | Is the organization local. | 
| MISP.Event.OwnerOrganization.ID | number | Owner organization ID. | 
| MISP.Event.OwnerOrganization.Name | string | Owner organization name. | 
| MISP.Event.OwnerOrganization.UUID | string | Owner organization UUID. | 
| MISP.Event.OwnerOrganization.local | boolean | Is the owner organization local. | 
| MISP.Event.ProposalEmailLock | boolean | Is email lock proposed. | 
| MISP.Event.LastChanged | date | Last change event timestamp. | 
| MISP.Event.Galaxy.Description | string | Event's galaxy description. | 
| MISP.Event.Galaxy.Name | string | Galaxy name. | 
| MISP.Event.Galaxy.Type | string | Galaxy type. | 
| MISP.Event.Published | boolean | Is the event published. | 
| MISP.Event.DisableCorrelation | boolean | Is correlation disabled. | 
| MISP.Event.UUID | string | Event UUID. | 
| MISP.Event.Analysis | string | Event analysis \(0 Initial, 1 Ongoing, 2 Completed\). | 
| MISP.Event.SharingGroupID | string | Event sharing group ID. | 
| MISP.Event.Tag.Name | string | All tag names in the event. | 
| MISP.Event.Tag.is_galaxy | boolean | Is the tag galaxy. | 
| MISP.Event.Object.Name | String | Name of the object. | 
| MISP.Event.Object.Description | String | Description of the object. | 
| MISP.Event.Object.ID | Number | ID of the object. | 
| MISP.Event.Object.UUID | String | UUID of the object. | 
| MISP.Event.Feed.ID | String | Feed id. | 
| MISP.Event.Feed.Name | String | Feed name. | 
| MISP.Event.Feed.Provider | String | Feed provider. | 
| MISP.Event.Feed.SourceFormat | String | Feed source format \(MISP for example\). | 
| MISP.Event.Feed.URL | String | Feed url. | 
| MISP.Event.Feed.EventUUIDS | Unknown | List of event uuids include the feed. | 
| MISP.Event.Attribute.Feed.ID | String | Attribute feed id. | 
| MISP.Event.Attribute.Feed.Name | String | Attribute feed name. | 
| MISP.Event.Attribute.Feed.Provider | String | Attribute feed provider. | 
| MISP.Event.Attribute.Feed.SourceFormat | String | Attribute feed source format \(MISP for example\). | 
| MISP.Event.Attribute.Feed.URL | String | Attribute feed url. | 
| MISP.Event.Attribute.Feed.EventUUIDS | Unknown | List of event uuids include the attribute feed. | 
| MISP.Event.Attribute.ID | String | MISP attribute ID. | 
| MISP.Event.Attribute.Value | String | MISP attribute value. | 

### domain

***
Checks the reputation of the given domain.

#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain to search. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The domain of the indicator. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| MISP.Attribute.Distribution | string | Attribute distribution. | 
| MISP.Attribute.Value | string | Attribute value. | 
| MISP.Attribute.EventID | string | Attribute event ID. | 
| MISP.Attribute.last_seen | string | Attribute last_seen timestamp. | 
| MISP.Attribute.first_seen | string | Attribute first_seen timestamp. | 
| MISP.Attribute.LastChanged | date | Attribute last changed timestamp. | 
| MISP.Attribute.ObjectID | string | Attribute object ID. | 
| MISP.Attribute.Deleted | boolean | Is the attribute deleted. | 
| MISP.Attribute.DisableCorrelation | boolean | Is attribute correlation disabled. | 
| MISP.Attribute.Type | string | Attribute type. | 
| MISP.Attribute.ID | string | Attribute ID. | 
| MISP.Attribute.UUID | string | Attribute UUID. | 
| MISP.Attribute.ToIDs | boolean | Is the Intrusion Detection System flag set. | 
| MISP.Attribute.Category | string | Attribute category. | 
| MISP.Attribute.SharingGroupID | string | Attribute sharing group ID. | 
| MISP.Attribute.Comment | string | Attribute comment. | 
| MISP.Attribute.Event.ID | string | MISP event ID. | 
| MISP.Attribute.Event.Distribution | string | MISP event distribution. | 
| MISP.Attribute.Event.Info | string | MISP event name. | 
| MISP.Attribute.Event.LastChanged | string | Last change event timestamp. | 
| MISP.Attribute.Event.Published | boolean | Is the event published. | 
| MISP.Attribute.Event.CreationDate | date | Event creation date. | 
| MISP.Attribute.Event.ThreatLevelID | string | Threat level of the MISP event \(1 High, 2 Medium, 3 Low, 4 Undefined\). | 
| MISP.Attribute.Event.PublishTimestamp | string | Timestamp of the publish time \(if published\). | 
| MISP.Attribute.Event.OrganizationID | string | MISP event organization ID. | 
| MISP.Attribute.Event.OwnerOrganization.ID | string | Owner organization ID. | 
| MISP.Attribute.Event.OwnerOrganization.Name | string | Owner organization name. | 
| MISP.Attribute.Event.OwnerOrganization.UUID | string | Owner organization UUID. | 
| MISP.Attribute.Event.OwnerOrganization.local | boolean | Is owner organization local. | 
| MISP.Attribute.Event.UUID | string | MISP event UUID. | 
| MISP.Attribute.Event.Analysis | string | Event analysis \(0 Initial, 1 Ongoing, 2 Completed\). | 
| MISP.Attribute.Event.SharingGroupID | string | Event sharing group ID. | 
| MISP.Attribute.Event.Tag.Name | string | Event tag name. | 
| MISP.Attribute.Event.Tag.ID | string | Event tag ID. | 
| MISP.Attribute.Tag.Name | string | Attribute tag name. | 
| MISP.Attribute.Tag.ID | string | Attribute tag ID. | 
| MISP.Attribute.Sighting.Type | string | Attribute's sighting type. | 

### email

***
Checks the reputation of the given email address.

#### Base Command

`email`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | Email address to search. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Email.Address | String | The email address of the indicator. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| MISP.Attribute.Distribution | string | Attribute distribution. | 
| MISP.Attribute.Value | string | Attribute value. | 
| MISP.Attribute.EventID | string | Attribute event ID. | 
| MISP.Attribute.last_seen | string | Attribute last_seen timestamp. | 
| MISP.Attribute.first_seen | string | Attribute first_seen timestamp. | 
| MISP.Attribute.LastChanged | date | Attribute last changed timestamp. | 
| MISP.Attribute.ObjectID | string | Attribute object ID. | 
| MISP.Attribute.Deleted | boolean | Is the attribute deleted. | 
| MISP.Attribute.DisableCorrelation | boolean | Is attribute correlation disabled. | 
| MISP.Attribute.Type | string | Attribute type. | 
| MISP.Attribute.ID | string | Attribute ID. | 
| MISP.Attribute.UUID | string | Attribute UUID. | 
| MISP.Attribute.ToIDs | boolean | Is the Intrusion Detection System flag set. | 
| MISP.Attribute.Category | string | Attribute category. | 
| MISP.Attribute.SharingGroupID | string | Attribute sharing group ID. | 
| MISP.Attribute.Comment | string | Attribute comment. | 
| MISP.Attribute.Event.ID | string | MISP event ID. | 
| MISP.Attribute.Event.Distribution | string | MISP event distribution. | 
| MISP.Attribute.Event.Info | string | MISP event name. | 
| MISP.Attribute.Event.LastChanged | string | Last change event timestamp. | 
| MISP.Attribute.Event.Published | boolean | Is the event published. | 
| MISP.Attribute.Event.CreationDate | date | Event creation date. | 
| MISP.Attribute.Event.ThreatLevelID | string | Threat level of the MISP event \(1 High, 2 Medium, 3 Low, 4 Undefined\). | 
| MISP.Attribute.Event.PublishTimestamp | string | Timestamp of the publish time \(if published\). | 
| MISP.Attribute.Event.OrganizationID | string | MISP event organization ID. | 
| MISP.Attribute.Event.OwnerOrganization.ID | string | Owner organization ID. | 
| MISP.Attribute.Event.OwnerOrganization.Name | string | Owner organization name. | 
| MISP.Attribute.Event.OwnerOrganization.UUID | string | Owner organization UUID. | 
| MISP.Attribute.Event.OwnerOrganization.local | boolean | Is owner organization local. | 
| MISP.Attribute.Event.UUID | string | MISP event UUID. | 
| MISP.Attribute.Event.Analysis | string | Event analysis \(0 Initial, 1 Ongoing, 2 Completed\). | 
| MISP.Attribute.Event.SharingGroupID | string | Event sharing group ID. | 
| MISP.Attribute.Event.Tag.Name | string | Event tag name. | 
| MISP.Attribute.Event.Tag.ID | string | Event tag ID. | 
| MISP.Attribute.Tag.Name | string | Attribute tag name. | 
| MISP.Attribute.Tag.ID | string | Attribute tag ID. | 
| MISP.Attribute.Sighting.Type | string | Attribute's sighting type. | 

### file

***
Checks the file reputation of the given hash.

#### Base Command

`file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | Hash of the file to query. Supports MD5, SHA-1, and SHA-256. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.MD5 | String | The MD5 hash of the file. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| MISP.Attribute.Distribution | string | Attribute distribution. | 
| MISP.Attribute.Value | string | Attribute value. | 
| MISP.Attribute.EventID | string | Attribute event ID. | 
| MISP.Attribute.last_seen | string | Attribute last_seen timestamp. | 
| MISP.Attribute.first_seen | string | Attribute first_seen timestamp. | 
| MISP.Attribute.LastChanged | date | Attribute last changed timestamp. | 
| MISP.Attribute.ObjectID | string | Attribute object ID. | 
| MISP.Attribute.Deleted | boolean | Is the attribute deleted. | 
| MISP.Attribute.DisableCorrelation | boolean | Is attribute correlation disabled. | 
| MISP.Attribute.Type | string | Attribute type. | 
| MISP.Attribute.ID | string | Attribute ID. | 
| MISP.Attribute.UUID | string | Attribute UUID. | 
| MISP.Attribute.ToIDs | boolean | Is the Intrusion Detection System flag set. | 
| MISP.Attribute.Category | string | Attribute category. | 
| MISP.Attribute.SharingGroupID | string | Attribute sharing group ID. | 
| MISP.Attribute.Comment | string | Attribute comment. | 
| MISP.Attribute.Event.ID | string | MISP event ID. | 
| MISP.Attribute.Event.Distribution | string | MISP event distribution. | 
| MISP.Attribute.Event.Info | string | MISP event name. | 
| MISP.Attribute.Event.LastChanged | string | Last change event timestamp. | 
| MISP.Attribute.Event.Published | boolean | Is the event published. | 
| MISP.Attribute.Event.CreationDate | date | Event creation date. | 
| MISP.Attribute.Event.ThreatLevelID | string | Threat level of the MISP event \(1 High, 2 Medium, 3 Low, 4 Undefined\). | 
| MISP.Attribute.Event.PublishTimestamp | string | Timestamp of the publish time \(if published\). | 
| MISP.Attribute.Event.OrganizationID | string | MISP event organization ID. | 
| MISP.Attribute.Event.OwnerOrganization.ID | string | Owner organization ID. | 
| MISP.Attribute.Event.OwnerOrganization.Name | string | Owner organization name. | 
| MISP.Attribute.Event.OwnerOrganization.UUID | string | Owner organization UUID. | 
| MISP.Attribute.Event.OwnerOrganization.local | boolean | Is owner organization local. | 
| MISP.Attribute.Event.UUID | string | MISP event UUID. | 
| MISP.Attribute.Event.Analysis | string | Event analysis \(0 Initial, 1 Ongoing, 2 Completed\). | 
| MISP.Attribute.Event.SharingGroupID | string | Event sharing group ID. | 
| MISP.Attribute.Event.Tag.Name | string | Event tag name. | 
| MISP.Attribute.Event.Tag.ID | string | Event tag ID. | 
| MISP.Attribute.Tag.Name | string | Attribute tag name. | 
| MISP.Attribute.Tag.ID | string | Attribute tag ID. | 
| MISP.Attribute.Sighting.Type | string | Attribute's sighting type. | 

### url

***
Checks the reputation of the given URL.

#### Base Command

`url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL to check. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL.Data | String | The URL of the indicator. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| MISP.Attribute.Distribution | string | Attribute distribution. | 
| MISP.Attribute.Value | string | Attribute value. | 
| MISP.Attribute.EventID | string | Attribute event ID. | 
| MISP.Attribute.last_seen | string | Attribute last_seen timestamp. | 
| MISP.Attribute.first_seen | string | Attribute first_seen timestamp. | 
| MISP.Attribute.LastChanged | date | Attribute last changed timestamp. | 
| MISP.Attribute.ObjectID | string | Attribute object ID. | 
| MISP.Attribute.Deleted | boolean | Is the attribute deleted. | 
| MISP.Attribute.DisableCorrelation | boolean | Is attribute correlation disabled. | 
| MISP.Attribute.Type | string | Attribute type. | 
| MISP.Attribute.ID | string | Attribute ID. | 
| MISP.Attribute.UUID | string | Attribute UUID. | 
| MISP.Attribute.ToIDs | boolean | Is the Intrusion Detection System flag set. | 
| MISP.Attribute.Category | string | Attribute category. | 
| MISP.Attribute.SharingGroupID | string | Attribute sharing group ID. | 
| MISP.Attribute.Comment | string | Attribute comment. | 
| MISP.Attribute.Event.ID | string | MISP event ID. | 
| MISP.Attribute.Event.Distribution | string | MISP event distribution. | 
| MISP.Attribute.Event.Info | string | MISP event name. | 
| MISP.Attribute.Event.LastChanged | string | Last change event timestamp. | 
| MISP.Attribute.Event.Published | boolean | Is the event published. | 
| MISP.Attribute.Event.CreationDate | date | Event creation date. | 
| MISP.Attribute.Event.ThreatLevelID | string | Threat level of the MISP event \(1 High, 2 Medium, 3 Low, 4 Undefined\). | 
| MISP.Attribute.Event.PublishTimestamp | string | Timestamp of the publish time \(if published\). | 
| MISP.Attribute.Event.OrganizationID | string | MISP event organization ID. | 
| MISP.Attribute.Event.OwnerOrganization.ID | string | Owner organization ID. | 
| MISP.Attribute.Event.OwnerOrganization.Name | string | Owner organization name. | 
| MISP.Attribute.Event.OwnerOrganization.UUID | string | Owner organization UUID. | 
| MISP.Attribute.Event.OwnerOrganization.local | boolean | Is owner organization local. | 
| MISP.Attribute.Event.UUID | string | MISP event UUID. | 
| MISP.Attribute.Event.Analysis | string | Event analysis \(0 Initial, 1 Ongoing, 2 Completed\). | 
| MISP.Attribute.Event.SharingGroupID | string | Event sharing group ID. | 
| MISP.Attribute.Event.Tag.Name | string | Event tag name. | 
| MISP.Attribute.Event.Tag.ID | string | Event tag ID. | 
| MISP.Attribute.Tag.Name | string | Attribute tag name. | 
| MISP.Attribute.Tag.ID | string | Attribute tag ID. | 
| MISP.Attribute.Sighting.Type | string | Attribute's sighting type. | 

### ip

***
Checks the reputation of an IP address.

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP address to check. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | String | The IP address. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| MISP.Attribute.Distribution | string | Attribute distribution. | 
| MISP.Attribute.Value | string | Attribute value. | 
| MISP.Attribute.EventID | string | Attribute event ID. | 
| MISP.Attribute.last_seen | string | Attribute last_seen timestamp. | 
| MISP.Attribute.first_seen | string | Attribute first_seen timestamp. | 
| MISP.Attribute.LastChanged | date | Attribute last changed timestamp. | 
| MISP.Attribute.ObjectID | string | Attribute object ID. | 
| MISP.Attribute.Deleted | boolean | Is the attribute deleted. | 
| MISP.Attribute.DisableCorrelation | boolean | Is attribute correlation disabled. | 
| MISP.Attribute.Type | string | Attribute type. | 
| MISP.Attribute.ID | string | Attribute ID. | 
| MISP.Attribute.UUID | string | Attribute UUID. | 
| MISP.Attribute.ToIDs | boolean | Is the Intrusion Detection System flag set. | 
| MISP.Attribute.Category | string | Attribute category. | 
| MISP.Attribute.SharingGroupID | string | Attribute sharing group ID. | 
| MISP.Attribute.Comment | string | Attribute comment. | 
| MISP.Attribute.Event.ID | string | MISP event ID. | 
| MISP.Attribute.Event.Distribution | string | MISP event distribution. | 
| MISP.Attribute.Event.Info | string | MISP event name. | 
| MISP.Attribute.Event.LastChanged | string | Last change event timestamp. | 
| MISP.Attribute.Event.Published | boolean | Is the event published. | 
| MISP.Attribute.Event.CreationDate | date | Event creation date. | 
| MISP.Attribute.Event.ThreatLevelID | string | Threat level of the MISP event \(1 High, 2 Medium, 3 Low, 4 Undefined\). | 
| MISP.Attribute.Event.PublishTimestamp | string | Timestamp of the publish time \(if published\). | 
| MISP.Attribute.Event.OrganizationID | string | MISP event organization ID. | 
| MISP.Attribute.Event.OwnerOrganization.ID | string | Owner organization ID. | 
| MISP.Attribute.Event.OwnerOrganization.Name | string | Owner organization name. | 
| MISP.Attribute.Event.OwnerOrganization.UUID | string | Owner organization UUID. | 
| MISP.Attribute.Event.OwnerOrganization.local | boolean | Is owner organization local. | 
| MISP.Attribute.Event.UUID | string | MISP event UUID. | 
| MISP.Attribute.Event.Analysis | string | Event analysis \(0 Initial, 1 Ongoing, 2 Completed\). | 
| MISP.Attribute.Event.SharingGroupID | string | Event sharing group ID. | 
| MISP.Attribute.Event.Tag.Name | string | Event tag name. | 
| MISP.Attribute.Event.Tag.ID | string | Event tag ID. | 
| MISP.Attribute.Tag.Name | string | Attribute tag name. | 
| MISP.Attribute.Tag.ID | string | Attribute tag ID. | 
| MISP.Attribute.Sighting.Type | string | Attribute's sighting type. | 

### misp-create-event

***
Creates a new MISP event.

#### Base Command

`misp-create-event`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | Attribute type to be created as part of the new event. For example: "md5", "sha1", "email", "url". Default is other. | Optional | 
| category | Attribute category to be created as part of the new event. For example: "Other", "Person", "Attribution", "Payload type". Default is External analysis. | Optional | 
| to_ids | Whether to create the event's attribute with the Intrusion Detection System flag. Possible values: "true" and "false". Possible values are: true, false. Default is true. | Optional | 
| distribution | Where to distribute the event. Possible values: "Your_organization_only", "This_community_only", "Connected_communities", "All_communities", "Sharing_group" and "Inherit_event". Possible values are: Your_organization_only, This_community_only, Connected_communities, All_communities, Sharing_group, Inherit_event. Default is Your_organization_only. | Optional | 
| comment | Attribute comment to be created as part of the new event. | Optional | 
| value | Attribute value to be created as part of the new event. For example: "1.2.3.4" (and other IP addresses), "google.com" (and other domains), "www.example.com" (and other URLs). | Required | 
| info | Event name. | Required | 
| published | Whether to publish the event. Possible values: "false" and "true". Possible values are: false, true. Default is false. | Optional | 
| threat_level_id | MISP Threat level ID. Possible values: "High", "Medium", "Low", and "Unknown". Possible values are: High, Medium, Low, Unknown. Default is High. | Optional | 
| analysis | The analysis event level. Possible values: "initial", "ongoing", and "completed". Possible values are: initial, ongoing, completed. Default is initial. | Optional | 
| sharing_group_id | Sharing group ID. Mandatory when Sharing_group distribution is set. | Optional | 
| creation_date | Set the creation date for the event in the format YYYY-MM-DD. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MISP.Event.ID | string | MISP event ID. | 
| MISP.Event.Distribution | string | MISP event distribution. | 
| MISP.Event.ThreatLevelID | string | Threat level of the MISP event \(1 High, 2 Medium, 3 Low, 4 Undefined\). | 
| MISP.Event.PublishTimestamp | number | Timestamp of the publish time \(if published\). | 
| MISP.Event.EventCreatorEmail | string | Email address of the event creator. | 
| MISP.Event.Info | string | Event name. | 
| MISP.Event.AttributeCount | string | Number of attributes of the event. | 
| MISP.Event.OrganizationID | string | Event organization ID. | 
| MISP.Event.CreationDate | date | Event creation date. | 
| MISP.Event.Locked | boolean | Is the event locked. | 
| MISP.Event.Organization.ID | number | Organization ID. | 
| MISP.Event.Organization.Name | string | Organization name. | 
| MISP.Event.Organization.UUID | string | Organization UUID. | 
| MISP.Event.Organization.local | boolean | Is the organization local. | 
| MISP.Event.OwnerOrganization.ID | number | Owner organization ID. | 
| MISP.Event.OwnerOrganization.Name | string | Owner organization name. | 
| MISP.Event.OwnerOrganization.UUID | string | Owner organization UUID. | 
| MISP.Event.OwnerOrganization.local | boolean | Is the owner organization local. | 
| MISP.Event.ProposalEmailLock | boolean | If email lock is proposed. | 
| MISP.Event.LastChanged | date | Last change event timestamp. | 
| MISP.Event.Galaxy.Description | string | Event's galaxy description. | 
| MISP.Event.Galaxy.Name | string | Galaxy name. | 
| MISP.Event.Galaxy.Type | string | Galaxy type. | 
| MISP.Event.Published | boolean | Is the event published. | 
| MISP.Event.DisableCorrelation | boolean | Is correlation disabled. | 
| MISP.Event.UUID | string | Event UUID. | 
| MISP.Event.Analysis | string | Event analysis \(0 Initial, 1 Ongoing, 2 Completed\). | 
| MISP.Event.SharingGroupID | string | Event sharing group ID. | 
| MISP.Event.Tag.Name | string | All tag names in the event. | 
| MISP.Event.Tag.is_galaxy | boolean | Is the tag galaxy. | 
| MISP.Event.Object.Name | String | Name of the object. | 
| MISP.Event.Object.Description | String | Description of the object. | 
| MISP.Event.Object.ID | Number | ID of the object. | 
| MISP.Event.Object.UUID | String | UUID of the object. | 

### misp-add-attribute

***
Adds an attribute to an existing MISP event.

#### Base Command

`misp-add-attribute`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | MISP event ID. | Required | 
| type | Attribute type. For example: "md5", "sha1", "email", "url". Default is other. | Optional | 
| category | Attribute category. For example: "Other", "Person", "Attribution", "Payload type". Default is External analysis. | Optional | 
| to_ids | Whether to create the attribute with the Intrusion Detection System flag. Possible values: "true" and "false". Possible values are: true, false. Default is true. | Optional | 
| distribution | Where to distribute the event. Possible values: "Your_organization_only", "This_community_only", "Connected_communities", "Sharing_group", "All_communities", and "Inherit_event". Possible values are: Your_organization_only, This_community_only, Connected_communities, All_communities, Sharing_group, Inherit_event. Default is Inherit_event. | Optional | 
| comment | Comment for the attribute. | Optional | 
| value | A comma-separated list of attribute values. For example: "1.2.3.4,1.1.1.1" (and other IP addresses), "google.com" (and other domains), "www.example.com" (and other URLs). | Required | 
| sharing_group_id | Sharing group ID. Mandatory when Sharing_group distribution is set. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MISP.Attribute.Distribution | string | Attribute distribution. | 
| MISP.Attribute.Value | string | Attribute value. | 
| MISP.Attribute.EventID | string | Attribute event ID. | 
| MISP.Attribute.last_seen | string | Attribute last_seen timestamp. | 
| MISP.Attribute.first_seen | string | Attribute first_seen timestamp. | 
| MISP.Attribute.LastChanged | date | Attribute last changed timestamp. | 
| MISP.Attribute.Deleted | boolean | Is the attribute deleted. | 
| MISP.Attribute.DisableCorrelation | boolean | Is attribute correlation disabled. | 
| MISP.Attribute.Type | string | Attribute type. | 
| MISP.Attribute.ID | string | Attribute ID. | 
| MISP.Attribute.UUID | string | Attribute UUID. | 
| MISP.Attribute.ToIDs | boolean | Is the Intrusion Detection System flag set. | 
| MISP.Attribute.Category | string | Attribute category. | 
| MISP.Attribute.SharingGroupID | string | Attribute sharing group ID. | 
| MISP.Attribute.Comment | string | Attribute comment. | 
| MISP.Attribute.Event.ID | string | MISP event ID. | 
| MISP.Attribute.Event.Distribution | string | MISP event distribution. | 
| MISP.Attribute.Event.Info | string | MISP event name. | 
| MISP.Attribute.Event.OrganizationID | string | MISP event organization ID. | 
| MISP.Attribute.Event.OwnerOrganization.ID | string | Event owner organization ID. | 
| MISP.Attribute.Event.UUID | string | MISP event UUID. | 

### misp-delete-event

***
Deletes an event according to the given event ID.

#### Base Command

`misp-delete-event`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | Event ID to delete. | Required | 

#### Context Output

There is no context output for this command.
### misp-remove-tag-from-event

***
Removes a tag from the given UUID event .

#### Base Command

`misp-remove-tag-from-event`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the event. For example, 59575300-4be8-4ff6-8767-0037ac110032. | Required | 
| tag | Tag to remove from the event. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MISP.Event.ID | string | MISP event ID. | 
| MISP.Event.Distribution | string | MISP event distribution. | 
| MISP.Event.ThreatLevelID | string | Threat level of the MISP event \(1 High, 2 Medium, 3 Low, 4 Undefined\). | 
| MISP.Event.PublishTimestamp | number | Timestamp of the publish time \(if published\). | 
| MISP.Event.EventCreatorEmail | string | Email address of the event creator. | 
| MISP.Event.Info | string | Event name. | 
| MISP.Event.AttributeCount | string | Number of attributes of the event. | 
| MISP.Event.OrganizationID | string | Event organization ID. | 
| MISP.Event.CreationDate | date | Event creation date. | 
| MISP.Event.Locked | boolean | Is the event locked. | 
| MISP.Event.Organization.ID | number | Organization ID. | 
| MISP.Event.Organization.Name | string | Organization name. | 
| MISP.Event.Organization.UUID | string | Organization UUID. | 
| MISP.Event.Organization.local | boolean | Is the organization local. | 
| MISP.Event.OwnerOrganization.ID | number | Owner organization ID. | 
| MISP.Event.OwnerOrganization.Name | string | Owner organization name. | 
| MISP.Event.OwnerOrganization.UUID | string | Owner organization UUID. | 
| MISP.Event.OwnerOrganization.local | boolean | Is the owner organization local. | 
| MISP.Event.ProposalEmailLock | boolean | If email lock proposed. | 
| MISP.Event.LastChanged | date | Last change event timestamp. | 
| MISP.Event.Galaxy.Description | string | Event's galaxy description. | 
| MISP.Event.Galaxy.Name | string | Galaxy name. | 
| MISP.Event.Galaxy.Type | string | Galaxy type. | 
| MISP.Event.Published | boolean | Is the event published. | 
| MISP.Event.DisableCorrelation | boolean | Is correlation disabled. | 
| MISP.Event.UUID | string | Event UUID. | 
| MISP.Event.Analysis | string | Event analysis \(0 Initial, 1 Ongoing, 2 Completed\). | 
| MISP.Event.SharingGroupID | string | Event sharing group ID. | 
| MISP.Event.Tag.Name | string | All tag names in the event. | 
| MISP.Event.Tag.is_galaxy | boolean | Is the tag galaxy. | 
| MISP.Event.Object.Name | String | Name of the object. | 
| MISP.Event.Object.Description | String | Description of the object. | 
| MISP.Event.Object.ID | Number | ID of the object. | 
| MISP.Event.Object.UUID | String | UUID of the object. | 

### misp-add-tag-to-event

***
Adds a tag to the given UUID event .

#### Base Command

`misp-add-tag-to-event`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the event. For example, 59575300-4be8-4ff6-8767-0037ac110032. | Required | 
| tag | Tag to add to the event. | Required | 
| is_local | Whether to add the tag as a local tag. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MISP.Event.ID | string | MISP event ID. | 
| MISP.Event.Distribution | string | MISP event distribution. | 
| MISP.Event.ThreatLevelID | string | Threat level of the MISP event \(1 High, 2 Medium, 3 Low, 4 Undefined\). | 
| MISP.Event.PublishTimestamp | number | Timestamp of the publish time \(if published\). | 
| MISP.Event.EventCreatorEmail | string | Email address of the event creator. | 
| MISP.Event.Info | string | Event name. | 
| MISP.Event.AttributeCount | string | Number of attributes of the event. | 
| MISP.Event.OrganizationID | string | Event organization ID. | 
| MISP.Event.CreationDate | date | Event creation date. | 
| MISP.Event.Locked | boolean | Is the event locked. | 
| MISP.Event.Organization.ID | number | Organization ID. | 
| MISP.Event.Organization.Name | string | Organization name. | 
| MISP.Event.Organization.UUID | string | Organization UUID. | 
| MISP.Event.Organization.local | boolean | Is the organization local. | 
| MISP.Event.OwnerOrganization.ID | number | Owner organization ID. | 
| MISP.Event.OwnerOrganization.Name | string | Owner organization name. | 
| MISP.Event.OwnerOrganization.UUID | string | Owner organization UUID. | 
| MISP.Event.OwnerOrganization.local | boolean | Is the owner organization local. | 
| MISP.Event.ProposalEmailLock | boolean | If email lock proposed. | 
| MISP.Event.LastChanged | date | Last change event timestamp. | 
| MISP.Event.Galaxy.Description | string | Event's galaxy description. | 
| MISP.Event.Galaxy.Name | string | Galaxy name. | 
| MISP.Event.Galaxy.Type | string | Galaxy type. | 
| MISP.Event.Published | boolean | Is the event published. | 
| MISP.Event.DisableCorrelation | boolean | Is correlation disabled. | 
| MISP.Event.UUID | string | Event UUID. | 
| MISP.Event.Analysis | string | Event analysis \(0 Initial, 1 Ongoing, 2 Completed\). | 
| MISP.Event.SharingGroupID | string | Event sharing group ID. | 
| MISP.Event.Tag.Name | string | All tag names in the event. | 
| MISP.Event.Tag.is_galaxy | boolean | Is the tag galaxy. | 
| MISP.Event.Object.Name | String | Name of the object. | 
| MISP.Event.Object.Description | String | Description of the object. | 
| MISP.Event.Object.ID | Number | ID of the object. | 
| MISP.Event.Object.UUID | String | UUID of the object. | 

### misp-add-tag-to-attribute

***
Adds a tag to the given UUID attribute.

#### Base Command

`misp-add-tag-to-attribute`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the attribute. For example, 59575300-4be8-4ff6-8767-0037ac110032. | Required | 
| tag | Tag to add to the attribute. | Required | 
| is_local | Whether to add the tag as a local tag. Possible values are: true, false. | Optional | 
| disable_output | If true, the attribute information will not be displayed in the response, reducing the runtime. Possible values are: false, true. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MISP.Attribute.Distribution | string | Attribute distribution. | 
| MISP.Attribute.Value | string | Attribute value. | 
| MISP.Attribute.EventID | string | Attribute event ID. | 
| MISP.Attribute.last_seen | string | Attribute last_seen timestamp. | 
| MISP.Attribute.first_seen | string | Attribute first_seen timestamp. | 
| MISP.Attribute.LastChanged | date | Attribute last changed timestamp. | 
| MISP.Attribute.ObjectID | string | Attribute object ID. | 
| MISP.Attribute.Deleted | boolean | Is the attribute deleted. | 
| MISP.Attribute.DisableCorrelation | boolean | Is attribute correlation disabled. | 
| MISP.Attribute.Type | string | Attribute type. | 
| MISP.Attribute.ID | string | Attribute ID. | 
| MISP.Attribute.UUID | string | Attribute UUID. | 
| MISP.Attribute.ToIDs | boolean | Is the Intrusion Detection System flag set. | 
| MISP.Attribute.Category | string | Attribute category. | 
| MISP.Attribute.SharingGroupID | string | Attribute sharing group ID. | 
| MISP.Attribute.Comment | string | Attribute comment. | 
| MISP.Attribute.Event.ID | string | MISP event ID. | 
| MISP.Attribute.Event.Distribution | string | MISP event distribution. | 
| MISP.Attribute.Event.Info | string | MISP event name. | 
| MISP.Attribute.Event.OrganizationID | string | MISP event organization ID. | 
| MISP.Attribute.Event.OwnerOrganization.ID | string | Event owner organization ID. | 
| MISP.Attribute.Event.UUID | string | MISP event UUID. | 
| MISP.Attribute.Tag.Name | string | Attribute tag name. | 
| MISP.Attribute.Tag.is_galaxy | string | Is the tag galaxy. | 

### misp-remove-tag-from-attribute

***
Removes a tag from the given UUID attribute.

#### Base Command

`misp-remove-tag-from-attribute`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the attribute. For example, 59575300-4be8-4ff6-8767-0037ac110032. | Required | 
| tag | Tag to remove from the attribute. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MISP.Attribute.Distribution | string | Attribute distribution. | 
| MISP.Attribute.Value | string | Attribute value. | 
| MISP.Attribute.EventID | string | Attribute event ID. | 
| MISP.Attribute.last_seen | string | Attribute last_seen timestamp. | 
| MISP.Attribute.first_seen | string | Attribute first_seen timestamp. | 
| MISP.Attribute.LastChanged | date | Attribute last changed timestamp. | 
| MISP.Attribute.ObjectID | string | Attribute object ID. | 
| MISP.Attribute.Deleted | boolean | Is the attribute deleted. | 
| MISP.Attribute.DisableCorrelation | boolean | Is attribute correlation disabled. | 
| MISP.Attribute.Type | string | Attribute type. | 
| MISP.Attribute.ID | string | Attribute ID. | 
| MISP.Attribute.UUID | string | Attribute UUID. | 
| MISP.Attribute.ToIDs | boolean | Is the Intrusion Detection System flag set. | 
| MISP.Attribute.Category | string | Attribute category. | 
| MISP.Attribute.SharingGroupID | string | Attribute sharing group ID. | 
| MISP.Attribute.Comment | string | Attribute comment. | 
| MISP.Attribute.Event.ID | string | MISP event ID. | 
| MISP.Attribute.Event.Distribution | string | MISP event distribution. | 
| MISP.Attribute.Event.Info | string | MISP event name. | 
| MISP.Attribute.Event.OrganizationID | string | MISP event organization ID. | 
| MISP.Attribute.Event.OwnerOrganization.ID | string | Event owner organization ID. | 
| MISP.Attribute.Event.UUID | string | MISP event UUID. | 
| MISP.Attribute.Tag.Name | string | Attribute tag name. | 
| MISP.Attribute.Tag.is_galaxy | string | Is the tag galaxy. | 

### misp-add-sighting

***
Add sighting to an attribute.

#### Base Command

`misp-add-sighting`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | Type of sighting to add. Possible values: "sighting", "false_positive", and "expiration". Possible values are: sighting, false_positive, expiration. | Required | 
| id | ID of attribute to add sighting to (Must be filled if UUID is empty). Can be retrieved from the misp-search commands. | Optional | 
| uuid | UUID of the attribute to add sighting to (Must be filled if ID is empty). Can be retrieved from the misp-search commands. | Optional | 

#### Context Output

There is no context output for this command.
### misp-add-events-from-feed

***
Adds an OSINT feed. Only feeds in the misp format are allowed. For example have manifest.json.

#### Base Command

`misp-add-events-from-feed`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| feed | URL of the feed to add. Possible values: CIRCL and "Botvrij.eu". Possible values are: CIRCL, Botvrij.eu. | Required | 
| limit | Maximum number of files to add. Default is 2. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MISP.Event.ID | string | IDs of the newly created events. | 

### misp-add-file-object

***
Adds a file object to the specified event ID.

#### Base Command

`misp-add-file-object`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | Entry ID of the file. | Required | 
| event_id | Event ID to which to add the object to. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MISP.Event.ID | number | MISP event ID. | 
| MISP.Event.Object.MetaCategory | String | Object meta category. | 
| MISP.Event.Object.Distribution | Number | Distribution of the object. | 
| MISP.Event.Object.Name | String | Name of the object. | 
| MISP.Event.Object.TemplateVersion | Number | Template version of the object. | 
| MISP.Event.Object.EventID | Number | ID of the event in which the object was first created. | 
| MISP.Event.Object.TemplateUUID | String | UUID of the template. | 
| MISP.Event.Object.LastChanged | String | Timestamp when the object was last changed. | 
| MISP.Event.Object.Deleted | Boolean | Whether the object was deleted. | 
| MISP.Event.Object.ID | Number | ID of the object. | 
| MISP.Event.Object.UUID | String | UUID of the object. | 
| MISP.Event.Object.Attribute.Value | String | Value of the attribute. | 
| MISP.Event.Object.Attribute.EventID | Number | ID of the first event from which the object originated. | 
| MISP.Event.Object.Attribute.LastChanged | Date | Attribute last changed timestamp. | 
| MISP.Event.Object.Attribute.Deleted | Boolean | Whether the object was deleted. | 
| MISP.Event.Object.Attribute.ObjectID | Number | ID of the object. | 
| MISP.Event.Object.Attribute.DisableCorrelation | Boolean | Whether correlation is disabled. | 
| MISP.Event.Object.Attribute.ID | Unknown | ID of the attribute. | 
| MISP.Event.Object.Attribute.ObjectRelation | String | Relation of the object. | 
| MISP.Event.Object.Attribute.Type | String | Object type. | 
| MISP.Event.Object.Attribute.UUID | String | UUID of the attribute. | 
| MISP.Event.Object.Attribute.ToIDs | Boolean | Whether the to_ids flag is on. | 
| MISP.Event.Object.Attribute.Category | String | Category of the attribute. | 
| MISP.Event.Object.Attribute.SharingGroupID | Number | ID of the sharing group. | 
| MISP.Event.Object.Attribute.Comment | String | Comment of the attribute. | 
| MISP.Event.Object.Description | String | Description of the object. | 

### misp-add-email-object

***
Adds an email object to the specified event ID.

#### Base Command

`misp-add-email-object`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | Entry ID of the email (only supports .eml files). | Required | 
| event_id | ID of the event to which to add object to. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MISP.Event.ID | number | MISP event ID. | 
| MISP.Event.Object.MetaCategory | String | Object meta category. | 
| MISP.Event.Object.Distribution | Number | Distribution of the object. | 
| MISP.Event.Object.Name | String | Name of the object. | 
| MISP.Event.Object.TemplateVersion | Number | Template version of the object. | 
| MISP.Event.Object.EventID | Number | ID of the event in which the object was first created. | 
| MISP.Event.Object.TemplateUUID | String | UUID of the template. | 
| MISP.Event.Object.LastChanged | String | Timestamp when the object was last changed. | 
| MISP.Event.Object.Deleted | Boolean | Whether the object was deleted. | 
| MISP.Event.Object.ID | Number | ID of the object. | 
| MISP.Event.Object.UUID | String | UUID of the object. | 
| MISP.Event.Object.Attribute.Value | String | Value of the attribute. | 
| MISP.Event.Object.Attribute.EventID | Number | ID of the first event from which the object originated. | 
| MISP.Event.Object.Attribute.LastChanged | Date | Attribute last changed timestamp. | 
| MISP.Event.Object.Attribute.Deleted | Boolean | Whether the object was deleted. | 
| MISP.Event.Object.Attribute.ObjectID | Number | ID of the object. | 
| MISP.Event.Object.Attribute.DisableCorrelation | Boolean | Whether correlation is disabled. | 
| MISP.Event.Object.Attribute.ID | Unknown | ID of the attribute. | 
| MISP.Event.Object.Attribute.ObjectRelation | String | Relation of the object. | 
| MISP.Event.Object.Attribute.Type | String | Object type. | 
| MISP.Event.Object.Attribute.UUID | String | UUID of the attribute. | 
| MISP.Event.Object.Attribute.ToIDs | Boolean | Whether the to_ids flag is on. | 
| MISP.Event.Object.Attribute.Category | String | Category of the attribute. | 
| MISP.Event.Object.Attribute.SharingGroupID | Number | ID of the sharing group. | 
| MISP.Event.Object.Attribute.Comment | String | Comment of the attribute. | 
| MISP.Event.Object.Description | String | Description of the object. | 

### misp-add-domain-object

***
Adds a domain object to MISP.

#### Base Command

`misp-add-domain-object`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | ID of an MISP event. | Required | 
| name | The domain name. For example, "google.com". | Required | 
| ip | A comma-separated list of IP addresses resolved by DNS. | Required | 
| text | A description of the domain. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MISP.Event.ID | number | MISP event ID. | 
| MISP.Event.Object.MetaCategory | String | Object meta category. | 
| MISP.Event.Object.Distribution | Number | Distribution of the object. | 
| MISP.Event.Object.Name | String | Name of the object. | 
| MISP.Event.Object.TemplateVersion | Number | Template version of the object. | 
| MISP.Event.Object.EventID | Number | ID of the event in which the object was first created. | 
| MISP.Event.Object.TemplateUUID | String | UUID of the template. | 
| MISP.Event.Object.LastChanged | String | Timestamp when the object was last changed. | 
| MISP.Event.Object.Deleted | Boolean | Whether the object was deleted. | 
| MISP.Event.Object.ID | Number | ID of the object. | 
| MISP.Event.Object.UUID | String | UUID of the object. | 
| MISP.Event.Object.Attribute.Value | String | Value of the attribute. | 
| MISP.Event.Object.Attribute.EventID | Number | ID of the first event from which the object originated. | 
| MISP.Event.Object.Attribute.LastChanged | Date | Attribute last changed timestamp. | 
| MISP.Event.Object.Attribute.Deleted | Boolean | Whether the object was deleted. | 
| MISP.Event.Object.Attribute.ObjectID | Number | ID of the object. | 
| MISP.Event.Object.Attribute.DisableCorrelation | Boolean | Whether correlation is disabled. | 
| MISP.Event.Object.Attribute.ID | Unknown | ID of the attribute. | 
| MISP.Event.Object.Attribute.ObjectRelation | String | Relation of the object. | 
| MISP.Event.Object.Attribute.Type | String | Object type. | 
| MISP.Event.Object.Attribute.UUID | String | UUID of the attribute. | 
| MISP.Event.Object.Attribute.ToIDs | Boolean | Whether the to_ids flag is on. | 
| MISP.Event.Object.Attribute.Category | String | Category of the attribute. | 
| MISP.Event.Object.Attribute.SharingGroupID | Number | ID of the sharing group. | 
| MISP.Event.Object.Attribute.Comment | String | Comment of the attribute. | 
| MISP.Event.Object.Description | String | Description of the object. | 

### misp-add-url-object

***
Adds a URL object to an MISP event.

#### Base Command

`misp-add-url-object`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | Full URL to add to the event. | Required | 
| first_seen | Date that this URL was first seen. For example, `2019-02-03`. | Optional | 
| text | Description of the URL. | Optional | 
| last_seen | Date that this URL was last seen. For example, `2019-02-03`. | Optional | 
| event_id | ID of a MISP event. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MISP.Event.ID | number | MISP event ID. | 
| MISP.Event.Object.MetaCategory | String | Object meta category. | 
| MISP.Event.Object.Distribution | Number | Distribution of the object. | 
| MISP.Event.Object.Name | String | Name of the object. | 
| MISP.Event.Object.TemplateVersion | Number | Template version of the object. | 
| MISP.Event.Object.EventID | Number | ID of the event in which the object was first created. | 
| MISP.Event.Object.TemplateUUID | String | UUID of the template. | 
| MISP.Event.Object.LastChanged | String | Timestamp when the object was last changed. | 
| MISP.Event.Object.Deleted | Boolean | Whether the object was deleted. | 
| MISP.Event.Object.ID | Number | ID of the object. | 
| MISP.Event.Object.UUID | String | UUID of the object. | 
| MISP.Event.Object.Attribute.Value | String | Value of the attribute. | 
| MISP.Event.Object.Attribute.EventID | Number | ID of the first event from which the object originated. | 
| MISP.Event.Object.Attribute.LastChanged | Date | Attribute last changed timestamp. | 
| MISP.Event.Object.Attribute.Deleted | Boolean | Whether the object was deleted. | 
| MISP.Event.Object.Attribute.ObjectID | Number | ID of the object. | 
| MISP.Event.Object.Attribute.DisableCorrelation | Boolean | Whether correlation is disabled. | 
| MISP.Event.Object.Attribute.ID | Unknown | ID of the attribute. | 
| MISP.Event.Object.Attribute.ObjectRelation | String | Relation of the object. | 
| MISP.Event.Object.Attribute.Type | String | Object type. | 
| MISP.Event.Object.Attribute.UUID | String | UUID of the attribute. | 
| MISP.Event.Object.Attribute.ToIDs | Boolean | Whether the to_ids flag is on. | 
| MISP.Event.Object.Attribute.Category | String | Category of the attribute. | 
| MISP.Event.Object.Attribute.SharingGroupID | Number | ID of the sharing group. | 
| MISP.Event.Object.Attribute.Comment | String | Comment of the attribute. | 
| MISP.Event.Object.Description | String | Description of the object. | 

### misp-add-object

***
Adds any other object to MISP.

#### Base Command

`misp-add-object`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | ID of the event to add the object to. | Required | 
| template | Template name. (Can be found at https://www.misp-project.org/objects.html). For example, 'vehicle'. | Required | 
| attributes | Attributes. For example, {"description": "Manager Ferrari", "make": "Ferrari", "model": "308 GTS"}. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MISP.Event.ID | number | MISP event ID. | 
| MISP.Event.Object.MetaCategory | String | Object meta category. | 
| MISP.Event.Object.Distribution | Number | Distribution of the object. | 
| MISP.Event.Object.Name | String | Name of the object. | 
| MISP.Event.Object.TemplateVersion | Number | Template version of the object. | 
| MISP.Event.Object.EventID | Number | ID of the event in which the object was first created. | 
| MISP.Event.Object.TemplateUUID | String | UUID of the template. | 
| MISP.Event.Object.LastChanged | String | Timestamp when the object was last changed. | 
| MISP.Event.Object.Deleted | Boolean | Whether the object was deleted. | 
| MISP.Event.Object.ID | Number | ID of the object. | 
| MISP.Event.Object.UUID | String | UUID of the object. | 
| MISP.Event.Object.Attribute.Value | String | Value of the attribute. | 
| MISP.Event.Object.Attribute.EventID | Number | ID of the first event from which the object originated. | 
| MISP.Event.Object.Attribute.LastChanged | Date | Attribute last changed timestamp. | 
| MISP.Event.Object.Attribute.Deleted | Boolean | Whether the object was deleted? | 
| MISP.Event.Object.Attribute.ObjectID | Number | ID of the object. | 
| MISP.Event.Object.Attribute.DisableCorrelation | Boolean | Whether correlation is disabled. | 
| MISP.Event.Object.Attribute.ID | Unknown | ID of the attribute. | 
| MISP.Event.Object.Attribute.ObjectRelation | String | Relation of the object. | 
| MISP.Event.Object.Attribute.Type | String | Object type. | 
| MISP.Event.Object.Attribute.UUID | String | UUID of the attribute. | 
| MISP.Event.Object.Attribute.ToIDs | Boolean | Whether the to_ids flag is on. | 
| MISP.Event.Object.Attribute.Category | String | Category of the attribute. | 
| MISP.Event.Object.Attribute.SharingGroupID | Number | ID of the sharing group. | 
| MISP.Event.Object.Attribute.Comment | String | Comment of the attribute. | 
| MISP.Event.Object.Description | String | Description of the object. | 

### misp-add-ip-object

***
Adds an IP object to the MISP event. The following arguments are optional, but at least one must be supplied for the command to run successfully: "ip", "dst_port", "src_port", "domain", "hostname", "ip_src", and "ip_dst".

#### Base Command

`misp-add-ip-object`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | ID of a MISP event. | Required | 
| ip | A comma-separated list of IP addresses. | Optional | 
| dst_port | Destination port number. | Optional | 
| src_port | Source port number. | Optional | 
| domain | Domain name. | Optional | 
| hostname | Hostname. For example, 'mail123.example.com'. | Optional | 
| ip_src | IP source address. | Optional | 
| ip_dst | IP destination address. | Optional | 
| first_seen | Date when the IP address was first seen. For example, `2019-02-03`. | Optional | 
| last_seen | Date when the IP address was last seen. For example, `2019-02-03`. | Optional | 
| comment | Description of the object to be set as a text attribute. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MISP.Event.ID | number | MISP event ID. | 
| MISP.Event.Object.MetaCategory | String | Object meta category. | 
| MISP.Event.Object.Distribution | Number | Distribution of the object. | 
| MISP.Event.Object.Name | String | Name of the object. | 
| MISP.Event.Object.TemplateVersion | Number | Template version of the object. | 
| MISP.Event.Object.EventID | Number | ID of the event in which the object was first created. | 
| MISP.Event.Object.TemplateUUID | String | UUID of the template. | 
| MISP.Event.Object.LastChanged | String | Timestamp when the object was last changed. | 
| MISP.Event.Object.Deleted | Boolean | Whether the object was deleted. | 
| MISP.Event.Object.ID | Number | ID of the object. | 
| MISP.Event.Object.UUID | String | UUID of the object. | 
| MISP.Event.Object.Attribute.Value | String | Value of the attribute. | 
| MISP.Event.Object.Attribute.EventID | Number | ID of the first event from which the object originated. | 
| MISP.Event.Object.Attribute.LastChanged | Date | Attribute last changed timestamp. | 
| MISP.Event.Object.Attribute.Deleted | Boolean | Whether the object was deleted. | 
| MISP.Event.Object.Attribute.ObjectID | Number | ID of the object. | 
| MISP.Event.Object.Attribute.DisableCorrelation | Boolean | Whether correlation is disabled. | 
| MISP.Event.Object.Attribute.ID | Unknown | ID of the attribute. | 
| MISP.Event.Object.Attribute.ObjectRelation | String | Relation of the object. | 
| MISP.Event.Object.Attribute.Type | String | Object type. | 
| MISP.Event.Object.Attribute.UUID | String | UUID of the attribute. | 
| MISP.Event.Object.Attribute.ToIDs | Boolean | Whether the to_ids flag is on. | 
| MISP.Event.Object.Attribute.Category | String | Category of the attribute. | 
| MISP.Event.Object.Attribute.SharingGroupID | Number | ID of the sharing group. | 
| MISP.Event.Object.Attribute.Comment | String | Comment of the attribute. | 
| MISP.Event.Object.Description | String | Description of the object. | 

### misp-search-attributes

***
Search for attributes in MISP.

#### Base Command

`misp-search-attributes`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The attribute type. Use any valid MISP attribute type. For example: "md5", "sha1", "email", "url". | Optional | 
| value | Search for the specified value in the attribute's value field. For example: "1.2.3.4" (and other IP addresses), "google.com" (and other domains), "www.example.com" (and other URLs). | Optional | 
| category | The attribute category. Use any valid MISP attribute category. For example: "Other", "Person", "Attribution", "Payload type". | Optional | 
| uuid | Return attributes with the given UUID. Alternatively, return all the attributes that are part of the given UUID's event. For example, 59523300-4be8-4fa6-8867-0037ac110002. | Optional | 
| to_ids | Whether to return only the attributes set with the "to_ids" flag. The default is to return all attributes without with and with out to_ids flag. Possible values: "true" and "false". Possible values are: true, false. | Optional | 
| last | Search attributes of events published within the last "x" amount of time. Valid time values are days, hours, and minutes. For example, "5d", "12h", "30m". This filter uses the published timestamp of the event. | Optional | 
| include_decay_score | Whether to return the decay score at the attribute level. Possible values: "true" and "false". Possible values are: true, false. | Optional | 
| org | Search by the creator organization by supplying the organization identifier. | Optional | 
| tags | A comma-separated list of tags to include in the results. To exclude a tag, prefix the tag name with "!". Can be: "AND", "OR", and "NOT" followed by ":". To chain logical operators use ";". For example, "AND:tag1,tag2;OR:tag3". | Optional | 
| from | Events with the date set to a date after the one specified. This filter will use the date of the event. | Optional | 
| to | Events with the date set to a date before the one specified. This filter will use the date of the event. | Optional | 
| event_id | A comma-separated list of event IDs. Returns the attributes that are part of the given event IDs. | Optional | 
| include_sightings | Whether to include the the sightings of the matching attributes. Default is false. Possible values: "true" and "false". Possible values are: true, false. | Optional | 
| include_correlations | Whether to include the full correlations of the matching attributes. Possible values: "true" and "false". Default is false. Possible values are: true, false. | Optional | 
| page | If a limit is set, sets the page to be returned. For example, page 3, limit 100 will return records 201-&gt;300. Default is 1. Default is 1. | Optional | 
| limit | Limit the number of attributes returned. Default is 50. Default is 50. | Optional | 
| enforceWarninglist | Whether to return only the values that are not on the warninglists. Possible values: "true" and "false". Possible values are: true, false. | Optional | 
| compact | Whether to return only the attribute's values that match the search query. In case you want to get the full attributes data, set this argument to false. Possible values: "true" and "false". Possible values are: true, false. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MISP.Attribute.Distribution | string | Attribute distribution. | 
| MISP.Attribute.last_seen | string | Attribute last_seen timestamp. | 
| MISP.Attribute.first_seen | string | Attribute first_seen timestamp. | 
| MISP.Attribute.Value | string | Attribute value. | 
| MISP.Attribute.EventID | string | Attribute event ID. | 
| MISP.Attribute.LastChanged | date | Attribute last changed timestamp. | 
| MISP.Attribute.Deleted | boolean | Is the attribute deleted. | 
| MISP.Attribute.DisableCorrelation | boolean | Is attribute correlation disabled. | 
| MISP.Attribute.Type | string | Attribute type. | 
| MISP.Attribute.ObjectID | string | Attribute's object ID. | 
| MISP.Attribute.ID | string | Attribute ID. | 
| MISP.Attribute.UUID | string | Attribute UUID. | 
| MISP.Attribute.ObjectRelation | string | Attribute's object relation. | 
| MISP.Attribute.ShadowAttribute | Unknown | Attribute shadow attribute. | 
| MISP.Attribute.ToIDs | boolean | Is the Intrusion Detection System flag set. | 
| MISP.Attribute.Category | string | Attribute category. | 
| MISP.Attribute.SharingGroupID | number | Attribute sharing group ID. | 
| MISP.Attribute.Comment | string | Attribute comment. | 
| MISP.Attribute.Event.ID | string | MISP event ID. | 
| MISP.Attribute.Event.Distribution | string | MISP event distribution. | 
| MISP.Attribute.Event.Info | string | MISP event name. | 
| MISP.Attribute.Event.OrganizationID | string | MISP event organization ID. | 
| MISP.Attribute.Event.OwnerOrganization.ID | string | MISP event owner organization ID. | 
| MISP.Attribute.Event.UUID | string | Event UUID. | 
| MISP.Attribute.Object.Distribution | Number | Distribution of object. | 
| MISP.Attribute.Object.ID | Number | ID of the object. | 
| MISP.Attribute.Object.SharingGroupID | String | Object sharing group ID. | 
| MISP.Attribute.Tag.Name | string | All tag names in the attribute. | 
| MISP.Attribute.Tag.is_galaxy | Boolean | Is the tag is a galaxy. | 
| MISP.Attribute.Sighting.Type | String | Sighting type. | 

### misp-add-user

***
Adding a new user to MISP.

#### Base Command

`misp-add-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | The email address of the new user to be added | Required | 
| org_id | ID number indicating which organization the new user will be added to. | Required | 
| role_id | Role of the new user to be added. | Required | 
| password | A password for the new user | Required |

#### Context Output

There is no context output for this command.

### misp-update-attribute

***
Update an attribute of an existing MISP event.

#### Base Command

`misp-update-attribute`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| attribute_uuid | UUID of the attribute to be updated. | Required | 
| type | Attribute type. For example: "md5", "sha1", "email", "url". | Optional | 
| category | Attribute category. For example: "Other", "Person", "Attribution", "Payload type". | Optional | 
| distribution | Where to distribute the event. Possible values: "Your_organization_only", "This_community_only", "Connected_communities", "All_communities", and "Inherit_event". Possible values are: Your_organization_only, This_community_only, Connected_communities, All_communities, Inherit_event. | Optional | 
| comment | Comment for the attribute. | Optional | 
| value | Attribute value. For example: "1.2.3.4" (and other IP addresses), "google.com" (and other domains), "www.example.com" (and other URLs). | Optional | 
| first_seen | Updated date when the attribute was first seen. For example, `2019-02-03`. | Optional | 
| last_seen | Updated date when the attribute was last seen. For example, `2019-02-03`. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MISP.Attribute.Distribution | string | Attribute distribution. | 
| MISP.Attribute.Value | string | Attribute value. | 
| MISP.Attribute.EventID | string | Attribute event ID. | 
| MISP.Attribute.last_seen | string | Attribute last_seen timestamp. | 
| MISP.Attribute.first_seen | string | Attribute first_seen timestamp. | 
| MISP.Attribute.LastChanged | date | Attribute last changed timestamp. | 
| MISP.Attribute.Deleted | boolean | Is the attribute deleted. | 
| MISP.Attribute.DisableCorrelation | boolean | Is attribute correlation disabled. | 
| MISP.Attribute.Type | string | Attribute type. | 
| MISP.Attribute.ID | string | Attribute ID. | 
| MISP.Attribute.UUID | string | Attribute UUID. | 
| MISP.Attribute.ToIDs | boolean | Is the Intrusion Detection System flag set. | 
| MISP.Attribute.Category | string | Attribute category. | 
| MISP.Attribute.SharingGroupID | string | Attribute sharing group ID. | 
| MISP.Attribute.Comment | string | Attribute comment. | 

### misp-delete-attribute

***
Delete an attribute according to the given attribute ID.

#### Base Command

`misp-delete-attribute`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| attribute_id | Attribute ID to delete. | Required | 

#### Context Output

There is no context output for this command.
### misp-publish-event

***
Publish an event.

#### Base Command

`misp-publish-event`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | Event ID to be published. | Required | 
| alert | Whether to send an email. The default is to not send a mail. Possible values are: true, false. | Optional | 

#### Context Output

There is no context output for this command.
### misp-set-event-attributes

***
Set event attributes according to the given attributes data.

#### Base Command

`misp-set-event-attributes`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | Event ID to set attributes for. | Required | 
| attribute_data | Adjust current attributes of an event to match the given attribute data. Has to be json formated list with attributes that should be part of the event. E.g.: [{"type":"domain","value":"target.domain"},{"type":"ip-dst","value":"1.2.3.4"}]. | Required | 

#### Context Output

There is no context output for this command.
### misp-check-warninglist

***
Check a list of indicator values against the MISP warninglist.

#### Base Command

`misp-check-warninglist`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| value | Indicator values to check against the MISP warninglist. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MISP.Warninglist.Count | number | Count on how many warninglists the value was found. | 
| MISP.Warninglist.Value | string | Value checked. | 
| MISP.Warninglist.Lists | string | Name of warninglists where the value was found. | 

### misp-add-user

***
Adding a new user to MISP.

#### Base Command

`misp-add-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | The email address of the new user to be added. | Required | 
| org_id | ID number indicating which organization the new user will be added to. | Required | 
| role_id | Role of the new user to be added. | Required | 
| password | A password for the new user. | Required | 

#### Context Output

There is no context output for this command.
## Breaking changes from the previous version of this integration - MISP v3

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

* Insert any API changes, any behavioral changes, limitations, or restrictions that would be new to this version.
