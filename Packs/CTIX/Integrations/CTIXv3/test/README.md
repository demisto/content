This is Cyware Threat Intelligence eXhange(CTIX) integration which enriches IP/Domain/URL/File Data.
This integration was integrated and tested with version xx of CTIX v3 Beta

## Configure CTIX v3 Beta on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for CTIX v3 Beta.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Endpoint URL | Enter the endpoint URL of your CTIX Instance, e.g. https://example.cyware.com/ctixapi/. | True |
    | Access Key | Enter the Access Key from the CTIX application. | True |
    | Secret Key | Enter the Secret Key from the CTIX application. | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Source Reliability | Reliability of the source providing the intelligence data. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ctix-create-tag
***
Create new tag in the ctix platform


#### Base Command

`ctix-create-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag_name | New tag's name. | Required | 
| color | New tag's name for the defined colour. If no colour selected, colour grey will be given. Possible values are: blue, purple, orange, red, green, yellow, turquoise, pink, light-red, grey. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.Tag.name | string | Name of the tag | 
| CTIX.Tag.tag_type | string | Type of the tag \(manual\) | 
| CTIX.Tag.colour_code | string | Colour Code of the tag | 
| CTIX.Tag.id | string | Id of the Created Tag | 
| CTIX.Tag.created | number | Created at timestamp | 
| CTIX.Tag.modified | number | Modified at timestamp | 

### ctix-get-tags
***
Get paginated list of tags


#### Base Command

`ctix-get-tags`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number for pagination. Default is 1. | Optional | 
| page_size | Page size for pagination. Default is 10. | Optional | 
| q | search query parameter. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.Tag.name | string | Name of the tag | 
| CTIX.Tag.id | string | ID of the tag | 
| CTIX.Tag.colour_code | string | Hex colour code associated with tag | 
| CTIX.Tag.tag_type | string | Type of the tag | 
| CTIX.Tag.created | number | Created at timestamp | 
| CTIX.Tag.modified | number | Modified at timestamp | 

### ctix-delete-tag
***
Delete a tag with given tag_name


#### Base Command

`ctix-delete-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag_name | Name of the tag. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.DeleteTag.result | string | Status | 

### ctix-allowed-iocs
***
Adds list of same type of iocs to allowed


#### Base Command

`ctix-allowed-iocs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | Type of ioc. Possible values are: ipv4-addr, ipv6-addr, autonomous-system, email-addr, MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SSDEEP, url, cidr, domain-name, mutex, windows-registry-key, user-agent. | Required | 
| values | Values of the given type. | Required | 
| reason | Descriptive reason. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.Details.invalid | unknown | Invalid iocs sent in request | 
| CTIX.Details.new_created | unknown | List of iocs added to allowed | 
| CTIX.Details.already_exists | unknown | List of iocs already existing | 

### ctix-get-allowed-iocs
***
get paginated list of allowed iocs


#### Base Command

`ctix-get-allowed-iocs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number . Default is 1. | Optional | 
| page_size | Page size. Default is 10. | Optional | 
| q | query param for searching. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.IOC.id | string | ID of the object | 
| CTIX.IOC.include_emails | boolean | If enabled then the emails to the corresponding emails will be allowed | 
| CTIX.IOC.include_sub_domains | boolean | If enabled then the emails to the corresponding sub domains will be allowed | 
| CTIX.IOC.include_urls | boolean | If enabled then the emails to the corresponding urls will be allowed | 
| CTIX.IOC.type | string | Type of the ioc | 
| CTIX.IOC.value | string | Value of the ioc | 
| CTIX.IOC.created | number | Created at timestamp | 
| CTIX.IOC.modified | number | Modified at timestamp | 

### ctix-remove-allowed-ioc
***
Removes a allowed ioc with given id


#### Base Command

`ctix-remove-allowed-ioc`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | allowed IOC ids. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| details | string | Operation result | 

### ctix-get-threat-data
***
Command for querying and listing threat data


#### Base Command

`ctix-get-threat-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Query statement for the thread data, please refer to the documentation. | Required | 
| page | page. Default is 1. | Optional | 
| page_size | size of page. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.ThreatData.confidence_score | number | Confidence Score of the IOC | 
| CTIX.ThreatData.confidence_type | string | Confidence Type of the IOC | 
| CTIX.ThreatData.created | number | When the IOC was created in source | 
| CTIX.ThreatData.ctix_created | number | When the IOC was created in CTIX | 
| CTIX.ThreatData.ctix_modified | number | When the IOC was modified in CTIX | 
| CTIX.ThreatData.id | string | ID of the IOC in CTIX | 
| CTIX.ThreatData.indicator_type | string | Type of the Indicator | 
| CTIX.ThreatData.ioc_type | string | Type of IOC | 
| CTIX.ThreatData.is_actioned | boolean | Is Actioned | 
| CTIX.ThreatData.is_deprecated | boolean | Is Deprecated | 
| CTIX.ThreatData.is_false_positive | boolean | Is False Positive | 
| CTIX.ThreatData.is_reviewed | boolean | Is reviewed | 
| CTIX.ThreatData.is_revoked | boolean | Is revoked | 
| CTIX.ThreatData.is_watchlist | boolean | Is Watchlist | 
| CTIX.ThreatData.is_whitelisted | boolean | Is allowed | 
| CTIX.ThreatData.modified | boolean | When the indicator modified | 
| CTIX.ThreatData.name | boolean | Name of the indicator | 
| CTIX.ThreatData.risk_severity | boolean | risk severity of the indicator | 
| CTIX.ThreatData.source_collections | unknown | Source Collections of the Indicator | 
| CTIX.ThreatData.source_confidence | string | Source Confidence of the indicator | 
| CTIX.ThreatData.sources | unknown | sources of the indicator | 
| CTIX.ThreatData.sub_type | string | Sub Type of the IOC | 
| CTIX.ThreatData.tlp | string | TLP of the indicator | 
| CTIX.ThreatData.type | string | Type of the IOC | 
| CTIX.ThreatData.valid_from | number | Date from which IOC is valid | 

### ctix-get-saved-searches
***
Saved Search listing api with pagination


#### Base Command

`ctix-get-saved-searches`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | page from where to start. | Optional | 
| page_size | page size of the result. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.SavedSearch.id | string | ID of the object | 
| CTIX.SavedSearch.editable | boolean | editable object details | 
| CTIX.SavedSearch.is_threat_data_search | boolean | is threat data search | 
| CTIX.SavedSearch.name | string | name of the IOC | 
| CTIX.SavedSearch.order | number | order details | 
| CTIX.SavedSearch.pinned | boolean | Pinned details | 
| CTIX.SavedSearch.query | string | CQL used | 
| CTIX.SavedSearch.shared_type | string | shared type | 
| CTIX.SavedSearch.type | string | type of the object | 
| CTIX.SavedSearch.meta_data | unknown | meta data of the object | 

### ctix-get-server-collections
***
Source Collection listing api with pagination


#### Base Command

`ctix-get-server-collections`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | page of the result. | Optional | 
| page_size | page size of the result. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.ServerCollection.name | string | Name of the server | 
| CTIX.ServerCollection.id | string | ID of the object | 
| CTIX.ServerCollection.inbox | boolean | Inbox is enabled or not | 
| CTIX.ServerCollection.is_active | boolean | Object if active or not | 
| CTIX.ServerCollection.is_editable | boolean | Object if editable or not | 
| CTIX.ServerCollection.polling | boolean | Object polling is enabled or not | 
| CTIX.ServerCollection.type | string | Object type | 
| CTIX.ServerCollection.description | string | description of the object | 
| CTIX.ServerCollection.created | number | Created timestamp | 

### ctix-get-actions
***
Enrichment tools listing API


#### Base Command

`ctix-get-actions`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | page of the result. | Optional | 
| page_size | page size of the result. | Optional | 
| object_type | object type of the indicator. | Optional | 
| action_type | action type of the indicator. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.Action.action_name | string | Name of the Action | 
| CTIX.Action.action_type | unknown | Description of the action | 
| CTIX.Action.actioned_on | number | Timestamp of when the action was taken  | 
| CTIX.Action.app_name | string | Name of the app for the action in CTIX | 
| CTIX.app_type | string | Type of the app | 
| CTIX.Action.id | string | ID of the action | 
| CTIX.Action.object_type | string | Type of the action | 

### ctix-add-indicator-as-false-positive
***
Add indicators as false positive in CTIX


#### Base Command

`ctix-add-indicator-as-false-positive`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_ids | , seperated list of indicator ids. | Required | 
| object_type | Type of object. Possible values are: attack-pattern, campaign, course-of-action, custom-object, grouping, identity, indicator, infrastructure, intrusion-set, location, malware, malware-analysis, observed-data, opinion, report, threat-actor, tool, note, vulnerability, artifact, directory, email-addr, user-account, email-message, file, ipv4-addr, ipv6-addr, mac-addr, autonomous-system, network-traffic, domain-name, process, software, windows-registry-key, mutex, url, observable, x509-certificate. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.IndicatorFalsePositive.message | unknown | Indicator change result | 

### ctix-ioc-manual-review
***
Adds ioc to manual review bulk api


#### Base Command

`ctix-ioc-manual-review`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_ids | Object ids of the items to be added for manual review. | Required | 
| object_type | object type. Possible values are: attack-pattern, campaign, course-of-action, custom-object, grouping, identity, indicator, infrastructure, intrusion-set, location, malware, malware-analysis, observed-data, opinion, report, threat-actor, tool, note, vulnerability, artifact, directory, email-addr, user-account, email-message, file, ipv4-addr, ipv6-addr, mac-addr, autonomous-system, network-traffic, domain-name, process, software, windows-registry-key, mutex, url, observable, x509-certificate. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.IOCManualReview.message | unknown | IOC Manual Review result | 

### ctix-deprecate-ioc
***
Deprecate ioc bulk api


#### Base Command

`ctix-deprecate-ioc`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_ids | Object ids . | Required | 
| object_type | object type. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.DeprecateIOC | unknown | Result of the IOC deprecation request | 

### ctix-add-analyst-tlp
***
Add Analyst TLP


#### Base Command

`ctix-add-analyst-tlp`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | object id. | Required | 
| object_type | object type. | Required | 
| data | data. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.AddAnalystTLP | unknown | Result of the addition of analyst TLP | 

### ctix-add-analyst-score
***
Add Analyst Score for a Threat data


#### Base Command

`ctix-add-analyst-score`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | object id. | Required | 
| object_type | object type. | Required | 
| data | data. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.AddAnalystScore | unknown | Result of adding analyst score to threat data | 

### ctix-saved-result-set
***
Saved Result Set


#### Base Command

`ctix-saved-result-set`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | page. Default is 1. | Optional | 
| page_size | page size. Default is 10. | Optional | 
| label_name | label name. | Optional | 
| query | CQL. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.SavedResultSet.analyst_score | number | Analyst score of the IOC | 
| CTIX.SavedResultSet.analyst_tlp | string | Analyst TLP of the IOC | 
| CTIX.SavedResultSet.confidence_score | number | Confidence score of the IOC | 
| CTIX.SavedResultSet.confidence_type | string | Confidence type of the IOC | 
| CTIX.SavedResultSet.country | string | Country of origin for the IOC | 
| CTIX.SavedResultSet.created | number | IOC creation date | 
| CTIX.SavedResultSet.ctix_created | number | IOC date of creation in CTIX | 
| CTIX.SavedResultSet.ctix_modified | number | IOC date of modification in CTIX | 
| CTIX.SavedResultSet.first_seen | date | IOC timestamp when it was first seen | 
| CTIX.SavedResultSet.id | number | IOC ID | 
| CTIX.SavedResultSet.indicator_type | string | Type of the indicator  | 
| CTIX.SavedResultSet.ioc_type | string | Type of the IOC  | 
| CTIX.SavedResultSet.is_actioned | boolean | If there is any action taken on the indicator | 
| CTIX.SavedResultSet.is_deprecated | boolean | If the indicator is deprecated or not | 
| CTIX.SavedResultSet.is_false_positive | boolean | Value of the indicator is false positive or not | 
| CTIX.SavedResultSet.is_reviewed | boolean | Whether the indicator reviewed or not  | 
| CTIX.SavedResultSet.is_revoked | boolean | Whether the indicator is revoked or not | 
| CTIX.SavedResultSet.is_watchlist | boolean | Whether the indicator is under watchlist or not | 
| CTIX.SavedResultSet.is_whitelisted | boolean | Whether the indicator is allowed or not | 
| CTIX.SavedResultSet.last_seen | date | Timestamp of the when the IOC was last seen | 
| CTIX.SavedResultSet.modified | date | Timestamp of the when the IOC was modified | 
| CTIX.SavedResultSet.name | string | Name of the indicator | 
| CTIX.SavedResultSet.null | unknown | null | 
| CTIX.SavedResultSet.primary_attribute | string | Primary attribute of the IOC | 
| CTIX.SavedResultSet.published_collections | unknown | Published collections of the IOC | 
| CTIX.SavedResultSet.risk_severity | unknown | Risk severity of the IOC | 
| CTIX.SavedResultSet.source_collections | unknown | Source collections of the IOC | 
| CTIX.SavedResultSet.name | string | Name of the IOC | 
| CTIX.SavedResultSet.sources | unknown | Sources of the IOC | 
| CTIX.SavedResultSet.sub_type | unknown | Sub type of the IOC | 
| CTIX.SavedResultSet.subscriber_collections | unknown | Subscription collections of the IOC | 
| CTIX.SavedResultSet.subscribers | unknown | Subscribers of the IOC | 
| CTIX.SavedResultSet.tags | unknown | Tags on the IOC | 
| CTIX.SavedResultSet.tlp | unknown | TLP of the IOC | 
| CTIX.SavedResultSet.type | unknown | Type of the IOC | 
| CTIX.SavedResultSet.valid_from | unknown | Timestamp from when the IOC is valid | 
| CTIX.SavedResultSet.valid_until | unknown | Timestamp till then the IOC is valid | 

### ctix-add-tag-indicator
***
Adding Tag to Indicator


#### Base Command

`ctix-add-tag-indicator`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | page from where data will be taken. Default is 1. | Optional | 
| page_size | total number of results to be fetched. Default is 10. | Optional | 
| q | query. | Optional | 
| object_id | object id. | Optional | 
| object_type | object type. | Optional | 
| tag_id | tag id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.TagUpdation.meesage | unknown | Result of the add indicator tag request | 

### ctix-remove-tag-from-indicator
***
Remove Tag From Indicator


#### Base Command

`ctix-remove-tag-from-indicator`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | which page to bring the data from. Default is 1. | Optional | 
| page_size | number of pages to bring data from. Default is 10. | Optional | 
| q | query. | Optional | 
| object_id | object_id. | Optional | 
| object_type | object_type. | Optional | 
| tag_id | tag_id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.TagUpdation.message | unknown | Result of the remove indicator tag request | 

### ctix-search-for-tag
***
Search for tag


#### Base Command

`ctix-search-for-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | number of page from where data needs to brought. Default is 1. | Optional | 
| page_size | size of the result. Default is 10. | Optional | 
| q | query. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.SearchTag.colour_code | unknown | Colour code of the tag | 
| CTIX.SearchTag.created | number | Timestamp of when the tag was created | 
| CTIX.SearchTag.created_by | unknown | details of the person who created the tag | 
| CTIX.SearchTag.id | string | ID of the tag | 
| CTIX.SearchTag.modified | number | Timestamp of when the tag was modified | 
| CTIX.SearchTag.modified_by | unknown | Details of the person who modified the tag | 
| CTIX.SearchTag.name | unknown | Name of the tag | 
| CTIX.SearchTag.type | unknown | type of the tag | 

### ctix-get-indicator-details
***
Get Indicator Details


#### Base Command

`ctix-get-indicator-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | from where data has to be brought. Default is 1. | Optional | 
| page_size | total number of results. Default is 10. | Optional | 
| object_id | object id. | Optional | 
| object_type | object type. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.IndicatorDetails.aliases | string | Aliases of the tag if any | 
| CTIX.IndicatorDetails.analyst_description | string | Analyst description provided if any | 
| CTIX.IndicatorDetails.analyst_score | number | Analyst score of the indicator | 
| CTIX.IndicatorDetails.analyst_tlp | string | Analyst provided TLP on the indicator | 
| CTIX.IndicatorDetails.asn | string | ASN of the indicator | 
| CTIX.IndicatorDetails.attribute_field | string | Attribute field of the indicator | 
| CTIX.IndicatorDetails.attribute_value | string | Attribute value of the indicator | 
| CTIX.IndicatorDetails.base_type | string | Base type of the indicator | 
| CTIX.IndicatorDetails.confidence_score | number | Confidence score of the IOC | 
| CTIX.IndicatorDetails.confidence_type | string | Confidence type of the IOC | 
| CTIX.IndicatorDetails.country | string | Country of origin of the IOC | 
| CTIX.IndicatorDetails.created | number | Timestamp of when the indicator was created | 
| CTIX.IndicatorDetails.ctix_created | number | Timestamp of when the indicator was created in CTIX | 
| CTIX.IndicatorDetails.ctix_modified | number | Timestamp of when the indicator was modified in CTIX | 
| CTIX.IndicatorDetails.ctix_score | number | CTIX score of the indicator | 
| CTIX.IndicatorDetails.ctix_tlp | string | CTIX assigned TLP of the indicator | 
| CTIX.IndicatorDetails.defang_analyst_description | string | Defanged analyst description of the indicator | 
| CTIX.IndicatorDetails.description | string | Description of the indicator | 
| CTIX.IndicatorDetails.fang_analyst_description | string | Fang analyst description of the indicator | 
| CTIX.IndicatorDetails.first_seen | number | Timestamp of then the indicator was first seen | 
| CTIX.IndicatorDetails.last_seen | number | Timestamp of then the indicator was last seen | 
| CTIX.IndicatorDetails.modified | number | Timestamp of then the indicator was modified | 
| CTIX.IndicatorDetails.name | string | Name of the indicator | 
| CTIX.IndicatorDetails.pattern | string | STIX pattern of the indicator | 
| CTIX.IndicatorDetails.pattern_type | string | pattern type of the indicator | 
| CTIX.IndicatorDetails.pattern_version | string | STIX pattern version | 
| CTIX.IndicatorDetails.sources | unknown | Sources of the indicator | 
| CTIX.IndicatorDetails.sub_type | string | Sub type of the indicator | 
| CTIX.IndicatorDetails.tld | string | TLD of the indicator | 
| CTIX.IndicatorDetails.tlp | string | TLP of the indicator | 
| CTIX.IndicatorDetails.type | string | Type of the indicator | 
| CTIX.IndicatorDetails.types | string | Types of the indicator | 
| CTIX.IndicatorDetails.valid_from | number | Timestamp of the indicator from then it was valid | 
| CTIX.IndicatorDetails.valid_until | unknown | Timestamp of the indicator till  | 

### ctix-get-indicator-tags
***
Get Indicator Tags


#### Base Command

`ctix-get-indicator-tags`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | object id. | Optional | 
| object_type | object type. | Optional | 
| page | page. Default is 1. | Optional | 
| page_size | page size. Default is 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.IndicatorTags.notes | unknown | Notes on the indicator's tag | 
| CTIX.IndicatorTags.is_deprecated | boolean | If the indicator's tag deprecated or not | 
| CTIX.IndicatorTags.is_revoked | boolean | If the indicator's tag revoked or not | 
| CTIX.IndicatorTags.ctix_created | number | Timestamp of when the Indicator tag was created in CTIX | 
| CTIX.IndicatorTags.is_false_positive | boolean | If the indicator's tag is false positive or not | 
| CTIX.IndicatorTags.name | string | Name of the indicator | 
| CTIX.IndicatorTags.is_reviewed | boolean | If the indicator reviewed or not | 
| CTIX.IndicatorTags.is_whitelisted | boolean | If the indicator allowed or not | 
| CTIX.IndicatorTags.is_under_review | boolean | If the indicator is under review or not | 
| CTIX.IndicatorTags.is_watchlist | boolean | If the indicator is under watchlist or not | 
| CTIX.IndicatorTags.tags | unknown | Tags of the indicator | 
| CTIX.IndicatorTags.sub_type | unknown | Sub type of the indicator | 
| CTIX.IndicatorTags.type | unknown | Type of Indicator | 

### ctix-get-indicator-relations
***
Get Indicator Relations


#### Base Command

`ctix-get-indicator-relations`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | page. Default is 1. | Optional | 
| page_size | page size. Default is 10. | Optional | 
| object_id | object id. | Optional | 
| object_type | object type. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.IndicatorRelations.relationship_type | unknown | Indicator relation types | 
| CTIX.IndicatorRelations.sources | unknown | Indicator sources | 
| CTIX.IndicatorRelations.target_ref | unknown | Indicator target reference  | 

### ctix-get-indicator-observations
***
Get Indicator Observations


#### Base Command

`ctix-get-indicator-observations`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | page. | Optional | 
| page_size | page size. | Optional | 
| object_id | object id. | Optional | 
| object_type | object type. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.IndicatorObservations.custom_attributes | unknown | Custom attributes if any | 
| CTIX.IndicatorObservations.ctix_modified | number | Timestamp when indicator was modified in CTIX | 
| CTIX.IndicatorObservations.created | number | Timestamp when indicator was created | 
| CTIX.IndicatorObservations.pattern_type | string | Pattern type of Indicator | 
| CTIX.IndicatorObservations.modified | number | Timestamp when indicator was modified  | 
| CTIX.IndicatorObservations.ctix_created | number | Timestamp when indicator was created in CTIX | 
| CTIX.IndicatorObservations.pattern_version | string | STIX Pattern version of indicator | 
| CTIX.IndicatorObservations.confidence | string | Confidence level of the indicator | 
| CTIX.IndicatorObservations.valid_from | number | Timestamp when indicator was valid from | 
| CTIX.IndicatorObservations.pattern | string | STIX pattern | 
| CTIX.IndicatorObservations.fang_description | string | FANG description  | 
| CTIX.IndicatorObservations.defang_description | string | DEFANG description | 
| CTIX.IndicatorObservations.spec_version | string | STIX Spec version | 
| CTIX.IndicatorObservations.tags | unknown | Tags attached to the indicator | 
| CTIX.IndicatorObservations.received_id | string | STIX ID when indicator was received | 
| CTIX.IndicatorObservations.types | unknown | STIX Types attached to the indicator | 
| CTIX.IndicatorObservations.source | unknown | STIX source of the indicator | 
| CTIX.IndicatorObservations.id | string | id of the indicator | 
| CTIX.IndicatorObservations.valid_until | number | Timestamp till when the indicator is valid | 
| CTIX.IndicatorObservations.sco_object_id | unknown | SCO object ID | 
| CTIX.IndicatorObservations.unique_hash | unknown | unique hash of the indicator | 
| CTIX.IndicatorObservations.description | unknown | description of the indicator | 
| CTIX.IndicatorObservations.granular_markings | unknown | Granular Markings if any | 
| CTIX.IndicatorObservations.collection | unknown | Collection details of the indicator | 

### ctix-get-conversion-feed-source
***
Get Conversion feed source


#### Base Command

`ctix-get-conversion-feed-source`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | page. Default is 1. | Optional | 
| page_size | page size. Default is 10. | Optional | 
| object_id | object id. | Optional | 
| object_type | object type. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.ConversionFeedSource.created | number | Indicator creation timestamp | 
| CTIX.ConversionFeedSource.id | string | ID of the indicator | 
| CTIX.ConversionFeedSource.name | string | name of the indicator | 
| CTIX.ConversionFeedSource.taxii_option | string | TAXII option | 

### ctix-get-lookup-threat-data
***
Lookup to get threat data


#### Base Command

`ctix-get-lookup-threat-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_type | object type. | Optional | 
| object_names | Will contain the SDO values. Example: If you need to get the object_ids of indicator 127.0.0.1 then the value will be 127.0.0.1. | Optional | 
| page_size | size of the page. Default is 10. | Optional | 
| createifnotexist | Specify whether to create a new threat data entry if it does not exist. | Optional | 
| source | The source of the threat data. | Optional | 
| collection | The collection to store the threat data in. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.ThreatDataLookup.Found.analyst_score | number | Analyst score of the indicator | 
| CTIX.ThreatDataLookup.Found.analyst_tlp | string | Analyst TLP of the indicator | 
| CTIX.ThreatDataLookup.Found.confidence_score | number | Confidence score of the indicator | 
| CTIX.ThreatDataLookup.Found.confidence_type | string | Confidence type of the indicator | 
| CTIX.ThreatDataLookup.Found.country | string | Indicator origin country | 
| CTIX.ThreatDataLookup.Found.created | number | Timestamp of when the indicator was created | 
| CTIX.ThreatDataLookup.Found.ctix_created | number | Timestamp of when the indicator was created in CTIX | 
| CTIX.ThreatDataLookup.Found.ctix_modified | number | Timestamp of when the indicator was modified in CTIX | 
| CTIX.ThreatDataLookup.Found.first_seen | number | Timestamp of when the indicator was first seen | 
| CTIX.ThreatDataLookup.Found.id | string | Indicator ID | 
| CTIX.ThreatDataLookup.Found.indicator_type | string | Indicator type | 
| CTIX.ThreatDataLookup.Found.ioc_type | string | IOC type | 
| CTIX.ThreatDataLookup.Found.is_actioned | boolean | Is actioned | 
| CTIX.ThreatDataLookup.Found.is_deprecated | boolean | is deprecated | 
| CTIX.ThreatDataLookup.Found.is_false_positive | boolean | is false positive | 
| CTIX.ThreatDataLookup.Found.is_reviewed | boolean | is reviewed  | 
| CTIX.ThreatDataLookup.Found.is_revoked | boolean | is revoked | 
| CTIX.ThreatDataLookup.Found.is_watchlist | boolean | is watchlisted | 
| CTIX.ThreatDataLookup.Found.is_whitelisted | boolean | is allowed | 
| CTIX.ThreatDataLookup.Found.last_seen | number | Timestamp of when the indicator was last seen | 
| CTIX.ThreatDataLookup.Found.modified | number | Timestamp of when the indicator was modified | 
| CTIX.ThreatDataLookup.Found.name | string | name of the indicator | 
| CTIX.ThreatDataLookup.Found.null | unknown | null | 
| CTIX.ThreatDataLookup.Found.primary_attribute | string | Primary Attribute | 
| CTIX.ThreatDataLookup.Found.published_collections | unknown | published collections | 
| CTIX.ThreatDataLookup.Found.risk_severity | string | Risk severity | 
| CTIX.ThreatDataLookup.Found.source_collections | unknown | sources collections | 
| CTIX.ThreatDataLookup.Found.source_confidence | string | Source confidence  | 
| CTIX.ThreatDataLookup.Found.sources | unknown | sources | 
| CTIX.ThreatDataLookup.Found.sub_type | string | Sub type | 
| CTIX.ThreatDataLookup.Found.subscriber_collections | unknown | subscriber collections | 
| CTIX.ThreatDataLookup.Found.subscribers | unknown | subscribers | 
| CTIX.ThreatDataLookup.Found.tags | unknown | Tags | 
| CTIX.ThreatDataLookup.Found.tlp | string | TLP | 
| CTIX.ThreatDataLookup.Found.type | string | Type | 
| CTIX.ThreatDataLookup.Found.valid_from | number | Timestamp from when the indicator was valid | 
| CTIX.ThreatDataLookup.Found.valid_until | number | Timestamp till when the indicator was valid | 
| CTIX.ThreatDataLookup.NotFoundCreated | string | IOCs that weren't found, but were created because \`createifnotexist\` was set to True | 
| CTIX.ThreatDataLookup.NotFoundInvalid | string | IOCs that were found to be invalid, so they were not created, despite \`createifnotexist\` was set to True | 

### domain
***
Lookup domain threat data


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Will contain domain SDO values. Example: If you need to get the object_ids of indicator example.com then the value will be example.com. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| Domain.Name | String | The domain name, for example: "google.com". | 

### ip
***
Lookup ip threat data


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | Will contain IP SDO values. Example: If you need to get the object_ids of indicator 1.2.3.4 then the value will be 1.2.3.4. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| IP.Address | String | The IP address, for example: 1.2.3.4. | 

### file
***
Lookup file threat data


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | Will contain file SDO values. Example: If you need to get the object_ids of a file hash 3ed0a30799543fa2c3a913c7985bffed then the value will be 3ed0a30799543fa2c3a913c7985bffed. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 

### url
***
Lookup url threat data


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | Will contain URL SDO values. Example: If you need to get the object_ids of a URL https://cyware.com/ then the value will be https://cyware.com/. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| URL.Data | String | The URL | 

### ctix-get-all-notes
***
Get paginated list of Notes


#### Base Command

`ctix-get-all-notes`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | if set, this will only retrieve Notes associated with the Threat Data object with ID=`object_id`. | Optional | 
| page | the page number of the Notes to look up, default is the first page. Default is 1. | Optional | 
| page_size | size of the result. Default is 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.Note.created | integer | The timestamp when the Note was created | 
| CTIX.Note.created_by | unknown | The user who created the Note | 
| CTIX.Note.created_by.email | string | The email of the user who created the Note | 
| CTIX.Note.created_by.first_name | string | The first name of the user who created the Note | 
| CTIX.Note.created_by.id | string | The ID of the user who created the Note | 
| CTIX.Note.created_by.last_name | string | The last name of the user who created the Note | 
| CTIX.Note.id | string | The ID of the Note | 
| CTIX.Note.is_json | boolean | A flag indicating whether the Note is in JSON format | 
| CTIX.Note.meta_data | unknown | Meta data for the Note | 
| CTIX.Note.meta_data.component | string | The component for the Note | 
| CTIX.Note.modified | integer | The timestamp when the Note was last modified | 
| CTIX.Note.modified_by | unknown | The user who last modified the Note | 
| CTIX.Note.modified_by.email | string | The email of the user who last modified the Note | 
| CTIX.Note.modified_by.first_name | string | The first name of the user who last modified the Note | 
| CTIX.Note.modified_by.id | string | The ID of the user who last modified the Note | 
| CTIX.Note.modified_by.last_name | string | The last name of the user who last modified the Note | 
| CTIX.Note.object_id | string | The object ID of the Note | 
| CTIX.Note.text | string | The text of the Note | 
| CTIX.Note.title | string | The title of the Note | 
| CTIX.Note.type | string | The type of the Note | 

### ctix-get-note-details
***
Get details of a Note as specified by its ID


#### Base Command

`ctix-get-note-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | the id of the Note. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.Note.created | integer | The timestamp when the Note was created | 
| CTIX.Note.created_by | unknown | The user who created the Note | 
| CTIX.Note.created_by.email | string | The email of the user who created the Note | 
| CTIX.Note.created_by.first_name | string | The first name of the user who created the Note | 
| CTIX.Note.created_by.id | string | The ID of the user who created the Note | 
| CTIX.Note.created_by.last_name | string | The last name of the user who created the Note | 
| CTIX.Note.id | string | The ID of the Note | 
| CTIX.Note.is_json | boolean | A flag indicating whether the Note is in JSON format | 
| CTIX.Note.meta_data | unknown | Meta data for the Note | 
| CTIX.Note.meta_data.component | string | The component for the Note | 
| CTIX.Note.modified | integer | The timestamp when the Note was last modified | 
| CTIX.Note.modified_by | unknown | The user who last modified the Note | 
| CTIX.Note.modified_by.email | string | The email of the user who last modified the Note | 
| CTIX.Note.modified_by.first_name | string | The first name of the user who last modified the Note | 
| CTIX.Note.modified_by.id | string | The ID of the user who last modified the Note | 
| CTIX.Note.modified_by.last_name | string | The last name of the user who last modified the Note | 
| CTIX.Note.object_id | string | The object ID of the Note | 
| CTIX.Note.text | string | The text of the Note | 
| CTIX.Note.title | string | The title of the Note | 
| CTIX.Note.type | string | The type of the Note | 

### ctix-create-note
***
Creates a new Note from the parameter 'text'


#### Base Command

`ctix-create-note`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| text | the text that you want the note to have. | Required | 
| object_id | if set, will associate Note to the Threat Data object with the provided ID. | Optional | 
| object_type | only required if `object_id` is set, used to specify the type of object `object_id` is. Possible values are: indicator, malware, threat-actor, vulnerability, attack-pattern, campaign, course-of-action, identity, infrastructure, intrusion-set, location, malware-analysis, observed-data, opinion, tool, report, custom-object, observable, incident, note. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.Note.created | integer | The timestamp when the Note was created | 
| CTIX.Note.created_by | unknown | The user who created the Note | 
| CTIX.Note.created_by.email | string | The email of the user who created the Note | 
| CTIX.Note.created_by.first_name | string | The first name of the user who created the Note | 
| CTIX.Note.created_by.id | string | The ID of the user who created the Note | 
| CTIX.Note.created_by.last_name | string | The last name of the user who created the Note | 
| CTIX.Note.id | string | The ID of the Note | 
| CTIX.Note.is_json | boolean | A flag indicating whether the Note is in JSON format | 
| CTIX.Note.meta_data | unknown | Meta data for the Note | 
| CTIX.Note.meta_data.component | string | The component for the Note | 
| CTIX.Note.modified | integer | The timestamp when the Note was last modified | 
| CTIX.Note.modified_by | unknown | The user who last modified the Note | 
| CTIX.Note.modified_by.email | string | The email of the user who last modified the Note | 
| CTIX.Note.modified_by.first_name | string | The first name of the user who last modified the Note | 
| CTIX.Note.modified_by.id | string | The ID of the user who last modified the Note | 
| CTIX.Note.modified_by.last_name | string | The last name of the user who last modified the Note | 
| CTIX.Note.object_id | string | The object ID of the Note | 
| CTIX.Note.text | string | The text of the Note | 
| CTIX.Note.title | string | The title of the Note | 
| CTIX.Note.type | string | The type of the Note | 

### ctix-update-note
***
Updates the Note text from an existing Note, as specified by its ID


#### Base Command

`ctix-update-note`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | the id of the Note. | Required | 
| text | the updated text that you want the note to have. | Optional | 
| object_id | if set, will associate Note to the Threat Data object with the provided ID. | Optional | 
| object_type | only required if `object_id` is set, used to specify the type of object `object_id` is. Possible values are: indicator, malware, threat-actor, vulnerability, attack-pattern, campaign, course-of-action, identity, infrastructure, intrusion-set, location, malware-analysis, observed-data, opinion, tool, report, custom-object, observable, incident, note. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.Note.created | integer | The timestamp when the Note was created | 
| CTIX.Note.created_by | unknown | The user who created the Note | 
| CTIX.Note.created_by.email | string | The email of the user who created the Note | 
| CTIX.Note.created_by.first_name | string | The first name of the user who created the Note | 
| CTIX.Note.created_by.id | string | The ID of the user who created the Note | 
| CTIX.Note.created_by.last_name | string | The last name of the user who created the Note | 
| CTIX.Note.id | string | The ID of the Note | 
| CTIX.Note.is_json | boolean | A flag indicating whether the Note is in JSON format | 
| CTIX.Note.meta_data | unknown | Meta data for the Note | 
| CTIX.Note.meta_data.component | string | The component for the Note | 
| CTIX.Note.modified | integer | The timestamp when the Note was last modified | 
| CTIX.Note.modified_by | unknown | The user who last modified the Note | 
| CTIX.Note.modified_by.email | string | The email of the user who last modified the Note | 
| CTIX.Note.modified_by.first_name | string | The first name of the user who last modified the Note | 
| CTIX.Note.modified_by.id | string | The ID of the user who last modified the Note | 
| CTIX.Note.modified_by.last_name | string | The last name of the user who last modified the Note | 
| CTIX.Note.object_id | string | The object ID of the Note | 
| CTIX.Note.text | string | The text of the Note | 
| CTIX.Note.title | string | The title of the Note | 
| CTIX.Note.type | string | The type of the Note | 

### ctix-delete-note
***
Deletes an existing Note, as specified by its ID


#### Base Command

`ctix-delete-note`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | the id of the Note. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.Note.deletion.details | string | Returns "success" if the deletion request was successful, otherwise "failure" | 

### ctix-make-request
***
allows you to make any HTTP request using CTIX endpoints


#### Base Command

`ctix-make-request`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | the HTTP method you would like to call. Possible values are: GET, POST, PUT, DELETE. | Required | 
| endpoint | URL suffix of the API call to CTIX. | Required | 
| body | any data you would like to pass, in JSON format. | Optional | 
| params | any parameters you would like to pass, in JSON format. | Optional | 


#### Context Output

There is no context output for this command.