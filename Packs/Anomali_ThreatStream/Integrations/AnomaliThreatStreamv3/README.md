Use Anomali ThreatStream to query and submit threats.

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous version of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration-anomali-threatstream-v3).

## Configure Anomali ThreatStream v3 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g., https://www.test.com) |  | True |
| Username |  | True |
| API Key |  | True |
| URL threshold |  | False |
| IP threshold |  | False |
| Domain threshold |  | False |
| File threshold |  | False |
| Email threshold | Email indicators with confidence value above this threshold are considered malicious. | False |
| Include inactive results | Whether to include inactive indicators in reputation commands. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Create relationships | Create relationships between indicators as part of enrichment. | False |
| Remote API | Gather additional information about the threat model from remote APIs. | False |
| Default DBOT score for indicators with low confidence |  | False |


### Configure Indicator Threshold Parameters
Each indicator has a threshold parameter and an integer `confidence` value that impacts the indicator's DBotScore calculation.  
The indicator DBotScore is calculated as follows:  
- If you do not specify the threshold parameter value in your instance configuration (recommended):  
If the indicator `confidence` > 65, the DBotScore value is set to 3 (Malicious).  
If the indicator `confidence` is between 25 and 65, the DBotScore value is set to 2 (Suspicious).  
If the indicator `confidence` < 25, the DBotScore value is set to 1 (Good).  
For example, 
If the **IP threshold** value is not specified during configuration and the IP indicator `confidence` value is 45, the DBotScore value is set to 2 (Suspicious).  
- If you configure the threshold parameter value:   
If the indicator `confidence` value is above the threshold parameter value, the DBotScore is set to 3 (Malicious). Otherwise the DBotScore is set to 1 (Good).  
**Note:** You cannot define a threshold that sets the DBotScore to 2 (Suspicious).  
For example, if in the instance configuration you set **File threshold** to 10 and the `confidence` value  is 15, the DBotScore is set to 3 (Malicious).

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ip
***
Checks the reputation of the given IP address.


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IP to check. | Required | 
| threshold | If confidence is greater than the threshold the IP address is considered malicious, otherwise it is considered good. This argument overrides the default IP threshold defined as a parameter. | Optional | 
| include_inactive | Whether to include results with an inactive status. Possible values are: True, False. | Optional | 
| threat_model_association | Enhance generic reputation commands to include additional information such as Threat Bulletins, Attach patterns, Actors, Campaigns, TTPs, vulnerabilities, etc. Note: If set to true, additional 6 API calls will be performed. Possible values are: True, False. Default is False. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| IP.ASN | String | The Autonomous System \(AS\) number associated with the indicator. | 
| IP.Address | String | The IP address of the indicator. | 
| IP.Geo.Country | String | The country associated with the indicator. | 
| IP.Geo.Location | String | The longitude and latitude of the IP address. | 
| ThreatStream.IP.ASN | String | The Autonomous System \(AS\) number associated with the indicator. | 
| ThreatStream.IP.Address | String | The IP address of the indicator. | 
| ThreatStream.IP.Country | String | The country associated with the indicator. | 
| ThreatStream.IP.Type | String | The indicator type. | 
| ThreatStream.IP.Modified | String | The time the indicator was last updated. The date format is: YYYYMMDDThhmmss, where "T" denotes the start of the value for time in UTC time. | 
| ThreatStream.IP.Severity | String | The indicator severity \("very-high", "high", "medium", or "low"\). | 
| ThreatStream.IP.Confidence | String | The observable certainty level of a reported indicator type. Confidence score can range from 0-100, in increasing order of confidence. | 
| ThreatStream.IP.Status | String | The status assigned to the indicator. | 
| ThreatStream.IP.Organization | String | The name of the business that owns the IP address associated with the indicator. | 
| ThreatStream.IP.Source | String | The indicator source. | 
| IP.Malicious.Vendor | String | The vendor that reported the indicator as malicious. | 
| ThreatStream.IP.Tags | Unknown | Tags assigned to the IP. | 
| ThreatStream.IP.IType | String | The itype of the indicator associated with the specified model. | 
| IP.Tags | Unknown | List of IP tags. | 
| IP.ThreatTypes | Unknown | Threat types associated with the IP. | 
| ThreatStream.IP.Actor.assignee_user | Unknown | The assignee user of the threat actor. | 
| ThreatStream.IP.Actor.association_info.comment | Unknown | The comment in the association info of the threat actor. | 
| ThreatStream.IP.Actor.association_info.created | Date | The date the association info was created. | 
| ThreatStream.IP.Actor.association_info.from_id | Number | The ID from which the association info is related. | 
| ThreatStream.IP.Actor.can_add_public_tags | Boolean | Whether you can add public tags to the threat actor. | 
| ThreatStream.IP.Actor.created_ts | Date | The date the threat actor was created. | 
| ThreatStream.IP.Actor.feed_id | Number | The feed ID of the threat actor. | 
| ThreatStream.IP.Actor.id | Number | The ID of the threat actor. | 
| ThreatStream.IP.Actor.is_anonymous | Boolean | Whether the threat actor is anonymous. | 
| ThreatStream.IP.Actor.is_cloneable | String | Whether the threat actor is cloneable. | 
| ThreatStream.IP.Actor.is_public | Boolean | Whether the threat actor is public. | 
| ThreatStream.IP.Actor.is_team | Boolean | Whether the threat actor is a team. | 
| ThreatStream.IP.Actor.modified_ts | Date | The date the threat actor was modified. | 
| ThreatStream.IP.Actor.name | String | The name of the threat actor. | 
| ThreatStream.IP.Actor.organization_id | Number | The organization ID of the threat actor. | 
| ThreatStream.IP.Actor.owner_user_id | Number | The owner user ID of the threat actor. | 
| ThreatStream.IP.Actor.primary_motivation | Unknown | The primary motivation of the threat actor. | 
| ThreatStream.IP.Actor.publication_status | String | The publication status of the threat actor. | 
| ThreatStream.IP.Actor.published_ts | Date | The date the threat actor was published. | 
| ThreatStream.IP.Actor.resource_level | Unknown | The resource level of the threat actor. | 
| ThreatStream.IP.Actor.resource_uri | String | The resource URI of the threat actor. | 
| ThreatStream.IP.Actor.source_created | Unknown | The date the source was created. | 
| ThreatStream.IP.Actor.source_modified | Unknown | The date the source was modified. | 
| ThreatStream.IP.Actor.start_date | Unknown | The start date. | 
| ThreatStream.IP.Actor.tags | String | The tags of the threat indicator. | 
| ThreatStream.IP.Actor.tags_v2.id | String | The ID of the tag. | 
| ThreatStream.IP.Actor.tags_v2.name | String | The name of the tag. | 
| ThreatStream.IP.Actor.tlp | String | The TLP of the threat actor. | 
| ThreatStream.IP.Actor.uuid | String | The UUID of the threat actor. | 
| ThreatStream.IP.Signature.assignee_user | Unknown | The assignee user of the signature. | 
| ThreatStream.IP.Signature.association_info.comment | Unknown | The comment in the association info of the signature. | 
| ThreatStream.IP.Signature.association_info.created | Date | The date the association info was created. | 
| ThreatStream.IP.Signature.association_info.from_id | Number | The ID from which the association info is related. | 
| ThreatStream.IP.Signature.can_add_public_tags | Boolean | Whether you can add public tags to the signature. | 
| ThreatStream.IP.Signature.created_ts | Date | The date the signature was created. | 
| ThreatStream.IP.Signature.feed_id | Number | The feed ID of the signature. | 
| ThreatStream.IP.Signature.id | Number | The ID of the signature. | 
| ThreatStream.IP.Signature.is_anonymous | Boolean | Whether the signature was anonymous. | 
| ThreatStream.IP.Signature.is_cloneable | String | Whether the signature is cloneable. | 
| ThreatStream.IP.Signature.is_public | Boolean | Whether the signature is public. | 
| ThreatStream.IP.Signature.is_team | Boolean | Whether the signature is a team signature. | 
| ThreatStream.IP.Signature.modified_ts | Date | The date the signature was modified. | 
| ThreatStream.IP.Signature.name | String | The name of the signature. | 
| ThreatStream.IP.Signature.organization_id | Number | The organization ID of the signature. | 
| ThreatStream.IP.Signature.owner_user_id | Number | The owner user ID of the signature. | 
| ThreatStream.IP.Signature.primary_motivation | Unknown | The primary motivation of the signature. | 
| ThreatStream.IP.Signature.publication_status | String | The publication status of the signature. | 
| ThreatStream.IP.Signature.published_ts | Date | The date the signature was published. | 
| ThreatStream.IP.Signature.resource_level | Unknown | The resource level of the signature. | 
| ThreatStream.IP.Signature.resource_uri | String | The resource URI of the signature. | 
| ThreatStream.IP.Signature.source_created | Unknown | The date the source was created. | 
| ThreatStream.IP.Signature.source_modified | Unknown | The date the source was modified. | 
| ThreatStream.IP.Signature.start_date | Unknown | The start date. | 
| ThreatStream.IP.Signature.tags | String | The tags of the threat indicator. | 
| ThreatStream.IP.Signature.tags_v2.id | String | The ID of the tag. | 
| ThreatStream.IP.Signature.tags_v2.name | String | The name of the tag. | 
| ThreatStream.IP.Signature.tlp | String | The TLP of the signature. | 
| ThreatStream.IP.Signature.uuid | String | The UUID of the signature. | 
| ThreatStream.IP.ThreatBulletin.all_circles_visible | Boolean | Whether all of the circles are visible. | 
| ThreatStream.IP.ThreatBulletin.assignee_org | String | The assignee organization. | 
| ThreatStream.IP.ThreatBulletin.assignee_org_id | String | The assignee organization ID. | 
| ThreatStream.IP.ThreatBulletin.assignee_org_name | String | The assignee organization name. | 
| ThreatStream.IP.ThreatBulletin.assignee_user | String | The assignee user. | 
| ThreatStream.IP.ThreatBulletin.assignee_user_id | String | The assignee user ID. | 
| ThreatStream.IP.ThreatBulletin.assignee_user_name | Unknown | The assignee user name. | 
| ThreatStream.IP.ThreatBulletin.association_info.comment | Unknown | The comment in the association info of the threat actor. | 
| ThreatStream.IP.ThreatBulletin.association_info.created | Date | The date the association info was created. | 
| ThreatStream.IP.ThreatBulletin.association_info.from_id | String | The ID from which the association info is related. | 
| ThreatStream.IP.ThreatBulletin.body_content_type | String | The body content type. | 
| ThreatStream.IP.ThreatBulletin.campaign | Unknown | The campaign of the threat bulletin. | 
| ThreatStream.IP.ThreatBulletin.can_add_public_tags | Boolean | Whether you can add public tags. | 
| ThreatStream.IP.ThreatBulletin.created_ts | Date | The date the threat bulletin was created. | 
| ThreatStream.IP.ThreatBulletin.feed_id | Number | The feed ID of the threat bulletin. | 
| ThreatStream.IP.ThreatBulletin.id | String | The ID of the threat bulletin. | 
| ThreatStream.IP.ThreatBulletin.is_anonymous | Boolean | Whether the threat bulletin is anonymous. | 
| ThreatStream.IP.ThreatBulletin.is_cloneable | String | Whether the threat bulletin is cloneable. | 
| ThreatStream.IP.ThreatBulletin.is_editable | Boolean | Whether the threat bulletin is editable. | 
| ThreatStream.IP.ThreatBulletin.is_email | Boolean | Whether the threat bulletin is an email. | 
| ThreatStream.IP.ThreatBulletin.is_public | Boolean | Whether the threat bulletin is public. | 
| ThreatStream.IP.ThreatBulletin.modified_ts | Date | The date the threat bulletin was modified. | 
| ThreatStream.IP.ThreatBulletin.name | String | The name of the threat bulletin. | 
| ThreatStream.IP.ThreatBulletin.original_source | String | The original source of the threat bulletin. | 
| ThreatStream.IP.ThreatBulletin.original_source_id | Unknown | The original source ID of the threat bulletin. | 
| ThreatStream.IP.ThreatBulletin.owner_org.id | String | The owner organization ID. | 
| ThreatStream.IP.ThreatBulletin.owner_org.name | String | The owner organization name. | 
| ThreatStream.IP.ThreatBulletin.owner_org.resource_uri | String | The owner organization URI. | 
| ThreatStream.IP.ThreatBulletin.owner_org_id | Number | The ID of the owner user. | 
| ThreatStream.IP.ThreatBulletin.owner_org_name | String | The name of the owner organization. | 
| ThreatStream.IP.ThreatBulletin.owner_user.avatar_s3_url | Unknown | The URL of the owner user. | 
| ThreatStream.IP.ThreatBulletin.owner_user.can_share_intelligence | Boolean | Whether you can share intelligence. | 
| ThreatStream.IP.ThreatBulletin.owner_user.email | String | The email of the owner user. | 
| ThreatStream.IP.ThreatBulletin.owner_user.id | String | The ID of the owner user. | 
| ThreatStream.IP.ThreatBulletin.owner_user.is_active | Boolean | Whether the owner user is active. | 
| ThreatStream.IP.ThreatBulletin.owner_user.is_readonly | Boolean | Whether the owner user has read-only permission. | 
| ThreatStream.IP.ThreatBulletin.owner_user.must_change_password | Boolean | Whether the owner user must change the password. | 
| ThreatStream.IP.ThreatBulletin.owner_user.name | String | The owner user name. | 
| ThreatStream.IP.ThreatBulletin.owner_user.nickname | String | The owner user nickname. | 
| ThreatStream.IP.ThreatBulletin.owner_user.organization.id | String | The ID of the owner user organization. | 
| ThreatStream.IP.ThreatBulletin.owner_user.organization.name | String | The name of the owner user organization. | 
| ThreatStream.IP.ThreatBulletin.owner_user.organization.resource_uri | String | The resource URI of the owner user organization. | 
| ThreatStream.IP.ThreatBulletin.owner_user.resource_uri | String | The resource URI of the owner user. | 
| ThreatStream.IP.ThreatBulletin.owner_user_id | Number | The owner user ID of the threat bulletin. | 
| ThreatStream.IP.ThreatBulletin.owner_user_name | String | The owner user name of the threat bulletin. | 
| ThreatStream.IP.ThreatBulletin.parent | Unknown | The parent of the threat bulletin. | 
| ThreatStream.IP.ThreatBulletin.published_ts | Unknown | The date the threat bulletin was published. | 
| ThreatStream.IP.ThreatBulletin.resource_uri | String | The resource URI of the threat bulletin. | 
| ThreatStream.IP.ThreatBulletin.source | Unknown | The source of the threat bulletin. | 
| ThreatStream.IP.ThreatBulletin.source_created | Unknown | The date the source was created. | 
| ThreatStream.IP.ThreatBulletin.source_modified | Unknown | The date the source was modified. | 
| ThreatStream.IP.ThreatBulletin.starred_by_me | Boolean | Whether the threat bulletin was started by me. | 
| ThreatStream.IP.ThreatBulletin.starred_total_count | Number | The total number of times the threat bulletin was starred. | 
| ThreatStream.IP.ThreatBulletin.status | String | The status of the threat bulletin. | 
| ThreatStream.IP.ThreatBulletin.threat_actor | Unknown | The threat actor of the threat bulletin. | 
| ThreatStream.IP.ThreatBulletin.tlp | Unknown | The TLP of the threat bulletin. | 
| ThreatStream.IP.ThreatBulletin.ttp | Unknown | The TTP of the threat bulletin. | 
| ThreatStream.IP.ThreatBulletin.uuid | String | The UUID of the threat bulletin. | 
| ThreatStream.IP.ThreatBulletin.votes.me | Unknown | The number of votes by me. | 
| ThreatStream.IP.ThreatBulletin.votes.total | Number | The number of total votes. | 
| ThreatStream.IP.ThreatBulletin.watched_by_me | Boolean | Whether the threat bulletin was watched by me. | 
| ThreatStream.IP.ThreatBulletin.watched_total_count | Number | The total number of watchers. | 
| ThreatStream.IP.TTP.assignee_user | Unknown | The assignee user of the TTP. | 
| ThreatStream.IP.TTP.association_info.comment | Unknown | The comment in the association info of the TTP. | 
| ThreatStream.IP.TTP.association_info.created | Date | The date the association info was created. | 
| ThreatStream.IP.TTP.association_info.from_id | Number | The ID from which the association info is related. | 
| ThreatStream.IP.TTP.can_add_public_tags | Boolean | Whether you can add public tags to the TTP. | 
| ThreatStream.IP.TTP.created_ts | Date | The date the TTP was created. | 
| ThreatStream.IP.TTP.feed_id | Number | The feed ID of the TTP. | 
| ThreatStream.IP.TTP.id | Number | The ID of the TTP. | 
| ThreatStream.IP.TTP.is_anonymous | Boolean | Whether the TTP was anonymous. | 
| ThreatStream.IP.TTP.is_cloneable | String | Whether the TTP was cloneable. | 
| ThreatStream.IP.TTP.is_public | Boolean | Whether the TTP is public. | 
| ThreatStream.IP.TTP.is_team | Boolean | Whether the TTP is a team. | 
| ThreatStream.IP.TTP.modified_ts | Date | The date the TTP was modified. | 
| ThreatStream.IP.TTP.name | String | The name of the TTP. | 
| ThreatStream.IP.TTP.organization_id | Number | The organization ID of the TTP. | 
| ThreatStream.IP.TTP.owner_user_id | Number | The owner user ID of the TTP. | 
| ThreatStream.IP.TTP.primary_motivation | Unknown | The primary motivation of the TTP. | 
| ThreatStream.IP.TTP.publication_status | String | The publication status of the TTP. | 
| ThreatStream.IP.TTP.published_ts | Date | The date the TTP was published. | 
| ThreatStream.IP.TTP.resource_level | Unknown | The resource level of the TTP. | 
| ThreatStream.IP.TTP.resource_uri | String | The resource URI of the TTP. | 
| ThreatStream.IP.TTP.source_created | Unknown | The date the source was created. | 
| ThreatStream.IP.TTP.source_modified | Unknown | The date the source was modified. | 
| ThreatStream.IP.TTP.start_date | Unknown | The start date. | 
| ThreatStream.IP.TTP.tags | String | The tags of the threat indicator. | 
| ThreatStream.IP.TTP.tags_v2.id | String | The ID of the tag. | 
| ThreatStream.IP.TTP.tags_v2.name | String | The name of the tag. | 
| ThreatStream.IP.TTP.tlp | String | The TLP of the TTP. | 
| ThreatStream.IP.TTP.uuid | String | The UUID of the TTP. | 
| ThreatStream.IP.Vulnerability.assignee_user | Unknown | The assignee user of the vulnerability. | 
| ThreatStream.IP.Vulnerability.association_info.comment | Unknown | The comment in the association info of the vulnerability. | 
| ThreatStream.IP.Vulnerability.association_info.created | Date | The date the association info was created. | 
| ThreatStream.IP.Vulnerability.association_info.from_id | Number | The ID from which the association info is related. | 
| ThreatStream.IP.Vulnerability.can_add_public_tags | Boolean | Whether you can add public tags to the threat actor. | 
| ThreatStream.IP.Vulnerability.circles.id | String | The ID of the circle. | 
| ThreatStream.IP.Vulnerability.circles.name | String | The name of the circle. | 
| ThreatStream.IP.Vulnerability.circles.resource_uri | String | The resource URI of the circle. | 
| ThreatStream.IP.Vulnerability.created_ts | Date | The date the vulnerability was created. | 
| ThreatStream.IP.Vulnerability.feed_id | Number | The feed ID of the vulnerability. | 
| ThreatStream.IP.Vulnerability.id | Number | The ID of the vulnerability. | 
| ThreatStream.IP.Vulnerability.is_anonymous | Boolean | Whether the vulnerability is anonymous. | 
| ThreatStream.IP.Vulnerability.is_cloneable | String | Whether the vulnerability is cloneable. | 
| ThreatStream.IP.Vulnerability.is_public | Boolean | Whether the vulnerability is public. | 
| ThreatStream.IP.Vulnerability.is_system | Boolean | Whether the vulnerability is in the system. | 
| ThreatStream.IP.Vulnerability.modified_ts | Date | The date the vulnerability was modified. | 
| ThreatStream.IP.Vulnerability.name | String | The name of the vulnerability. | 
| ThreatStream.IP.Vulnerability.organization_id | Number | The organization ID of the vulnerability. | 
| ThreatStream.IP.Vulnerability.owner_user_id | Unknown | The owner user ID of the vulnerability. | 
| ThreatStream.IP.Vulnerability.publication_status | String | The publication status of the vulnerability. | 
| ThreatStream.IP.Vulnerability.published_ts | Date | The date the vulnerability was published. | 
| ThreatStream.IP.Vulnerability.resource_uri | String | The resource URI of the vulnerability. | 
| ThreatStream.IP.Vulnerability.source | String | The source of the vulnerability. | 
| ThreatStream.IP.Vulnerability.source_created | Unknown | The feed ID of the vulnerability. | 
| ThreatStream.IP.Vulnerability.source_modified | Unknown | Whether the source was modified. | 
| ThreatStream.IP.Vulnerability.tags | String | The tags of the vulnerability. | 
| ThreatStream.IP.Vulnerability.tags_v2.id | String | The ID of the tag. | 
| ThreatStream.IP.Vulnerability.tags_v2.name | String | The name of the tag. | 
| ThreatStream.IP.Vulnerability.tlp | String | The TLP of the vulnerability. | 
| ThreatStream.IP.Vulnerability.update_id | Number | The update ID of the vulnerability. | 
| ThreatStream.IP.Vulnerability.uuid | String | The UUID of the vulnerability. | 
| ThreatStream.IP.Campaign.assignee_user | Unknown | The assignee user of the vulnerability. | 
| ThreatStream.IP.Campaign.association_info.comment | Unknown | The comment in the association info of the vulnerability. | 
| ThreatStream.IP.Campaign.association_info.created | Date | The date the association info was created. | 
| ThreatStream.IP.Campaign.association_info.from_id | Number | The ID from which the association info is related. | 
| ThreatStream.IP.Campaign.can_add_public_tags | Boolean | Whether you can add public tags to the campaign. | 
| ThreatStream.IP.Campaign.created_ts | Date | The date the campaign was created. | 
| ThreatStream.IP.Campaign.end_date | Unknown | The end date of the campaign. | 
| ThreatStream.IP.Campaign.feed_id | Number | The feed ID of the campaign. | 
| ThreatStream.IP.Campaign.id | Number | The ID of the campaign. | 
| ThreatStream.IP.Campaign.is_anonymous | Boolean | Whether the campaign is anonymous. | 
| ThreatStream.IP.Campaign.is_cloneable | String | Whether the campaign is cloneable. | 
| ThreatStream.IP.Campaign.is_public | Boolean | Whether the campaign is public. | 
| ThreatStream.IP.Campaign.modified_ts | Date | The date the campaign was modified. | 
| ThreatStream.IP.Campaign.name | String | The name of the campaign. | 
| ThreatStream.IP.Campaign.objective | Unknown | The objective of the campaign. | 
| ThreatStream.IP.Campaign.organization_id | Number | The organization ID of the campaign. | 
| ThreatStream.IP.Campaign.owner_user_id | Number | The owner user ID of the campaign. | 
| ThreatStream.IP.Campaign.publication_status | String | The publication status of the campaign. | 
| ThreatStream.IP.Campaign.published_ts | Unknown | The date the campaign was published. | 
| ThreatStream.IP.Campaign.resource_uri | String | The resource URI of the campaign. | 
| ThreatStream.IP.Campaign.source_created | Date | The date the campaign was created. | 
| ThreatStream.IP.Campaign.source_modified | Date | Whether the source was modified. | 
| ThreatStream.IP.Campaign.start_date | Unknown | The start date of the campaign. | 
| ThreatStream.IP.Campaign.status.display_name | String | The display name of the status. | 
| ThreatStream.IP.Campaign.status.id | Number | The ID of the status of the campaign. | 
| ThreatStream.IP.Campaign.status.resource_uri | String | The resource URI of the status of the campaign. | 
| ThreatStream.IP.Campaign.tlp | String | The TLP of the campaign. | 
| ThreatStream.IP.Campaign.uuid | String | The UUID of the campaign. | 

#### Command example
```!ip ip=23.98.23.98 threat_model_association=True```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "23.98.23.98",
        "Reliability": "B - Usually reliable",
        "Score": 3,
        "Type": "ip",
        "Vendor": "Anomali ThreatStream v3 May"
    },
    "IP": {
        "Address": "23.98.23.98",
        "Malicious": {
            "Description": null,
            "Vendor": "Anomali ThreatStream v3 May"
        },
        "Relationships": [
            {
                "EntityA": "23.98.23.98",
                "EntityAType": "IP",
                "EntityB": "Test Investigation",
                "EntityBType": "Campaign",
                "Relationship": "related-to"
            }
        ],
        "Tags": [
            "apt",
            "PANW_Test"
        ],
        "ThreatTypes": [
            {
                "threatcategory": "apt",
                "threatcategoryconfidence": null
            }
        ]
    },
    "ThreatStream": {
        "IP": {
            "ASN": "",
            "Actor": [],
            "Address": "23.98.23.98",
            "Campaign": [
                {
                    "assignee_user": {
                        "email": "user@email.com",
                        "id": "111",
                        "name": "",
                        "resource_uri": "/api/v1/user/111/"
                    },
                    "association_info": [
                        {
                            "comment": null,
                            "created": "2022-08-01T09:52:10.246877",
                            "from_id": 239450621,
                            "sro": {}
                        }
                    ],
                    "can_add_public_tags": true,
                    "circles": [],
                    "created_ts": "2022-08-01T09:52:10.252091",
                    "end_date": null,
                    "feed_id": 0,
                    "id": 111111,
                    "intelligence_initiatives": [],
                    "is_anonymous": false,
                    "is_cloneable": "yes",
                    "is_public": false,
                    "modified_ts": "2022-08-01T09:52:10.246877",
                    "name": "Test Investigation",
                    "objective": null,
                    "organization_id": 88,
                    "owner_user_id": 111,
                    "publication_status": "new",
                    "published_ts": null,
                    "resource_uri": "/api/v1/campaign/111111/",
                    "source_created": null,
                    "source_modified": null,
                    "start_date": null,
                    "status": {
                        "display_name": "Ongoing",
                        "id": 1,
                        "resource_uri": "/api/v1/campaignstatus/1/"
                    },
                    "tags": [],
                    "tags_v2": [],
                    "tlp": "white",
                    "uuid": "9b7872f1-beb7-42d7-a500-d37df74af644",
                    "workgroups": []
                }
            ],
            "Confidence": 100,
            "Country": null,
            "IType": "apt_ip",
            "Modified": "2022-08-01T09:46:41.715Z",
            "Organization": "",
            "Severity": "very-high",
            "Signature": [],
            "Source": "Analyst",
            "Status": "active",
            "TTP": [],
            "Tags": [
                "apt",
                "PANW_Test"
            ],
            "ThreatBulletin": [],
            "Type": "ip",
            "Vulnerability": []
        }
    }
}
```

#### Human Readable Output

>### IP reputation for: 23.98.23.98
>|ASN|Address|Confidence|Country|IType|Modified|Organization|Severity|Source|Status|Tags|Type|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>|  | 23.98.23.98 | 100 |  | apt_ip | 2022-08-01T09:46:41.715Z |  | very-high | Analyst | active | apt, PANW_Test | ip |
>### Actor details:
>**No entries.**
>### Signature details:
>**No entries.**
>### ThreatBulletin details:
>**No entries.**
>### TTP details:
>**No entries.**
>### Vulnerability details:
>**No entries.**
>### Campaign details:
>|name|id|
>|---|---|
>| Test Investigation | 111111 |


### domain
***
Checks the reputation of the given domain name.


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain name to check. | Required | 
| threshold | If confidence is greater than the threshold the domain is considered malicious, otherwise it is considered good. This argument overrides the default domain threshold defined as a parameter. | Optional | 
| include_inactive | Whether to include results with an inactive status. Possible values are: True, False. | Optional | 
| threat_model_association | Enhance generic reputation commands to include additional information such as Threat Bulletins, Attach patterns, Actors, Campaigns, TTPs, vulnerabilities, etc. Note: If set to true, additional 6 API calls will be performed. Possible values are: True, False. Default is False. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The domain name. | 
| Domain.DNS | String | The IP addresses resolved by the DNS. | 
| Domain.WHOIS.CreationDate | Date | The date the domain was created. The date format is: YYYYMMDDThhmmss, where T denotes the start of the value
for time in UTC time. | 
| Domain.WHOIS.UpdatedDate | Date | The date the domain was last updated. The date format is: YYYYMMDDThhmmss, where T denotes the start of the value
for time in UTC time. | 
| Domain.WHOIS.Registrant.Name | String | The registrant name. | 
| Domain.WHOIS.Registrant.Email | String | The registrant email address. | 
| Domain.WHOIS.Registrant.Phone | String | The registrant phone number. | 
| ThreatStream.Domain.ASN | String | The Autonomous System \(AS\) number associated with the indicator. | 
| ThreatStream.Domain.Address | String | The indicator domain name. | 
| ThreatStream.Domain.Country | String | The country associated with the indicator. | 
| ThreatStream.Domain.Type | String | The indicator type. | 
| ThreatStream.Domain.Modified | String | The date and time the indicator was last updated. The date format is: YYYYMMDDThhmmss, where "T" denotes the start of the value
for time in UTC time. | 
| ThreatStream.Domain.Severity | String | The indicator severity \("very-high", "high", "medium", "low"\). | 
| ThreatStream.Domain.Confidence | String | The observable certainty level of a reported indicator type. Confidence score ranges from 0-100, in increasing order of confidence. | 
| ThreatStream.Domain.Status | String | The status assigned to the indicator. | 
| ThreatStream.Domain.Organization | String | The name of the business that owns the IP address associated with the indicator. | 
| ThreatStream.Domain.Source | String | The indicator source. | 
| Domain.Malicious.Vendor | String | The vendor that reported the indicator as malicious. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| ThreatStream.Domain.Tags | Unknown | Tags assigned to the domain. | 
| ThreatStream.Domain.IType | String | The itype of the indicator associated with the specified model. | 
| Domain.Tags | Unknown | List of domain tags. | 
| Domain.ThreatTypes | Unknown | Threat types associated with the domain. | 
| ThreatStream.Domain.Actor.assignee_user | Unknown | The assignee user of the threat actor. | 
| ThreatStream.Domain.Actor.association_info.comment | Unknown | The comment in the association info of the threat actor. | 
| ThreatStream.Domain.Actor.association_info.created | Date | The date the association info was created. | 
| ThreatStream.Domain.Actor.association_info.from_id | Number | The ID from which the association info is related. | 
| ThreatStream.Domain.Actor.can_add_public_tags | Boolean | Whether you can add public tags to the threat actor. | 
| ThreatStream.Domain.Actor.created_ts | Date | The date the threat actor was created. | 
| ThreatStream.Domain.Actor.feed_id | Number | The feed ID of the threat actor. | 
| ThreatStream.Domain.Actor.id | Number | The ID of the threat actor. | 
| ThreatStream.Domain.Actor.is_anonymous | Boolean | Whether the threat actor is anonymous. | 
| ThreatStream.Domain.Actor.is_cloneable | String | Whether the threat actor is cloneable. | 
| ThreatStream.Domain.Actor.is_public | Boolean | Whether the threat actor is public. | 
| ThreatStream.Domain.Actor.is_team | Boolean | Whether the threat actor is a team. | 
| ThreatStream.Domain.Actor.modified_ts | Date | The date the threat actor was modified. | 
| ThreatStream.Domain.Actor.name | String | The name of the threat actor. | 
| ThreatStream.Domain.Actor.organization_id | Number | The organization ID of the threat actor. | 
| ThreatStream.Domain.Actor.owner_user_id | Number | The owner user ID of the threat actor. | 
| ThreatStream.Domain.Actor.primary_motivation | Unknown | The primary motivation of the threat actor. | 
| ThreatStream.Domain.Actor.publication_status | String | The publication status of the threat actor. | 
| ThreatStream.Domain.Actor.published_ts | Date | The date the threat actor was published. | 
| ThreatStream.Domain.Actor.resource_level | Unknown | The resource level of the threat actor. | 
| ThreatStream.Domain.Actor.resource_uri | String | The resource URI of the threat actor. | 
| ThreatStream.Domain.Actor.source_created | Unknown | The date the source was created. | 
| ThreatStream.Domain.Actor.source_modified | Unknown | The date the source was modified. | 
| ThreatStream.Domain.Actor.start_date | Unknown | The start date. | 
| ThreatStream.Domain.Actor.tags | String | The tags of the threat indicator. | 
| ThreatStream.Domain.Actor.tags_v2.id | String | The ID of the tag. | 
| ThreatStream.Domain.Actor.tags_v2.name | String | The name of the tag. | 
| ThreatStream.Domain.Actor.tlp | String | The TLP of the threat actor. | 
| ThreatStream.Domain.Actor.uuid | String | The UUID of the threat actor. | 
| ThreatStream.Domain.Signature.assignee_user | Unknown | The assignee user of the signature. | 
| ThreatStream.Domain.Signature.association_info.comment | Unknown | The comment in the association info of the signature. | 
| ThreatStream.Domain.Signature.association_info.created | Date | The date the association info was created. | 
| ThreatStream.Domain.Signature.association_info.from_id | Number | The ID from which the association info is related. | 
| ThreatStream.Domain.Signature.can_add_public_tags | Boolean | Whether you can add public tags to the signature. | 
| ThreatStream.Domain.Signature.created_ts | Date | The date the signature was created. | 
| ThreatStream.Domain.Signature.feed_id | Number | The feed ID of the signature. | 
| ThreatStream.Domain.Signature.id | Number | The ID of the signature. | 
| ThreatStream.Domain.Signature.is_anonymous | Boolean | Whether the signature is anonymous. | 
| ThreatStream.Domain.Signature.is_cloneable | String | Whether the signature is cloneable. | 
| ThreatStream.Domain.Signature.is_public | Boolean | Whether the signature is public. | 
| ThreatStream.Domain.Signature.is_team | Boolean | Whether the signature is a team signature. | 
| ThreatStream.Domain.Signature.modified_ts | Date | The date the signature was modified. | 
| ThreatStream.Domain.Signature.name | String | The name of the signature. | 
| ThreatStream.Domain.Signature.organization_id | Number | The organization ID of the signature. | 
| ThreatStream.Domain.Signature.owner_user_id | Number | The owner user ID of the signature. | 
| ThreatStream.Domain.Signature.primary_motivation | Unknown | The primary motivation of the signature. | 
| ThreatStream.Domain.Signature.publication_status | String | The publication status of the signature. | 
| ThreatStream.Domain.Signature.published_ts | Date | The date the signature was published. | 
| ThreatStream.Domain.Signature.resource_level | Unknown | The resource level of the signature. | 
| ThreatStream.Domain.Signature.resource_uri | String | The resource URI of the signature. | 
| ThreatStream.Domain.Signature.source_created | Unknown | The date the source was created. | 
| ThreatStream.Domain.Signature.source_modified | Unknown | The date the source was modified. | 
| ThreatStream.Domain.Signature.start_date | Unknown | The start date. | 
| ThreatStream.Domain.Signature.tags | String | The tags of the threat indicator. | 
| ThreatStream.Domain.Signature.tags_v2.id | String | The ID of the tag. | 
| ThreatStream.Domain.Signature.tags_v2.name | String | The name of the tag. | 
| ThreatStream.Domain.Signature.tlp | String | The TLP of the signature. | 
| ThreatStream.Domain.Signature.uuid | String | The UUID of the signature. | 
| ThreatStream.Domain.ThreatBulletin.all_circles_visible | Boolean | Whether all of the circles are visible. | 
| ThreatStream.Domain.ThreatBulletin.assignee_org | String | The assignee organization. | 
| ThreatStream.Domain.ThreatBulletin.assignee_org_id | String | The assignee organization ID. | 
| ThreatStream.Domain.ThreatBulletin.assignee_org_name | String | The assignee organization name. | 
| ThreatStream.Domain.ThreatBulletin.assignee_user | String | The assignee user. | 
| ThreatStream.Domain.ThreatBulletin.assignee_user_id | String | The assignee user ID. | 
| ThreatStream.Domain.ThreatBulletin.assignee_user_name | Unknown | The assignee user name. | 
| ThreatStream.Domain.ThreatBulletin.association_info.comment | Unknown | The comment in the association info of the threat actor. | 
| ThreatStream.Domain.ThreatBulletin.association_info.created | Date | The date the association info was created. | 
| ThreatStream.Domain.ThreatBulletin.association_info.from_id | String | The ID from which the association info is related. | 
| ThreatStream.Domain.ThreatBulletin.body_content_type | String | The body content type. | 
| ThreatStream.Domain.ThreatBulletin.campaign | Unknown | The campaign of the threat bulletin. | 
| ThreatStream.Domain.ThreatBulletin.can_add_public_tags | Boolean | Whether you can add public tags. | 
| ThreatStream.Domain.ThreatBulletin.created_ts | Date | The date the threat bulletin was created. | 
| ThreatStream.Domain.ThreatBulletin.feed_id | Number | The feed ID of the threat bulletin. | 
| ThreatStream.Domain.ThreatBulletin.id | String | The ID of the threat bulletin. | 
| ThreatStream.Domain.ThreatBulletin.is_anonymous | Boolean | Whether the threat bulletin is anonymous. | 
| ThreatStream.Domain.ThreatBulletin.is_cloneable | String | Whether the threat bulletin is cloneable. | 
| ThreatStream.Domain.ThreatBulletin.is_editable | Boolean | Whether the threat bulletin is editable. | 
| ThreatStream.Domain.ThreatBulletin.is_email | Boolean | Whether the threat bulletin is an email. | 
| ThreatStream.Domain.ThreatBulletin.is_public | Boolean | Whether the threat bulletin is public. | 
| ThreatStream.Domain.ThreatBulletin.modified_ts | Date | The date the threat bulletin was modified. | 
| ThreatStream.Domain.ThreatBulletin.name | String | The name of the threat bulletin. | 
| ThreatStream.Domain.ThreatBulletin.original_source | String | The original source of the threat bulletin. | 
| ThreatStream.Domain.ThreatBulletin.original_source_id | Unknown | The original source ID of the threat bulletin. | 
| ThreatStream.Domain.ThreatBulletin.owner_org.id | String | The owner organization ID. | 
| ThreatStream.Domain.ThreatBulletin.owner_org.name | String | The owner organization name. | 
| ThreatStream.Domain.ThreatBulletin.owner_org.resource_uri | String | The owner organization URI. | 
| ThreatStream.Domain.ThreatBulletin.owner_org_id | Number | The ID of the owner user. | 
| ThreatStream.Domain.ThreatBulletin.owner_org_name | String | The name of the owner organization. | 
| ThreatStream.Domain.ThreatBulletin.owner_user.avatar_s3_url | Unknown | The URL of the owner user. | 
| ThreatStream.Domain.ThreatBulletin.owner_user.can_share_intelligence | Boolean | Whether you can share intelligence. | 
| ThreatStream.Domain.ThreatBulletin.owner_user.email | String | The email of the owner user. | 
| ThreatStream.Domain.ThreatBulletin.owner_user.id | String | The ID of the owner user. | 
| ThreatStream.Domain.ThreatBulletin.owner_user.is_active | Boolean | Whether the owner user is active. | 
| ThreatStream.Domain.ThreatBulletin.owner_user.is_readonly | Boolean | Whether the owner user has read-only permission. | 
| ThreatStream.Domain.ThreatBulletin.owner_user.must_change_password | Boolean | Whether the owner user must change the password. | 
| ThreatStream.Domain.ThreatBulletin.owner_user.name | String | The owner user name. | 
| ThreatStream.Domain.ThreatBulletin.owner_user.nickname | String | The owner user nickname. | 
| ThreatStream.Domain.ThreatBulletin.owner_user.organization.id | String | The ID of the owner user organization. | 
| ThreatStream.Domain.ThreatBulletin.owner_user.organization.name | String | The name of the owner user organization. | 
| ThreatStream.Domain.ThreatBulletin.owner_user.organization.resource_uri | String | The resource URI of the owner user organization. | 
| ThreatStream.Domain.ThreatBulletin.owner_user.resource_uri | String | The resource URI of the owner user. | 
| ThreatStream.Domain.ThreatBulletin.owner_user_id | Number | The owner user ID of the threat bulletin. | 
| ThreatStream.Domain.ThreatBulletin.owner_user_name | String | The owner user name of the threat bulletin. | 
| ThreatStream.Domain.ThreatBulletin.parent | Unknown | The parent of the threat bulletin. | 
| ThreatStream.Domain.ThreatBulletin.published_ts | Unknown | The date the threat bulletin was published. | 
| ThreatStream.Domain.ThreatBulletin.resource_uri | String | The resource URI of the threat bulletin. | 
| ThreatStream.Domain.ThreatBulletin.source | Unknown | The source of the threat bulletin. | 
| ThreatStream.Domain.ThreatBulletin.source_created | Unknown | The date the source was created. | 
| ThreatStream.Domain.ThreatBulletin.source_modified | Unknown | The date the source was modified. | 
| ThreatStream.Domain.ThreatBulletin.starred_by_me | Boolean | Whether the threat bulletin was started by me. | 
| ThreatStream.Domain.ThreatBulletin.starred_total_count | Number | The total number of times the threat bulletin was starred. | 
| ThreatStream.Domain.ThreatBulletin.status | String | The status of the threat bulletin. | 
| ThreatStream.Domain.ThreatBulletin.threat_actor | Unknown | The threat actor of the threat bulletin. | 
| ThreatStream.Domain.ThreatBulletin.tlp | Unknown | The TLP of the threat bulletin. | 
| ThreatStream.Domain.ThreatBulletin.ttp | Unknown | The TTP of the threat bulletin. | 
| ThreatStream.Domain.ThreatBulletin.uuid | String | The UUID of the threat bulletin. | 
| ThreatStream.Domain.ThreatBulletin.votes.me | Unknown | The number of votes by me. | 
| ThreatStream.Domain.ThreatBulletin.votes.total | Number | The number of total votes. | 
| ThreatStream.Domain.ThreatBulletin.watched_by_me | Boolean | Whether the threat bulletin was watched by me. | 
| ThreatStream.Domain.ThreatBulletin.watched_total_count | Number | The total number of watchers. | 
| ThreatStream.Domain.TTP.assignee_user | Unknown | The assignee user of the TTP. | 
| ThreatStream.Domain.TTP.association_info.comment | Unknown | The comment in the association info of the TTP. | 
| ThreatStream.Domain.TTP.association_info.created | Date | The date the association info was created. | 
| ThreatStream.Domain.TTP.association_info.from_id | Number | The ID from which the association info is related. | 
| ThreatStream.Domain.TTP.can_add_public_tags | Boolean | Whether you can add public tags to the TTP. | 
| ThreatStream.Domain.TTP.created_ts | Date | The date the TTP was created. | 
| ThreatStream.Domain.TTP.feed_id | Number | The feed ID of the TTP. | 
| ThreatStream.Domain.TTP.id | Number | The ID of the TTP. | 
| ThreatStream.Domain.TTP.is_anonymous | Boolean | Whether the TTP was anonymous. | 
| ThreatStream.Domain.TTP.is_cloneable | String | Whether the TTP was cloneable. | 
| ThreatStream.Domain.TTP.is_public | Boolean | Whether the TTP is public. | 
| ThreatStream.Domain.TTP.is_team | Boolean | Whether the TTP is a team. | 
| ThreatStream.Domain.TTP.modified_ts | Date | The date the TTP was modified. | 
| ThreatStream.Domain.TTP.name | String | The name of the TTP. | 
| ThreatStream.Domain.TTP.organization_id | Number | The organization ID of the TTP. | 
| ThreatStream.Domain.TTP.owner_user_id | Number | The owner user ID of the TTP. | 
| ThreatStream.Domain.TTP.primary_motivation | Unknown | The primary motivation of the TTP. | 
| ThreatStream.Domain.TTP.publication_status | String | The publication status of the TTP. | 
| ThreatStream.Domain.TTP.published_ts | Date | The date the TTP was published. | 
| ThreatStream.Domain.TTP.resource_level | Unknown | The resource level of the TTP. | 
| ThreatStream.Domain.TTP.resource_uri | String | The resource URI of the TTP. | 
| ThreatStream.Domain.TTP.source_created | Unknown | The date the source was created. | 
| ThreatStream.Domain.TTP.source_modified | Unknown | The date the source was modified. | 
| ThreatStream.Domain.TTP.start_date | Unknown | The start date. | 
| ThreatStream.Domain.TTP.tags | String | The tags of the threat indicator. | 
| ThreatStream.Domain.TTP.tags_v2.id | String | The ID of the tag. | 
| ThreatStream.Domain.TTP.tags_v2.name | String | The name of the tag. | 
| ThreatStream.Domain.TTP.tlp | String | The TLP of the TTP. | 
| ThreatStream.Domain.TTP.uuid | String | The UUID of the TTP. | 
| ThreatStream.Domain.Vulnerability.assignee_user | Unknown | The assignee user of the vulnerability. | 
| ThreatStream.Domain.Vulnerability.association_info.comment | Unknown | The comment in the association info of the vulnerability. | 
| ThreatStream.Domain.Vulnerability.association_info.created | Date | The date the association info was created. | 
| ThreatStream.Domain.Vulnerability.association_info.from_id | Number | The ID from which the association info is related. | 
| ThreatStream.Domain.Vulnerability.can_add_public_tags | Boolean | Whether you can add public tags to the threat actor. | 
| ThreatStream.Domain.Vulnerability.circles.id | String | The ID of the circle. | 
| ThreatStream.Domain.Vulnerability.circles.name | String | The name of the circle. | 
| ThreatStream.Domain.Vulnerability.circles.resource_uri | String | The resource URI of the circle. | 
| ThreatStream.Domain.Vulnerability.created_ts | Date | The date the vulnerability was created. | 
| ThreatStream.Domain.Vulnerability.feed_id | Number | The feed ID of the vulnerability. | 
| ThreatStream.Domain.Vulnerability.id | Number | The ID of the vulnerability. | 
| ThreatStream.Domain.Vulnerability.is_anonymous | Boolean | Whether the vulnerability is anonymous. | 
| ThreatStream.Domain.Vulnerability.is_cloneable | String | Whether the vulnerability is cloneable. | 
| ThreatStream.Domain.Vulnerability.is_public | Boolean | Whether the vulnerability is public. | 
| ThreatStream.Domain.Vulnerability.is_system | Boolean | Whether the vulnerability is in the system. | 
| ThreatStream.Domain.Vulnerability.modified_ts | Date | The date the vulnerability was modified. | 
| ThreatStream.Domain.Vulnerability.name | String | The name of the vulnerability. | 
| ThreatStream.Domain.Vulnerability.organization_id | Number | The organization ID of the vulnerability. | 
| ThreatStream.Domain.Vulnerability.owner_user_id | Unknown | The owner user ID of the vulnerability. | 
| ThreatStream.Domain.Vulnerability.publication_status | String | The publication status of the vulnerability. | 
| ThreatStream.Domain.Vulnerability.published_ts | Date | The date the vulnerability was published. | 
| ThreatStream.Domain.Vulnerability.resource_uri | String | The resource URI of the vulnerability. | 
| ThreatStream.Domain.Vulnerability.source | String | The source of the vulnerability. | 
| ThreatStream.Domain.Vulnerability.source_created | Unknown | The feed ID of the vulnerability. | 
| ThreatStream.Domain.Vulnerability.source_modified | Unknown | Whether the source was modified. | 
| ThreatStream.Domain.Vulnerability.tags | String | The tags of the vulnerability. | 
| ThreatStream.Domain.Vulnerability.tags_v2.id | String | The ID of the tag. | 
| ThreatStream.Domain.Vulnerability.tags_v2.name | String | The name of the tag. | 
| ThreatStream.Domain.Vulnerability.tlp | String | The TLP of the vulnerability. | 
| ThreatStream.Domain.Vulnerability.update_id | Number | The update ID of the vulnerability. | 
| ThreatStream.Domain.Vulnerability.uuid | String | The UUID of the vulnerability. | 
| ThreatStream.Domain.Campaign.assignee_user | Unknown | The assignee user of the vulnerability. | 
| ThreatStream.Domain.Campaign.association_info.comment | Unknown | The comment in the association info of the vulnerability. | 
| ThreatStream.Domain.Campaign.association_info.created | Date | The date the association info was created. | 
| ThreatStream.Domain.Campaign.association_info.from_id | Number | The ID from which the association info is related. | 
| ThreatStream.Domain.Campaign.can_add_public_tags | Boolean | Whether you can add public tags to the campaign. | 
| ThreatStream.Domain.Campaign.created_ts | Date | The date the campaign was created. | 
| ThreatStream.Domain.Campaign.end_date | Unknown | The end date of the campaign. | 
| ThreatStream.Domain.Campaign.feed_id | Number | The feed ID of the campaign. | 
| ThreatStream.Domain.Campaign.id | Number | The ID of the campaign. | 
| ThreatStream.Domain.Campaign.is_anonymous | Boolean | Whether the campaign is anonymous. | 
| ThreatStream.Domain.Campaign.is_cloneable | String | Whether the campaign is cloneable. | 
| ThreatStream.Domain.Campaign.is_public | Boolean | Whether the campaign is public. | 
| ThreatStream.Domain.Campaign.modified_ts | Date | The date the campaign was modified. | 
| ThreatStream.Domain.Campaign.name | String | The name of the campaign. | 
| ThreatStream.Domain.Campaign.objective | Unknown | The objective of the campaign. | 
| ThreatStream.Domain.Campaign.organization_id | Number | The organization ID of the campaign. | 
| ThreatStream.Domain.Campaign.owner_user_id | Number | The owner user ID of the campaign. | 
| ThreatStream.Domain.Campaign.publication_status | String | The publication status of the campaign. | 
| ThreatStream.Domain.Campaign.published_ts | Unknown | The date the campaign was published. | 
| ThreatStream.Domain.Campaign.resource_uri | String | The resource URI of the campaign. | 
| ThreatStream.Domain.Campaign.source_created | Date | The date the campaign was created. | 
| ThreatStream.Domain.Campaign.source_modified | Date | Whether the source was modified. | 
| ThreatStream.Domain.Campaign.start_date | Unknown | The start date of the campaign. | 
| ThreatStream.Domain.Campaign.status.display_name | String | The display name of the status. | 
| ThreatStream.Domain.Campaign.status.id | Number | The ID of the status of the campaign. | 
| ThreatStream.Domain.Campaign.status.resource_uri | String | The resource URI of the status of the campaign. | 
| ThreatStream.Domain.Campaign.tlp | String | The TLP of the campaign. | 
| ThreatStream.Domain.Campaign.uuid | String | The UUID of the campaign. | 

#### Command example
```!domain domain=y.gp threat_model_association=True```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "y.gp",
        "Reliability": "B - Usually reliable",
        "Score": 2,
        "Type": "domain",
        "Vendor": "Anomali ThreatStream v3 May"
    },
    "Domain": {
        "CreationDate": "2021-03-31T10:17:13.553Z",
        "DNS": "1.2.4.5",
        "Geo": {
            "Country": "DE",
            "Location": "51.2993,9.491"
        },
        "Name": "y.gp",
        "Organization": "Hetzner Online GmbH",
        "Relationships": [
            {
                "EntityA": "y.gp",
                "EntityAType": "Domain",
                "EntityB": "1.2.4.5",
                "EntityBType": "IP",
                "Relationship": "resolved-from"
            }
        ],
        "Tags": [
            "malware"
        ],
        "ThreatTypes": [
            {
                "threatcategory": "malware",
                "threatcategoryconfidence": null
            }
        ],
        "TrafficLightProtocol": "amber",
        "UpdatedDate": "2021-03-31T10:17:56.207Z",
        "WHOIS": {
            "CreationDate": "2021-03-31T10:17:13.553Z",
            "UpdatedDate": "2021-03-31T10:17:56.207Z"
        }
    },
    "ThreatStream": {
        "Domain": {
            "ASN": "24940",
            "Actor": [],
            "Address": "y.gp",
            "Campaign": [],
            "Confidence": 50,
            "Country": "DE",
            "IType": "mal_domain",
            "Modified": "2021-03-31T10:17:56.207Z",
            "Organization": "Hetzner Online GmbH",
            "Severity": "very-high",
            "Signature": [],
            "Source": "Analyst",
            "Status": "active",
            "TTP": [],
            "Tags": [
                "malware"
            ],
            "ThreatBulletin": [],
            "Type": "domain",
            "Vulnerability": []
        }
    }
}
```

#### Human Readable Output

>### Domain reputation for: y.gp
>|ASN|Address|Confidence|Country|IType|Modified|Organization|Severity|Source|Status|Tags|Type|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 24940 | y.gp | 50 | DE | mal_domain | 2021-03-31T10:17:56.207Z | Hetzner Online GmbH | very-high | Analyst | active | malware | domain |
>### Actor details:
>**No entries.**
>### Signature details:
>**No entries.**
>### ThreatBulletin details:
>**No entries.**
>### TTP details:
>**No entries.**
>### Vulnerability details:
>**No entries.**
>### Campaign details:
>**No entries.**


### file
***
Checks the reputation of the given hash of the file.


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | The hash of file to check. | Required | 
| threshold | If the confidence is greater than the threshold the hash of the file is considered malicious, otherwise it is considered good. This argument overrides the default file threshold defined as a parameter. | Optional | 
| include_inactive | Whether to include results with an inactive status. Possible values are: True, False. | Optional | 
| threat_model_association | Enhance generic reputation commands to include additional information such as Threat Bulletins, Attach patterns, Actors, Campaigns, TTPs, vulnerabilities, etc. Note: If set to true, additional 6 API calls will be performed. Possible values are: True, False. Default is False. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.SHA512 | String | The SHA512 hash of the file. | 
| File.Malicious.Vendor | String | The vendor that reported the indicator as malicious. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| ThreatStream.File.Severity | String | The indicator severity \("very-high", "high", "medium", "low"\). | 
| ThreatStream.File.Confidence | String | The observable certainty level of a reported indicator type. Confidence score ranges from 0-100, in increasing order of confidence. | 
| ThreatStream.File.Status | String | The status assigned to the indicator. | 
| ThreatStream.File.Type | String | The indicator type. | 
| ThreatStream.File.MD5 | String | The MD5 hash of the indicator. | 
| ThreatStream.File.SHA1 | String | The SHA1 hash of the indicator. | 
| ThreatStream.File.SHA256 | String | The SHA256 hash of the indicator. | 
| ThreatStream.File.SHA512 | String | The SHA512 hash of the indicator. | 
| ThreatStream.File.Modified | String | The date and time the indicator was last updated. The date format is: YYYYMMDDThhmmss, where "T" denotes the start of the value
for time in UTC time. | 
| ThreatStream.File.Source | String | The indicator source. | 
| ThreatStream.File.Tags | Unknown | Tags assigned to the file. | 
| ThreatStream.File.IType | String | The itype of the indicator associated with the specified model. | 
| File.Tags | Unknown | List of file tags. | 
| File.ThreatTypes | Unknown | Threat types associated with the file. | 
| ThreatStream.File.Actor.assignee_user | Unknown | The assignee user of the threat actor. | 
| ThreatStream.File.Actor.association_info.comment | Unknown | The comment in the association info of the threat actor. | 
| ThreatStream.File.Actor.association_info.created | Date | The date the association info was created. | 
| ThreatStream.File.Actor.association_info.from_id | Number | The ID from which the association info is related. | 
| ThreatStream.File.Actor.can_add_public_tags | Boolean | Whether you can add public tags to the threat actor. | 
| ThreatStream.File.Actor.created_ts | Date | The date the threat actor was created. | 
| ThreatStream.File.Actor.feed_id | Number | The feed ID of the threat actor. | 
| ThreatStream.File.Actor.id | Number | The ID of the threat actor. | 
| ThreatStream.File.Actor.is_anonymous | Boolean | Whether the threat actor is anonymous. | 
| ThreatStream.File.Actor.is_cloneable | String | Whether the threat actor is cloneable. | 
| ThreatStream.File.Actor.is_public | Boolean | Whether the threat actor is public. | 
| ThreatStream.File.Actor.is_team | Boolean | Whether the threat actor is a team. | 
| ThreatStream.File.Actor.modified_ts | Date | The date the threat actor was modified. | 
| ThreatStream.File.Actor.name | String | The name of the threat actor. | 
| ThreatStream.File.Actor.organization_id | Number | The organization ID of the threat actor. | 
| ThreatStream.File.Actor.owner_user_id | Number | The owner user ID of the threat actor. | 
| ThreatStream.File.Actor.primary_motivation | Unknown | The primary motivation of the threat actor. | 
| ThreatStream.File.Actor.publication_status | String | The publication status of the threat actor. | 
| ThreatStream.File.Actor.published_ts | Date | The date the threat actor was published. | 
| ThreatStream.File.Actor.resource_level | Unknown | The resource level of the threat actor. | 
| ThreatStream.File.Actor.resource_uri | String | The resource URI of the threat actor. | 
| ThreatStream.File.Actor.source_created | Unknown | The date the source was created. | 
| ThreatStream.File.Actor.source_modified | Unknown | The date the source was modified. | 
| ThreatStream.File.Actor.start_date | Unknown | The start date. | 
| ThreatStream.File.Actor.tags | String | The tags of the threat indicator. | 
| ThreatStream.File.Actor.tags_v2.id | String | The ID of the tag. | 
| ThreatStream.File.Actor.tags_v2.name | String | The name of the tag. | 
| ThreatStream.File.Actor.tlp | String | The TLP of the threat actor. | 
| ThreatStream.File.Actor.uuid | String | The UUID of the threat actor. | 
| ThreatStream.File.Signature.assignee_user | Unknown | The assignee user of the signature. | 
| ThreatStream.File.Signature.association_info.comment | Unknown | The comment in the association info of the signature. | 
| ThreatStream.File.Signature.association_info.created | Date | The date the association info was created. | 
| ThreatStream.File.Signature.association_info.from_id | Number | The ID from which the association info is related. | 
| ThreatStream.File.Signature.can_add_public_tags | Boolean | Whether you can add public tags to the signature. | 
| ThreatStream.File.Signature.created_ts | Date | The date the signature was created. | 
| ThreatStream.File.Signature.feed_id | Number | The feed ID of the signature. | 
| ThreatStream.File.Signature.id | Number | The ID of the signature. | 
| ThreatStream.File.Signature.is_anonymous | Boolean | Whether the signature is anonymous. | 
| ThreatStream.File.Signature.is_cloneable | String | Whether the signature is cloneable. | 
| ThreatStream.File.Signature.is_public | Boolean | Whether the signature is public. | 
| ThreatStream.File.Signature.is_team | Boolean | Whether the signature is a team signature. | 
| ThreatStream.File.Signature.modified_ts | Date | The date the signature was modified. | 
| ThreatStream.File.Signature.name | String | The name of the signature. | 
| ThreatStream.File.Signature.organization_id | Number | The organization ID of the signature. | 
| ThreatStream.File.Signature.owner_user_id | Number | The owner user ID of the signature. | 
| ThreatStream.File.Signature.primary_motivation | Unknown | The primary motivation of the signature. | 
| ThreatStream.File.Signature.publication_status | String | The publication status of the signature. | 
| ThreatStream.File.Signature.published_ts | Date | The date the signature was published. | 
| ThreatStream.File.Signature.resource_level | Unknown | The resource level of the signature. | 
| ThreatStream.File.Signature.resource_uri | String | The resource URI of the signature. | 
| ThreatStream.File.Signature.source_created | Unknown | The date the source was created. | 
| ThreatStream.File.Signature.source_modified | Unknown | The date the source was modified. | 
| ThreatStream.File.Signature.start_date | Unknown | The start date. | 
| ThreatStream.File.Signature.tags | String | The tags of the threat indicator. | 
| ThreatStream.File.Signature.tags_v2.id | String | The ID of the tag. | 
| ThreatStream.File.Signature.tags_v2.name | String | The name of the tag. | 
| ThreatStream.File.Signature.tlp | String | The TLP of the signature. | 
| ThreatStream.File.Signature.uuid | String | The UUID of the signature. | 
| ThreatStream.File.ThreatBulletin.all_circles_visible | Boolean | Whether all of the circles are visible. | 
| ThreatStream.File.ThreatBulletin.assignee_org | String | The assignee organization. | 
| ThreatStream.File.ThreatBulletin.assignee_org_id | String | The assignee organization ID. | 
| ThreatStream.File.ThreatBulletin.assignee_org_name | String | The assignee organization name. | 
| ThreatStream.File.ThreatBulletin.assignee_user | String | The assignee user. | 
| ThreatStream.File.ThreatBulletin.assignee_user_id | String | The assignee user ID. | 
| ThreatStream.File.ThreatBulletin.assignee_user_name | Unknown | The assignee user name. | 
| ThreatStream.File.ThreatBulletin.association_info.comment | Unknown | The comment in the association info of the threat actor. | 
| ThreatStream.File.ThreatBulletin.association_info.created | Date | The date the association info was created. | 
| ThreatStream.File.ThreatBulletin.association_info.from_id | String | The ID from which the association info is related. | 
| ThreatStream.File.ThreatBulletin.body_content_type | String | The body content type. | 
| ThreatStream.File.ThreatBulletin.campaign | Unknown | The campaign of the threat bulletin. | 
| ThreatStream.File.ThreatBulletin.can_add_public_tags | Boolean | Whether you can add public tags. | 
| ThreatStream.File.ThreatBulletin.created_ts | Date | The date the threat bulletin was created. | 
| ThreatStream.File.ThreatBulletin.feed_id | Number | The feed ID of the threat bulletin. | 
| ThreatStream.File.ThreatBulletin.id | String | The ID of the threat bulletin. | 
| ThreatStream.File.ThreatBulletin.is_anonymous | Boolean | Whether the threat bulletin is anonymous. | 
| ThreatStream.File.ThreatBulletin.is_cloneable | String | Whether the threat bulletin is cloneable. | 
| ThreatStream.File.ThreatBulletin.is_editable | Boolean | Whether the threat bulletin is editable. | 
| ThreatStream.File.ThreatBulletin.is_email | Boolean | Whether the threat bulletin is an email. | 
| ThreatStream.File.ThreatBulletin.is_public | Boolean | Whether the threat bulletin is public. | 
| ThreatStream.File.ThreatBulletin.modified_ts | Date | The date the threat bulletin was modified. | 
| ThreatStream.File.ThreatBulletin.name | String | The name of the threat bulletin. | 
| ThreatStream.File.ThreatBulletin.original_source | String | The original source of the threat bulletin. | 
| ThreatStream.File.ThreatBulletin.original_source_id | Unknown | The original source ID of the threat bulletin. | 
| ThreatStream.File.ThreatBulletin.owner_org.id | String | The owner organization ID. | 
| ThreatStream.File.ThreatBulletin.owner_org.name | String | The owner organization name. | 
| ThreatStream.File.ThreatBulletin.owner_org.resource_uri | String | The owner organization URI. | 
| ThreatStream.File.ThreatBulletin.owner_org_id | Number | The ID of the owner user. | 
| ThreatStream.File.ThreatBulletin.owner_org_name | String | The name of the owner organization. | 
| ThreatStream.File.ThreatBulletin.owner_user.avatar_s3_url | Unknown | The URL of the owner user. | 
| ThreatStream.File.ThreatBulletin.owner_user.can_share_intelligence | Boolean | Whether you can share intelligence. | 
| ThreatStream.File.ThreatBulletin.owner_user.email | String | The email of the owner user. | 
| ThreatStream.File.ThreatBulletin.owner_user.id | String | The ID of the owner user. | 
| ThreatStream.File.ThreatBulletin.owner_user.is_active | Boolean | Whether the owner user is active. | 
| ThreatStream.File.ThreatBulletin.owner_user.is_readonly | Boolean | Whether the owner user has read-only permission. | 
| ThreatStream.File.ThreatBulletin.owner_user.must_change_password | Boolean | Whether the owner user must change the password. | 
| ThreatStream.File.ThreatBulletin.owner_user.name | String | The owner user name. | 
| ThreatStream.File.ThreatBulletin.owner_user.nickname | String | The owner user nickname. | 
| ThreatStream.File.ThreatBulletin.owner_user.organization.id | String | The ID of the owner user organization. | 
| ThreatStream.File.ThreatBulletin.owner_user.organization.name | String | The name of the owner user organization. | 
| ThreatStream.File.ThreatBulletin.owner_user.organization.resource_uri | String | The resource URI of the owner user organization. | 
| ThreatStream.File.ThreatBulletin.owner_user.resource_uri | String | The resource URI of the owner user. | 
| ThreatStream.File.ThreatBulletin.owner_user_id | Number | The owner user ID of the threat bulletin. | 
| ThreatStream.File.ThreatBulletin.owner_user_name | String | The owner user name of the threat bulletin. | 
| ThreatStream.File.ThreatBulletin.parent | Unknown | The parent of the threat bulletin. | 
| ThreatStream.File.ThreatBulletin.published_ts | Unknown | The date the threat bulletin was published. | 
| ThreatStream.File.ThreatBulletin.resource_uri | String | The resource URI of the threat bulletin. | 
| ThreatStream.File.ThreatBulletin.source | Unknown | The source of the threat bulletin. | 
| ThreatStream.File.ThreatBulletin.source_created | Unknown | The date the source was created. | 
| ThreatStream.File.ThreatBulletin.source_modified | Unknown | The date the source was modified. | 
| ThreatStream.File.ThreatBulletin.starred_by_me | Boolean | Whether the threat bulletin was started by me. | 
| ThreatStream.File.ThreatBulletin.starred_total_count | Number | The total number of times the threat bulletin was starred. | 
| ThreatStream.File.ThreatBulletin.status | String | The status of the threat bulletin. | 
| ThreatStream.File.ThreatBulletin.threat_actor | Unknown | The threat actor of the threat bulletin. | 
| ThreatStream.File.ThreatBulletin.tlp | Unknown | The TLP of the threat bulletin. | 
| ThreatStream.File.ThreatBulletin.ttp | Unknown | The TTP of the threat bulletin. | 
| ThreatStream.File.ThreatBulletin.uuid | String | The UUID of the threat bulletin. | 
| ThreatStream.File.ThreatBulletin.votes.me | Unknown | The number of votes by me. | 
| ThreatStream.File.ThreatBulletin.votes.total | Number | The number of total votes. | 
| ThreatStream.File.ThreatBulletin.watched_by_me | Boolean | Whether the threat bulletin was watched by me. | 
| ThreatStream.File.ThreatBulletin.watched_total_count | Number | The total number of watchers. | 
| ThreatStream.File.TTP.assignee_user | Unknown | The assignee user of the TTP. | 
| ThreatStream.File.TTP.association_info.comment | Unknown | The comment in the association info of the TTP. | 
| ThreatStream.File.TTP.association_info.created | Date | The date the association info was created. | 
| ThreatStream.File.TTP.association_info.from_id | Number | The ID from which the association info is related. | 
| ThreatStream.File.TTP.can_add_public_tags | Boolean | Whether you can add public tags to the TTP. | 
| ThreatStream.File.TTP.created_ts | Date | The date the TTP was created. | 
| ThreatStream.File.TTP.feed_id | Number | The feed ID of the TTP. | 
| ThreatStream.File.TTP.id | Number | The ID of the TTP. | 
| ThreatStream.File.TTP.is_anonymous | Boolean | Whether the TTP was anonymous. | 
| ThreatStream.File.TTP.is_cloneable | String | Whether the TTP was cloneable. | 
| ThreatStream.File.TTP.is_public | Boolean | Whether the TTP is public. | 
| ThreatStream.File.TTP.is_team | Boolean | Whether the TTP is a team. | 
| ThreatStream.File.TTP.modified_ts | Date | The date the TTP was modified. | 
| ThreatStream.File.TTP.name | String | The name of the TTP. | 
| ThreatStream.File.TTP.organization_id | Number | The organization ID of the TTP. | 
| ThreatStream.File.TTP.owner_user_id | Number | The owner user ID of the TTP. | 
| ThreatStream.File.TTP.primary_motivation | Unknown | The primary motivation of the TTP. | 
| ThreatStream.File.TTP.publication_status | String | The publication status of the TTP. | 
| ThreatStream.File.TTP.published_ts | Date | The date the TTP was published. | 
| ThreatStream.File.TTP.resource_level | Unknown | The resource level of the TTP. | 
| ThreatStream.File.TTP.resource_uri | String | The resource URI of the TTP. | 
| ThreatStream.File.TTP.source_created | Unknown | The date the source was created. | 
| ThreatStream.File.TTP.source_modified | Unknown | The date the source was modified. | 
| ThreatStream.File.TTP.start_date | Unknown | The start date. | 
| ThreatStream.File.TTP.tags | String | The tags of the threat indicator. | 
| ThreatStream.File.TTP.tags_v2.id | String | The ID of the tag. | 
| ThreatStream.File.TTP.tags_v2.name | String | The name of the tag. | 
| ThreatStream.File.TTP.tlp | String | The TLP of the TTP. | 
| ThreatStream.File.TTP.uuid | String | The UUID of the TTP. | 
| ThreatStream.File.Vulnerability.assignee_user | Unknown | The assignee user of the vulnerability. | 
| ThreatStream.File.Vulnerability.association_info.comment | Unknown | The comment in the association info of the vulnerability. | 
| ThreatStream.File.Vulnerability.association_info.created | Date | The date the association info was created. | 
| ThreatStream.File.Vulnerability.association_info.from_id | Number | The ID from which the association info is related. | 
| ThreatStream.File.Vulnerability.can_add_public_tags | Boolean | Whether you can add public tags to the threat actor. | 
| ThreatStream.File.Vulnerability.circles.id | String | The ID of the circle. | 
| ThreatStream.File.Vulnerability.circles.name | String | The name of the circle. | 
| ThreatStream.File.Vulnerability.circles.resource_uri | String | The resource URI of the circle. | 
| ThreatStream.File.Vulnerability.created_ts | Date | The date the vulnerability was created. | 
| ThreatStream.File.Vulnerability.feed_id | Number | The feed ID of the vulnerability. | 
| ThreatStream.File.Vulnerability.id | Number | The ID of the vulnerability. | 
| ThreatStream.File.Vulnerability.is_anonymous | Boolean | Whether the vulnerability is anonymous. | 
| ThreatStream.File.Vulnerability.is_cloneable | String | Whether the vulnerability is cloneable. | 
| ThreatStream.File.Vulnerability.is_public | Boolean | Whether the vulnerability is public. | 
| ThreatStream.File.Vulnerability.is_system | Boolean | Whether the vulnerability is in the system. | 
| ThreatStream.File.Vulnerability.modified_ts | Date | The date the vulnerability was modified. | 
| ThreatStream.File.Vulnerability.name | String | The name of the vulnerability. | 
| ThreatStream.File.Vulnerability.organization_id | Number | The organization ID of the vulnerability. | 
| ThreatStream.File.Vulnerability.owner_user_id | Unknown | The owner user ID of the vulnerability. | 
| ThreatStream.File.Vulnerability.publication_status | String | The publication status of the vulnerability. | 
| ThreatStream.File.Vulnerability.published_ts | Date | The date the vulnerability was published. | 
| ThreatStream.File.Vulnerability.resource_uri | String | The resource URI of the vulnerability. | 
| ThreatStream.File.Vulnerability.source | String | The source of the vulnerability. | 
| ThreatStream.File.Vulnerability.source_created | Unknown | The feed ID of the vulnerability. | 
| ThreatStream.File.Vulnerability.source_modified | Unknown | Whether the source was modified. | 
| ThreatStream.File.Vulnerability.tags | String | The tags of the vulnerability. | 
| ThreatStream.File.Vulnerability.tags_v2.id | String | The ID of the tag. | 
| ThreatStream.File.Vulnerability.tags_v2.name | String | The name of the tag. | 
| ThreatStream.File.Vulnerability.tlp | String | The TLP of the vulnerability. | 
| ThreatStream.File.Vulnerability.update_id | Number | The update ID of the vulnerability. | 
| ThreatStream.File.Vulnerability.uuid | String | The UUID of the vulnerability. | 
| ThreatStream.File.Campaign.assignee_user | Unknown | The assignee user of the vulnerability. | 
| ThreatStream.File.Campaign.association_info.comment | Unknown | The comment in the association info of the vulnerability. | 
| ThreatStream.File.Campaign.association_info.created | Date | The date the association info was created. | 
| ThreatStream.File.Campaign.association_info.from_id | Number | The ID from which the association info is related. | 
| ThreatStream.File.Campaign.can_add_public_tags | Boolean | Whether you can add public tags to the campaign. | 
| ThreatStream.File.Campaign.created_ts | Date | The date the campaign was created. | 
| ThreatStream.File.Campaign.end_date | Unknown | The end date of the campaign. | 
| ThreatStream.File.Campaign.feed_id | Number | The feed ID of the campaign. | 
| ThreatStream.File.Campaign.id | Number | The ID of the campaign. | 
| ThreatStream.File.Campaign.is_anonymous | Boolean | Whether the campaign is anonymous. | 
| ThreatStream.File.Campaign.is_cloneable | String | Whether the campaign is cloneable. | 
| ThreatStream.File.Campaign.is_public | Boolean | Whether the campaign is public. | 
| ThreatStream.File.Campaign.modified_ts | Date | The date the campaign was modified. | 
| ThreatStream.File.Campaign.name | String | The name of the campaign. | 
| ThreatStream.File.Campaign.objective | Unknown | The objective of the campaign. | 
| ThreatStream.File.Campaign.organization_id | Number | The organization ID of the campaign. | 
| ThreatStream.File.Campaign.owner_user_id | Number | The owner user ID of the campaign. | 
| ThreatStream.File.Campaign.publication_status | String | The publication status of the campaign. | 
| ThreatStream.File.Campaign.published_ts | Unknown | The date the campaign was published. | 
| ThreatStream.File.Campaign.resource_uri | String | The resource URI of the campaign. | 
| ThreatStream.File.Campaign.source_created | Date | The date the campaign was created. | 
| ThreatStream.File.Campaign.source_modified | Date | Whether the source was modified. | 
| ThreatStream.File.Campaign.start_date | Unknown | The start date of the campaign. | 
| ThreatStream.File.Campaign.status.display_name | String | The display name of the status. | 
| ThreatStream.File.Campaign.status.id | Number | The ID of the status of the campaign. | 
| ThreatStream.File.Campaign.status.resource_uri | String | The resource URI of the status of the campaign. | 
| ThreatStream.File.Campaign.tlp | String | The TLP of the campaign. | 
| ThreatStream.File.Campaign.uuid | String | The UUID of the campaign. | 

#### Command example
```!file file=275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f threat_model_association=True```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        "Reliability": "B - Usually reliable",
        "Score": 2,
        "Type": "file",
        "Vendor": "Anomali ThreatStream v3 May"
    },
    "File": {
        "Hashes": [
            {
                "type": "SHA256",
                "value": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
            }
        ],
        "Relationships": [
            {
                "EntityA": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                "EntityAType": "File",
                "EntityB": "Alert report",
                "EntityBType": "Threat Actor",
                "Relationship": "related-to"
            }
        ],
        "SHA256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        "Tags": [
            "apt"
        ],
        "ThreatTypes": [
            {
                "threatcategory": "apt",
                "threatcategoryconfidence": null
            }
        ],
        "TrafficLightProtocol": "red"
    },
    "ThreatStream": {
        "File": {
            "Actor": [
                {
                    "aliases": [],
                    "assignee_user": null,
                    "association_info": [
                        {
                            "comment": null,
                            "created": "2022-07-11T16:26:11.530823",
                            "from_id": 366645476,
                            "sro": {}
                        }
                    ],
                    "can_add_public_tags": true,
                    "circles": [],
                    "created_ts": "2022-04-25T03:06:21.595651",
                    "feed_id": 269,
                    "id": 47096,
                    "intelligence_initiatives": [],
                    "is_anonymous": false,
                    "is_cloneable": "yes",
                    "is_public": true,
                    "is_team": false,
                    "modified_ts": "2022-07-11T16:30:00.437522",
                    "name": "Alert report",
                    "organization_id": 17,
                    "owner_user_id": 327,
                    "primary_motivation": null,
                    "publication_status": "published",
                    "published_ts": "2022-04-25T03:06:21.481665",
                    "resource_level": null,
                    "resource_uri": "/api/v1/actor/47096/",
                    "source_created": null,
                    "source_modified": null,
                    "start_date": null,
                    "tags": [
                        "packetstorm",
                        "microsoft"
                    ],
                    "tags_v2": [
                        {
                            "id": "gvp",
                            "name": "microsoft"
                        },
                        {
                            "id": "wli",
                            "name": "packetstorm"
                        }
                    ],
                    "tlp": "red",
                    "uuid": "0db81103-6728-4051-9fe0-4022ae24cc24",
                    "workgroups": []
                }
            ],
            "Campaign": [],
            "Confidence": 50,
            "IType": "apt_md5",
            "Modified": "2022-07-11T16:30:00.359Z",
            "SHA256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            "Severity": "very-high",
            "Signature": [
                {
                    "assignee_user": null,
                    "association_info": [
                        {
                            "comment": null,
                            "created": "2022-07-11T16:27:15.271832",
                            "from_id": 366645476,
                            "sro": {}
                        }
                    ],
                    "can_add_public_tags": true,
                    "circles": [],
                    "created_ts": "2020-07-31T20:56:33.459260",
                    "feed_id": 155,
                    "id": 333,
                    "intelligence_initiatives": [],
                    "is_anonymous": false,
                    "is_cloneable": "yes",
                    "is_public": true,
                    "modified_ts": "2022-08-02T06:20:19.772588",
                    "name": "signature_threat_model_2",
                    "organization_id": 39,
                    "owner_user_id": 64,
                    "publication_status": "published",
                    "published_ts": "2020-07-31T20:56:33.295192",
                    "resource_uri": "/api/v1/signature/333/",
                    "s_type": "Carbon Black Query",
                    "source_created": null,
                    "source_modified": null,
                    "tags": [
                        "actor_tag1"
                    ],
                    "tags_v2": [
                        {
                            "id": "igh",
                            "name": "actor_tag1"
                        }
                    ],
                    "tlp": "white",
                    "uuid": "4c0d74d9-6bd5-45c0-a288-5bc1d714eee8",
                    "workgroups": []
                }
            ],
            "Source": "user@email.com",
            "Status": "active",
            "TTP": [
                {
                    "assignee_user": null,
                    "association_info": [
                        {
                            "comment": null,
                            "created": "2022-07-11T16:27:43.327492",
                            "from_id": 366645476,
                            "sro": {}
                        }
                    ],
                    "can_add_public_tags": true,
                    "children": [],
                    "circles": [],
                    "created_ts": "2019-02-19T20:48:37.938265",
                    "feed_id": 3,
                    "id": 1500,
                    "intelligence_initiatives": [],
                    "is_anonymous": false,
                    "is_category": false,
                    "is_cloneable": "yes",
                    "is_mitre": false,
                    "is_public": true,
                    "modified_ts": "2022-08-02T06:17:07.420212",
                    "name": "FleaHopper TTP",
                    "organization_id": 4,
                    "owner_user_id": 7,
                    "publication_status": "published",
                    "published_ts": "2019-02-19T20:48:37.665110",
                    "resource_uri": "/api/v1/ttp/1500/",
                    "source_created": null,
                    "source_modified": null,
                    "tags": [],
                    "tags_v2": [],
                    "tlp": "red",
                    "uuid": null,
                    "workgroups": []
                }
            ],
            "Tags": [
                "apt"
            ],
            "ThreatBulletin": [],
            "Type": "SHA256",
            "Vulnerability": [
                {
                    "assignee_user": null,
                    "association_info": [
                        {
                            "comment": null,
                            "created": "2022-07-11T16:16:43.125297",
                            "from_id": 366645476,
                            "sro": {}
                        }
                    ],
                    "can_add_public_tags": true,
                    "circles": [
                        {
                            "id": "310",
                            "name": "NVD CVEs",
                            "resource_uri": "/api/v1/trustedcircle/310/"
                        }
                    ],
                    "created_ts": "2022-06-28T00:14:01.266128",
                    "feed_id": 0,
                    "id": 177244,
                    "intelligence_initiatives": [],
                    "is_anonymous": false,
                    "is_cloneable": "yes_private_only",
                    "is_public": false,
                    "is_system": true,
                    "modified_ts": "2022-07-11T13:54:00",
                    "name": "CVE-2022-31098",
                    "organization_id": 1,
                    "owner_user_id": null,
                    "publication_status": "published",
                    "published_ts": "2022-06-27T22:15:00",
                    "resource_uri": "/api/v1/vulnerability/177244/",
                    "source": "mitre",
                    "source_created": null,
                    "source_modified": null,
                    "tags": [
                        "CWE-532"
                    ],
                    "tags_v2": [
                        {
                            "id": "30h",
                            "name": "CWE-532"
                        }
                    ],
                    "tlp": "white",
                    "update_id": 8849957,
                    "uuid": "9f209a42-4cd2-4405-8176-3a925c86ac03",
                    "workgroups": []
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### File reputation for: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
>|Confidence|IType|Modified|SHA256|Severity|Source|Status|Tags|Type|
>|---|---|---|---|---|---|---|---|---|
>| 50 | apt_md5 | 2022-07-11T16:30:00.359Z | 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f | very-high | user@email.com | active | apt | SHA256 |
>### Actor details:
>|name|id|
>|---|---|
>| Alert report | 47096 |
>### Signature details:
>|name|id|
>|---|---|
>| signature_threat_model_2 | 333 |
>### ThreatBulletin details:
>**No entries.**
>### TTP details:
>|name|id|
>|---|---|
>| FleaHopper TTP | 1500 |
>### Vulnerability details:
>|name|id|
>|---|---|
>| CVE-2022-31098 | 177244 |
>### Campaign details:
>**No entries.**


### threatstream-email-reputation
***
Checks the reputation of the given email address.


#### Base Command

`threatstream-email-reputation`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | The email address to check. | Required | 
| threshold | If the confidence is greater than the threshold the email address is considered malicious, otherwise it is considered good. This argument overrides the default email threshold defined as a parameter. | Optional | 
| include_inactive | Whether to include results with an inactive status. Possible values are: True, False. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The tested indicator. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| ThreatStream.EmailReputation.Severity | String | The indicator severity \("very-high", "high", "medium", "low"\). | 
| ThreatStream.EmailReputation.Confidence | String | The observable certainty level of a reported indicator type. Confidence score ranges from 0-100, in increasing order of confidence. | 
| ThreatStream.EmailReputation.Status | String | The status assigned to the indicator. | 
| ThreatStream.EmailReputation.Type | String | The indicator type. | 
| ThreatStream.EmailReputation.Email | String | The indicator email address. | 
| ThreatStream.EmailReputation.Source | String | The indicator source. | 
| ThreatStream.EmailReputation.Modified | String | The date and time the indicator was last updated. The date format is: YYYYMMDDThhmmss, where "T" denotes the start of the value
for time in UTC time. | 
| ThreatStream.EmailReputation.Tags | Unknown | Tags assigned to the email. | 


#### Command Example
```!threatstream-email-reputation email=egov@ac.in```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "egov@ac.in",
        "Reliability": "B - Usually reliable",
        "Score": 3,
        "Type": "email",
        "Vendor": "Anomali ThreatStream v3"
    },
    "Email": {
        "Address": "egov@ac.in"
    },
    "ThreatStream": {
        "EmailReputation": {
            "Confidence": 10000,
            "Email": "egov@ac.in",
            "Modified": "2021-08-01T10:35:53.484Z",
            "Severity": "high",
            "Source": "Analyst",
            "Status": "active",
            "Tags": [
                "apt"
            ],
            "Type": "email"
        }
    }
}
```

#### Human Readable Output

>### Email reputation for: egov@ac.in
>|Confidence|Email|Modified|Severity|Source|Status|Tags|Type|
>|---|---|---|---|---|---|---|---|
>| 10000 | egov@ac.in | 2021-08-01T10:35:53.484Z | high | Analyst | active | apt | email |


### threatstream-get-passive-dns

***
Returns enrichment data for Domain or IP for available observables.

#### Base Command

`threatstream-get-passive-dns`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The type of passive DNS search ("ip", "domain"). Possible values are: ip, domain. Default is ip. | Required | 
| value | The values that can be sent to the API should correspond to the type that is chosen. For example, if IP is chosen in the type argument, then a valid IP address should be sent in the value argument. | Required | 
| limit | The maximum number of results to return. Default is 50. | Optional | 
| all_results | Whether to retrieve all results. The "limit" argument will be ignored. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.PassiveDNS.Domain | String | The domain value. | 
| ThreatStream.PassiveDNS.Ip | String | The IP value. | 
| ThreatStream.PassiveDNS.Rrtype | String | The RRTYPE value. | 
| ThreatStream.PassiveDNS.Source | String | The source value. | 
| ThreatStream.PassiveDNS.FirstSeen | String | The first seen date. The date format is: YYYYMMDDThhmmss, where "T" denotes the start of the value
for time, in UTC time. | 
| ThreatStream.PassiveDNS.LastSeen | String | The last seen date. The date format is: YYYYMMDDThhmmss, where "T" denotes the start of the value
for time in UTC time. | 

#### Command example
```!threatstream-get-passive-dns type="domain" value="y.gp" limit="1"```
#### Context Example
```json
{
    "ThreatStream": {
        "PassiveDNS": [
            {
                "Domain": "y.gp",
                "FirstSeen": "2015-07-20 02:33:47",
                "Ip": "78.78.78.67",
                "LastSeen": "2015-12-19 06:44:35",
                "Rrtype": "A",
                "Source": "Anomali Labs"
            }
        ]
    }
}
```

#### Human Readable Output

>### Passive DNS enrichment data for: y.gp
>|Domain|FirstSeen|Ip|LastSeen|Rrtype|Source|
>|---|---|---|---|---|---|
>| y.gp | 2015-07-20 02:33:47 | 78.78.78.67 | 2015-12-19 06:44:35 | A | Anomali Labs |


### threatstream-import-indicator-with-approval

***
Imports indicators (observables) into ThreatStream. The imported data must be approved using the ThreatStream UI. The data can be imported using one of three methods: plain-text, file, or URL. You must have the Approve Import privilege in order to import observables through the API with default_state set to active.

#### Base Command

`threatstream-import-indicator-with-approval`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| confidence | The observable certainty level of a reported indicator type. Default is 50. | Optional | 
| source_confidence_weight | Ratio (0-100) between the source confidence and the ThreatStream confidence. To use your specified confidence entirely and not re-assess the value using machine learning algorithms, set this argument to 100. | Optional | 
| classification | Whether the indicator data is public or private to the organization. Possible values are: private, public. Default is private. | Optional | 
| threat_type | Type of threat associated with the imported observables. Possible values are: adware, anomalous, anonymization, apt, bot, brute, c2, compromised, crypto, data_leakage, ddos, dyn_dns, exfil, exploit, hack_tool, i2p, informational, malware, p2p, parked, phish, scan, sinkhole, spam, suppress, suspicious, tor, vps. Default is exploit. | Optional | 
| severity | The potential impact of the indicator type with which the observable is believed to be associated. Possible values are: low, medium, high, very-high. Default is low. | Optional | 
| import_type | The import type of the indicator. Possible values are: datatext, file-id, url. | Required | 
| import_value | The imported data source. Can be one of the following: url or file-id datatext of the file uploaded to the War Room. Supported file types for file-id are: CSV, HTML, IOC, JSON, PDF, TXT. | Required | 
| ip_mapping | Indicator type to assign if a specific type is not associated with an observable. This is a global setting that applies to any imported IP-type observable when an explicit itype is not specified for it. | Optional | 
| domain_mapping | Indicator type to assign if a specific type is not associated with an observable. This is a global setting that applies to any imported domain-type observable when an explicit itype is not specified for it. | Optional | 
| url_mapping | Indicator type to assign if a specific type is not associated with an observable. This is a global setting that applies to any imported URL-type observable when an explicit itype is not specified for it. | Optional | 
| email_mapping | Indicator type to assign if a specific type is not associated with an observable. This is a global setting that applies to any imported email-type observable when an explicit itype is not specified for it. | Optional | 
| md5_mapping | Indicator type to assign if a specific type is not associated with an observable. This is a global setting that applies to any imported MD5-type observable when an explicit itype is not specified for it. | Optional | 
| tags | A comma-separated list of tags applied to the imported observables. For example, tag1,tag2. | Optional | 
| tags_tlp | You can add tags that are private to your organization by setting the tlp attribute for the tag to red. If you do not specify a tlp setting, the tag is visible to any ThreatStream user with access to the observable. Possible values are: Red, Amber, Green, White. | Optional | 
| expiration_ts | The timestamp when intelligence will expire on ThreatStream, in ISO format. For example, 2020-12-24T00:00:00. By default, the expiration_ts is set to 90 days from the current date. | Optional | 
| default_state | Whether the import job must be approved from the ThreatStream user interface before observables become active. When default_state is set to active, observables become active upon submission, without requiring approval. In these cases, an import job is created on ThreatStream which is automatically approved. Possible values are: active, inactive. Default is inactive. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.Import.JobID | Number | The identifier for the job on ThreatStream. | 
| ThreatStream.Import.ImportID | Number | The ID for the import job. | 

#### Command Example
```!threatstream-import-indicator-with-approval import_type=datatext import_value=78.78.78.67```

#### Context Example
```json
{
    "ThreatStream": {
        "Import": {
            "ImportID": "111111",
            "JobID": "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
        }
    }
}
```

#### Human Readable Output

>The data was imported successfully.
>The ID of imported job is: 111111.
> The identifier for the job on ThreatStream is: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX.

### threatstream-import-indicator-without-approval
***
Imports indicators (observables) into ThreatStream. Approval is not required for the imported data. You must have the Approve Intel user permission to import without approval using the API.

 Note: This command indicates that the JSON you submitted was valid. However, in cases where data is incorrect or required fields are left unspecified, observables can be ignored or imported as false positive.
Valid itypes values for the JSON can be found in the Anomaly ThreatStream API documentation under the Indicator Types in Threat Stream API section.

#### Base Command

`threatstream-import-indicator-without-approval`
#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                                                                        | **Required** |
| --- |------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| confidence | The observable certainty level of a reported indicator type. Default is 50.                                                                                                                                                                                            | Optional | 
| source_confidence_weight | Ratio (0-100) between the source confidence and the ThreatStream confidence. To use your specified confidence entirely and not re-assess the value using machine learning algorithms, set this argument to 100.                                                        | Optional | 
| expiration_ts | The timestamp when intelligence will expire on ThreatStream, in ISO format. For example, 2020-12-24T00:00:00. By default, the expiration_ts is set to 90 days from the current date.                                                                                   | Optional | 
| severity | The severity to assign to the observable when it is imported. Possible values are: low, medium, high, very-high.                                                                                                                                                       | Optional | 
| tags | A comma-separated list of tags applied to the imported observables. For example, tag1,tag2. Note: In cases where tags are specified at both the global and per observable level, tags specified per observable overwrite global tags.                                  | Optional | 
| trustedcircles | A comma-separated list of trusted circle IDs with which threat data should be shared.                                                                                                                                                                                  | Optional | 
| classification | Denotes whether the indicator data is public or private to the organization. Possible values are: private, public.                                                                                                                                                     | Required | 
| allow_unresolved | Whether unresolved domain observables included in the file will be accepted as valid in ThreatStream and imported. Possible values are: yes, no.                                                                                                                       | Optional | 
| file_id | The entry ID of a file (containing a JSON with an "objects" array and "meta" maps) that is uploaded to the War Room. It is recommended to use the "ThreatstreamBuildIocImportJson" script to build a valid JSON file if possible.                                      | Optional | 
| indicators_json | The “meta” section will be added to this json, and we will send this json to the api endpoint. It is recommended to use the "ThreatstreamBuildIocImportJson" script to build a valid JSON file if possible.                                                            | Optional | 
| tags_tlp | You can add tags that are private to your organization by setting the tlp attribute for the tag to red. If you do not specify a tlp setting, the tag is visible to any ThreatStream user with access to the observable. Possible values are: Red, Amber, Green, White. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!threatstream-import-indicator-without-approval classification=private file_id=2761@3c9bd2a0-9eac-465b-8799-459df4997b2d```

#### Human Readable Output

>The data was imported successfully.

### threatstream-get-model-list
***
Returns a list of threat models.


#### Base Command

`threatstream-get-model-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| model | The threat model of the returned list. Possible values are: actor, campaign, incident, signature, ttp, vulnerability, tipreport, malware, attack pattern. | Required | 
| limit | Limits the model size list. Specifying limit=0 returns up to a maximum of 1000 models. For limit=0, the output is not set in the context. | Optional | 
| page | Page number to get result from. Needs to be used with the page_size argument. | Optional | 
| page_size | The page size of the returned results. Needs to be used with the page argument. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.List.Type | String | The threat model type. | 
| ThreatStream.List.Name | String | The threat model name. | 
| ThreatStream.List.ID | String | The threat model ID. | 
| ThreatStream.List.CreatedTime | String | The date and time of threat model creation. The date format is: YYYYMMDDThhmmss, where "T" denotes the start of the value for time in UTC time. | 


#### Command Example
```!threatstream-get-model-list model=actor limit=10```

#### Context Example
```json
{
    "ThreatStream": {
        "List": [
            {
                "CreatedTime": "2019-02-19T16:42:00.933984",
                "ID": 1,
                "Name": "Fleahopper Actor",
                "Type": "Actor"
            },
            {
                "CreatedTime": "2019-08-24T02:47:29.204380",
                "ID": 10158,
                "Name": "report actor 1",
                "Type": "Actor"
            },
            {
                "CreatedTime": "2019-08-28T16:35:39.316135",
                "ID": 10159,
                "Name": "report actor 1",
                "Type": "Actor"
            },
            {
                "CreatedTime": "2020-10-14T12:28:54.937276",
                "ID": 10909,
                "Name": "MANDRA",
                "Type": "Actor"
            },
            {
                "CreatedTime": "2021-09-14T13:37:02.111599",
                "ID": 26769,
                "Name": "New_Created_Actor",
                "Type": "Actor"
            }
        ]
    }
}
```

#### Human Readable Output

>### List of Actors
>|CreatedTime|ID|Name|Type|
>|---|---|---|---|
>| 2019-02-19T16:42:00.933984 | 1 | Fleahopper Actor | Actor |
>| 2019-08-24T02:47:29.204380 | 10158 | report actor 1 | Actor |
>| 2019-08-28T16:35:39.316135 | 10159 | report actor 1 | Actor |
>| 2020-10-14T12:28:54.937276 | 10909 | MANDRA | Actor |
>| 2021-09-14T13:37:02.111599 | 26769 | New_Created_Actor | Actor |


### threatstream-get-model-description
***
Returns an HTML file with a description of the threat model.


#### Base Command

`threatstream-get-model-description`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| model | The threat model. Can be "actor", "campaign", "incident", "signature", "ttp", "vulnerability", or "tipreport". Possible values are: actor, campaign, incident, signature, ttp, vulnerability, tipreport. | Required | 
| id | The threat model ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Name | String | The file name of the model description. | 
| File.EntryID | String | The entry ID of the model description. | 


#### Command Example
```!threatstream-get-model-description model=actor id=1```

#### Context Example
```json
{
    "File": {
        "EntryID": "3171@3c9bd2a0-9eac-465b-8799-459df4997b2d",
        "Extension": "html",
        "Info": "text/html; charset=utf-8",
        "MD5": "18d7610f85c1216e78c59cbde5c470d9",
        "Name": "actor_1.html",
        "SHA1": "c778f72fd7799108db427f632ca6b2bb07c9bde4",
        "SHA256": "6d06bdc613490216373e2b189c8d41143974c7a128da26e8fc4ba4f45a7e718b",
        "SHA512": "989b0ae32b61b3b5a7ea1c3e629b50f07e7086310f8e4057ec046b368e55fc82cae873bd81eada657d827c96c71253b6ba3688561844ce983cdc5019d9666aa4",
        "SSDeep": "48:32u8P32apgpIph9/gldn2++TnlCC4i72gSmB2rXpzNZx:32tuapgpCglM++TCE2gSN/",
        "Size": 1868,
        "Type": "ASCII text, with very long lines, with no line terminators"
    }
}
```

#### Human Readable Output



### threatstream-get-indicators-by-model
***
Returns a list of indicators associated with the specified model and ID of the model.


#### Base Command

`threatstream-get-indicators-by-model`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| model | The threat model of the returned list. Possible values are: actor, campaign, incident, signature, ttp, vulnerability, tipreport, malware, attack pattern. | Required | 
| limit | Limits the model size list. Specifying limit=0 returns up to a maximum of 1000 models. For limit=0, the output is not set in the context. | Optional | 
| page | Page number to get result from. Needs to be used with the page_size argument. | Optional | 
| page_size | The page size of the returned results. Needs to be used with the page argument. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.Model.ModelType | String | The threat model type. | 
| ThreatStream.Model.ModelID | String | The threat model ID. | 
| ThreatStream.Model.Indicators.Value | String | The value of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.ID | String | The ID of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.IType | String | The iType of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Severity | String | The indicator severity associated with the specified model. | 
| ThreatStream.Model.Indicators.Confidence | String | The confidence of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Country | String | The country of the indicator associated with the specified model | 
| ThreatStream.Model.Indicators.Organization | String | The organization of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.ASN | String | The ASN of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Status | String | The status of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Tags | String | The tags of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Modified | String | The date and time the indicator was last modified. | 
| ThreatStream.Model.Indicators.Source | String | The indicator source. | 
| ThreatStream.Model.Indicators.Type | String | The indicator type. | 


#### Command Example
```!threatstream-get-indicators-by-model id=731 model=incident```

#### Context Example
```json
{
    "ThreatStream": {
        "Model": {
            "Indicators": [
                {
                    "ASN": "",
                    "Confidence": 50,
                    "Country": null,
                    "ID": 181481953,
                    "IType": "mal_email",
                    "Modified": "2021-03-25T13:27:58.922Z",
                    "Organization": "",
                    "Severity": "low",
                    "Source": "Analyst",
                    "Status": "inactive",
                    "Tags": "tag-approved",
                    "Type": "email",
                    "Value": "testemail123@test.com"
                }
            ],
            "ModelID": "731",
            "ModelType": "Incident"
        }
    }
}
```

#### Human Readable Output

>### Indicators list for Threat Model Incident with id 731
>|ASN|Confidence|Country|ID|IType|Modified|Organization|Severity|Source|Status|Tags|Type|Value|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|  | 50 |  | 181481953 | mal_email | 2021-03-25T13:27:58.922Z |  | low | Analyst | inactive | tag-approved | email | testemail123@test.com |


### threatstream-submit-to-sandbox
***
Submits a file or URL to the ThreatStream-hosted sandbox for detonation.


#### Base Command

`threatstream-submit-to-sandbox`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| submission_classification | Classification of the Sandbox submission. Can be "private" or "public". Possible values are: private, public. Default is private. | Optional | 
| report_platform | The platform on which the submitted URL or file is run. To obtain a list supported platforms run the threatstream-supported-platforms command. Can be "WINDOWS7", or "WINDOWSXP". Possible values are: WINDOWS7, WINDOWSXP. Default is WINDOWS7. | Optional | 
| submission_type | The detonation type. Can be "file" or "url". Possible values are: file, url. Default is file. | Required | 
| submission_value | The submission value. Possible values are a valid URL or a file ID that was uploaded to the War Room to detonate. | Required | 
| premium_sandbox | Whether the premium sandbox should be used for detonation. Possible values are: false, true. Default is false. | Optional | 
| detail | A comma-separated list of additional details for the indicator. This information is displayed in the Tag column of the ThreatStream UI. | Optional | 
| import_indicators | If you want to initiate an import job for observables discovered during detonation, set this value to true. Default value is true. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.Analysis.ReportID | String | The report ID submitted to the sandbox. | 
| ThreatStream.Analysis.Status | String | The analysis status. | 
| ThreatStream.Analysis.Platform | String | The platform of the submission submitted to the sandbox. | 


#### Command Example
```!threatstream-submit-to-sandbox submission_classification="private" report_platform="WINDOWS7" submission_type="file" submission_value="1711@3c9bd2a0-9eac-465b-8799-459df4997b2d" premium_sandbox="false"```

#### Context Example
```json
{
    "ThreatStream": {
        "Analysis": {
            "Platform": "WINDOWS7",
            "ReportID": 12418,
            "Status": "processing"
        }
    }
}
```

#### Human Readable Output

>### The submission info for 1711@3c9bd2a0-9eac-465b-8799-459df4997b2d
>|Platform|ReportID|Status|
>|---|---|---|
>| WINDOWS7 | 12418 | processing |


### threatstream-get-analysis-status
***
Returns the current status of the report submitted to the sandbox. The report ID is returned from the threatstream-submit-to-sandbox command.


#### Base Command

`threatstream-get-analysis-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | The report ID to check the status. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.Analysis.ReportID | String | The report ID of the file or URL that was detonated in the sandbox. | 
| ThreatStream.Analysis.Status | String | The report status of the file or URL that was detonated in the sandbox. | 
| ThreatStream.Analysis.Platform | String | The platform used for detonation. | 
| ThreatStream.Analysis.Verdict | String | The report verdict of the file or URL detonated in the sandbox. The verdict remains "benign" until detonation is complete. | 


#### Command Example
```!threatstream-get-analysis-status report_id=12414```

#### Context Example
```json
{
    "ThreatStream": {
        "Analysis": {
            "Platform": "WINDOWS7",
            "ReportID": "12414",
            "Status": "errors",
            "Verdict": "Benign"
        }
    }
}
```

#### Human Readable Output

>### The analysis status for id 12414
>|Platform|ReportID|Status|Verdict|
>|---|---|---|---|
>| WINDOWS7 | 12414 | errors | Benign |


### threatstream-analysis-report
***
Returns the report of a file or URL submitted to the sandbox.


#### Base Command

`threatstream-analysis-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | The report ID to return. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.Analysis.ReportID | String | The ID of the report submitted to the sandbox. | 
| ThreatStream.Analysis.Category | String | The report category. | 
| ThreatStream.Analysis.Started | String | The detonation start time. | 
| ThreatStream.Analysis.Completed | String | The detonation completion time. | 
| ThreatStream.Analysis.Duration | Number | The duration of the detonation \(in seconds\). | 
| ThreatStream.Analysis.VmName | String | The VM name. | 
| ThreatStream.Analysis.VmID | String | The VM ID. | 
| ThreatStream.Analysis.Network.UdpSource | String | The UDP source. | 
| ThreatStream.Analysis.Network.UdpDestination | String | The UDP destination. | 
| ThreatStream.Analysis.Network.UdpPort | String | The UDP port. | 
| ThreatStream.Analysis.Network.IcmpSource | String | The ICMP source. | 
| ThreatStream.Analysis.Network.IcmpDestination | String | The ICMP destination. | 
| ThreatStream.Analysis.Network.IcmpPort | String | The ICMP port. | 
| ThreatStream.Analysis.Network.TcpSource | String | The TCP source. | 
| ThreatStream.Analysis.Network.TcpDestination | String | The TCP destination. | 
| ThreatStream.Analysis.Network.TcpPort | String | The TCP port. | 
| ThreatStream.Analysis.Network.HttpSource | String | The source of the HTTP address. | 
| ThreatStream.Analysis.Network.HttpDestinaton | String | The destination of the HTTP address. | 
| ThreatStream.Analysis.Network.HttpPort | String | The port of the HTTP address. | 
| ThreatStream.Analysis.Network.HttpsSource | String | The source of the HTTPS address. | 
| ThreatStream.Analysis.Network.HttpsDestinaton | String | The destination of the HTTPS address. | 
| ThreatStream.Analysis.Network.HttpsPort | String | The port of the HTTPS address. | 
| ThreatStream.Analysis.Network.Hosts | String | The network analysis hosts. | 
| ThreatStream.Analysis.Verdict | String | The verdict of the sandbox detonation. | 


#### Command Example
```!threatstream-analysis-report report_id="12212"```

#### Context Example
```json
{
    "ThreatStream": {
        "Analysis": {
            "Category": "Url",
            "Completed": "2021-08-19 06:51:52",
            "Duration": 152,
            "Network": [
                {
                    "UdpDestinaton": "1.2.4.5",
                    "UdpPort": 53,
                    "UdpSource": "192.168.2.4"
                },
                {
                    "Hosts": "78.78.78.67"
                }
            ],
            "ReportID": "12212",
            "Started": "2021-08-19 06:49:20",
            "Verdict": "Benign",
            "VmID": "",
            "VmName": ""
        }
    }
}
```

#### Human Readable Output

>### Report 12212 analysis results
>|Category|Completed|Duration|ReportID|Started|Verdict|VmID|VmName|
>|---|---|---|---|---|---|---|---|
>| Url | 2021-08-19 06:51:52 | 152 | 12212 | 2021-08-19 06:49:20 | Benign |  |  |


### threatstream-get-indicators
***
Return filtered indicators from ThreatStream. If a query is defined, it overrides all other arguments that were passed to the command.


#### Base Command

`threatstream-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The Anomali Observable Search Filter Language query to filter indicator results. If a query is passed as an argument, it overrides all other arguments. | Optional | 
| asn | The Autonomous System (AS) number associated with the indicator. | Optional | 
| confidence | The observable certainty level<br/>of a reported indicator type. Confidence scores range from 0-100 in increasing order of confidence, and are assigned by ThreatStream based on several factors. | Optional | 
| country | The country associated with the indicator. | Optional | 
| created_ts | The date the indicator was first seen on<br/>the ThreatStream cloud platform. The date must be specified in this format:<br/>YYYYMMDDThhmmss, where "T" denotes the start of the value for time, in UTC time.<br/>For example, 2014-10-02T20:44:35. | Optional | 
| id | The unique ID for the indicator. | Optional | 
| is_public | Whether the classification of the indicator is public. Default is "false". Possible values are: false, true. | Optional | 
| indicator_severity | The severity assigned to the indicator by ThreatStream. | Optional | 
| org | The registered owner (organization) of the IP address associated with the indicator. | Optional | 
| status | The status assigned to the indicator. Possible values are: active, inactive, falsepos. | Optional | 
| tags_name | The tag assigned to the indicator. | Optional | 
| type | The type of indicator. Possible values are: domain, email, ip, md5, string, url. | Optional | 
| indicator_value | The value of the indicator. . | Optional | 
| limit | The maximum number of results to return from ThreatStream. Default value is 20. | Optional | 
| page | Page number to get result from. Needs to be used with the page_size argument. | Optional | 
| page_size | The page size of the returned results. Needs to be used with the page argument. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.Indicators.IType | String | The indicator type. | 
| ThreatStream.Indicators.Modified | String | The date and time the indicator was last updated in ThreatStream. The date format is: YYYYMMDDThhmmss, where T denotes the start of the value
for time in UTC time. | 
| ThreatStream.Indicators.Confidence | String | The observable certainty level of a reported indicator type. | 
| ThreatStream.Indicators.Value | String | The indicator value. | 
| ThreatStream.Indicators.Status | String | The indicator status. | 
| ThreatStream.Indicators.Organization | String | The registered owner \(organization\) of the IP address associated with the indicator. | 
| ThreatStream.Indicators.Country | String | The country associated with the indicator. | 
| ThreatStream.Indicators.Tags | String | The tag assigned to the indicator. | 
| ThreatStream.Indicators.Source | String | The indicator source. | 
| ThreatStream.Indicators.ID | String | The indicator ID. | 
| ThreatStream.Indicators.ASN | String | The Autonomous System \(AS\) number associated with the indicator. | 
| ThreatStream.Indicators.Severity | String | The severity assigned to the indicator. | 


#### Command Example
```!threatstream-get-indicators type=ip status=active limit=5```

#### Context Example
```json
{
    "ThreatStream": {
        "Indicators": [
            {
                "ASN": "",
                "Confidence": 100,
                "Country": null,
                "ID": 239450621,
                "IType": "apt_ip",
                "Modified": "2021-05-24T16:42:09.245Z",
                "Organization": "",
                "Severity": "very-high",
                "Source": "Analyst",
                "Status": "active",
                "Tags": null,
                "Type": "ip",
                "Value": "78.78.78.67"
            },
            {
                "ASN": "",
                "Confidence": -1,
                "Country": null,
                "ID": 235549247,
                "IType": "apt_ip",
                "Modified": "2021-04-29T16:02:17.558Z",
                "Organization": "",
                "Severity": "very-high",
                "Source": "Analyst",
                "Status": "active",
                "Tags": null,
                "Type": "ip",
                "Value": "78.78.78.67"
            }
        ]
    }
}
```

#### Human Readable Output

>### The indicators results
>|ASN|Confidence|Country|ID|IType|Modified|Organization|Severity|Source|Status|Tags|Type|Value|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|  | 100 |  | 239450621 | apt_ip | 2021-05-24T16:42:09.245Z |  | very-high | Analyst | active |  | ip | 78.78.78.67 |
>|  | -1 |  | 235549247 | apt_ip | 2021-04-29T16:02:17.558Z |  | very-high | Analyst | active |  | ip | 78.78.78.67 |


### threatstream-add-tag-to-model
***
Adds tags to intelligence to filter for related entities.


#### Base Command

`threatstream-add-tag-to-model`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| model | The type of threat model entity to which to add the tag. Can be "actor", "campaign", "incident", "intelligence", "signature", "tipreport", "ttp", or "vulnerability". Possible values are: actor, campaign, incident, intelligence, signature, tipreport, ttp, vulnerability. Default is intelligence. | Optional | 
| tags | A comma separated list of tags applied to the specified threat model entities or observable. . | Required | 
| model_id | The ID of the model to which to add the tag. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!threatstream-add-tag-to-model model=incident model_id=130 tags="suspicious,not valid"```

#### Human Readable Output

>Added successfully tags: ['suspicious', 'not valid'] to incident with 130

### threatstream-create-model
***
Creates a threat model with the specified parameters.


#### Base Command

`threatstream-create-model`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| model | The type of threat model to create. Can be "actor", "campaign", "incident", "ttp", "vulnerability", or "tipreport". Possible values are: actor, campaign, incident, ttp, vulnerability, tipreport. | Required | 
| name | The name of the threat model to create. | Required | 
| is_public | Whether the scope of threat model is visible. Possible values are: true, false. Default is false. | Optional | 
| tlp | The Traffic Light Protocol designation for the threat model. Can be "red", "amber", "green", or "white". Possible values are: red, amber, green, white. Default is red. | Optional | 
| tags | A comma separated list of tags. | Optional | 
| intelligence | A comma separated list of indicators IDs associated with the threat model on the ThreatStream platform. | Optional | 
| description | The description of the threat model. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.Model.ModelType | String | The threat model type. | 
| ThreatStream.Model.ModelID | String | The threat model ID. | 
| ThreatStream.Model.Indicators.Value | String | The value of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.ID | String | The ID of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.IType | String | The iType of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Severity | String | The severity of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Confidence | String | The confidence of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Country | String | The country of the indicator associated with the specified model | 
| ThreatStream.Model.Indicators.Organization | String | The organization of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.ASN | String | The ASN of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Status | String | The status of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Tags | String | The tags of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Modified | String | The date and time the indicator was last modified. | 
| ThreatStream.Model.Indicators.Source | String | The indicator source. | 
| ThreatStream.Model.Indicators.Type | String | The indicator type. | 


#### Command Example
```!threatstream-create-model model=actor name="New_Created_Actor_1" description="Description of the actor threat model" intelligence=191431508 tags="new actor,test" tlp=red```

#### Context Example
```json
{
    "ThreatStream": {
        "Model": {
            "Indicators": [
                {
                    "ASN": "",
                    "Confidence": 50,
                    "Country": null,
                    "ID": 191431508,
                    "IType": "apt_md5",
                    "Modified": "2021-09-13T12:40:42.596Z",
                    "Organization": "",
                    "Severity": "medium",
                    "Source": "TestSource",
                    "Status": "active",
                    "Tags": null,
                    "Type": "SHA256",
                    "Value": "178ba564b39bd07577e974a9b677dfd86ffa1f1d0299dfd958eb883c5ef6c3e1"
                }
            ],
            "ModelID": 26770,
            "ModelType": "Actor"
        }
    }
}
```

#### Human Readable Output

>### Indicators list for Threat Model Actor with id 26770
>|ASN|Confidence|Country|ID|IType|Modified|Organization|Severity|Source|Status|Tags|Type|Value|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|  | 50 |  | 191431508 | apt_md5 | 2021-09-13T12:40:42.596Z |  | medium | TestSource | active |  | SHA256 | 178ba564b39bd07577e974a9b677dfd86ffa1f1d0299dfd958eb883c5ef6c3e1 |


### threatstream-update-model
***
Updates a threat model with specific parameters. If one or more optional parameters are defined, the command overrides previous data stored in ThreatStream.


#### Base Command

`threatstream-update-model`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| model | The type of threat model to update. Can be "actor", "campaign", "incident", "ttp", "vulnerability", or "tipreport". Possible values are: actor, campaign, incident, ttp, vulnerability, tipreport. | Required | 
| model_id | The ID of the threat model to update. | Required | 
| name | The name of the threat model to update. | Optional | 
| is_public | Whether the scope of threat model is visible. Possible values are: true, false. Default is false. | Optional | 
| tlp | The Traffic Light Protocol designation for the threat model. Can be "red", "amber", "green", or "white". Possible values are: red, amber, green, white. Default is red. | Optional | 
| tags | A comma separated list of tags. | Optional | 
| intelligence | A comma separated list of indicator IDs associated with the threat model on the ThreatStream platform. | Optional | 
| description | The description of the threat model. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.Model.ModelType | String | The threat model type. | 
| ThreatStream.Model.ModelID | String | The threat model ID. | 
| ThreatStream.Model.Indicators.Value | String | The value of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.ID | String | The ID of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.IType | String | The iType of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Severity | String | The severity of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Confidence | String | The confidence of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Country | String | The country of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Organization | String | The organization of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.ASN | String | The ASN of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Status | String | The status of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Tags | String | The tags of the indicator associated with the specified model. | 
| ThreatStream.Model.Indicators.Modified | String | The date and time the indicator was last modified. | 
| ThreatStream.Model.Indicators.Source | String | The indicator source. | 
| ThreatStream.Model.Indicators.Type | String | The indicator type. | 


#### Command Example
```!threatstream-update-model model=actor model_id=26769 intelligence=191431508 tags="updated tag,gone"```

#### Context Example
```json
{
    "ThreatStream": {
        "Model": {
            "Indicators": [
                {
                    "ASN": "",
                    "Confidence": 50,
                    "Country": null,
                    "ID": 191431508,
                    "IType": "apt_md5",
                    "Modified": "2021-09-13T12:40:42.596Z",
                    "Organization": "",
                    "Severity": "medium",
                    "Source": "TestSource",
                    "Status": "active",
                    "Tags": null,
                    "Type": "SHA256",
                    "Value": "178ba564b39bd07577e974a9b677dfd86ffa1f1d0299dfd958eb883c5ef6c3e1"
                }
            ],
            "ModelID": "26769",
            "ModelType": "Actor"
        }
    }
}
```

#### Human Readable Output

>### Indicators list for Threat Model Actor with id 26769
>|ASN|Confidence|Country|ID|IType|Modified|Organization|Severity|Source|Status|Tags|Type|Value|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|  | 50 |  | 191431508 | apt_md5 | 2021-09-13T12:40:42.596Z |  | medium | TestSource | active |  | SHA256 | 178ba564b39bd07577e974a9b677dfd86ffa1f1d0299dfd958eb883c5ef6c3e1 |


### threatstream-supported-platforms
***
Returns a list of supported platforms for default or premium sandbox.


#### Base Command

`threatstream-supported-platforms`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sandbox_type | The type of sandbox. Possible values are: default, premium. Default is default. | Optional | 
| limit | The maximum number of results to return from ThreatStream. Default is 50. | Optional | 
| all_results | Whether to retrieve all results. The "limit" argument will be ignored. Possible values are: false, true. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.PremiumPlatforms.Name | String | The name of the supported platform for premium sandbox. | 
| ThreatStream.PremiumPlatforms.Types | String | The type of supported submissions for premium sandbox. | 
| ThreatStream.PremiumPlatforms.Label | String | The display name of the supported platform of premium sandbox. | 
| ThreatStream.DefaultPlatforms.Name | String | The name of the supported platform for standard sandbox. | 
| ThreatStream.DefaultPlatforms.Types | String | The type of the supported submissions for standard sandbox. | 
| ThreatStream.DefaultPlatforms.Label | String | The display name of the supported platform of standard sandbox. | 


#### Command Example
```!threatstream-supported-platforms sandbox_type=default```

#### Context Example
```json
{
    "ThreatStream": {
        "DefaultPlatforms": [
            {
                "Label": "Windows 7",
                "Name": "WINDOWS7",
                "Platform": "windows",
                "Types": [
                    "file",
                    "url"
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>### Supported platforms for default sandbox
>|Label|Name|Platform|Types|
>|---|---|---|---|
>| Windows 7 | WINDOWS7 | windows | file,<br/>url |


### url
***
Checks the reputation of the given URL.


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The URL to check. | Required | 
| threshold | If confidence is greater than the threshold the URL is considered malicious, otherwise it is considered good. This argument overrides the default URL threshold defined as a parameter. | Optional | 
| include_inactive | Whether to include results with an inactive status. Possible values are: True, False. | Optional | 
| threat_model_association | Enhance generic reputation commands to include additional information such as Threat Bulletins, Attach patterns, Actors, Campaigns, TTPs, vulnerabilities, etc. Note: If set to true, additional 6 API calls will be performed. Possible values are: True, False. Default is False. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| URL.Data | String | The URL of the indicator. | 
| URL.Malicious.Vendor | String | The vendor that reported the indicator as malicious. | 
| ThreatStream.URL.Modified | String | The date and time the indicator was last updated. The date format is: YYYYMMDDThhmmss, where "T" denotes the start of the value
for time in UTC time. | 
| ThreatStream.URL.Confidence | String | The observable certainty level of a reported indicator type. Confidence score ranges from 0-100, in increasing order of confidence. | 
| ThreatStream.URL.Status | String | The indicator status. | 
| ThreatStream.URL.Organization | String | The name of the business that owns the IP address associated with the indicator. | 
| ThreatStream.URL.Address | String | The indicator URL. | 
| ThreatStream.URL.Country | String | The country associated with the indicator. | 
| ThreatStream.URL.Type | String | The indicator type. | 
| ThreatStream.URL.Source | String | The indicator source. | 
| ThreatStream.URL.Severity | String | The indicator severity \("very-high", "high", "medium", or "low"\). | 
| ThreatStream.URL.Tags | Unknown | Tags assigned to the URL. | 
| ThreatStream.URL.IType | String | The itype of the indicator associated with the specified model. | 
| URL.Tags | Unknown | List of URL tags. | 
| URL.ThreatTypes | Unknown | Threat types associated with the url. | 
| ThreatStream.URL.Actor.assignee_user | Unknown | The assignee user of the threat actor. | 
| ThreatStream.URL.Actor.association_info.comment | Unknown | The comment in the association info of the threat actor. | 
| ThreatStream.URL.Actor.association_info.created | Date | The date the association info was created. | 
| ThreatStream.URL.Actor.association_info.from_id | Number | The ID from which the association info is related. | 
| ThreatStream.URL.Actor.can_add_public_tags | Boolean | Whether you can add public tags to the threat actor. | 
| ThreatStream.URL.Actor.created_ts | Date | The date the threat actor was created. | 
| ThreatStream.URL.Actor.feed_id | Number | The feed ID of the threat actor. | 
| ThreatStream.URL.Actor.id | Number | The ID of the threat actor. | 
| ThreatStream.URL.Actor.is_anonymous | Boolean | Whether the threat actor is anonymous. | 
| ThreatStream.URL.Actor.is_cloneable | String | Whether the threat actor is cloneable. | 
| ThreatStream.URL.Actor.is_public | Boolean | Whether the threat actor is public. | 
| ThreatStream.URL.Actor.is_team | Boolean | Whether the threat actor is a team. | 
| ThreatStream.URL.Actor.modified_ts | Date | The date the threat actor was modified. | 
| ThreatStream.URL.Actor.name | String | The name of the threat actor. | 
| ThreatStream.URL.Actor.organization_id | Number | The organization ID of the threat actor. | 
| ThreatStream.URL.Actor.owner_user_id | Number | The owner user ID of the threat actor. | 
| ThreatStream.URL.Actor.primary_motivation | Unknown | The primary motivation of the threat actor. | 
| ThreatStream.URL.Actor.publication_status | String | The publication status of the threat actor. | 
| ThreatStream.URL.Actor.published_ts | Date | The date the threat actor was published. | 
| ThreatStream.URL.Actor.resource_level | Unknown | The resource level of the threat actor. | 
| ThreatStream.URL.Actor.resource_uri | String | The resource URI of the threat actor. | 
| ThreatStream.URL.Actor.source_created | Unknown | The date the source was created. | 
| ThreatStream.URL.Actor.source_modified | Unknown | The date the source was modified. | 
| ThreatStream.URL.Actor.start_date | Unknown | The start date. | 
| ThreatStream.URL.Actor.tags | String | The tags of the threat indicator. | 
| ThreatStream.URL.Actor.tags_v2.id | String | The ID of the tag. | 
| ThreatStream.URL.Actor.tags_v2.name | String | The name of the tag. | 
| ThreatStream.URL.Actor.tlp | String | The TLP of the threat actor. | 
| ThreatStream.URL.Actor.uuid | String | The UUID of the threat actor. | 
| ThreatStream.URL.Signature.assignee_user | Unknown | The assignee user of the signature. | 
| ThreatStream.URL.Signature.association_info.comment | Unknown | The comment in the association info of the signature. | 
| ThreatStream.URL.Signature.association_info.created | Date | The date the association info was created. | 
| ThreatStream.URL.Signature.association_info.from_id | Number | The ID from which the association info is related. | 
| ThreatStream.URL.Signature.can_add_public_tags | Boolean | Whether you can add public tags to the signature. | 
| ThreatStream.URL.Signature.created_ts | Date | The date the signature was created. | 
| ThreatStream.URL.Signature.feed_id | Number | The feed ID of the signature. | 
| ThreatStream.URL.Signature.id | Number | The ID of the signature. | 
| ThreatStream.URL.Signature.is_anonymous | Boolean | Whether the signature is anonymous. | 
| ThreatStream.URL.Signature.is_cloneable | String | Whether the signature is cloneable. | 
| ThreatStream.URL.Signature.is_public | Boolean | Whether the signature is public. | 
| ThreatStream.URL.Signature.is_team | Boolean | Whether the signature is a team signature. | 
| ThreatStream.URL.Signature.modified_ts | Date | The date the signature was modified. | 
| ThreatStream.URL.Signature.name | String | The name of the signature. | 
| ThreatStream.URL.Signature.organization_id | Number | The organization ID of the signature. | 
| ThreatStream.URL.Signature.owner_user_id | Number | The owner user ID of the signature. | 
| ThreatStream.URL.Signature.primary_motivation | Unknown | The primary motivation of the signature. | 
| ThreatStream.URL.Signature.publication_status | String | The publication status of the signature. | 
| ThreatStream.URL.Signature.published_ts | Date | The date the signature was published. | 
| ThreatStream.URL.Signature.resource_level | Unknown | The resource level of the signature. | 
| ThreatStream.URL.Signature.resource_uri | String | The resource URI of the signature. | 
| ThreatStream.URL.Signature.source_created | Unknown | The date the source was created. | 
| ThreatStream.URL.Signature.source_modified | Unknown | The date the source was modified. | 
| ThreatStream.URL.Signature.start_date | Unknown | The start date. | 
| ThreatStream.URL.Signature.tags | String | The tags of the threat indicator. | 
| ThreatStream.URL.Signature.tags_v2.id | String | The ID of the tag. | 
| ThreatStream.URL.Signature.tags_v2.name | String | The name of the tag. | 
| ThreatStream.URL.Signature.tlp | String | The TLP of the signature. | 
| ThreatStream.URL.Signature.uuid | String | The UUID of the signature. | 
| ThreatStream.URL.ThreatBulletin.all_circles_visible | Boolean | Whether all of the circles are visible. | 
| ThreatStream.URL.ThreatBulletin.assignee_org | String | The assignee organization. | 
| ThreatStream.URL.ThreatBulletin.assignee_org_id | String | The assignee organization ID. | 
| ThreatStream.URL.ThreatBulletin.assignee_org_name | String | The assignee organization name. | 
| ThreatStream.URL.ThreatBulletin.assignee_user | String | The assignee user. | 
| ThreatStream.URL.ThreatBulletin.assignee_user_id | String | The assignee user ID. | 
| ThreatStream.URL.ThreatBulletin.assignee_user_name | Unknown | The assignee user name. | 
| ThreatStream.URL.ThreatBulletin.association_info.comment | Unknown | The comment in the association info of the threat actor. | 
| ThreatStream.URL.ThreatBulletin.association_info.created | Date | The date the association info was created. | 
| ThreatStream.URL.ThreatBulletin.association_info.from_id | String | The ID from which the association info is related. | 
| ThreatStream.URL.ThreatBulletin.body_content_type | String | The body content type. | 
| ThreatStream.URL.ThreatBulletin.campaign | Unknown | The campaign of the threat bulletin. | 
| ThreatStream.URL.ThreatBulletin.can_add_public_tags | Boolean | Whether you can add public tags. | 
| ThreatStream.URL.ThreatBulletin.created_ts | Date | The date the threat bulletin was created. | 
| ThreatStream.URL.ThreatBulletin.feed_id | Number | The feed ID of the threat bulletin. | 
| ThreatStream.URL.ThreatBulletin.id | String | The ID of the threat bulletin. | 
| ThreatStream.URL.ThreatBulletin.is_anonymous | Boolean | Whether the threat bulletin is anonymous. | 
| ThreatStream.URL.ThreatBulletin.is_cloneable | String | Whether the threat bulletin is cloneable. | 
| ThreatStream.URL.ThreatBulletin.is_editable | Boolean | Whether the threat bulletin is editable. | 
| ThreatStream.URL.ThreatBulletin.is_email | Boolean | Whether the threat bulletin is an email. | 
| ThreatStream.URL.ThreatBulletin.is_public | Boolean | Whether the threat bulletin is public. | 
| ThreatStream.URL.ThreatBulletin.modified_ts | Date | The date the threat bulletin was modified. | 
| ThreatStream.URL.ThreatBulletin.name | String | The name of the threat bulletin. | 
| ThreatStream.URL.ThreatBulletin.original_source | String | The original source of the threat bulletin. | 
| ThreatStream.URL.ThreatBulletin.original_source_id | Unknown | The original source ID of the threat bulletin. | 
| ThreatStream.URL.ThreatBulletin.owner_org.id | String | The owner organization ID. | 
| ThreatStream.URL.ThreatBulletin.owner_org.name | String | The owner organization name. | 
| ThreatStream.URL.ThreatBulletin.owner_org.resource_uri | String | The owner organization URI. | 
| ThreatStream.URL.ThreatBulletin.owner_org_id | Number | The ID of the owner user. | 
| ThreatStream.URL.ThreatBulletin.owner_org_name | String | The name of the owner organization. | 
| ThreatStream.URL.ThreatBulletin.owner_user.avatar_s3_url | Unknown | The URL of the owner user. | 
| ThreatStream.URL.ThreatBulletin.owner_user.can_share_intelligence | Boolean | Whether you can share intelligence. | 
| ThreatStream.URL.ThreatBulletin.owner_user.email | String | The email of the owner user. | 
| ThreatStream.URL.ThreatBulletin.owner_user.id | String | The ID of the owner user. | 
| ThreatStream.URL.ThreatBulletin.owner_user.is_active | Boolean | Whether the owner user is active. | 
| ThreatStream.URL.ThreatBulletin.owner_user.is_readonly | Boolean | Whether the owner user has read-only permission. | 
| ThreatStream.URL.ThreatBulletin.owner_user.must_change_password | Boolean | Whether the owner user must change the password. | 
| ThreatStream.URL.ThreatBulletin.owner_user.name | String | The owner user name. | 
| ThreatStream.URL.ThreatBulletin.owner_user.nickname | String | The owner user nickname. | 
| ThreatStream.URL.ThreatBulletin.owner_user.organization.id | String | The ID of the owner user organization. | 
| ThreatStream.URL.ThreatBulletin.owner_user.organization.name | String | The name of the owner user organization. | 
| ThreatStream.URL.ThreatBulletin.owner_user.organization.resource_uri | String | The resource URI of the owner user organization. | 
| ThreatStream.URL.ThreatBulletin.owner_user.resource_uri | String | The resource URI of the owner user. | 
| ThreatStream.URL.ThreatBulletin.owner_user_id | Number | The owner user ID of the threat bulletin. | 
| ThreatStream.URL.ThreatBulletin.owner_user_name | String | The owner user name of the threat bulletin. | 
| ThreatStream.URL.ThreatBulletin.parent | Unknown | The parent of the threat bulletin. | 
| ThreatStream.URL.ThreatBulletin.published_ts | Unknown | The date the threat bulletin was published. | 
| ThreatStream.URL.ThreatBulletin.resource_uri | String | The resource URI of the threat bulletin. | 
| ThreatStream.URL.ThreatBulletin.source | Unknown | The source of the threat bulletin. | 
| ThreatStream.URL.ThreatBulletin.source_created | Unknown | The date the source was created. | 
| ThreatStream.URL.ThreatBulletin.source_modified | Unknown | The date the source was modified. | 
| ThreatStream.URL.ThreatBulletin.starred_by_me | Boolean | Whether the threat bulletin was started by me. | 
| ThreatStream.URL.ThreatBulletin.starred_total_count | Number | The total number of times the threat bulletin was starred. | 
| ThreatStream.URL.ThreatBulletin.status | String | The status of the threat bulletin. | 
| ThreatStream.URL.ThreatBulletin.threat_actor | Unknown | The threat actor of the threat bulletin. | 
| ThreatStream.URL.ThreatBulletin.tlp | Unknown | The TLP of the threat bulletin. | 
| ThreatStream.URL.ThreatBulletin.ttp | Unknown | The TTP of the threat bulletin. | 
| ThreatStream.URL.ThreatBulletin.uuid | String | The UUID of the threat bulletin. | 
| ThreatStream.URL.ThreatBulletin.votes.me | Unknown | The number of votes by me. | 
| ThreatStream.URL.ThreatBulletin.votes.total | Number | The number of total votes. | 
| ThreatStream.URL.ThreatBulletin.watched_by_me | Boolean | Whether the threat bulletin was watched by me. | 
| ThreatStream.URL.ThreatBulletin.watched_total_count | Number | The total number of watchers. | 
| ThreatStream.URL.TTP.assignee_user | Unknown | The assignee user of the TTP. | 
| ThreatStream.URL.TTP.association_info.comment | Unknown | The comment in the association info of the TTP. | 
| ThreatStream.URL.TTP.association_info.created | Date | The date the association info was created. | 
| ThreatStream.URL.TTP.association_info.from_id | Number | The ID from which the association info is related. | 
| ThreatStream.URL.TTP.can_add_public_tags | Boolean | Whether you can add public tags to the TTP. | 
| ThreatStream.URL.TTP.created_ts | Date | The date the TTP was created. | 
| ThreatStream.URL.TTP.feed_id | Number | The feed ID of the TTP. | 
| ThreatStream.URL.TTP.id | Number | The ID of the TTP. | 
| ThreatStream.URL.TTP.is_anonymous | Boolean | Whether the TTP was anonymous. | 
| ThreatStream.URL.TTP.is_cloneable | String | Whether the TTP was cloneable. | 
| ThreatStream.URL.TTP.is_public | Boolean | Whether the TTP is public. | 
| ThreatStream.URL.TTP.is_team | Boolean | Whether the TTP is a team. | 
| ThreatStream.URL.TTP.modified_ts | Date | The date the TTP was modified. | 
| ThreatStream.URL.TTP.name | String | The name of the TTP. | 
| ThreatStream.URL.TTP.organization_id | Number | The organization ID of the TTP. | 
| ThreatStream.URL.TTP.owner_user_id | Number | The owner user ID of the TTP. | 
| ThreatStream.URL.TTP.primary_motivation | Unknown | The primary motivation of the TTP. | 
| ThreatStream.URL.TTP.publication_status | String | The publication status of the TTP. | 
| ThreatStream.URL.TTP.published_ts | Date | The date the TTP was published. | 
| ThreatStream.URL.TTP.resource_level | Unknown | The resource level of the TTP. | 
| ThreatStream.URL.TTP.resource_uri | String | The resource URI of the TTP. | 
| ThreatStream.URL.TTP.source_created | Unknown | The date the source was created. | 
| ThreatStream.URL.TTP.source_modified | Unknown | The date the source was modified. | 
| ThreatStream.URL.TTP.start_date | Unknown | The start date. | 
| ThreatStream.URL.TTP.tags | String | The tags of the threat indicator. | 
| ThreatStream.URL.TTP.tags_v2.id | String | The ID of the tag. | 
| ThreatStream.URL.TTP.tags_v2.name | String | The name of the tag. | 
| ThreatStream.URL.TTP.tlp | String | The TLP of the TTP. | 
| ThreatStream.URL.TTP.uuid | String | The UUID of the TTP. | 
| ThreatStream.URL.Vulnerability.assignee_user | Unknown | The assignee user of the vulnerability. | 
| ThreatStream.URL.Vulnerability.association_info.comment | Unknown | The comment in the association info of the vulnerability. | 
| ThreatStream.URL.Vulnerability.association_info.created | Date | The date the association info was created. | 
| ThreatStream.URL.Vulnerability.association_info.from_id | Number | The ID from which the association info is related. | 
| ThreatStream.URL.Vulnerability.can_add_public_tags | Boolean | Whether you can add public tags to the threat actor. | 
| ThreatStream.URL.Vulnerability.circles.id | String | The ID of the circle. | 
| ThreatStream.URL.Vulnerability.circles.name | String | The name of the circle. | 
| ThreatStream.URL.Vulnerability.circles.resource_uri | String | The resource URI of the circle. | 
| ThreatStream.URL.Vulnerability.created_ts | Date | The date the vulnerability was created. | 
| ThreatStream.URL.Vulnerability.feed_id | Number | The feed ID of the vulnerability. | 
| ThreatStream.URL.Vulnerability.id | Number | The ID of the vulnerability. | 
| ThreatStream.URL.Vulnerability.is_anonymous | Boolean | Whether the vulnerability is anonymous. | 
| ThreatStream.URL.Vulnerability.is_cloneable | String | Whether the vulnerability is cloneable. | 
| ThreatStream.URL.Vulnerability.is_public | Boolean | Whether the vulnerability is public. | 
| ThreatStream.URL.Vulnerability.is_system | Boolean | Whether the vulnerability is in the system. | 
| ThreatStream.URL.Vulnerability.modified_ts | Date | The date the vulnerability was modified. | 
| ThreatStream.URL.Vulnerability.name | String | The name of the vulnerability. | 
| ThreatStream.URL.Vulnerability.organization_id | Number | The organization ID of the vulnerability. | 
| ThreatStream.URL.Vulnerability.owner_user_id | Unknown | The owner user ID of the vulnerability. | 
| ThreatStream.URL.Vulnerability.publication_status | String | The publication status of the vulnerability. | 
| ThreatStream.URL.Vulnerability.published_ts | Date | The date the vulnerability was published. | 
| ThreatStream.URL.Vulnerability.resource_uri | String | The resource URI of the vulnerability. | 
| ThreatStream.URL.Vulnerability.source | String | The source of the vulnerability. | 
| ThreatStream.URL.Vulnerability.source_created | Unknown | The feed ID of the vulnerability. | 
| ThreatStream.URL.Vulnerability.source_modified | Unknown | Whether the source was modified. | 
| ThreatStream.URL.Vulnerability.tags | String | The tags of the vulnerability. | 
| ThreatStream.URL.Vulnerability.tags_v2.id | String | The ID of the tag. | 
| ThreatStream.URL.Vulnerability.tags_v2.name | String | The name of the tag. | 
| ThreatStream.URL.Vulnerability.tlp | String | The TLP of the vulnerability. | 
| ThreatStream.URL.Vulnerability.update_id | Number | The update ID of the vulnerability. | 
| ThreatStream.URL.Vulnerability.uuid | String | The UUID of the vulnerability. | 
| ThreatStream.URL.Campaign.assignee_user | Unknown | The assignee user of the vulnerability. | 
| ThreatStream.URL.Campaign.association_info.comment | Unknown | The comment in the association info of the vulnerability. | 
| ThreatStream.URL.Campaign.association_info.created | Date | The date the association info was created. | 
| ThreatStream.URL.Campaign.association_info.from_id | Number | The ID from which the association info is related. | 
| ThreatStream.URL.Campaign.can_add_public_tags | Boolean | Whether you can add public tags to the campaign. | 
| ThreatStream.URL.Campaign.created_ts | Date | The date the campaign was created. | 
| ThreatStream.URL.Campaign.end_date | Unknown | The end date of the campaign. | 
| ThreatStream.URL.Campaign.feed_id | Number | The feed ID of the campaign. | 
| ThreatStream.URL.Campaign.id | Number | The ID of the campaign. | 
| ThreatStream.URL.Campaign.is_anonymous | Boolean | Whether the campaign is anonymous. | 
| ThreatStream.URL.Campaign.is_cloneable | String | Whether the campaign is cloneable. | 
| ThreatStream.URL.Campaign.is_public | Boolean | Whether the campaign is public. | 
| ThreatStream.URL.Campaign.modified_ts | Date | The date the campaign was modified. | 
| ThreatStream.URL.Campaign.name | String | The name of the campaign. | 
| ThreatStream.URL.Campaign.objective | Unknown | The objective of the campaign. | 
| ThreatStream.URL.Campaign.organization_id | Number | The organization ID of the campaign. | 
| ThreatStream.URL.Campaign.owner_user_id | Number | The owner user ID of the campaign. | 
| ThreatStream.URL.Campaign.publication_status | String | The publication status of the campaign. | 
| ThreatStream.URL.Campaign.published_ts | Unknown | The date the campaign was published. | 
| ThreatStream.URL.Campaign.resource_uri | String | The resource URI of the campaign. | 
| ThreatStream.URL.Campaign.source_created | Date | The date the campaign was created. | 
| ThreatStream.URL.Campaign.source_modified | Date | Whether the source was modified. | 
| ThreatStream.URL.Campaign.start_date | Unknown | The start date of the campaign. | 
| ThreatStream.URL.Campaign.status.display_name | String | The display name of the status. | 
| ThreatStream.URL.Campaign.status.id | Number | The ID of the status of the campaign. | 
| ThreatStream.URL.Campaign.status.resource_uri | String | The resource URI of the status of the campaign. | 
| ThreatStream.URL.Campaign.tlp | String | The TLP of the campaign. | 
| ThreatStream.URL.Campaign.uuid | String | The UUID of the campaign. | 

#### Command example
```!url url=http://www.ujhy1.com/ threat_model_association=True```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "http://www.ujhy1.com/",
        "Message": "No results found.",
        "Reliability": "B - Usually reliable",
        "Score": 0,
        "Type": "url",
        "Vendor": "Anomali ThreatStream v3 May"
    },
    "URL": {
        "Data": "http://www.ujhy1.com/"
    }
}
```

#### Human Readable Output

>### Anomali ThreatStream v3 May:
>|URL|Result|
>|---|---|
>| http:<span>//</span>www.ujhy1.com/ | Not found |


## Additional Considerations for this version
- Remove the **default_threshold** integration parameter.
- Add integration parameter for global threshold in ***ip***, ***domain***, ***file***, ***url***, and ***threatstream-email-reputation*** commands. 
- Add ***Include inactive results*** checkbox in integration settings for the ability to get inactive results.
### threatstream-search-intelligence
***
Returns filtered intelligence from ThreatStream. If a query is defined, it overrides all other arguments that were passed to the command.


#### Base Command

`threatstream-search-intelligence`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| value | The value of an intelligence. | Optional | 
| uuid | The UUID of an intelligence. When several UUIDs stated, an “OR” operator is used. | Optional | 
| type | The type of an intelligence. Possible values are: domain, email, ip, md5, string, url. | Optional | 
| itype | The itType of an intelligence. (e.g., apt_ip, apt_email). | Optional | 
| status | The status of an intelligence. Possible values are: active, inactive, falsepos. | Optional | 
| tags | The tags of an intelligence. Comma-separated list. When several tags are stated, an “OR” operator is used. | Optional | 
| asn | The ASN of an intelligence. | Optional | 
| confidence | The confidence of an intelligence. Input will be operator then value, i.e., “gt 65” or “lt 85”. If only a value is stated, then it must match exactly. | Optional | 
| threat_type | The threat type of an intelligence. | Optional | 
| is_public | Whether the intelligence is public. | Optional | 
| query | Query that overrides all other arguments. The filter operators used for the filter language query are the symbolic form (=, &lt;, &gt;, and so on) and not the descriptive form (exact, lt, gt, and so on). E.g., (confidence&gt;=90+AND+(itype="apt_ip"+OR+itype="bot_ip"+OR+itype="c2_ip")). | Optional | 
| update_id_gt | An incrementing numeric identifier associated with each update to intelligence on ThreatStream. If specified, then it is recommended to use order_by=update_id. | Optional | 
| order_by | How to order the results. | Optional | 
| limit | The maximum number of results to return from ThreatStream. The maximum number of returned results is 1000. For more results, use the page and page_size arguments. Default is 50. | Optional | 
| page | Page number to get result from. Needs to be used with page_size argument. | Optional | 
| page_size | The page size of the returned results. Needs to be used with the page argument. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.Intelligence.source_created | String | The source from which the intelligence was created. | 
| ThreatStream.Intelligence.status | String | The status of the intelligence. | 
| ThreatStream.Intelligence.itype | String | The itype of the intelligence. | 
| ThreatStream.Intelligence.expiration_ts | Date | The expiration timestamp of the intelligence. | 
| ThreatStream.Intelligence.ip | String | The IP address of the intelligence. | 
| ThreatStream.Intelligence.is_editable | Boolean | Whether the intelligence is editable. | 
| ThreatStream.Intelligence.feed_id | String | The feed ID of the intelligence. | 
| ThreatStream.Intelligence.update_id | String | The update ID of the intelligence. | 
| ThreatStream.Intelligence.value | String | The value of the intelligence. | 
| ThreatStream.Intelligence.is_public | Boolean | Whether the intelligence is public. | 
| ThreatStream.Intelligence.threattype | String | The threat type of the intelligence. | 
| ThreatStream.Intelligence.workgroups | String | The work groups of the intelligence. | 
| ThreatStream.Intelligence.confidence | String | The confidence of the intelligence. | 
| ThreatStream.Intelligence.uuid | String | The UUID of the intelligence. | 
| ThreatStream.Intelligence.retina_confidence | String | The retina confidence of the intelligence. | 
| ThreatStream.Intelligence.trusted_circle_ids | String | The trusted circleIDs of the intelligence. | 
| ThreatStream.Intelligence.id | String | The ID of the intelligence. | 
| ThreatStream.Intelligence.source | String | The source of the iIntelligence. | 
| ThreatStream.Intelligence.owner_organization_id | String | The owner organization ID of the intelligence. | 
| ThreatStream.Intelligence.import_session_id | String | The import session ID of the intelligence. | 
| ThreatStream.Intelligence.source_modified | Boolean | Whether the the source was modified. | 
| ThreatStream.Intelligence.type | String | The type of the intelligence. | 
| ThreatStream.Intelligence.description | String | The description of the intelligence. | 
| ThreatStream.Intelligence.tags | String | The tags of the intelligence. | 
| ThreatStream.Intelligence.threatscore | String | The threat score of the intelligence. | 
| ThreatStream.Intelligence.latitude | String | The latitude of the intelligence. | 
| ThreatStream.Intelligence.longitude | String | The longitude of the intelligence. | 
| ThreatStream.Intelligence.modified_ts | Date | The date the intelligence was modified. | 
| ThreatStream.Intelligence.org | String | The organization of the intelligence. | 
| ThreatStream.Intelligence.asn | Number | The ASN of the intelligence. | 
| ThreatStream.Intelligence.created_ts | Date | The date the intelligence was created. | 
| ThreatStream.Intelligence.tlp | String | The TLP of the intelligence. | 
| ThreatStream.Intelligence.is_anonymous | Boolean | Whether the intelligence is anonymous. | 
| ThreatStream.Intelligence.country | String | The country of the intelligence. | 
| ThreatStream.Intelligence.source_reported_confidence | String | The confidence of the reported source. | 
| ThreatStream.Intelligence.subtype | String | The subtype of the intelligence. | 
| ThreatStream.Intelligence.resource_uri | String | The resource URI of the intelligence | 
| ThreatStream.Intelligence.severity | String | The severity of the intelligence. | 

#### Command example
```!threatstream-search-intelligence limit=1 status=inactive value=1.2.4.5```
#### Context Example
```json
{
    "ThreatStream": {
        "Intelligence": [
            {
                "asn": "",
                "can_add_public_tags": true,
                "confidence": 100,
                "country": null,
                "created_ts": "2022-04-21T14:27:51.242Z",
                "description": null,
                "expiration_ts": "2022-07-20T14:27:51.041Z",
                "feed_id": 0,
                "id": 355250247,
                "import_session_id": null,
                "ip": "1.2.4.5",
                "is_anonymous": false,
                "is_editable": false,
                "is_public": true,
                "itype": "c2_ip",
                "latitude": null,
                "longitude": null,
                "meta": {
                    "detail2": "bifocals_deactivated_on_2022-07-20_14:30:00.151050",
                    "severity": "medium"
                },
                "modified_ts": "2022-07-20T14:30:02.307Z",
                "org": "",
                "owner_organization_id": 67,
                "rdns": null,
                "resource_uri": "/api/v2/intelligence/355250247/",
                "retina_confidence": -1,
                "sort": [
                    1658327402307,
                    "355250247"
                ],
                "source": "Analyst",
                "source_created": null,
                "source_modified": null,
                "source_reported_confidence": 100,
                "status": "inactive",
                "subtype": null,
                "tags": [
                    {
                        "id": "4w0",
                        "name": "abc"
                    },
                    {
                        "id": "o8x",
                        "name": "feb3fbcf-d18c-4a1a-89af-fbe054e16f6c"
                    },
                    {
                        "id": "vuj",
                        "name": "Playboook_source_without_approval_on_cloud"
                    }
                ],
                "threat_type": "c2",
                "threatscore": 70,
                "tlp": null,
                "trusted_circle_ids": null,
                "type": "ip",
                "update_id": 940700580,
                "uuid": "3e141a49-6fc9-4567-8efb-919565a39752",
                "value": "1.2.4.5",
                "workgroups": []
            }
        ]
    }
}
```

#### Human Readable Output

>### The intelligence results
>|Can Add Public Tags|Confidence|Created Ts|Expiration Ts|Feed Id|Id|Ip|Is Anonymous|Is Editable|Is Public|Itype|Meta|Modified Ts|Owner Organization Id|Resource Uri|Retina Confidence|Sort|Source|Source Reported Confidence|Status|Tags|Threat Type|Threatscore|Type|Update Id|Uuid|Value|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| true | 100 | 2022-04-21T14:27:51.242Z | 2022-07-20T14:27:51.041Z | 0 | 355250247 | 1.2.4.5 | false | false | true | c2_ip | detail2: bifocals_deactivated_on_2022-07-20_14:30:00.151050<br/>severity: medium | 2022-07-20T14:30:02.307Z | 67 | /api/v2/intelligence/355250247/ | -1 | 1658327402307,<br/>355250247 | Analyst | 100 | inactive | {'id': '4w0', 'name': 'abc'},<br/>{'id': 'o8x', 'name': 'feb3fbcf-d18c-4a1a-89af-fbe054e16f6c'},<br/>{'id': 'vuj', 'name': 'Playboook_source_without_approval_on_cloud'} | c2 | 70 | ip | 940700580 | 3e141a49-6fc9-4567-8efb-919565a39752 | 1.2.4.5 |

### threatstream-list-rule

***
Gets a list of rules from ThreatStream.

#### Base Command

`threatstream-list-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | Unique ID assigned to the rule. | Optional | 
| limit | The maximum number of results to return. Default is 50. | Optional | 
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of objects to retrieve per page. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.Rule.adv_keyword | Unknown | Advanced keyword or regular expression that the rule is designed to match. | 
| ThreatStream.Rule.backfill | Unknown | Objects that define additional filters or conditions for the rule. | 
| ThreatStream.Rule.create_investigation | Boolean | Whether an investigation should be created when the rule is triggered. | 
| ThreatStream.Rule.created_ts | Date | Rule creation time. | 
| ThreatStream.Rule.description | Unknown | The rule description. | 
| ThreatStream.Rule.exclude_notify_org_whitelisted | Boolean | Whether to exclude the rule from matching observables that are included in the organization whitelist. | 
| ThreatStream.Rule.exclude_notify_owner_org | Boolean | Whether to exclude the rule from keyword matches on observables imported by the organization from keyword match or hourly digest email notifications. | 
| ThreatStream.Rule.has_associations | Boolean | Whether the rule has associations. | 
| ThreatStream.Rule.id | Number | Unique ID assigned to the rule. | 
| ThreatStream.Rule.intelligence_initiatives | Unknown | Intelligence initiatives associated with the rule. | 
| ThreatStream.Rule.is_editable | Boolean | Indicates whether the imported rule can be updated by an intelligence source. | 
| ThreatStream.Rule.is_enabled | Boolean | Whether the rule is currently enabled. | 
| ThreatStream.Rule.keyword | String | Keyword associated with the rule. | 
| ThreatStream.Rule.keywords | String | A list of keywords associated with the rule. | 
| ThreatStream.Rule.match_actors | Boolean | Whether the rule matches keywords in newly created actors. | 
| ThreatStream.Rule.match_all_tm | Boolean | Whether the rule should match against all threat models. | 
| ThreatStream.Rule.match_attackpatterns | Boolean | Whether the rule matches keywords in newly created attack patterns. | 
| ThreatStream.Rule.match_campaigns | Boolean | Whether the rule matches keywords in newly created campaigns. | 
| ThreatStream.Rule.match_courseofactions | Boolean | Whether the rule matches keywords in newly created course of actions. | 
| ThreatStream.Rule.match_customtms | Boolean | Whether the rule should match custom threat models. | 
| ThreatStream.Rule.match_identities | Boolean | Whether the rule matches keywords in newly created identities. | 
| ThreatStream.Rule.match_incidents | Boolean | Whether the rule matches keywords in newly created incidents. | 
| ThreatStream.Rule.match_infrastructures | Boolean | Whether the rule matches keywords in newly created infrastructures. | 
| ThreatStream.Rule.match_intrusionsets | Boolean | Whether the rule matches keywords in newly created intrusion sets. | 
| ThreatStream.Rule.match_malware | Boolean | Whether the rule matches keywords in newly created malware. | 
| ThreatStream.Rule.match_observables | Boolean | Whether the rule matches keywords in newly created observables. | 
| ThreatStream.Rule.match_reportedfiles | Boolean | Whether the rule should match keywords in newly created sandbox reports. | 
| ThreatStream.Rule.match_signatures | Boolean | Whether the rule should match keywords in newly created signatures. | 
| ThreatStream.Rule.match_tips | Boolean | Whether the rule matches keywords in newly created threat bulletins. | 
| ThreatStream.Rule.match_tools | Boolean | Whether the rule should match keywords in newly created tools. | 
| ThreatStream.Rule.match_ttps | Boolean | Whether the rule should match keywords in newly created TTPs. | 
| ThreatStream.Rule.match_vulnerabilities | Boolean | Whether the rule matches keywords in newly created vulnerabilities. | 
| ThreatStream.Rule.matches | Number | Total number of keyword matches for the rule. | 
| ThreatStream.Rule.messages | Unknown | Messages or notifications generated by the rule. | 
| ThreatStream.Rule.modified_ts | Date | Timestamp of when the rule was last modified, in UTC format. | 
| ThreatStream.Rule.name | String | The rule name. | 
| ThreatStream.Rule.notify_list_groups | Unknown | List of groups that should be notified when the rule triggers an alert. | 
| ThreatStream.Rule.notify_me | Boolean | Whether the user who created the rule should be notified when the rule triggers an alert. | 
| ThreatStream.Rule.org_id | Number | ID associated with the organization that created the rule. | 
| ThreatStream.Rule.org_shared | Boolean | Whether a rule is shared across an organization. | 
| ThreatStream.Rule.organization.id | String | ID associated with the organization that created the rule. | 
| ThreatStream.Rule.organization.name | String | Name associated with the organization that created the rule. | 
| ThreatStream.Rule.organization.resource_uri | String | Resource URI associated with the organization that created the rule. | 
| ThreatStream.Rule.resource_uri | String | Resource URI associated with the rule. | 
| ThreatStream.Rule.user.avatar_s3_url | Unknown | URL for the avatar image associated with the user who created the rule. | 
| ThreatStream.Rule.user.can_share_intelligence | Boolean | Whether the user who created the rule can share intelligence. | 
| ThreatStream.Rule.user.email | String | Email of the user who created the rule. | 
| ThreatStream.Rule.user.id | String | ID of the user who created the rule. | 
| ThreatStream.Rule.user.is_active | Boolean | Whether the user who created the rule is active. | 
| ThreatStream.Rule.user.is_readonly | Boolean | Whether the user who created the rule should be restricted to Read Only status. | 
| ThreatStream.Rule.user.must_change_password | Boolean | Whether the user who created the rule will be forced to change their password the next time they log in. | 
| ThreatStream.Rule.user.name | String | Name of the user who created the rule. | 
| ThreatStream.Rule.user.nickname | String | Nickname of the user who created the rule. | 
| ThreatStream.Rule.user.organization.id | String | The ID associated to the organization. | 
| ThreatStream.Rule.user.organization.name | String | The user's organization name. | 
| ThreatStream.Rule.user.organization.resource_uri | String | The user's organization resource URI. | 
| ThreatStream.Rule.user.resource_uri | String | The user's resource URI. | 
| ThreatStream.Rule.user_id | Number | User ID of the user who created the rule. | 
| ThreatStream.Rule.workgroups | Unknown | Assigned workgroups. | 
| ThreatStream.Rule.actors.id | String | Actor's ID associated with the rule. | 
| ThreatStream.Rule.actors.name | String | Actor's name associated with the rule. | 
| ThreatStream.Rule.actors.resource_uri | String | Actor's resource URI associated with the rule. | 
| ThreatStream.Rule.attackpatterns | Unknown | Attack patterns associated with the rule. | 
| ThreatStream.Rule.campaigns.id | String | Campaign's ID associated with the rule. | 
| ThreatStream.Rule.campaigns.name | String | Campaign's name associated with the rule. | 
| ThreatStream.Rule.campaigns.resource_uri | String | Campaign's resource URI associated with the rule. | 
| ThreatStream.Rule.courseofaction | Unknown | Course of action entities associated with the rule. | 
| ThreatStream.Rule.customtms | Unknown | Custom threat model entities associated with the rule. | 
| ThreatStream.Rule.exclude_impacts | String | Indicator types that are excluded from rule matches. | 
| ThreatStream.Rule.identities | Unknown | List of identities associated with the rule. | 
| ThreatStream.Rule.incidents.id | String | Incident's ID associated with the rule. | 
| ThreatStream.Rule.incidents.name | String | Incident's name associated with the rule. | 
| ThreatStream.Rule.incidents.resource_uri | String | Incident's resource URI associated with the rule. | 
| ThreatStream.Rule.infrastructure | Unknown | Infrastructure entities associated with the rule. | 
| ThreatStream.Rule.intrusionsets | Unknown | Intrusion sets associated with the rule. | 
| ThreatStream.Rule.investigation.assignee.assignee_type | String | Type of assignee: "user" or "tsworkgroup". | 
| ThreatStream.Rule.investigation.assignee.avatar_s3_url | Unknown | URL for the avatar image associated with the assignee user. | 
| ThreatStream.Rule.investigation.assignee.can_share_intelligence | Boolean | Whether the assignee user can share intelligence. | 
| ThreatStream.Rule.investigation.assignee.email | String | The email of the assignee user. | 
| ThreatStream.Rule.investigation.assignee.id | String | The ID of the assignee user. | 
| ThreatStream.Rule.investigation.assignee.is_active | Boolean | Whether the assignee user is active. | 
| ThreatStream.Rule.investigation.assignee.is_readonly | Boolean | Whether the assignee user should be restricted to Read Only status. | 
| ThreatStream.Rule.investigation.assignee.must_change_password | Boolean | Whether the investigation assignee user will be forced to change their password the next time they log in. | 
| ThreatStream.Rule.investigation.assignee.name | String | The investigation assignee user name. | 
| ThreatStream.Rule.investigation.assignee.nickname | Unknown | The investigation assignee user nickname. | 
| ThreatStream.Rule.investigation.assignee.resource_uri | String | Resource URI associated with investigation assignee user. | 
| ThreatStream.Rule.investigation.id | String | The ID of the investigation. | 
| ThreatStream.Rule.investigation.name | String | The name of the investigation. | 
| ThreatStream.Rule.investigation.resource_uri | String | The resource URI of the investigation. | 
| ThreatStream.Rule.investigation.users | Unknown | List of users associated with the investigation created by the rule. | 
| ThreatStream.Rule.investigation.workgroups | Unknown | Assigned workgroups. | 
| ThreatStream.Rule.malware.id | String | ID of the malware that associates to the rule. | 
| ThreatStream.Rule.malware.name | String | Name of the malware that associates to the rule. | 
| ThreatStream.Rule.malware.resource_uri | String | Resource URI of the malware that associates to the rule. | 
| ThreatStream.Rule.match_impacts | String | Indicator types in which you want to look for rule matches at the exclusion of all others. | 
| ThreatStream.Rule.signatures.id | String | ID of the signature that associates to the rule. | 
| ThreatStream.Rule.signatures.name | String | Name of the signature that associates to the rule. | 
| ThreatStream.Rule.signatures.resource_uri | String | Resource URI of the signature that associates to the rule. | 
| ThreatStream.Rule.tags.name | String | Name of the tag applied to matched entities. | 
| ThreatStream.Rule.tips.id | String | ID of the threat bulletin that associates to matched entities. | 
| ThreatStream.Rule.tips.name | String | Name of the threat bulletin that associates to matched entities. | 
| ThreatStream.Rule.tips.resource_uri | String | Resource URI of the threat bulletin that associates to matched entities. | 
| ThreatStream.Rule.tools | Unknown | List of tools associated with the rule. | 
| ThreatStream.Rule.ttps.id | String | ID of the TTPs that associates to the rule. | 
| ThreatStream.Rule.ttps.name | String | Name of the TTPs that associates to the rule. | 
| ThreatStream.Rule.ttps.resource_uri | String | Resource URI of the TTPs that associates to the rule. | 
| ThreatStream.Rule.vulnerabilities.id | String | ID of the vulnerability with which to associate matched entities. | 
| ThreatStream.Rule.vulnerabilities.name | String | Name of the vulnerability with which to associate matched entities. | 
| ThreatStream.Rule.vulnerabilities.resource_uri | String | Resource URI of the vulnerability with which to associate matched entities. | 

#### Command example
```!threatstream-list-rule page=2 page_size=2```
#### Context Example
```json
{
    "ThreatStream": {
        "Rule": [
            {
                "adv_keyword": null,
                "backfill": [],
                "create_investigation": false,
                "created_ts": "2023-03-30T13:25:42.306343",
                "description": null,
                "exclude_notify_org_whitelisted": false,
                "exclude_notify_owner_org": false,
                "has_associations": false,
                "id": 44444,
                "intelligence_initiatives": [],
                "is_editable": true,
                "is_enabled": true,
                "keyword": "keywords",
                "keywords": [
                    "keywords"
                ],
                "match_actors": false,
                "match_all_tm": false,
                "match_attackpatterns": false,
                "match_campaigns": false,
                "match_courseofactions": false,
                "match_customtms": false,
                "match_identities": false,
                "match_incidents": false,
                "match_infrastructures": false,
                "match_intrusionsets": false,
                "match_malware": false,
                "match_observables": false,
                "match_reportedfiles": false,
                "match_signatures": false,
                "match_tips": false,
                "match_tools": false,
                "match_ttps": false,
                "match_vulnerabilities": false,
                "matches": 0,
                "messages": [],
                "modified_ts": "2023-03-30T13:25:45.435220",
                "name": "rule_2",
                "notify_list_groups": [],
                "notify_me": true,
                "org_id": 11,
                "org_shared": false,
                "organization": {
                    "id": "11",
                    "name": "name",
                    "resource_uri": "resource_uri"
                },
                "resource_uri": "/api/v1/rule/44444/",
                "tags": [],
                "user": {
                    "avatar_s3_url": null,
                    "can_share_intelligence": false,
                    "email": "user@email.com",
                    "id": "111",
                    "is_active": true,
                    "is_readonly": false,
                    "must_change_password": false,
                    "name": "",
                    "nickname": null,
                    "organization": {
                        "id": "11",
                        "name": "name",
                        "resource_uri": "resource_uri"
                    },
                    "resource_uri": "/api/v1/user/111/"
                },
                "user_id": 111,
                "workgroups": []
            },
            {
                "adv_keyword": null,
                "backfill": [],
                "create_investigation": false,
                "created_ts": "2023-03-30T13:25:05.014893",
                "description": null,
                "exclude_notify_org_whitelisted": false,
                "exclude_notify_owner_org": false,
                "has_associations": false,
                "id": 55555,
                "intelligence_initiatives": [],
                "is_editable": true,
                "is_enabled": true,
                "keyword": "keywords",
                "keywords": [
                    "keywords"
                ],
                "match_actors": false,
                "match_all_tm": false,
                "match_attackpatterns": false,
                "match_campaigns": false,
                "match_courseofactions": false,
                "match_customtms": false,
                "match_identities": false,
                "match_incidents": false,
                "match_infrastructures": false,
                "match_intrusionsets": false,
                "match_malware": false,
                "match_observables": false,
                "match_reportedfiles": false,
                "match_signatures": false,
                "match_tips": false,
                "match_tools": false,
                "match_ttps": false,
                "match_vulnerabilities": false,
                "matches": 0,
                "messages": [],
                "modified_ts": "2023-03-30T13:25:09.301784",
                "name": "rule_1",
                "notify_list_groups": [],
                "notify_me": true,
                "org_id": 11,
                "org_shared": false,
                "organization": {
                    "id": "11",
                    "name": "name",
                    "resource_uri": "resource_uri"
                },
                "resource_uri": "/api/v1/rule/55555/",
                "tags": [],
                "user": {
                    "avatar_s3_url": null,
                    "can_share_intelligence": false,
                    "email": "user@email.com",
                    "id": "111",
                    "is_active": true,
                    "is_readonly": false,
                    "must_change_password": false,
                    "name": "",
                    "nickname": null,
                    "organization": {
                        "id": "11",
                        "name": "name",
                        "resource_uri": "resource_uri"
                    },
                    "resource_uri": "/api/v1/user/111/"
                },
                "user_id": 111,
                "workgroups": []
            }
        ]
    }
}
```

#### Human Readable Output

>### Rules
>|Name|Id|Matches|Created At|Modified At|Is Notify Me|Is Enabled|
>|---|---|---|---|---|---|---|
>| rule_2 | 44444 | 0 | 2023-03-30T13:25:42.306343 | 2023-03-30T13:25:45.435220 | true | true |
>| rule_1 | 55555 | 0 | 2023-03-30T13:25:05.014893 | 2023-03-30T13:25:09.301784 | true | true |

### threatstream-create-rule

***
Create a rule in the ThreatStream platform.

#### Base Command

`threatstream-create-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule. | Required | 
| keywords | A comma-separated list of keywords for which you want the rule to match. Keywords added to rules must adhere to the following requirements: IP addresses must be expressed as regular expressions. IP subnets should be expressed using CIDR notation and not as regular expressions. Do not start or end keywords with *. Keywords must contain at least three characters. | Required | 
| match_include | A comma-separated list of fields you want the rule to match to their keywords. Possible values: observables, sandbox reports, threat bulletins, signatures, vulnerabilities. | Required | 
| actor_ids | A comma-separated list of IDs of the actors with which you want to associate matched entities. Use the threatstream-get-model-list command to get the actor IDs. | Optional | 
| campaign_ids | A comma-separated list of IDs of the campaigns with which you want to associate matched entities. Use the threatstream-get-model-list command to get the campaign IDs. | Optional | 
| investigation_action | The action you want to perform related to the investigation. Default is 'No Action'. Possible values are: Create New, Add To Existing, No Action. | Optional | 
| new_investigation_name | The investigation name. Required when 'Create New' is selected in the investigation_action argument. | Optional | 
| existing_investigation_id | Existing investigation ID. Required when 'Add To Existing' is selected in the investigation_action argument. Use the threatstream-list-investigation command to get the investigation ID. | Optional | 
| exclude_indicator | A comma-separated list of indicator types you want to exclude from rule matches. Example: actor_ipv6. | Optional | 
| include_indicator | A comma-separated list of indicator types you want to include from rule matches. Example: actor_ipv6. | Optional | 
| exclude_notify_org_whitelisted | Whether you want to exclude the rule from matching observables that are included in your organization whitelist. Possible values are: True, False. | Optional | 
| exclude_notify_owner_org | Whether you want to exclude keyword matches on observables imported by your organization from a keyword match or hourly digest email notifications. Possible values are: True, False. | Optional | 
| incident_ids | A comma-separated list of IDs of the incidents with which you want to associate matched entities. Use the threatstream-get-model-list command to get the incident IDs. | Optional | 
| malware_ids | A comma-separated list of IDs of the malwares with which you want to associate matched entities. Use the threatstream-get-model-list command to get the malware IDs. | Optional | 
| signature_ids | A comma-separated list of IDs of the signatures with which you want to associate matched entities. Use the threatstream-get-model-list command to get the signature IDs. | Optional | 
| threat_bulletin_ids | A comma-separated list of IDs of the threat bulletin with which you want to associate matched entities. Use the threatstream-get-model-list command to get the threat bulletin IDs. | Optional | 
| ttp_ids | A comma-separated list of IDs of the TTPs with which you want to associate matched entities. Use the threatstream-get-model-list command to get the TTPs IDs. | Optional | 
| vulnerability_ids | A comma-separated list of IDs of the vulnerabilities with which you want to associate matched entities. Use the threatstream-get-model-list command to get the vulnerabilities IDs. | Optional | 
| tags | A comma-separated list of IDs of the tags with which you want to associate matched entities. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.Rule.actors.id | String | Actor's ID associated with the rule. | 
| ThreatStream.Rule.actors.name | String | Actor's name associated with the rule. | 
| ThreatStream.Rule.actors.resource_uri | String | Actor's resource URI associated with the rule. | 
| ThreatStream.Rule.adv_keyword | Unknown | Advanced keyword or regular expression that the rule is designed to match. | 
| ThreatStream.Rule.attackpatterns | Unknown | Attack patterns associated with the rule. | 
| ThreatStream.Rule.backfill | Unknown | Objects that define additional filters or conditions for the rule. | 
| ThreatStream.Rule.campaigns.id | String | Campaign's ID associated with the rule. | 
| ThreatStream.Rule.campaigns.name | String | Campaign's name associated with the rule. | 
| ThreatStream.Rule.campaigns.resource_uri | String | Campaign's resource URI associated with the rule. | 
| ThreatStream.Rule.courseofaction | Unknown | Course of action entities associated with the rule. | 
| ThreatStream.Rule.create_investigation | Boolean | Whether an investigation should be created when the rule is triggered. | 
| ThreatStream.Rule.created_ts | Date | Rule creation time. | 
| ThreatStream.Rule.customtms | Unknown | Custom threat model entities associated with the rule. | 
| ThreatStream.Rule.description | Unknown | The rule description. | 
| ThreatStream.Rule.exclude_impacts | String | Indicator types that are excluded from rule matches. | 
| ThreatStream.Rule.exclude_notify_org_whitelisted | Boolean | Whether observables whitelisted by your organization are excluded from rule matches. | 
| ThreatStream.Rule.exclude_notify_owner_org | Boolean | Whether to exclude keyword matches on observables imported by your organization from keyword match or hourly digest email notifications. | 
| ThreatStream.Rule.id | Number | Unique ID assigned to the rule. | 
| ThreatStream.Rule.identities | Unknown | List of identities associated with the rule. | 
| ThreatStream.Rule.incidents.id | String | Incident's ID associated with the rule. | 
| ThreatStream.Rule.incidents.name | String | Incident's name associated with the rule. | 
| ThreatStream.Rule.incidents.resource_uri | String | Incident's resource URI associated with the rule. | 
| ThreatStream.Rule.infrastructure | Unknown | Infrastructure entities associated with the rule. | 
| ThreatStream.Rule.intelligence_initiatives | Unknown | Intelligence initiatives associated with the rule. | 
| ThreatStream.Rule.intrusionsets | Unknown | Intrusion sets associated with the rule. | 
| ThreatStream.Rule.investigation.assignee.assignee_type | String | Type of assignee: "user" or "tsworkgroup". | 
| ThreatStream.Rule.investigation.assignee.avatar_s3_url | Unknown | URL for the avatar image associated with the assignee user. | 
| ThreatStream.Rule.investigation.assignee.can_share_intelligence | Boolean | Whether the assignee user can share intelligence. | 
| ThreatStream.Rule.investigation.assignee.email | String | The email of the assignee user. | 
| ThreatStream.Rule.investigation.assignee.id | String | The ID of the assignee user. | 
| ThreatStream.Rule.investigation.assignee.is_active | Boolean | Whether the assignee user is active. | 
| ThreatStream.Rule.investigation.assignee.is_readonly | Boolean | Whether the assignee user should be restricted to Read Only status. | 
| ThreatStream.Rule.investigation.assignee.must_change_password | Boolean | Whether the assignee user will be forced to change their password the next time they log in. | 
| ThreatStream.Rule.investigation.assignee.name | String | The investigation assignee user name. | 
| ThreatStream.Rule.investigation.assignee.nickname | Unknown | The investigation assignee user nickname. | 
| ThreatStream.Rule.investigation.assignee.resource_uri | String | Resource URI associated with investigation assignee user. | 
| ThreatStream.Rule.investigation.investigation_config.name | String | The name of the investigation configuration associated with the rule. | 
| ThreatStream.Rule.investigation.id | String | The ID of the investigation. | 
| ThreatStream.Rule.investigation.name | String | The name of the investigation. | 
| ThreatStream.Rule.investigation.resource_uri | String | The resource URI of the investigation. | 
| ThreatStream.Rule.investigation.users | Unknown | List of users associated with the investigation created by the rule. | 
| ThreatStream.Rule.investigation.workgroups | Unknown | Assigned workgroups. | 
| ThreatStream.Rule.is_editable | Boolean | Indicates whether the imported rule can be updated by an intelligence source. | 
| ThreatStream.Rule.is_enabled | Boolean | Whether the rule is currently enabled. | 
| ThreatStream.Rule.keyword | String | Keyword associated with the rule. | 
| ThreatStream.Rule.keywords | String | A list of keywords associated with the rule. | 
| ThreatStream.Rule.malware.id | String | ID of the malware that associates to the rule. | 
| ThreatStream.Rule.malware.name | String | Name of the malware that associates to the rule. | 
| ThreatStream.Rule.malware.resource_uri | String | Resource URI of the malware that associates to the rule. | 
| ThreatStream.Rule.match_actors | Boolean | Whether the rule matches keywords in newly created actors. | 
| ThreatStream.Rule.match_all_tm | Boolean | Whether the rule should match against all threat models. | 
| ThreatStream.Rule.match_attackpatterns | Boolean | Whether the rule matches keywords in newly created attack patterns. | 
| ThreatStream.Rule.match_campaigns | Boolean | Whether the rule matches keywords in newly created campaigns. | 
| ThreatStream.Rule.match_courseofactions | Boolean | Whether the rule matches keywords in newly created course of actions. | 
| ThreatStream.Rule.match_customtms | Boolean | Whether the rule should match custom threat models. | 
| ThreatStream.Rule.match_identities | Boolean | Whether the rule matches keywords in newly created identities. | 
| ThreatStream.Rule.match_impacts | String | Indicator types in which you want to look for rule matches at the exclusion of all others. | 
| ThreatStream.Rule.match_incidents | Boolean | Whether the rule matches keywords in newly created incidents. | 
| ThreatStream.Rule.match_infrastructures | Boolean | Whether the rule matches keywords in newly created infrastructures. | 
| ThreatStream.Rule.match_intrusionsets | Boolean | Whether the rule matches keywords in newly created intrusion sets. | 
| ThreatStream.Rule.match_malware | Boolean | Whether the rule matches keywords in newly created malware. | 
| ThreatStream.Rule.match_observables | Boolean | Whether the rule matches keywords in newly created observables. | 
| ThreatStream.Rule.match_reportedfiles | Boolean | Whether the rule should match keywords in newly created sandbox reports. | 
| ThreatStream.Rule.match_signatures | Boolean | Whether the rule should match keywords in newly created signatures. | 
| ThreatStream.Rule.match_tips | Boolean | Whether the rule should match keywords in newly created threat bulletins. | 
| ThreatStream.Rule.match_tools | Boolean | Whether the rule should match keywords in newly created tools. | 
| ThreatStream.Rule.match_ttps | Boolean | Whether the rule should match keywords in newly created TTPs. | 
| ThreatStream.Rule.match_vulnerabilities | Boolean | Whether the rule should match keywords in newly created vulnerabilities. | 
| ThreatStream.Rule.matches | Number | Total number of keyword matches for the rule. | 
| ThreatStream.Rule.messages | Unknown | Messages or notifications generated by the rule. | 
| ThreatStream.Rule.modified_ts | Date | Timestamp of when the rule was last modified, in UTC format. | 
| ThreatStream.Rule.name | String | The rule name. | 
| ThreatStream.Rule.notify_list_groups | Unknown | List of groups that should be notified when the rule triggers an alert. | 
| ThreatStream.Rule.notify_me | Boolean | Whether the user who created the rule should be notified when the rule triggers an alert. | 
| ThreatStream.Rule.org_id | Number | ID associated with the organization that created the rule. | 
| ThreatStream.Rule.org_shared | Boolean | Whether a rule is shared across an organization. | 
| ThreatStream.Rule.organization.id | String | ID associated with the organization that created the rule. | 
| ThreatStream.Rule.organization.name | String | Name associated with the organization that created the rule. | 
| ThreatStream.Rule.organization.resource_uri | String | Resource URI associated with the organization that created the rule. | 
| ThreatStream.Rule.resource_uri | String | Resource URI associated with the rule. | 
| ThreatStream.Rule.signatures.id | String | ID of the signature that associates to the rule. | 
| ThreatStream.Rule.signatures.name | String | Name of the signature that associates to the rule. | 
| ThreatStream.Rule.signatures.resource_uri | String | Resource URI of the signature that associates to the rule. | 
| ThreatStream.Rule.tags.name | String | Name of the tag applied to matched entities. | 
| ThreatStream.Rule.tips.id | String | ID of the threat bulletin that associates to matched entities. | 
| ThreatStream.Rule.tips.name | String | Name of the threat bulletin that associates to matched entities. | 
| ThreatStream.Rule.tips.resource_uri | String | Resource URI of the threat bulletin that associates to matched entities. | 
| ThreatStream.Rule.tools | Unknown | List of tools associated with the rule. | 
| ThreatStream.Rule.ttps.id | String | ID of the TTPs that associates to the rule. | 
| ThreatStream.Rule.ttps.name | String | Name of the TTPs that associates to the rule. | 
| ThreatStream.Rule.ttps.resource_uri | String | Resource URI of the TTPs that associates to the rule. | 
| ThreatStream.Rule.user.avatar_s3_url | Unknown | URL for the avatar image associated with the user who created the rule. | 
| ThreatStream.Rule.user.can_share_intelligence | Boolean | Whether the assignee user can share intelligence. | 
| ThreatStream.Rule.user.email | String | Email of the user who created the rule. | 
| ThreatStream.Rule.user.id | String | ID of the user who created the rule. | 
| ThreatStream.Rule.user.is_active | Boolean | Whether the user who created the rule is active. | 
| ThreatStream.Rule.user.is_readonly | Boolean | Whether the user who created the rule should be restricted to Read Only status. | 
| ThreatStream.Rule.user.must_change_password | Boolean | Whether the user who created the rule will be forced to change their password the next time they log in. | 
| ThreatStream.Rule.user.name | String | Name of the user who created the rule. | 
| ThreatStream.Rule.user.nickname | String | Nickname of the user who created the rule. | 
| ThreatStream.Rule.user.organization.id | String | The ID associated with the organization. | 
| ThreatStream.Rule.user.organization.name | String | The user's organization name. | 
| ThreatStream.Rule.user.organization.resource_uri | String | The user's organization resource URI. | 
| ThreatStream.Rule.user.resource_uri | String | The user's resource URI. | 
| ThreatStream.Rule.user_id | Number | User ID of the user who created the rule. | 
| ThreatStream.Rule.vulnerabilities.id | String | ID of the vulnerability with which to associate matched entities. | 
| ThreatStream.Rule.vulnerabilities.name | String | Name of the vulnerability with which to associate matched entities. | 
| ThreatStream.Rule.vulnerabilities.resource_uri | String | ID of the vulnerability with which to associate matched entities. | 
| ThreatStream.Rule.workgroups | Unknown | Assigned workgroups. | 

#### Command example
```!threatstream-create-rule rule_name=test_rule keywords=some_keywords match_include=signatures```
#### Context Example
```json
{
    "ThreatStream": {
        "Rule": {
            "actors": [],
            "adv_keyword": null,
            "attackpatterns": [],
            "backfill": [],
            "campaigns": [],
            "courseofaction": [],
            "create_investigation": false,
            "created_ts": "2023-04-03T14:01:19.322247",
            "customtms": [],
            "description": null,
            "exclude_impacts": [],
            "exclude_notify_org_whitelisted": false,
            "exclude_notify_owner_org": false,
            "id": 14093,
            "identities": [],
            "incidents": [],
            "infrastructure": [],
            "intrusionsets": [],
            "investigation": null,
            "is_editable": true,
            "is_enabled": true,
            "keyword": "some_keywords",
            "keywords": [
                "some_keywords"
            ],
            "malware": [],
            "match_actors": false,
            "match_all_tm": false,
            "match_attackpatterns": false,
            "match_campaigns": false,
            "match_courseofactions": false,
            "match_customtms": false,
            "match_identities": false,
            "match_impacts": [],
            "match_incidents": false,
            "match_infrastructures": false,
            "match_intrusionsets": false,
            "match_malware": false,
            "match_observables": false,
            "match_reportedfiles": false,
            "match_signatures": true,
            "match_tips": false,
            "match_tools": false,
            "match_ttps": false,
            "match_vulnerabilities": false,
            "matches": 0,
            "messages": [],
            "modified_ts": "2023-04-03T14:01:19.322261",
            "name": "test_rule",
            "notify_list_groups": [],
            "notify_me": true,
            "org_id": 11,
            "org_shared": false,
            "organization": {
                "id": "11",
                "name": "name",
                "resource_uri": "resource_uri"
            },
            "resource_uri": "/api/v1/rule/14093/",
            "signatures": [],
            "tags": [],
            "tips": [],
            "tools": [],
            "ttps": [],
            "user": {
                "avatar_s3_url": null,
                "can_share_intelligence": false,
                "email": "user@email.com",
                "id": "111",
                "is_active": true,
                "is_readonly": false,
                "must_change_password": false,
                "name": "",
                "nickname": null,
                "organization": {
                    "id": "11",
                    "name": "name",
                    "resource_uri": "resource_uri"
                },
                "resource_uri": "/api/v1/user/111/"
            },
            "user_id": 111,
            "vulnerabilities": [],
            "workgroups": []
        }
    }
}
```

#### Human Readable Output

>The rule was created successfully with id: 14093.
### threatstream-update-rule

***
Updates existing rule from ThreatStream.

Note: Executing this command will overwrite any existing values.
#### Base Command

`threatstream-update-rule`


#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | The rule ID. | Required | 
| rule_name | The rule name. | Optional | 
| keywords | A comma-separated list of keywords for which you want the rule to match. Keywords added to rules must adhere to the following requirements: IP addresses must be expressed as regular expressions. IP subnets should be expressed using CIDR notation and not as regular expressions. Do not start or end keywords with *. Keywords must contain at least three characters. | Optional | 
| match_include | A comma-separated list of fields you want the rule to match to their keywords. Possible values: observables, sandbox reports, threat bulletins, signatures, vulnerabilities. | Optional | 
| actor_ids | A comma-separated list of IDs of the actors with which you want to associate matched entities. Use the threatstream-get-model-list command to get the actor IDs. | Optional | 
| campaign_ids | A comma-separated list of IDs of the campaigns with which you want to associate matched entities. Use the threatstream-get-model-list command to get the campaign IDs. | Optional | 
| investigation_action | The action you want to perform related to the investigation. Default is 'No Action'. Possible values are: Create New, Add To Existing, No Action. | Optional | 
| new_investigation_name | The investigation name. Required when 'Create New' is selected in the investigation_action argument. | Optional | 
| existing_investigation_id | Existing investigation ID. Required when 'Add To Existing' is selected in the investigation_action argument. Use the threatstream-list-investigation command to get the investigation ID. | Optional | 
| exclude_indicator | A comma-separated list of indicator types you want to exclude from rule matches. | Optional | 
| include_indicator | A comma-separated list of indicator types you want to include from rule matches. | Optional | 
| exclude_notify_org_whitelisted | Whether observables whitelisted by your organization are excluded from rule matches. Possible values are: True, False. | Optional | 
| exclude_notify_owner_org | Whether you want to exclude keyword matches on observables imported by your organization from a keyword match or hourly digest email notifications. Possible values are: True, False. Default is False. | Optional | 
| incident_ids | A comma-separated list of IDs of the incidents with which you want to associate matched entities. Use the threatstream-get-model-list command to get the incident IDs. | Optional | 
| malware_ids | A comma-separated list of IDs of the malwares with which you want to associate matched entities. Use the threatstream-get-model-list command to get the malware IDs. | Optional | 
| signature_ids | A comma-separated list of IDs of the signatures with which you want to associate matched entities. Use the threatstream-get-model-list command to get the signature IDs. | Optional | 
| threat_bulletin_ids | A comma-separated list of IDs of the threat bulletin with which you want to associate matched entities. Use the threatstream-get-model-list command to get the threat bulletin IDs. | Optional | 
| ttp_ids | A comma-separated list of IDs of the TTPs with which you want to associate matched entities. Use the threatstream-get-model-list command to get the TTPs IDs. | Optional | 
| vulnerability_ids | A comma-separated list of IDs of the vulnerabilities with which you want to associate matched entities. Use the threatstream-get-model-list command to get the vulnerabilities IDs. | Optional | 
| tags | A comma-separated list of tags. For example, tag1,tag2. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.Rule.actors.id | String | Actor's ID associated with the rule. | 
| ThreatStream.Rule.actors.name | String | Actor's name associated with the rule. | 
| ThreatStream.Rule.actors.resource_uri | String | Actor's resource URI associated with the rule. | 
| ThreatStream.Rule.adv_keyword | Unknown | Advanced keyword or regular expression that the rule is designed to match. | 
| ThreatStream.Rule.attackpatterns | Unknown | Attack patterns associated with the rule. | 
| ThreatStream.Rule.backfill | Unknown | Objects that define additional filters or conditions for the rule. | 
| ThreatStream.Rule.campaigns.id | String | Campaign's ID associated with the rule. | 
| ThreatStream.Rule.campaigns.name | String | Campaign's name associated with the rule. | 
| ThreatStream.Rule.campaigns.resource_uri | String | Campaign's resource URI associated with the rule. | 
| ThreatStream.Rule.courseofaction | Unknown | Course of action entities associated with the rule. | 
| ThreatStream.Rule.create_investigation | Boolean | Whether an investigation should be created when the rule is triggered. | 
| ThreatStream.Rule.created_ts | Date | Rule creation time. | 
| ThreatStream.Rule.customtms | Unknown | Custom threat model entities associated with the rule. | 
| ThreatStream.Rule.description | String | The rule description. | 
| ThreatStream.Rule.exclude_impacts | String | Indicator types that are excluded from rule matches. | 
| ThreatStream.Rule.exclude_notify_org_whitelisted | Boolean | Whether observables whitelisted by your organization are excluded from rule matches. | 
| ThreatStream.Rule.exclude_notify_owner_org | Boolean | Whether to exclude keyword matches on observables imported by your organization from keyword match or hourly digest email notifications. | 
| ThreatStream.Rule.id | Number | Unique ID assigned to the rule. | 
| ThreatStream.Rule.identities | Unknown | List of identities associated with the rule. | 
| ThreatStream.Rule.incidents.id | String | Incident's ID associated with the rule. | 
| ThreatStream.Rule.incidents.name | String | Incident's name associated with the rule. | 
| ThreatStream.Rule.incidents.resource_uri | String | Incident's resource URI associated with the rule. | 
| ThreatStream.Rule.infrastructure | Unknown | Infrastructure entities associated with the rule. | 
| ThreatStream.Rule.intelligence_initiatives | Unknown | Intelligence initiatives associated with the rule. | 
| ThreatStream.Rule.intrusionsets | Unknown | Intrusion sets associated with the rule. | 
| ThreatStream.Rule.investigation.assignee.assignee_type | String | Type of assignee: "user" or "tsworkgroup". | 
| ThreatStream.Rule.investigation.assignee.avatar_s3_url | Unknown | URL for the avatar image associated with the assignee user. | 
| ThreatStream.Rule.investigation.assignee.can_share_intelligence | Boolean | Whether the assignee user can share intelligence. | 
| ThreatStream.Rule.investigation.assignee.email | String | The email of the assignee user. | 
| ThreatStream.Rule.investigation.assignee.id | String | The ID of the assignee user. | 
| ThreatStream.Rule.investigation.assignee.is_active | Boolean | Whether the assignee user is active. | 
| ThreatStream.Rule.investigation.assignee.is_readonly | Boolean | Whether the assignee user should be restricted to Read Only status. | 
| ThreatStream.Rule.investigation.assignee.must_change_password | Boolean | Whether the assignee user will be forced to change their password the next time they log in. | 
| ThreatStream.Rule.investigation.assignee.name | String | The investigation assignee user name. | 
| ThreatStream.Rule.investigation.assignee.nickname | Unknown | The investigation assignee user nickname. | 
| ThreatStream.Rule.investigation.assignee.resource_uri | String | Resource URI associated with investigation assignee user. | 
| ThreatStream.Rule.investigation.investigation_config.name | String | The name of the investigation configuration associated with the rule. | 
| ThreatStream.Rule.investigation.id | String | The ID of the investigation. | 
| ThreatStream.Rule.investigation.name | String | The name of the investigation. | 
| ThreatStream.Rule.investigation.resource_uri | String | The resource URI of the investigation. | 
| ThreatStream.Rule.investigation.users | Unknown | List of users associated with the investigation created by the rule. | 
| ThreatStream.Rule.investigation.workgroups | Unknown | Assigned workgroups. | 
| ThreatStream.Rule.is_editable | Boolean | Indicates whether the imported entity can be updated by an intelligence source. | 
| ThreatStream.Rule.is_enabled | Boolean | Whether the rule is currently enabled. | 
| ThreatStream.Rule.keyword | String | Keyword associated with the rule. | 
| ThreatStream.Rule.keywords | String | A list of keywords associated with the rule. | 
| ThreatStream.Rule.malware.id | String | ID of the malware that associates to the rule. | 
| ThreatStream.Rule.malware.name | String | Name of the malware that associates to the rule. | 
| ThreatStream.Rule.malware.resource_uri | String | Resource URI of the malware that associates to the rule. | 
| ThreatStream.Rule.match_actors | Boolean | Whether the rule matches keywords in newly created actors. | 
| ThreatStream.Rule.match_all_tm | Boolean | Whether the rule should match against all threat models. | 
| ThreatStream.Rule.match_attackpatterns | Boolean | Whether the rule matches keywords in newly created attack patterns. | 
| ThreatStream.Rule.match_campaigns | Boolean | Whether the rule matches keywords in newly created campaigns. | 
| ThreatStream.Rule.match_courseofactions | Boolean | Whether the rule matches keywords in newly created course of action. | 
| ThreatStream.Rule.match_customtms | Boolean | Whether the rule should match custom threat models. | 
| ThreatStream.Rule.match_identities | Boolean | Whether the rule matches keywords in newly created identities. | 
| ThreatStream.Rule.match_impacts | String | Indicator types in which you want to look for rule matches at the exclusion of all others. | 
| ThreatStream.Rule.match_incidents | Boolean | Whether the rule matches keywords in newly created incidents. | 
| ThreatStream.Rule.match_infrastructures | Boolean | Whether the rule matches keywords in newly created infrastructures. | 
| ThreatStream.Rule.match_intrusionsets | Boolean | Whether the rule matches keywords in newly created intrusion sets. | 
| ThreatStream.Rule.match_malware | Boolean | Whether the rule matches keywords in newly created malware. | 
| ThreatStream.Rule.match_observables | Boolean | Whether the rule matches keywords in newly created observables. | 
| ThreatStream.Rule.match_reportedfiles | Boolean | Whether the rule should match keywords in newly created sandbox reports. | 
| ThreatStream.Rule.match_signatures | Boolean | Whether the rule should match keywords in newly created signatures. | 
| ThreatStream.Rule.match_tips | Boolean | Whether the rule should match keywords in newly created threat bulletins. | 
| ThreatStream.Rule.match_tools | Boolean | Whether the rule should match keywords in newly created tools. | 
| ThreatStream.Rule.match_ttps | Boolean | Whether the rule should match keywords in newly created TTPs. | 
| ThreatStream.Rule.match_vulnerabilities | Boolean | Whether the rule should match keywords in newly created vulnerabilities. | 
| ThreatStream.Rule.matches | Number | Total number of keyword matches for the rule. | 
| ThreatStream.Rule.messages | Unknown | Messages or notifications generated by the rule. | 
| ThreatStream.Rule.modified_ts | Date | Timestamp of when the rule was last modified, in UTC format. | 
| ThreatStream.Rule.name | String | The rule name. | 
| ThreatStream.Rule.notify_list_groups | Unknown | List of groups that should be notified when the rule triggers an alert. | 
| ThreatStream.Rule.notify_me | Boolean | Whether the user who created the rule should be notified when the rule triggers an alert. | 
| ThreatStream.Rule.org_id | Number | ID associated with the organization that created the rule. | 
| ThreatStream.Rule.org_shared | Boolean | Whether a rule is shared across an organization. | 
| ThreatStream.Rule.organization.id | String | ID associated with the organization that created the rule. | 
| ThreatStream.Rule.organization.name | String | Name associated with the organization that created the rule. | 
| ThreatStream.Rule.organization.resource_uri | String | Resource URI associated with the organization that created the rule. | 
| ThreatStream.Rule.resource_uri | String | Resource URI associated with the rule. | 
| ThreatStream.Rule.signatures.id | String | ID of the signature that associates to the rule. | 
| ThreatStream.Rule.signatures.name | String | Name of the signature that associates to the rule. | 
| ThreatStream.Rule.signatures.resource_uri | String | Resource URI of the signature that associates to the rule. | 
| ThreatStream.Rule.tags.name | String | Name of the tag applied to matched entities. | 
| ThreatStream.Rule.tips.id | String | ID of the threat bulletin that associates to matched entities. | 
| ThreatStream.Rule.tips.name | String | Name of the threat bulletin that associates to matched entities. | 
| ThreatStream.Rule.tips.resource_uri | String | Resource URI of the threat bulletin that associates to matched entities. | 
| ThreatStream.Rule.tools | Unknown | List of tools associated with the rule. | 
| ThreatStream.Rule.ttps.id | String | ID of the TTPs that associates to the rule. | 
| ThreatStream.Rule.ttps.name | String | Name of the TTPs that associates to the rule. | 
| ThreatStream.Rule.ttps.resource_uri | String | Resource URI of the TTPs that associates to the rule. | 
| ThreatStream.Rule.user.avatar_s3_url | Unknown | URL for the avatar image associated with the user who created the rule. | 
| ThreatStream.Rule.user.can_share_intelligence | Boolean | Whether the user who created the rule can share intelligence. | 
| ThreatStream.Rule.user.email | String | Email of the user who created the rule. | 
| ThreatStream.Rule.user.id | String | ID of the user who created the rule. | 
| ThreatStream.Rule.user.is_active | Boolean | Whether the user who created the rule is active. | 
| ThreatStream.Rule.user.is_readonly | Boolean | Whether the user who created the rule should be restricted to Read Only status. | 
| ThreatStream.Rule.user.must_change_password | Boolean | Whether the user who created the rule will be forced to change their password the next time they log in. | 
| ThreatStream.Rule.user.name | String | Name of the user who created the rule. | 
| ThreatStream.Rule.user.nickname | String | Nickname of the user who created the rule. | 
| ThreatStream.Rule.user.organization.id | String | The ID associated with the organization. | 
| ThreatStream.Rule.user.organization.name | String | The user's organization name. | 
| ThreatStream.Rule.user.organization.resource_uri | String | The user's organization resource URI. | 
| ThreatStream.Rule.user.resource_uri | String | The user's resource URI. | 
| ThreatStream.Rule.user_id | Number | User ID of the user who created the rule. | 
| ThreatStream.Rule.vulnerabilities.id | String | ID of the vulnerability with which to associate matched entities. | 
| ThreatStream.Rule.vulnerabilities.name | String | Name of the vulnerability with which to associate matched entities. | 
| ThreatStream.Rule.vulnerabilities.resource_uri | String | Resource URI of the vulnerability with which to associate matched entities. | 
| ThreatStream.Rule.workgroups | Unknown | Assigned workgroups. | 

#### Command example
```!threatstream-update-rule rule_id=14093 keywords=some_keywords match_include=signatures ```
#### Context Example
```json
{
    "ThreatStream": {
        "Rule": {
            "actors": [],
            "adv_keyword": null,
            "attackpatterns": [],
            "backfill": [],
            "campaigns": [],
            "courseofaction": [],
            "create_investigation": false,
            "created_ts": "2023-04-03T14:01:19.321124",
            "customtms": [],
            "description": null,
            "exclude_impacts": [],
            "exclude_notify_org_whitelisted": false,
            "exclude_notify_owner_org": false,
            "id": 14093,
            "identities": [],
            "incidents": [],
            "infrastructure": [],
            "intrusionsets": [],
            "investigation": null,
            "is_editable": true,
            "is_enabled": true,
            "keyword": "some_keywords",
            "keywords": [
                "some_keywords"
            ],
            "malware": [],
            "match_actors": false,
            "match_all_tm": false,
            "match_attackpatterns": false,
            "match_campaigns": false,
            "match_courseofactions": false,
            "match_customtms": false,
            "match_identities": false,
            "match_impacts": [],
            "match_incidents": false,
            "match_infrastructures": false,
            "match_intrusionsets": false,
            "match_malware": false,
            "match_observables": false,
            "match_reportedfiles": false,
            "match_signatures": true,
            "match_tips": false,
            "match_tools": false,
            "match_ttps": false,
            "match_vulnerabilities": false,
            "matches": 0,
            "messages": [],
            "modified_ts": "2023-04-03T14:02:45.179609",
            "name": "test_rule",
            "notify_list_groups": [],
            "notify_me": true,
            "org_id": 11,
            "org_shared": false,
            "organization": {
                "id": "11",
                "name": "name",
                "resource_uri": "resource_uri"
            },
            "resource_uri": "/api/v1/rule/14093/",
            "signatures": [],
            "tags": [],
            "tips": [],
            "tools": [],
            "ttps": [],
            "user": {
                "avatar_s3_url": null,
                "can_share_intelligence": false,
                "email": "user@email.com",
                "id": "111",
                "is_active": true,
                "is_readonly": false,
                "must_change_password": false,
                "name": "",
                "nickname": null,
                "organization": {
                    "id": "11",
                    "name": "name",
                    "resource_uri": "resource_uri"
                },
                "resource_uri": "/api/v1/user/111/"
            },
            "user_id": 111,
            "vulnerabilities": [],
            "workgroups": []
        }
    }
}
```

#### Human Readable Output

>### Rules
>|Name|Id|Matches|Created At|Modified At|Is Notify Me|Is Enabled|
>|---|---|---|---|---|---|---|
>| test_rule | 14093 | 0 | 2023-04-03T14:01:19.321124 | 2023-04-03T14:02:45.179609 | true | true |

### threatstream-delete-rule

***
Delete a rule from ThreatStream.

#### Base Command

`threatstream-delete-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | The rule ID. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!threatstream-delete-rule rule_id=14093```
#### Human Readable Output

>The rule was deleted successfully.
### threatstream-list-user

***
Gets list of users from ThreatStream. Only users with org admin permission can run this command.

##### Required Permissions

`org admin`

#### Base Command

`threatstream-list-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | ID of the user. If specified, returns the specific user. | Optional | 
| limit | The maximum number of results to return. Default is 50. | Optional | 
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of objects to retrieve per page. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.User.avatar_s3_url | String | URL for the avatar image associated with the user. | 
| ThreatStream.User.can_approve_intel | Boolean | Whether the user can approve intel. | 
| ThreatStream.User.can_import_to_taxii_inbox | Boolean | Whether the user can import to TAXII inbox. | 
| ThreatStream.User.can_see_api_key | Boolean | Whether the user can see the API key. | 
| ThreatStream.User.can_share_intelligence | Boolean | Whether the user can share intelligence. | 
| ThreatStream.User.can_submit_sandbox | Boolean | Whether the user can submit a sandbox. | 
| ThreatStream.User.can_use_chat | Boolean | Whether the user can use chat. | 
| ThreatStream.User.can_use_match | Boolean | Whether the user can use match. | 
| ThreatStream.User.date_joined | Date | Timestamp when the user was added to ThreatStream. | 
| ThreatStream.User.date_password_changed | Unknown | Timestamp when the user last changed their password. | 
| ThreatStream.User.email | String | The user email. | 
| ThreatStream.User.is_active | Boolean | Whether the user is active. | 
| ThreatStream.User.is_locked | Boolean | Whether the user is currently locked. | 
| ThreatStream.User.is_org_admin | Boolean | Whether the user is an Org Admin. | 
| ThreatStream.User.is_readonly | Boolean | Whether the user should be restricted to Read Only status. | 
| ThreatStream.User.is_tfa_exempt | Boolean | Whether the user is excluded from having to use multi-factor authentication. | 
| ThreatStream.User.last_access_ts | Date | Timestamp when the user last accessed ThreatStream. | 
| ThreatStream.User.last_login | Unknown | Timestamp when the user was last authenticated to ThreatStream. | 
| ThreatStream.User.must_change_password | Boolean | Whether the user will be forced to change their password the next time they log in. | 
| ThreatStream.User.name | String | Name entered by the user on the My Profile tab within ThreatStream settings. | 
| ThreatStream.User.next_password_change_ts | Unknown | Future timestamp when the user will be forced to change their password. | 
| ThreatStream.User.nickname | String | The user nickname. | 
| ThreatStream.User.resource_uri | String | Resource URI of the user. | 
| ThreatStream.User.user_id | String | ID of the user. | 

#### Command example
```!threatstream-list-user```
#### Context Example
```json
{
    "ThreatStream": {
        "User": [
            {
                "avatar_s3_url": "",
                "can_approve_intel": true,
                "can_import_to_taxii_inbox": false,
                "can_see_api_key": true,
                "can_share_intelligence": false,
                "can_submit_sandbox": true,
                "can_use_chat": false,
                "can_use_match": true,
                "date_joined": "2020-08-26T12:54:37",
                "date_password_changed": null,
                "email": "user@email.com",
                "is_active": true,
                "is_locked": false,
                "is_org_admin": true,
                "is_readonly": false,
                "is_tfa_exempt": false,
                "last_access_ts": "2023-04-03T14:02:59.193422",
                "last_login": "2023-03-30T10:36:23.792915",
                "must_change_password": false,
                "name": "",
                "next_password_change_ts": null,
                "nickname": "",
                "resource_uri": "/api/v1/orgadmin/111/",
                "user_id": "111"
            },
            {
                "avatar_s3_url": "",
                "can_approve_intel": false,
                "can_import_to_taxii_inbox": false,
                "can_see_api_key": true,
                "can_share_intelligence": false,
                "can_submit_sandbox": false,
                "can_use_chat": false,
                "can_use_match": true,
                "date_joined": "2022-08-26T16:51:25",
                "date_password_changed": null,
                "email": "user@email.com",
                "is_active": true,
                "is_locked": false,
                "is_org_admin": false,
                "is_readonly": false,
                "is_tfa_exempt": false,
                "last_access_ts": "1970-01-01T00:00:00",
                "last_login": null,
                "must_change_password": true,
                "name": "",
                "next_password_change_ts": null,
                "nickname": "",
                "resource_uri": "/api/v1/orgadmin/222/",
                "user_id": "222"
            },
            {
                "avatar_s3_url": "",
                "can_approve_intel": true,
                "can_import_to_taxii_inbox": false,
                "can_see_api_key": true,
                "can_share_intelligence": false,
                "can_submit_sandbox": true,
                "can_use_chat": false,
                "can_use_match": true,
                "date_joined": "2020-08-26T12:53:08",
                "date_password_changed": null,
                "email": "user@email.com",
                "is_active": true,
                "is_locked": false,
                "is_org_admin": false,
                "is_readonly": false,
                "is_tfa_exempt": false,
                "last_access_ts": "2023-03-30T10:36:06.847434",
                "last_login": "2023-03-26T10:47:59.037318",
                "must_change_password": false,
                "name": "",
                "next_password_change_ts": null,
                "nickname": "",
                "resource_uri": "/api/v1/orgadmin/333/",
                "user_id": "333"
            }
        ]
    }
}
```

#### Human Readable Output

>### Users
>|User Id|Email|Is Active|Last Login|
>|---|---|---|---|
>| 111 | user@email.com | true | 2023-03-30T10:36:23.792915 |
>| 222 | user@email.com | true |  |
>| 333 | user@email.com | true | 2023-03-26T10:47:59.037318 |

### threatstream-list-investigation

***
Gets a list of investigations from ThreatStream.

#### Base Command

`threatstream-list-investigation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| investigation_id | ID of the investigation. If specified, returns the specific investigation. | Optional | 
| limit | The maximum number of results to return. Default is 50. | Optional | 
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of objects to retrieve per page. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.Investigation.assignee.assignee_type | String | Type of assignee: "user" or "tsworkgroup". | 
| ThreatStream.Investigation.assignee.avatar_s3_url | Unknown | URL for the avatar image associated with the assignee user. | 
| ThreatStream.Investigation.assignee.can_share_intelligence | Boolean | Whether the assignee user can share intelligence. | 
| ThreatStream.Investigation.assignee.email | String | The email of the assignee user. | 
| ThreatStream.Investigation.assignee.id | String | The ID of the assignee user. | 
| ThreatStream.Investigation.assignee.is_active | Boolean | Whether the assignee user is active. | 
| ThreatStream.Investigation.assignee.is_readonly | Boolean | Whether the assignee user should be restricted to Read Only status. | 
| ThreatStream.Investigation.assignee.must_change_password | Boolean | Whether the assignee user will be forced to change their password the next time they log in. | 
| ThreatStream.Investigation.assignee.name | String | The investigation assignee user name. | 
| ThreatStream.Investigation.assignee.nickname | Unknown | The investigation assignee user nickname. | 
| ThreatStream.Investigation.assignee.resource_uri | String | Resource URI associated with the investigation assignee user. | 
| ThreatStream.Investigation.attachments | Unknown | The investigation attachments. | 
| ThreatStream.Investigation.candidate_session | Unknown | Investigation candidate session details. | 
| ThreatStream.Investigation.circles | Unknown | IDs of the trusted circles with which the investigation is shared. | 
| ThreatStream.Investigation.created_ts | Date | Timestamp when the investigation was created. | 
| ThreatStream.Investigation.description | String | The investigation description. | 
| ThreatStream.Investigation.elements | Number | The number of elements associated with the investigation. | 
| ThreatStream.Investigation.graph_content | Boolean | The investigation graph content details. | 
| ThreatStream.Investigation.id | Number | The ID of the investigation. | 
| ThreatStream.Investigation.intelligence_initiatives | Unknown | Intelligence initiatives associated with the investigation. | 
| ThreatStream.Investigation.investigation_attachments | Unknown | List of attachments that are associated with the investigation. | 
| ThreatStream.Investigation.is_public | Boolean | Whether the entity is public or private. | 
| ThreatStream.Investigation.modified_ts | Date | The date the investigation was modified. | 
| ThreatStream.Investigation.name | String | The investigation name. | 
| ThreatStream.Investigation.owner_org.id | String | The owner organization ID. | 
| ThreatStream.Investigation.owner_org.name | String | The owner organization name. | 
| ThreatStream.Investigation.owner_org.resource_uri | String | The owner organization resource URI. | 
| ThreatStream.Investigation.owner_org_id | Unknown | The owner organization ID. | 
| ThreatStream.Investigation.pending_import_sessions | Unknown | Number of sessions that are currently waiting to be imported into the investigation. | 
| ThreatStream.Investigation.priority | String | The priority of the investigation. | 
| ThreatStream.Investigation.reporter.email | String | Email address of the user who created the investigation. | 
| ThreatStream.Investigation.reporter.id | String | ID of the user who created the investigation. | 
| ThreatStream.Investigation.reporter.name | String | Name of the user who created the investigation. | 
| ThreatStream.Investigation.reporter.resource_uri | String | Resource URI of the user who created the investigation. | 
| ThreatStream.Investigation.reporter_id | Number | ID of the user who created the investigation. | 
| ThreatStream.Investigation.resource_uri | String | The investigation resource URI. | 
| ThreatStream.Investigation.source_type | String | The type of source used to create the investigation. | 
| ThreatStream.Investigation.status | String | The investigation status. | 
| ThreatStream.Investigation.tags | String | The tags associated with the investigation. | 
| ThreatStream.Investigation.tasks | Unknown | Tasks associated with the investigation. | 
| ThreatStream.Investigation.tlp | String | Traffic Light Protocol designation for the investigation—red, amber, green, white. | 
| ThreatStream.Investigation.users | Unknown | List of users associated with the investigation. | 
| ThreatStream.Investigation.workgroups | Unknown | Assigned workgroups. | 

#### Command example
```!threatstream-list-investigation page=2 page_size=2```
#### Context Example
```json
{
    "ThreatStream": {
        "Investigation": [
            {
                "assignee": null,
                "circles": [],
                "created_ts": "2023-03-30T11:04:35.320726",
                "id": 111,
                "intelligence_initiatives": [],
                "is_public": false,
                "modified_ts": "2023-03-30T11:04:38.416192",
                "name": "investigation_1",
                "owner_org": {
                    "id": "11",
                    "name": "name",
                    "resource_uri": "resource_uri"
                },
                "owner_org_id": null,
                "priority": "medium",
                "reporter": {
                    "email": "user@email.com",
                    "id": "111",
                    "name": "",
                    "resource_uri": "/api/v1/user/111/"
                },
                "reporter_id": 111,
                "resource_uri": "/api/v1/investigation/111/",
                "source_type": "user",
                "status": "in-progress",
                "tags": [
                    "tag1",
                    "tag2"
                ],
                "tlp": "green",
                "workgroups": []
            },
            {
                "assignee": null,
                "circles": [],
                "created_ts": "2023-03-30T11:03:54.265766",
                "id": 222,
                "intelligence_initiatives": [],
                "is_public": false,
                "modified_ts": "2023-03-30T11:03:57.703889",
                "name": "investigation_2",
                "owner_org": {
                    "id": "11",
                    "name": "name",
                    "resource_uri": "resource_uri"
                },
                "owner_org_id": null,
                "priority": "medium",
                "reporter": {
                    "email": "user@email.com",
                    "id": "111",
                    "name": "",
                    "resource_uri": "/api/v1/user/111/"
                },
                "reporter_id": 111,
                "resource_uri": "/api/v1/investigation/222/",
                "source_type": "user",
                "status": "in-progress",
                "tags": [
                    "tag1",
                    "tag2"
                ],
                "tlp": "green",
                "workgroups": []
            }
        ]
    }
}
```

#### Human Readable Output

>### Investigations
>|Name|Id|Created At|Status|Source Type|Reporter|
>|---|---|---|---|---|---|
>| investigation_1 | 111 | 2023-03-30T11:04:35.320726 | in-progress | user | user@email.com |
>| investigation_2 | 222 | 2023-03-30T11:03:54.265766 | in-progress | user | user@email.com |

### threatstream-create-investigation

***
Create an investigation at ThreatStream.

#### Base Command

`threatstream-create-investigation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the investigation. | Required | 
| description | The description of the investigation. | Optional | 
| priority | The priority of the investigation. Possible values are: Very Low, Low, Medium, High, Very High. | Optional | 
| status | The status of the investigation. Possible values are: Completed, In-Progress, Pending, Unassigned. | Optional | 
| tags | A comma-separated list of tags. For example, tag1,tag2. | Optional | 
| tlp | tlp. Possible values are: White, Green, Amber, Red. | Optional | 
| assignee_id | Assignee ID. Use the threatstream-list-user command to get the user ID value. | Optional | 
| connect_related_indicators | When enabled, observables related to the entity you are associating with the investigation are also added. Possible values are: True, False. | Optional | 
| associated_actor_ids | A comma-separated list of IDs of the actors with which you want to associate matched entities. Use the threatstream-get-model-list command to get the actor IDs. | Optional | 
| associated_campaign_ids | A comma-separated list of IDs of the campaigns with which you want to associate matched entities. Use the threatstream-get-model-list command to get the campaign IDs. | Optional | 
| associated_incident_ids | A comma-separated list of IDs of the incidents with which you want to associate matched entities. Use the threatstream-get-model-list command to get the incident IDs. | Optional | 
| associated_observable_ids | A comma-separated list of IDs of the observables with which you want to associate matched entities. Use the threatstream-get-indicators command to get the observable IDs. | Optional | 
| associated_signature_ids | A comma-separated list of IDs of the signatures with which you want to associate matched entities. Use the threatstream-get-model-list command to get the signature IDs. | Optional | 
| associated_threat_bulletin_ids | A comma-separated list of IDs of the threat bulletin with which you want to associate matched entities. Use the threatstream-get-model-list command to get the threat bulletin IDs. | Optional | 
| associated_ttp_ids | A comma-separated list of IDs of the TTPs with which you want to associate matched entities. Use the threatstream-get-model-list command to get the TTPs IDs. | Optional | 
| associated_vulnerability_ids | A comma-separated list of IDs of the vulnerabilities with which you want to associate matched entities. Use the threatstream-get-model-list command to get the vulnerabilities IDs. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.Investigation.add_related_indicators | Number | Whether to add related indicators to the investigation. | 
| ThreatStream.Investigation.added_elements_count | Number | Number of elements added to the investigation. | 
| ThreatStream.Investigation.all_added | Boolean | Whether all the elements were added. | 
| ThreatStream.Investigation.already_exists_elements_count | Number | Number of elements that already exists. | 
| ThreatStream.Investigation.assignee.assignee_type | String | Type of assignee: "user" or "tsworkgroup". | 
| ThreatStream.Investigation.assignee.avatar_s3_url | Unknown | URL for the avatar image associated with the assignee user. | 
| ThreatStream.Investigation.assignee.can_share_intelligence | Boolean | Whether the assignee user can share intelligence. | 
| ThreatStream.Investigation.assignee.email | String | The email of the assignee user. | 
| ThreatStream.Investigation.assignee.id | String | The ID of the assignee user. | 
| ThreatStream.Investigation.assignee.is_active | Boolean | Whether the assignee user is active. | 
| ThreatStream.Investigation.assignee.is_readonly | Boolean | Whether the assignee user should be restricted to Read Only status. | 
| ThreatStream.Investigation.assignee.must_change_password | Boolean | Whether the assignee user will be forced to change their password the next time they log in. | 
| ThreatStream.Investigation.assignee.name | String | The investigation assignee user name. | 
| ThreatStream.Investigation.assignee.nickname | Unknown | The investigation assignee user nickname. | 
| ThreatStream.Investigation.assignee.resource_uri | String | Resource URI associated with the investigation assignee user. | 
| ThreatStream.Investigation.assignee_id | Number | ID of the user or workgroup to which the investigation is assigned. | 
| ThreatStream.Investigation.assignee_type | String | Type of assignee: "user" or "tsworkgroup". | 
| ThreatStream.Investigation.circles | Unknown | The trusted circles with which the investigation is shared. | 
| ThreatStream.Investigation.created_ts | Date | Timestamp when the investigation was created. | 
| ThreatStream.Investigation.description | String | The investigation description. | 
| ThreatStream.Investigation.elements.add_related_indicators | Number | Whether to add related indicators to the investigation. | 
| ThreatStream.Investigation.elements.entity.assignee_user | Unknown | The assignee user. | 
| ThreatStream.Investigation.elements.entity.created_ts | Date | Timestamp when the entity was created. | 
| ThreatStream.Investigation.elements.entity.feed_id | Number | The feed ID of the entity. | 
| ThreatStream.Investigation.elements.entity.id | Number | Unique ID assigned for the entity. | 
| ThreatStream.Investigation.elements.entity.intelligence_initiatives | Unknown | Intelligence initiatives associated with the investigation. | 
| ThreatStream.Investigation.elements.entity.is_anonymous | Boolean | Whether the entity is anonymous. | 
| ThreatStream.Investigation.elements.entity.is_cloneable | String | Whether the entity is cloneable. | 
| ThreatStream.Investigation.elements.entity.is_mitre | Boolean | Whether the entity is mitre. | 
| ThreatStream.Investigation.elements.entity.is_public | Boolean | Whether the entity is public or private. | 
| ThreatStream.Investigation.elements.entity.is_team | Boolean | Whether the entity is a team. | 
| ThreatStream.Investigation.elements.entity.modified_ts | Date | Timestamp of when the entity was last updated on ThreatStream, in UTC format. | 
| ThreatStream.Investigation.elements.entity.name | String | The entity name. | 
| ThreatStream.Investigation.elements.entity.organization_id | Number | ID of the \(ThreatStream\) organization that brought in the entity. | 
| ThreatStream.Investigation.elements.entity.owner_user_id | Number | ID of the ThreatStream user who created the entity. | 
| ThreatStream.Investigation.elements.entity.primary_motivation | Unknown | The primary motivation. | 
| ThreatStream.Investigation.elements.entity.publication_status | String | The publication status of the entity. | 
| ThreatStream.Investigation.elements.entity.published_ts | Date | Timestamp of when the entity was published on ThreatStream, in UTC format. | 
| ThreatStream.Investigation.elements.entity.resource_level | Unknown | The resource level. | 
| ThreatStream.Investigation.elements.entity.resource_uri | String | Resource URI of the entity. | 
| ThreatStream.Investigation.elements.entity.source_created | Unknown | Timestamp of when the entity was created by its original source. | 
| ThreatStream.Investigation.elements.entity.source_modified | Unknown | Timestamp of when the entity was last updated by its original source. | 
| ThreatStream.Investigation.elements.entity.start_date | Unknown | The start date. | 
| ThreatStream.Investigation.elements.entity.tlp | String | Traffic Light Protocol designation for the entity—red, amber, green, white. | 
| ThreatStream.Investigation.elements.entity.uuid | String | UUID assigned to the entity. | 
| ThreatStream.Investigation.elements.entity.workgroups | Unknown | Assigned workgroups. | 
| ThreatStream.Investigation.elements.id | Number | Unique ID assigned to the entity. | 
| ThreatStream.Investigation.elements.r_id | Number | Unique ID assigned to the element entity. | 
| ThreatStream.Investigation.elements.r_type | String | Type of entity associated with the investigation. | 
| ThreatStream.Investigation.elements.entity.s_type | String | Signature type of entity associated with the investigation. | 
| ThreatStream.Investigation.elements.entity.children.id | String | A string representing the ID of the child entity. | 
| ThreatStream.Investigation.elements.entity.children.name | String | A string representing the name of the child entity. | 
| ThreatStream.Investigation.elements.entity.children.resource_uri | String | A string representing the resource URI of the child entity. | 
| ThreatStream.Investigation.elements.entity.is_category | Boolean | Whether the entity is a category. | 
| ThreatStream.Investigation.elements.entity.children | Unknown | The children of the entity. | 
| ThreatStream.Investigation.elements.entity.aliases | Unknown | The aliases of the entity. | 
| ThreatStream.Investigation.elements.entity.is_system | Boolean | Whether the entity is a system entity. | 
| ThreatStream.Investigation.elements.entity.source | String | A string representing the source of the entity. | 
| ThreatStream.Investigation.elements.entity.update_id | Number | The update ID of the entity. | 
| ThreatStream.Investigation.elements.entity.assignee_user.email | String | The assignee user email. | 
| ThreatStream.Investigation.elements.entity.assignee_user.id | String | The assignee user ID. | 
| ThreatStream.Investigation.elements.entity.assignee_user.name | String | The assignee user name. | 
| ThreatStream.Investigation.elements.entity.assignee_user.resource_uri | String | The assignee user resource URI. | 
| ThreatStream.Investigation.elements.entity.end_date | Unknown | The end date of the entity. | 
| ThreatStream.Investigation.elements.entity.objective | Unknown | The objective of the entity. | 
| ThreatStream.Investigation.elements.entity.status.display_name | String | The display name of the entity. | 
| ThreatStream.Investigation.elements.entity.status.id | Number | The status ID of the entity. | 
| ThreatStream.Investigation.elements.entity.status.resource_uri | String | The resource URI of the status of the entity. | 
| ThreatStream.Investigation.elements.entity.asn | String | The ASN of the entity. | 
| ThreatStream.Investigation.elements.entity.comments | Unknown | Comments related to the  entity. | 
| ThreatStream.Investigation.elements.entity.confidence | Number | The confidence of the associated entity. | 
| ThreatStream.Investigation.elements.entity.country | String | The country associated with the entity. | 
| ThreatStream.Investigation.elements.entity.created_by | String | A string representing the creator of the entity. | 
| ThreatStream.Investigation.elements.entity.expiration_ts | Date | The timestamp when the entity will expire on ThreatStream. | 
| ThreatStream.Investigation.elements.entity.import_session_id | Number | A number representing the import session ID of the entity. | 
| ThreatStream.Investigation.elements.entity.import_source | String | A string representing the import source of the entity. | 
| ThreatStream.Investigation.elements.entity.ip | String | The IP of the entity. | 
| ThreatStream.Investigation.elements.entity.itype | String | The itype of the entity. | 
| ThreatStream.Investigation.elements.entity.latitude | String | The latitude of the entity. | 
| ThreatStream.Investigation.elements.entity.longitude | String | The longitude of the entity. | 
| ThreatStream.Investigation.elements.entity.meta.detail2 | String | Additional details associated with state of an entity. | 
| ThreatStream.Investigation.elements.entity.meta.severity | String | Severity assigned to the entity through machine-learning algorithms ThreatStream deploys. | 
| ThreatStream.Investigation.elements.entity.org | String | Registered owner \(organization\) associated with the entity. | 
| ThreatStream.Investigation.elements.entity.owner_organization_id | Number | The owner organization ID of the entity. | 
| ThreatStream.Investigation.elements.entity.rdns | Unknown | Domain name \(obtained through reverse domain name lookup\) associated with the entity. | 
| ThreatStream.Investigation.elements.entity.retina_confidence | Number | The retina confidence of the entity. | 
| ThreatStream.Investigation.elements.entity.source_reported_confidence | Number | The source reported confidence of the entity. | 
| ThreatStream.Investigation.elements.entity.status | String | The status of the entity. | 
| ThreatStream.Investigation.elements.entity.subtype | Unknown | The subtype of the entity. | 
| ThreatStream.Investigation.elements.entity.tags | Unknown | List of tags associated with the entity. | 
| ThreatStream.Investigation.elements.entity.threat_type | String | Type of threat associated with the entity. | 
| ThreatStream.Investigation.elements.entity.threatscore | Number | The threat score of the entity. | 
| ThreatStream.Investigation.elements.entity.trusted_circle_ids | Unknown | The trusted circleIDs of the entity. | 
| ThreatStream.Investigation.elements.entity.trusted_circles_ids | Unknown | ID of the trusted circle to which the entity data should be associated. | 
| ThreatStream.Investigation.elements.entity.type | String | The type of the entity. | 
| ThreatStream.Investigation.elements.entity.value | String | Value of the entity. | 
| ThreatStream.Investigation.errors | Unknown | Errors related to the investigation. | 
| ThreatStream.Investigation.graph_content | Unknown | The investigation graph content details. | 
| ThreatStream.Investigation.id | Number | The ID of the investigation. | 
| ThreatStream.Investigation.intelligence_initiatives | Unknown | Intelligence initiatives associated with the investigation. | 
| ThreatStream.Investigation.is_public | Boolean | Whether the entity is public or private. | 
| ThreatStream.Investigation.modified_ts | Date | The date the investigation was modified. | 
| ThreatStream.Investigation.name | String | The investigation name. | 
| ThreatStream.Investigation.owner_org.id | String | The owner organization ID. | 
| ThreatStream.Investigation.owner_org.name | String | The owner organization name. | 
| ThreatStream.Investigation.owner_org.resource_uri | String | The owner organization resource URI. | 
| ThreatStream.Investigation.owner_org_id | Unknown | Organization ID of the owner. | 
| ThreatStream.Investigation.priority | String | The priority of the investigation. | 
| ThreatStream.Investigation.reporter.email | String | Email address of the user who created the investigation. | 
| ThreatStream.Investigation.reporter.id | String | ID of the user who created the investigation. | 
| ThreatStream.Investigation.reporter.name | String | Name of the user who created the investigation. | 
| ThreatStream.Investigation.reporter.resource_uri | String | Resource URI of the user who created the investigation. | 
| ThreatStream.Investigation.reporter_id | Number | ID of the user who created the investigation. | 
| ThreatStream.Investigation.resource_uri | String | The investigation resource URI. | 
| ThreatStream.Investigation.source_type | String | The type of source used to create the investigation. | 
| ThreatStream.Investigation.status | String | The investigation status. | 
| ThreatStream.Investigation.tags | String | The tags associated with the investigation. | 
| ThreatStream.Investigation.tlp | String | Traffic Light Protocol designation for the investigation—red, amber, green, white. | 
| ThreatStream.Investigation.users | Unknown | List of users associated with the investigation. | 
| ThreatStream.Investigation.workgroups | Unknown | Assigned workgroups. | 

#### Command example
```!threatstream-create-investigation name=new_investigation```
#### Context Example
```json
{
    "ThreatStream": {
        "Investigation": {
            "add_related_indicators": 0,
            "assignee": null,
            "circles": [],
            "created_ts": "2023-04-03T14:05:47.392664",
            "description": null,
            "graph_content": null,
            "id": 1022,
            "intelligence_initiatives": [],
            "is_public": false,
            "modified_ts": "2023-04-03T14:05:47.392680",
            "name": "new_investigation",
            "owner_org": {
                "id": "11",
                "name": "name",
                "resource_uri": "resource_uri"
            },
            "owner_org_id": null,
            "priority": "medium",
            "reporter": {
                "email": "user@email.com",
                "id": "111",
                "name": "",
                "resource_uri": "/api/v1/user/111/"
            },
            "reporter_id": 111,
            "resource_uri": "/api/v1/investigation/1022/",
            "source_type": "user",
            "status": "unassigned",
            "tags": null,
            "tlp": "white",
            "users": [],
            "workgroups": []
        }
    }
}
```

#### Human Readable Output

>Investigation was created successfully with ID: 1022.

### threatstream-update-investigation

***
Updates an existing investigation at ThreatStream.

#### Base Command

`threatstream-update-investigation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| investigation_id | The ID of the investigation. Use the threatstream-list-investigation command to get the investigation ID. | Required | 
| priority | The priority of the investigation. Possible values are: Very Low, Low, Medium, High, Very High. | Optional | 
| status | The status of the investigation. Possible values are: Completed, In-Progress, Pending, Unassigned. | Optional | 
| tags | A comma-separated list of tags. For example, tag1,tag2. | Optional | 
| tlp | The tlp (Traffic Light Protocol designation) of the investigation. Possible values are: White, Green, Amber, Red. | Optional | 
| assignee_id | Assignee ID. Use the threatstream-list-user command to get the user ID. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.Investigation.add_related_indicators | Number | Errors related to the investigation. | 
| ThreatStream.Investigation.assignee.assignee_type | String | Type of assignee: "user" or "tsworkgroup". | 
| ThreatStream.Investigation.assignee.avatar_s3_url | Unknown | URL for the avatar image associated with the assignee user. | 
| ThreatStream.Investigation.assignee.can_share_intelligence | Boolean | Whether the assignee user can share intelligence. | 
| ThreatStream.Investigation.assignee.email | String | The email of the assignee user. | 
| ThreatStream.Investigation.assignee.id | String | The ID of the assignee user. | 
| ThreatStream.Investigation.assignee.is_active | Boolean | Whether the assignee user is active. | 
| ThreatStream.Investigation.assignee.is_readonly | Boolean | Whether the assignee user should be restricted to Read Only status. | 
| ThreatStream.Investigation.assignee.must_change_password | Boolean | Whether the assignee user will be forced to change their password the next time they log in. | 
| ThreatStream.Investigation.assignee.name | String | The investigation assignee user name. | 
| ThreatStream.Investigation.assignee.nickname | Unknown | The investigation assignee user nickname. | 
| ThreatStream.Investigation.assignee.resource_uri | String | Resource URI associated with the investigation assignee user. | 
| ThreatStream.Investigation.assignee_id | Number | ID of the user or workgroup to which the investigation is assigned. | 
| ThreatStream.Investigation.assignee_type | String | Type of assignee: "user" or "tsworkgroup". | 
| ThreatStream.Investigation.created_ts | Date | Timestamp when the investigation was created. | 
| ThreatStream.Investigation.description | String | The investigation description. | 
| ThreatStream.Investigation.elements.add_related_indicators | Number | When enabled, observables related to the entity you are associating with the investigation are also added. | 
| ThreatStream.Investigation.elements.r_id | Number | Unique ID assigned to the entity. | 
| ThreatStream.Investigation.elements.r_type | String | Type of entity associated with the investigation. | 
| ThreatStream.Investigation.graph_content | Unknown | The investigation graph content details. | 
| ThreatStream.Investigation.id | Number | The ID of the investigation. | 
| ThreatStream.Investigation.is_public | Boolean | Whether the entity is public or private. | 
| ThreatStream.Investigation.modified_ts | Date | The date the investigation was modified. | 
| ThreatStream.Investigation.name | String | The investigation name. | 
| ThreatStream.Investigation.owner_org.id | String | The owner organization ID. | 
| ThreatStream.Investigation.owner_org.name | String | The owner organization name. | 
| ThreatStream.Investigation.owner_org.resource_uri | String | The owner organization resource URI. | 
| ThreatStream.Investigation.owner_org_id | Unknown | Organization ID of the owner. | 
| ThreatStream.Investigation.priority | String | The priority of the investigation. | 
| ThreatStream.Investigation.reporter.email | String | Email address of the user who created the investigation. | 
| ThreatStream.Investigation.reporter.id | String | ID of the user who created the investigation. | 
| ThreatStream.Investigation.reporter.name | String | Name of the user who created the investigation. | 
| ThreatStream.Investigation.reporter.resource_uri | String | Resource URI of the user who created the investigation. | 
| ThreatStream.Investigation.reporter_id | Number | ID of the user who created the investigation. | 
| ThreatStream.Investigation.resource_uri | String | The investigation resource URI. | 
| ThreatStream.Investigation.source_type | String | The type of source used to create the investigation. | 
| ThreatStream.Investigation.status | String | The investigation status. | 
| ThreatStream.Investigation.tags | String | The tags associated with the investigation. | 
| ThreatStream.Investigation.tlp | String | Traffic Light Protocol designation for the investigation—red, amber, green, white. | 

#### Command example
```!threatstream-update-investigation investigation_id=1022 priority=Low status="In-Progress" assignee_id=203```
#### Context Example
```json
{
    "ThreatStream": {
        "Investigation": {
            "assignee": {
                "assignee_type": "user",
                "avatar_s3_url": null,
                "can_share_intelligence": false,
                "email": "user@email.com",
                "id": "111",
                "is_active": true,
                "is_readonly": false,
                "must_change_password": false,
                "name": "",
                "nickname": null,
                "resource_uri": "/api/v1/user/111/"
            },
            "assignee_id": 111,
            "assignee_type": "user",
            "circles": [],
            "created_ts": "2023-04-03T14:05:47.389934",
            "description": null,
            "graph_content": null,
            "id": 1022,
            "intelligence_initiatives": [],
            "is_public": false,
            "modified_ts": "2023-04-03T14:06:53.575922",
            "name": "new_investigation",
            "owner_org": {
                "id": "11",
                "name": "name",
                "resource_uri": "resource_uri"
            },
            "owner_org_id": null,
            "priority": "low",
            "reporter": {
                "email": "user@email.com",
                "id": "111",
                "name": "",
                "resource_uri": "/api/v1/user/111/"
            },
            "reporter_id": 111,
            "resource_uri": "/api/v1/investigation/1022/",
            "source_type": "user",
            "status": "in-progress",
            "tags": null,
            "tlp": "white",
            "users": [],
            "workgroups": []
        }
    }
}
```

#### Human Readable Output

>Investigation was updated successfully with ID: 1022
### threatstream-add-investigation-element

***
Add an element to the existing investigation at ThreatStream.

#### Base Command

`threatstream-add-investigation-element`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| investigation_id | The ID of the investigation. Use the threatstream-get-model-list command to get the investigation ID. | Required | 
| connect_related_indicators | When enabled, observables related to the entity you are associating with the investigation are also added. Possible values are: True, False. | Optional | 
| associated_actor_ids | A comma-separated list of IDs of the actors with which you want to associate matched entities. Use the threatstream-get-model-list command to get the actor IDs. | Optional | 
| associated_campaign_ids | A comma-separated list of IDs of the campaigns with which you want to associate matched entities. Use the threatstream-get-model-list command to get the campaign IDs. | Optional | 
| associated_incident_ids | A comma-separated list of IDs of the incidents with which you want to associate matched entities. Use the threatstream-get-model-list command to get the incident IDs. | Optional | 
| associated_observable_ids | A comma-separated list of IDs of the observables with which you want to associate matched entities. Use the threatstream-get-indicators command to get the observable IDs. | Optional | 
| associated_signature_ids | A comma-separated list of IDs of the signatures with which you want to associate matched entities. Use the threatstream-get-model-list command to get the signature IDs. | Optional | 
| associated_threat_bulletin_ids | A comma-separated list of IDs of the threat bulletin with which you want to associate matched entities. Use the threatstream-get-model-list command to get the threat bulletin IDs. | Optional | 
| associated_ttp_ids | A comma-separated list of IDs of the TTPs with which you want to associate matched entities. Use the threatstream-get-model-list command to get the TTPs IDs. | Optional | 
| associated_vulnerability_ids | A comma-separated list of IDs of the vulnerabilities with which you want to associate matched entities. Use the threatstream-get-model-list command to get the vulnerabilities IDs. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!threatstream-add-investigation-element investigation_id=1022 associated_campaign_ids=111111```
#### Human Readable Output

>All The elements was added successfully to investigation ID: 1022
### threatstream-delete-investigation

***
Deletes an existing investigation at ThreatStream.

#### Base Command

`threatstream-delete-investigation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| investigation_id | The ID of the investigation. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!threatstream-delete-investigation investigation_id=1022```
#### Human Readable Output

>Investigation was deleted successfully.
### threatstream-list-whitelist-entry

***
Get a list of whitelist entries.

#### Base Command

`threatstream-list-whitelist-entry`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| format | Defines the format of the response. Possible values are: CSV, JSON. Default is JSON. | Optional | 
| limit | The maximum number of results to return. Default is 50. | Optional | 
| page | Page number to get result from. Needs to be used with the page_size argument. | Optional | 
| page_size | The page size of the returned results. Needs to be used with the page argument. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Name | string | Name of the file. | 
| InfoFile.EntryID | string | The entry ID of the report. | 
| InfoFile.Size | number | Size of the file. | 
| InfoFile.Type | string | File type, e.g., "PE". | 
| InfoFile.Info | string | Basic information of the file. | 
| ThreatStream.WhitelistEntry.created_ts | Date | Timestamp of when the entry was created. | 
| ThreatStream.WhitelistEntry.id | Number | Unique ID associated with the whitelist entry. | 
| ThreatStream.WhitelistEntry.modified_ts | Date | Timestamp of when the entry was most recently modified. | 
| ThreatStream.WhitelistEntry.notes | String | Contextual note associated with the entry. | 
| ThreatStream.WhitelistEntry.resource_uri | String | Resource URI of the entry. | 
| ThreatStream.WhitelistEntry.value | String | Value of the entry. | 
| ThreatStream.WhitelistEntry.value_type | String | Value type of the entry. | 

#### Command example
```!threatstream-list-whitelist-entry page=2 page_size=2```
#### Context Example
```json
{
    "ThreatStream": {
        "WhitelistEntry": [
            {
                "created_ts": "2023-04-02T13:18:00.862395",
                "id": 111,
                "modified_ts": "2023-04-02T13:18:00.862395",
                "notes": null,
                "resource_uri": "/api/v1/orgwhitelist/111/",
                "value": "1.2.4.5",
                "value_type": "ip"
            },
            {
                "created_ts": "2023-04-02T13:18:00.862395",
                "id": 222,
                "modified_ts": "2023-04-02T13:18:00.862395",
                "notes": null,
                "resource_uri": "/api/v1/orgwhitelist/222/",
                "value": "1.2.4.5",
                "value_type": "ip"
            }
        ]
    }
}
```

#### Human Readable Output

>### Whitelist entries
>|Id|Value|Resource Uri|Created At|Modified At|Value Type|
>|---|---|---|---|---|---|
>| 111 | 1.2.4.5 | /api/v1/orgwhitelist/111/ | 2023-04-02T13:18:00.862395 | 2023-04-02T13:18:00.862395 | ip |
>| 222 | 1.2.4.5 | /api/v1/orgwhitelist/222/ | 2023-04-02T13:18:00.862395 | 2023-04-02T13:18:00.862395 | ip |

### threatstream-create-whitelist-entry

***
Creates a new whitelist entry.

#### Base Command

`threatstream-create-whitelist-entry`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | The entry ID of the file you want to upload. | Optional | 
| cidr | A comma-separated list of CIDRs associated with the entry. | Optional | 
| domains | A comma-separated list of domains associated with the entry. | Optional | 
| emails | A comma-separated list of emails associated with the entry. | Optional | 
| ips | A comma-separated list of IPs associated with the entry. | Optional | 
| md5 | A comma-separated list of MD5 hashes associated with the entry. | Optional | 
| urls | A comma-separated list of URLs associated with the entry. | Optional | 
| user_agents | A comma-separated list of user agents associated with the entry. | Optional | 
| note | A note that will be associated with all the indicator types that are provided in the command arguments. | Optional | 

Note: The requirements for the file for the entry_id are:
The entries must be contained in a valid CSV file with the following header line: value_type,value,notes.
value_type must be specified for each entry, possible types include domain, email, ip, md5, url, user-agent, and cidr.
value must be specified for each entry. 
Values must be valid entries based on the specified type.
For example, if you specify ip for type, the corresponding value must be a valid IP address.
notes is optional for each entry.
All text in the CSV file must be lower-cased.

#### Context Output

There is no context output for this command.
#### Command example
```!threatstream-create-whitelist-entry ips=1.2.4.5```
#### Human Readable Output

>Created 1 item(s).
### threatstream-update-whitelist-entry-note

***
Modify contextual notes associated with existing whitelist entries

#### Base Command

`threatstream-update-whitelist-entry-note`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | The ID of the entry you want to update. | Required | 
| note | A note that will be associated with all the indicator types that are provided in the command arguments. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!threatstream-update-whitelist-entry-note note="some_note" entry_id=222```
#### Human Readable Output

>The note was updated successfully.
### threatstream-delete-whitelist-entry

***
Delete a whitelist entry.

#### Base Command

`threatstream-delete-whitelist-entry`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | The ID of the entry you want to update. Use the threatstream-list-whitelist-entry command to get the entry ID. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!threatstream-delete-whitelist-entry entry_id=222```
#### Human Readable Output

>The entity was deleted successfully
### threatstream-list-import-job

***
Gets an import list.

#### Base Command

`threatstream-list-import-job`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| import_id | When specified, the results returned in the list are limited to specific import ID. | Optional | 
| status_in | When specified, the results returned in the list are limited to the selected status. Possible values are: Processing, Errors, Ready To Review, Rejected, Approved. | Optional | 
| limit | The maximum number of results to return. Default is 50. | Optional | 
| page | Page number to get result from. Needs to be used with the page_size argument. | Optional | 
| page_size | The page size of the returned results. Needs to be used with the page argument. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.Import.approved_by_id | Unknown | The ID of the user who approved the import. | 
| ThreatStream.Import.confidence | Number | Confidence scores assigned to the import. | 
| ThreatStream.Import.date | Date | A date representing the import date. | 
| ThreatStream.Import.date_modified | Date | A date representing the last modified date of the import. | 
| ThreatStream.Import.default_comment | Unknown | Default comment. | 
| ThreatStream.Import.email | String | A string representing the email associated with the import. | 
| ThreatStream.Import.exclude_source_domain | Boolean | Whether the source domain is excluded. | 
| ThreatStream.Import.expiration_ts | Date | The timestamp when the import will expire on ThreatStream. | 
| ThreatStream.Import.fileName | String | A string representing the name of file associated with the import. | 
| ThreatStream.Import.fileType | String | A string representing the type of file associated with the import. | 
| ThreatStream.Import.file_name_label | Unknown | The file name label. | 
| ThreatStream.Import.id | Number | A number representing the import ID. | 
| ThreatStream.Import.intelligence_source | String | A string representing the intelligence source of the import. | 
| ThreatStream.Import.is_anonymous | Boolean | Whether the entity is anonymous. | 
| ThreatStream.Import.is_public | Boolean | Whether the entity is public or private. | 
| ThreatStream.Import.jobID | Unknown | The job ID. | 
| ThreatStream.Import.messages | String | A string representing the messages associated with the import. | 
| ThreatStream.Import.name | String | The import name. | 
| ThreatStream.Import.notes | String | A string representing the notes associated with the import. | 
| ThreatStream.Import.numIndicators | Number | The number of observables that were accepted for importing. | 
| ThreatStream.Import.numRejected | Number | The number of observables that were rejected for importing. | 
| ThreatStream.Import.num_private | Number | A number representing the number of private entities associated with the import. | 
| ThreatStream.Import.num_public | Number | A number representing the number of public entities associated with the import. | 
| ThreatStream.Import.organization.id | String | ID associated with the organization that created the import. | 
| ThreatStream.Import.organization.name | String | Name associated with the organization that created the import. | 
| ThreatStream.Import.organization.resource_uri | String | Resource URI associated with the organization that created the import. | 
| ThreatStream.Import.processed_ts | Date | A date representing the timestamp when the import was processed. | 
| ThreatStream.Import.resource_uri | String | Resource URI associated with the entity. | 
| ThreatStream.Import.sandbox_submit | Unknown | The sandbox submit. | 
| ThreatStream.Import.source_confidence_weight | Number | The source confidence weight of the entity. | 
| ThreatStream.Import.status | String | The import status. | 
| ThreatStream.Import.threat_type | String | The threat type. | 
| ThreatStream.Import.tlp | Unknown | Traffic Light Protocol designation. | 
| ThreatStream.Import.user_id | Number | A string representing the ID associated with the user who created the import. | 
| ThreatStream.Import.visibleForReview | Boolean | Whether the entity is visible for review. | 

#### Command example
```!threatstream-list-import-job page=2 page_size=2```
#### Context Example
```json
{
    "ThreatStream": {
        "Import": [
            {
                "ImportID": 111111,
                "JobID": null,
                "approved_by": {
                    "avatar_s3_url": null,
                    "can_share_intelligence": false,
                    "email": "user@email.com",
                    "id": "111",
                    "is_active": true,
                    "is_readonly": false,
                    "must_change_password": false,
                    "name": "",
                    "nickname": null,
                    "organization": {
                        "id": "11",
                        "name": "name",
                        "resource_uri": "resource_uri"
                    },
                    "resource_uri": "/api/v1/user/111/"
                },
                "approved_by_id": 111,
                "confidence": 50,
                "date": "2023-04-03T14:27:51.896155",
                "date_modified": "2023-04-03T14:27:52.714429",
                "default_comment": null,
                "email": "user@email.com",
                "exclude_source_domain": false,
                "expiration_ts": "2023-07-02T14:27:51.887354",
                "fileName": null,
                "fileType": "analyst",
                "file_name_label": null,
                "intelligence_initiatives": [],
                "intelligence_source": "",
                "is_anonymous": false,
                "is_public": false,
                "messages": "",
                "name": "",
                "notes": "",
                "numIndicators": 0,
                "numRejected": 0,
                "num_private": 0,
                "num_public": 0,
                "organization": {
                    "id": "11",
                    "name": "name",
                    "resource_uri": "resource_uri"
                },
                "processed_ts": "2023-04-03T14:27:51.935305",
                "resource_uri": "/api/v1/importsession/111111/",
                "sandbox_submit": null,
                "source_confidence_weight": 0,
                "status": "approved",
                "tags": [],
                "threat_type": "exploit",
                "tlp": null,
                "trusted_circles": [],
                "user_id": 111,
                "visibleForReview": true,
                "workgroups": []
            },
            {
                "ImportID": 222222,
                "JobID": null,
                "approved_by": {
                    "avatar_s3_url": null,
                    "can_share_intelligence": false,
                    "email": "user@email.com",
                    "id": "111",
                    "is_active": true,
                    "is_readonly": false,
                    "must_change_password": false,
                    "name": "",
                    "nickname": null,
                    "organization": {
                        "id": "11",
                        "name": "name",
                        "resource_uri": "resource_uri"
                    },
                    "resource_uri": "/api/v1/user/111/"
                },
                "approved_by_id": 111,
                "confidence": 50,
                "date": "2023-04-03T14:27:22.263119",
                "date_modified": "2023-04-03T14:27:23.128873",
                "default_comment": null,
                "email": "user@email.com",
                "exclude_source_domain": false,
                "expiration_ts": "2023-07-02T14:27:22.260221",
                "fileName": null,
                "fileType": "analyst",
                "file_name_label": null,
                "intelligence_initiatives": [],
                "intelligence_source": "",
                "is_anonymous": false,
                "is_public": false,
                "messages": "",
                "name": "",
                "notes": "",
                "numIndicators": 0,
                "numRejected": 0,
                "num_private": 0,
                "num_public": 0,
                "organization": {
                    "id": "11",
                    "name": "name",
                    "resource_uri": "resource_uri"
                },
                "processed_ts": "2023-04-03T14:27:22.290096",
                "resource_uri": "/api/v1/importsession/222222/",
                "sandbox_submit": null,
                "source_confidence_weight": 0,
                "status": "approved",
                "tags": [],
                "threat_type": "exploit",
                "tlp": null,
                "trusted_circles": [],
                "user_id": 111,
                "visibleForReview": true,
                "workgroups": []
            }
        ]
    }
}
```

#### Human Readable Output

>### Import entries
>|Id|Date|Status|Reviewed By|Submitted By|Included|Excluded|
>|---|---|---|---|---|---|---|
>| 111111 | 2023-04-03T14:27:51.896155 | approved | user@email.com | user@email.com | 0 | 0 |
>| 222222 | 2023-04-03T14:27:22.263119 | approved | user@email.com | user@email.com | 0 | 0 |

### threatstream-approve-import-job

***
Approve all observables in an import job.

#### Base Command

`threatstream-approve-import-job`

##### Required Permissions

`Approve Intel user permission`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| import_id | The ID of the import job. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!threatstream-approve-import-job import_id=111111```
#### Human Readable Output

>The import session was successfully approved.
### threatstream-search-threat-model

***
Retrieve threat model entities from ThreatStream.

#### Base Command

`threatstream-search-threat-model`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| model_type | A comma-separated list of model types. Supported values are: actor, attackpattern , campaign, courseofaction, incident,identity, infrastructure, intrusionset, malware,signature, tipreport, ttp, tool, vulnerability. | Optional | 
| name | The name of the threat model. | Optional | 
| keyword_search | Free text to search string in the fields: Aliases, Description, Name, Tags. | Optional | 
| alias | Other names by which the entity are known. | Optional | 
| feed_id | Numeric ID of the threat feed that provided the Threat Model entity. | Optional | 
| is_email | Whether the entity was created as a result of an email import. Possible values are: True, False. | Optional | 
| is_public | Whether the entity is public or private. True—if the entity is public, False—if the entity is private or belongs to a Trusted Circle. Possible values are: True, False. | Optional | 
| publication_status | A comma-separated list of publication statuses. Supported values are: new, pending_review, review_requested, reviewed. | Optional | 
| signature_type | A comma-separated list of signature types. Supported values are: Bro, Carbon Black Query, ClamAV, Custom, CybOX, OpenIOC, RSA NetWitness, Snort, Splunk Query, Suricata, YARA. | Optional | 
| tags | A comma-separated list of additional comments and context associated with the entity when it was imported from its original threat feed. | Optional | 
| trusted_circle_id | Used for querying entities associated with specified trusted circles. | Optional | 
| limit | The maximum number of results to return. Default is 50. | Optional | 
| page | Page number to get result from. Needs to be used with the page_size argument. | Optional | 
| page_size | The page size of the returned results. Needs to be used with the page argument. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.ThreatModel.source_created | Unknown | Timestamp of when the entity was created by its original source. | 
| ThreatStream.ThreatModel.circles | Unknown | Trusted circles with which data from streams is shared. | 
| ThreatStream.ThreatModel.feed_id | Number | Numeric ID of the threat feed that provided the threat model entity. | 
| ThreatStream.ThreatModel.workgroups | Unknown | Workgroups to which the threat model is visible. | 
| ThreatStream.ThreatModel.aliases | Unknown | Other names by which the threat model are known. | 
| ThreatStream.ThreatModel.is_email | Unknown | Whether the threat model was created as a result of an email import. | 
| ThreatStream.ThreatModel.published_ts | String | Timestamp of when the entity was published on ThreatStream, in UTC format. | 
| ThreatStream.ThreatModel.id | Number | Unique ID assigned to the entity. | 
| ThreatStream.ThreatModel.source_modified | Date | Timestamp of when the entity was last updated by its original source. | 
| ThreatStream.ThreatModel.type | String | The threat model type. | 
| ThreatStream.ThreatModel.start_date | Unknown | Time when a threat model was known to have started. | 
| ThreatStream.ThreatModel.publication_status | String | The publication status. A threat model can be in new, pending_review, review_requested, reviewed, published statuses. | 
| ThreatStream.ThreatModel.end_date | Unknown | Time when a threat model was known to have ended. | 
| ThreatStream.ThreatModel.tags.id | String | The ID of the tag assigned to the threat model. | 
| ThreatStream.ThreatModel.tags.name | String | The name of the tag assigned to the threat model. | 
| ThreatStream.ThreatModel.modified_ts | String | Timestamp of when the tag was last updated on ThreatStream, in UTC format. | 
| ThreatStream.ThreatModel.is_public | Boolean | Whether the entity is public or private. | 
| ThreatStream.ThreatModel.uuid | String | UUID \(universally unique identifier\) assigned to the threat model for STIX compliance. | 
| ThreatStream.ThreatModel.created_ts | String | Timestamp when the threat model was created. | 
| ThreatStream.ThreatModel.tlp | String | TLP setting associated with the entity. | 
| ThreatStream.ThreatModel.name | String | Name of the entity. | 
| ThreatStream.ThreatModel.status | Unknown | Status of the entity. | 
| ThreatStream.ThreatModel.model_type | String | Type of threat model entity. | 
| ThreatStream.ThreatModel.resource_uri | String | Resource URI associated with the entity. | 

#### Command example
```!threatstream-search-threat-model model_type="signature" signature_type="Carbon Black Query,Bro,ClamAV" limit="50" page="2" page_size="2"```
#### Context Example
```json
{
    "ThreatStream": {
        "ThreatModel": [
            {
                "aliases": [],
                "circles": [],
                "created_ts": "2023-03-19T10:04:13.272377+00:00",
                "end_date": null,
                "feed_id": 0,
                "id": 111111,
                "is_email": null,
                "is_public": false,
                "model_type": "signature",
                "modified_ts": "2023-03-19T10:09:09.150405+00:00",
                "name": "signature_threat_model_1",
                "organization": {
                    "id": 11,
                    "title": "title"
                },
                "owner_user": {
                    "email": "user@email.com",
                    "id": 111,
                    "name": ""
                },
                "publication_status": "new",
                "published_ts": null,
                "resource_uri": "/api/v1/signature/111111/",
                "sort": [
                    11111111111111111,
                    "signature-111111"
                ],
                "source_created": null,
                "source_modified": null,
                "start_date": null,
                "status": null,
                "tags": [
                    {
                        "id": "as2",
                        "name": "Reconnaissance",
                        "org_id": 11,
                        "tlp": "white"
                    }
                ],
                "tlp": "red",
                "type": "Carbon Black Query",
                "uuid": "XXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXX",
                "workgroups": []
            },
            {
                "aliases": [],
                "circles": [],
                "created_ts": "2020-07-31T20:56:33.459260+00:00",
                "end_date": null,
                "feed_id": 155,
                "id": 333,
                "is_email": null,
                "is_public": true,
                "model_type": "signature",
                "modified_ts": "2022-10-08T05:18:20.389951+00:00",
                "name": "signature_threat_model_2",
                "publication_status": "published",
                "published_ts": "2020-07-31T20:56:33.295192+00:00",
                "resource_uri": "/api/v1/signature/333/",
                "sort": [
                    11111111111111111,
                    "signature-333"
                ],
                "source_created": null,
                "source_modified": null,
                "start_date": null,
                "status": null,
                "tags": [
                    {
                        "id": "id1",
                        "name": "actor_tag1"
                    }
                ],
                "tlp": "white",
                "type": "Carbon Black Query",
                "uuid": "XXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXX",
                "workgroups": []
            }
        ]
    }
}
```

#### Human Readable Output

>### Threat model entities
>|Id|Type|Name|Publication Status|Modified At|
>|---|---|---|---|---|
>| 111111 | signature | signature_threat_model_1 | new | 2023-03-19T10:09:09.150405+00:00 |
>| 333 | signature | signature_threat_model_2 | published | 2022-10-08T05:18:20.389951+00:00 |

### threatstream-add-threat-model-association

***
Creates associations between threat model entities on the ThreatStream platform.

#### Base Command

`threatstream-add-threat-model-association`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_type | The type of threat model entity to which you are adding the association. Possible values are: Actor, Attack Pattern, Campaign, Course Of Action, Identity, Infrastructure, Intrusion Set, Incident, Malware, Signature, Threat Bulletin, Tool, Ttp, Vulnerability. | Required | 
| entity_id | The ID of the threat model entity to which you are adding the association. | Required | 
| associated_entity_ids | The entities IDs to associate with the primary entity. Note: The model type of all the IDs must be equal to the type in the “associated_entity_type” argument. | Required | 
| associated_entity_type | The type of threat model entity to which you are adding the association. Possible values are: Actor, Attack Pattern, Campaign, Course Of Action, Identity, Infrastructure, Intrusion Set, Incident, Malware, Signature, Threat Bulletin, Tool, Ttp, Vulnerability. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!threatstream-add-threat-model-association entity_type="Actor" entity_id="26769" associated_entity_ids="1111,2222" associated_entity_type="Attack Pattern"```
#### Human Readable Output

>The Attack Pattern entities with ids 2222, 1111 were associated successfully to entity id: 26769.

### threatstream-add-indicator-tag

***
Add tags to the indicators

#### Base Command

`threatstream-add-indicator-tag`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_ids | A comma-separated list of unique IDs of the indicator to which you are adding tags. | Required | 
| tags | A comma-separated list of values of the tags you want to add. | Required | 

#### Context Output

There is no context output for this command.
### threatstream-remove-indicator-tag

***
Remove tags from the indicators

#### Base Command

`threatstream-remove-indicator-tag`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_ids | A comma-separated list of unique IDs of the indicator to which you are removing tags. | Required | 
| tags | A comma-separated list of values of the tags you want to remove. | Required | 

#### Context Output

There is no context output for this command.

***
Clones already imported indicators (observables), used with the edit classification to move to a trusted circle

#### Base Command

`threatstream-clone-imported-indicator`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_id | ID of the indicator to clone. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.Clone.ID | String | Indicator ID. | 
| ThreatStream.Clone.Import_Session_ID | String | Import Session ID for the clone request. | 
| ThreatStream.Clone.Job_ID | String | Job ID for the clone request. | 

***
Edit the values for observable that have been cloned

#### Base Command

`threatstream-edit-classification`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| import_id | Import Session ID of the import session from the clone-imported-indicator command. | Required | 
| data | JSON data of edits to be made {"is_public":false,"circles":[12866]}. | Required |

#### Context Output

There is no context output for this command.