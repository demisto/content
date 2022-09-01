Use Anomali ThreatStream to query and submit threats.

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous version of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration-anomali-threatstream-v3).

## Configure Anomali ThreatStream v3 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Anomali ThreatStream v3.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL (e.g., https://www.test.com) |  | True |
    | Username |  | True |
    | API Key |  | True |
    | URL threshold |  | False |
    | IP threshold |  | False |
    | Domain threshold |  | False |
    | File threshold |  | False |
    | Email threshold |  | False |
    | Include inactive results | Whether to include inactive indicators in reputation commands. | False |
    | Source Reliability | Reliability of the source providing the intelligence data. | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Create relationships | Create relationships between indicators as part of enrichment. | False |

4. Click **Test** to validate the URLs, token, and connection.

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
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
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
                        "email": "darbel@paloaltonetworks.com",
                        "id": "202",
                        "name": "",
                        "resource_uri": "/api/v1/user/202/"
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
                    "id": 372437,
                    "intelligence_initiatives": [],
                    "is_anonymous": false,
                    "is_cloneable": "yes",
                    "is_public": false,
                    "modified_ts": "2022-08-01T09:52:10.246877",
                    "name": "Test Investigation",
                    "objective": null,
                    "organization_id": 88,
                    "owner_user_id": 202,
                    "publication_status": "new",
                    "published_ts": null,
                    "resource_uri": "/api/v1/campaign/372437/",
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
>| Test Investigation | 372437 |


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
        "DNS": "1.1.1.1",
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
                "EntityB": "1.1.1.1",
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
                    "id": 631,
                    "intelligence_initiatives": [],
                    "is_anonymous": false,
                    "is_cloneable": "yes",
                    "is_public": true,
                    "modified_ts": "2022-08-02T06:20:19.772588",
                    "name": "Feeds SDK 2.0: Signature Carbon Black Query test 1",
                    "organization_id": 39,
                    "owner_user_id": 64,
                    "publication_status": "published",
                    "published_ts": "2020-07-31T20:56:33.295192",
                    "resource_uri": "/api/v1/signature/631/",
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
            "Source": "tmalache@paloaltonetworks.com",
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
>| 50 | apt_md5 | 2022-07-11T16:30:00.359Z | 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f | very-high | tmalache@paloaltonetworks.com | active | apt | SHA256 |
>### Actor details:
>|name|id|
>|---|---|
>| Alert report | 47096 |
>### Signature details:
>|name|id|
>|---|---|
>| Feeds SDK 2.0: Signature Carbon Black Query test 1 | 631 |
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
| value | Possible values are "IP" or "Domain". | Required | 
| limit | The maximum number of results to return. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.PassiveDNS.Domain | String | The domain value. | 
| ThreatStream.PassiveDNS.Ip | String | The IP value. | 
| ThreatStream.PassiveDNS.Rrtype | String | The Rrtype value. | 
| ThreatStream.PassiveDNS.Source | String | The source value. | 
| ThreatStream.PassiveDNS.FirstSeen | String | The first seen date. The date format is: YYYYMMDDThhmmss, where "T" denotes the start of the value
for time, in UTC time. | 
| ThreatStream.PassiveDNS.LastSeen | String | The last seen date. The date format is: YYYYMMDDThhmmss, where "T" denotes the start of the value
for time in UTC time. | 


#### Command Example
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
Imports indicators (observables) into ThreatStream. The imported data must be approved using the ThreatStream UI. The data can be imported using one of three methods: plain-text, file, or URL.


#### Base Command

`threatstream-import-indicator-with-approval`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| confidence | The observable certainty level of a reported indicator type. Default is 50. | Optional | 
| classification | Whether the indicator data is public or private to the organization. Possible values are: private, public. Default is private. | Optional | 
| threat_type | Type of threat associated with the imported observables. Can be "adware", "anomalous", "anonymization", "apt", "bot", "brute", "c2", "compromised", "crypto", "data_leakage", "ddos", "dyn_dns", "exfil", "exploit", "hack_tool", "i2p", "informational", "malware", "p2p", "parked", "phish", "scan", "sinkhole", "spam", "suppress", "suspicious", "tor", or "vps". Possible values are: adware, anomalous, anonymization, apt, bot, brute, c2, compromised, crypto, data_leakage, ddos, dyn_dns, exfil, exploit, hack_tool, i2p, informational, malware, p2p, parked, phish, scan, sinkhole, spam, suppress, suspicious, tor, vps. Default is exploit. | Optional | 
| severity | The potential impact of the indicator type with which the observable is believed to be associated. Can be "low", "medium", "high", or "very-high". Possible values are: low, medium, high, very-high. Default is low. | Optional | 
| import_type | The import type of the indicator. Can be "datatext", "file-id", or "url". Possible values are: datatext, file-id, url. | Required | 
| import_value | The source of imported data. Can be one of the following: url, datatext of file-id of uploaded file to the War Room. Supported file types for file-id are: CSV, HTML, IOC, JSON, PDF, TXT. | Required | 
| ip_mapping | Indicator type to assign if a specific type is not associated with an observable. This is a global setting that applies to any imported IP-type observable when an explicit itype is not specified for it. | Optional | 
| domain_mapping | Indicator type to assign if a specific type is not associated with an observable. This is a global setting that applies to any imported domain-type observable when an explicit itype is not specified for it. | Optional | 
| url_mapping | Indicator type to assign if a specific type is not associated with an observable. This is a global setting that applies to any imported URL-type observable when an explicit itype is not specified for it. | Optional | 
| email_mapping | Indicator type to assign if a specific type is not associated with an observable. This is a global setting that applies to any imported email-type observable when an explicit itype is not specified for it. | Optional | 
| md5_mapping | Indicator type to assign if a specific type is not associated with an observable. This is a global setting that applies to any imported MD5-type observable when an explicit itype is not specified for it. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!threatstream-import-indicator-with-approval import_type=datatext import_value=78.78.78.67```

#### Context Example
```json
{
    "ThreatStream": {
        "Import": {
            "ImportID": "36118"
        }
    }
}
```

#### Human Readable Output

>The data was imported successfully. The ID of imported job is: 36118

### threatstream-import-indicator-without-approval
***
Imports indicators (observables) into ThreatStream. Approval is not required for the imported data. You must have the Approve Intel user permission to import without approval using the API.


#### Base Command

`threatstream-import-indicator-without-approval`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| confidence | The observable certainty level of a reported indicator type. Default is 50. | Optional | 
| source_confidence_weight | To use your specified confidence entirely and not re-assess the value using machine learning algorithms, set source_confidence_ weight to 100. | Optional | 
| expiration_ts | The time stamp when intelligence will expire on ThreatStream, in ISO format. For example, 2020-12-24T00:00:00. | Optional | 
| severity | The severity to assign to the observable when it is imported. Can be "low", "medium", "high" , or "very-high". Possible values are: low, medium, high, very-high. | Optional | 
| tags | A comma-separated list of tags. For example, tag1,tag2. | Optional | 
| trustedcircles | A comma-separated list of trusted circle IDs with which threat data should be shared. | Optional | 
| classification | Denotes whether the indicator data is public or private to the organization. Possible values are: private, public. | Required | 
| allow_unresolved | Whether unresolved domain observables are included in the file will be accepted as valid in ThreatStream and imported. Possible values are: yes, no. | Optional | 
| file_id | The entry ID of a file (containing a JSON with an "objects" array and "meta" maps) that is uploaded to the War Room. | Required | 


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
| model | The threat model of the returned list. Can be "actor", "campaign", "incident", "signature", "ttp", "vulnerability", or "tipreport". Possible values are: actor, campaign, incident, signature, ttp, vulnerability, tipreport. | Required | 
| limit | Limits the model size list. Specifying limit=0 returns up to a maximum of 1000 models. For limit=0, the output is not set in the context. Default is 50. | Optional | 


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
| model | The threat model. Can be "actor", "campaign", "incident", "signature", "ttp", "vulnerability", or "tipreport". Possible values are: actor, campaign, incident, signature, ttp, vulnerability, tipreport. | Required | 
| id | The model ID. | Required | 
| limit | The maximum number of results to return. Default is 20. | Optional | 


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
                    "UdpDestinaton": "8.8.8.8",
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
| created_ts | When the indicator was first seen on<br/>the ThreatStream cloud platform. The date must be specified in this format:<br/>YYYYMMDDThhmmss, where "T" denotes the start of the value for time, in UTC time.<br/>For example, 2014-10-02T20:44:35. | Optional | 
| id | The unique ID for the indicator. | Optional | 
| is_public | Whether the classification of the indicator is public. Default is "false". Possible values are: false, true. | Optional | 
| indicator_severity | The severity assigned to the indicator by ThreatStream. | Optional | 
| org | The registered owner (organization) of the IP address associated with the indicator. | Optional | 
| status | The status assigned to the indicator. Can be "active", "inactive", or "falsepos". Possible values are: active, inactive, falsepos. | Optional | 
| tags_name | The tag assigned to the indicator. | Optional | 
| type | The type of indicator. Can be "domain", "email", "ip", "MD5", "string", or "url". Possible values are: domain, email, ip, md5, string, url. | Optional | 
| indicator_value | The value of the indicator. . | Optional | 
| limit | The maximum number of results to return from ThreatStream. Default is 20. Default is 20. | Optional | 


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
| sandbox_type | The type of sandbox ("default" or "premium"). Possible values are: default, premium. Default is default. | Optional | 


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

