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
| threat_model_association | Note: if set to true, additional 6 API calls will be performed. Possible values are: True, False. Default is False. | Optional | 


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
| ThreatStream.IP.IType | String | The iType of the indicator associated with the specified model. | 
| IP.Tags | Unknown | List of IP Tags. | 
| IP.ThreatTypes | Unknown | Threat types associated with the IP. | 
| ThreatStream.IP.Actor.assignee_user | Unknown | The Assignee User of the Threat Actor | 
| ThreatStream.IP.Actor.association_info.comment | Unknown | The comment in the association info of the threat actor. | 
| ThreatStream.IP.Actor.association_info.created | Date | When was the association info created. | 
| ThreatStream.IP.Actor.association_info.from_id | Number | From which id the association info is related. | 
| ThreatStream.IP.Actor.can_add_public_tags | Boolean | Can we add a public tags or not to the threat actor. | 
| ThreatStream.IP.Actor.created_ts | Date | When was the threat actor cretad. | 
| ThreatStream.IP.Actor.feed_id | Number | The feed ID of the threat actor. | 
| ThreatStream.IP.Actor.id | Number | The id of the threat actor. | 
| ThreatStream.IP.Actor.is_anonymous | Boolean | Is the threat actor anonymus or not. | 
| ThreatStream.IP.Actor.is_cloneable | String | Is the threat actor clonable or not. | 
| ThreatStream.IP.Actor.is_public | Boolean | Is the threat actor public or not. | 
| ThreatStream.IP.Actor.is_team | Boolean | Is the threat actor in a team or not. | 
| ThreatStream.IP.Actor.modified_ts | Date | When was the threat actor modified. | 
| ThreatStream.IP.Actor.name | String | The name of the threat actor. | 
| ThreatStream.IP.Actor.organization_id | Number | The organization ID of the threat actor. | 
| ThreatStream.IP.Actor.owner_user_id | Number | The owner user ID of the threat actor. | 
| ThreatStream.IP.Actor.primary_motivation | Unknown | The primary motivation of the threat actor. | 
| ThreatStream.IP.Actor.publication_status | String | The publication status of the threat actor. | 
| ThreatStream.IP.Actor.published_ts | Date | When was the threat actor published. | 
| ThreatStream.IP.Actor.resource_level | Unknown | The resource level of the threat actor. | 
| ThreatStream.IP.Actor.resource_uri | String | The resource uri of the threat actor. | 
| ThreatStream.IP.Actor.source_created | Unknown | When was the source created. | 
| ThreatStream.IP.Actor.source_modified | Unknown | When was the source modified. | 
| ThreatStream.IP.Actor.start_date | Unknown | The start date. | 
| ThreatStream.IP.Actor.tags | String | The tags of the threat indicator | 
| ThreatStream.IP.Actor.tags_v2.id | String | The id of the tag. | 
| ThreatStream.IP.Actor.tags_v2.name | String | The name of the tag. | 
| ThreatStream.IP.Actor.tlp | String | The tlp of the threat actor. | 
| ThreatStream.IP.Actor.uuid | String | The uuid of the threat actor. | 
| ThreatStream.IP.Signature.assignee_user | Unknown | The Assignee User of the signature | 
| ThreatStream.IP.Signature.association_info.comment | Unknown | The comment in the association info of the signature. | 
| ThreatStream.IP.Signature.association_info.created | Date | When was the association info created. | 
| ThreatStream.IP.Signature.association_info.from_id | Number | From which id the association info is related. | 
| ThreatStream.IP.Signature.can_add_public_tags | Boolean | Can we add a public tags or not to the signature. | 
| ThreatStream.IP.Signature.created_ts | Date | When was the signature cretad. | 
| ThreatStream.IP.Signature.feed_id | Number | The feed ID of the signature. | 
| ThreatStream.IP.Signature.id | Number | The id of the signature. | 
| ThreatStream.IP.Signature.is_anonymous | Boolean | Is the signature anonymus or not. | 
| ThreatStream.IP.Signature.is_cloneable | String | Is the signature clonable or not. | 
| ThreatStream.IP.Signature.is_public | Boolean | Is the signature public or not. | 
| ThreatStream.IP.Signature.is_team | Boolean | Is the signature in a team or not. | 
| ThreatStream.IP.Signature.modified_ts | Date | When was the signature modified. | 
| ThreatStream.IP.Signature.name | String | The name of the signature. | 
| ThreatStream.IP.Signature.organization_id | Number | The organization ID of the signature. | 
| ThreatStream.IP.Signature.owner_user_id | Number | The owner user ID of the signature. | 
| ThreatStream.IP.Signature.primary_motivation | Unknown | The primary motivation of the signature. | 
| ThreatStream.IP.Signature.publication_status | String | The publication status of the signature. | 
| ThreatStream.IP.Signature.published_ts | Date | When was the signature published. | 
| ThreatStream.IP.Signature.resource_level | Unknown | The resource level of the signature. | 
| ThreatStream.IP.Signature.resource_uri | String | The resource uri of the signature. | 
| ThreatStream.IP.Signature.source_created | Unknown | When was the source created. | 
| ThreatStream.IP.Signature.source_modified | Unknown | When was the source modified. | 
| ThreatStream.IP.Signature.start_date | Unknown | The start date. | 
| ThreatStream.IP.Signature.tags | String | The tags of the threat indicator | 
| ThreatStream.IP.Signature.tags_v2.id | String | The id of the tag. | 
| ThreatStream.IP.Signature.tags_v2.name | String | The name of the tag. | 
| ThreatStream.IP.Signature.tlp | String | The tlp of the signature. | 
| ThreatStream.IP.Signature.uuid | String | The uuid of the signature. | 
| ThreatStream.IP.ThreatBulletin.all_circles_visible | Boolean | Are all of the circles visible. | 
| ThreatStream.IP.ThreatBulletin.assignee_org | String | The assignee organization. | 
| ThreatStream.IP.ThreatBulletin.assignee_org_id | String | The assignee organization ID. | 
| ThreatStream.IP.ThreatBulletin.assignee_org_name | String | The assignee organization name. | 
| ThreatStream.IP.ThreatBulletin.assignee_user | String | The assignee user. | 
| ThreatStream.IP.ThreatBulletin.assignee_user_id | String | The assignee user ID. | 
| ThreatStream.IP.ThreatBulletin.assignee_user_name | Unknown | The assignee user name. | 
| ThreatStream.IP.ThreatBulletin.association_info.comment | Unknown | The comment in the association info of the threat actor. | 
| ThreatStream.IP.ThreatBulletin.association_info.created | Date | When was the association info created. | 
| ThreatStream.IP.ThreatBulletin.association_info.from_id | String | From which id the association info is related. | 
| ThreatStream.IP.ThreatBulletin.body_content_type | String | The body content type. | 
| ThreatStream.IP.ThreatBulletin.campaign | Unknown | The campaign of the threat bulletin. | 
| ThreatStream.IP.ThreatBulletin.can_add_public_tags | Boolean | Can we add public tags. | 
| ThreatStream.IP.ThreatBulletin.created_ts | Date | When was the threat bulletin created. | 
| ThreatStream.IP.ThreatBulletin.feed_id | Number | The feed ID of the threat bulletin. | 
| ThreatStream.IP.ThreatBulletin.id | String | The ID of the threat bulletin. | 
| ThreatStream.IP.ThreatBulletin.is_anonymous | Boolean | Is the threat bulletin anonymous. | 
| ThreatStream.IP.ThreatBulletin.is_cloneable | String | Is the threat bulletin cloneble. | 
| ThreatStream.IP.ThreatBulletin.is_editable | Boolean | Is the threat bulletin editable. | 
| ThreatStream.IP.ThreatBulletin.is_email | Boolean | Is the threat bulletin an email. | 
| ThreatStream.IP.ThreatBulletin.is_public | Boolean | Is the threat bulletin public. | 
| ThreatStream.IP.ThreatBulletin.modified_ts | Date | When was the threat bulletin modified. | 
| ThreatStream.IP.ThreatBulletin.name | String | The name of the threat bulletin. | 
| ThreatStream.IP.ThreatBulletin.original_source | String | The original source of the threat bulletin. | 
| ThreatStream.IP.ThreatBulletin.original_source_id | Unknown | The original source ID of the threat bulletin. | 
| ThreatStream.IP.ThreatBulletin.owner_org.id | String | The owner organizetion ID. | 
| ThreatStream.IP.ThreatBulletin.owner_org.name | String | The owner organizetion name. | 
| ThreatStream.IP.ThreatBulletin.owner_org.resource_uri | String | The owner organizetion uri. | 
| ThreatStream.IP.ThreatBulletin.owner_org_id | Number | The id of the owner user. | 
| ThreatStream.IP.ThreatBulletin.owner_org_name | String | The name of the owner organization. | 
| ThreatStream.IP.ThreatBulletin.owner_user.avatar_s3_url | Unknown | The url of the owner user. | 
| ThreatStream.IP.ThreatBulletin.owner_user.can_share_intelligence | Boolean | Can we share intelligence or not. | 
| ThreatStream.IP.ThreatBulletin.owner_user.email | String | The email of the owner user. | 
| ThreatStream.IP.ThreatBulletin.owner_user.id | String | The ID of the owner user. | 
| ThreatStream.IP.ThreatBulletin.owner_user.is_active | Boolean | Is the owner user active. | 
| ThreatStream.IP.ThreatBulletin.owner_user.is_readonly | Boolean | Is the owner user read only. | 
| ThreatStream.IP.ThreatBulletin.owner_user.must_change_password | Boolean | Does the owner user must change password. | 
| ThreatStream.IP.ThreatBulletin.owner_user.name | String | The owner user name. | 
| ThreatStream.IP.ThreatBulletin.owner_user.nickname | String | The owner user nickname | 
| ThreatStream.IP.ThreatBulletin.owner_user.organization.id | String | The ID of the owner user organization. | 
| ThreatStream.IP.ThreatBulletin.owner_user.organization.name | String | The name of the owner user organization. | 
| ThreatStream.IP.ThreatBulletin.owner_user.organization.resource_uri | String | The resource uri of the owner user organization. | 
| ThreatStream.IP.ThreatBulletin.owner_user.resource_uri | String | The resource uri of the owner user. | 
| ThreatStream.IP.ThreatBulletin.owner_user_id | Number | The owner user ID of the threat bulletin. | 
| ThreatStream.IP.ThreatBulletin.owner_user_name | String | The owner user name of the threat bulletin. | 
| ThreatStream.IP.ThreatBulletin.parent | Unknown | The parent of the threat bulletin. | 
| ThreatStream.IP.ThreatBulletin.published_ts | Unknown | When was the threat bulletin published. | 
| ThreatStream.IP.ThreatBulletin.resource_uri | String | The resource uri of the threat bulletin. | 
| ThreatStream.IP.ThreatBulletin.source | Unknown | The source of the threat bulletin. | 
| ThreatStream.IP.ThreatBulletin.source_created | Unknown | When was the source created. | 
| ThreatStream.IP.ThreatBulletin.source_modified | Unknown | When was the source modified. | 
| ThreatStream.IP.ThreatBulletin.starred_by_me | Boolean | Was the threat bulletin started bt me. | 
| ThreatStream.IP.ThreatBulletin.starred_total_count | Number | The total count of times the threat bulletin was starred. | 
| ThreatStream.IP.ThreatBulletin.status | String | The status of the threat bulletin. | 
| ThreatStream.IP.ThreatBulletin.threat_actor | Unknown | The threat actor of the threat bulletin. | 
| ThreatStream.IP.ThreatBulletin.tlp | Unknown | The TLP of the threat bulletin. | 
| ThreatStream.IP.ThreatBulletin.ttp | Unknown | The TTP of the threat bulletin. | 
| ThreatStream.IP.ThreatBulletin.uuid | String | The UUID of the threat bulletin. | 
| ThreatStream.IP.ThreatBulletin.votes.me | Unknown | How nany votes by me. | 
| ThreatStream.IP.ThreatBulletin.votes.total | Number | How many votes total. | 
| ThreatStream.IP.ThreatBulletin.watched_by_me | Boolean | Was the threat bulletin watched by me? | 
| ThreatStream.IP.ThreatBulletin.watched_total_count | Number | The total count of watchers. | 
| ThreatStream.IP.TTP.assignee_user | Unknown | The Assignee User of the TTP. | 
| ThreatStream.IP.TTP.association_info.comment | Unknown | The comment in the association info of the TTP. | 
| ThreatStream.IP.TTP.association_info.created | Date | When was the association info created. | 
| ThreatStream.IP.TTP.association_info.from_id | Number | From which id the association info is related. | 
| ThreatStream.IP.TTP.can_add_public_tags | Boolean | Can we add a public tags or not to the TTP. | 
| ThreatStream.IP.TTP.created_ts | Date | When was the TTP cretad. | 
| ThreatStream.IP.TTP.feed_id | Number | The feed ID of the TTP. | 
| ThreatStream.IP.TTP.id | Number | The id of the TTP. | 
| ThreatStream.IP.TTP.is_anonymous | Boolean | Is the TTP anonymus or not. | 
| ThreatStream.IP.TTP.is_cloneable | String | Is the TTP clonable or not. | 
| ThreatStream.IP.TTP.is_public | Boolean | Is the TTP public or not. | 
| ThreatStream.IP.TTP.is_team | Boolean | Is the TTP in a team or not. | 
| ThreatStream.IP.TTP.modified_ts | Date | When was the TTP modified. | 
| ThreatStream.IP.TTP.name | String | The name of the TTP. | 
| ThreatStream.IP.TTP.organization_id | Number | The organization ID of the TTP. | 
| ThreatStream.IP.TTP.owner_user_id | Number | The owner user ID of the TTP. | 
| ThreatStream.IP.TTP.primary_motivation | Unknown | The primary motivation of the TTP. | 
| ThreatStream.IP.TTP.publication_status | String | The publication status of the TTP. | 
| ThreatStream.IP.TTP.published_ts | Date | When was the TTP published. | 
| ThreatStream.IP.TTP.resource_level | Unknown | The resource level of the TTP. | 
| ThreatStream.IP.TTP.resource_uri | String | The resource uri of the TTP. | 
| ThreatStream.IP.TTP.source_created | Unknown | When was the source created. | 
| ThreatStream.IP.TTP.source_modified | Unknown | When was the source modified. | 
| ThreatStream.IP.TTP.start_date | Unknown | The start date. | 
| ThreatStream.IP.TTP.tags | String | The tags of the threat indicator | 
| ThreatStream.IP.TTP.tags_v2.id | String | The id of the tag. | 
| ThreatStream.IP.TTP.tags_v2.name | String | The name of the tag. | 
| ThreatStream.IP.TTP.tlp | String | The tlp of the TTP. | 
| ThreatStream.IP.TTP.uuid | String | The uuid of the TTP. | 
| ThreatStream.IP.Vulnerability.assignee_user | Unknown | The Assignee User of the vulnerability. | 
| ThreatStream.IP.Vulnerability.association_info.comment | Unknown | The comment in the association info of the vulnerability. | 
| ThreatStream.IP.Vulnerability.association_info.created | Date | When was the association info created. | 
| ThreatStream.IP.Vulnerability.association_info.from_id | Number | From which id the association info is related. | 
| ThreatStream.IP.Vulnerability.can_add_public_tags | Boolean | Can we add a public tags or not to the vulnerability. | 
| ThreatStream.IP.Vulnerability.circles.id | String | The ID of the circle. | 
| ThreatStream.IP.Vulnerability.circles.name | String | The name of the circle. | 
| ThreatStream.IP.Vulnerability.circles.resource_uri | String | The resource uri of the circle. | 
| ThreatStream.IP.Vulnerability.created_ts | Date | When was the vulnerability created. | 
| ThreatStream.IP.Vulnerability.feed_id | Number | The feed ID of the vulnerability. | 
| ThreatStream.IP.Vulnerability.id | Number | The ID of the vulnerability. | 
| ThreatStream.IP.Vulnerability.is_anonymous | Boolean | Is the vulnerability anonymus or not. | 
| ThreatStream.IP.Vulnerability.is_cloneable | String | Is the vulnerability clonable or not. | 
| ThreatStream.IP.Vulnerability.is_public | Boolean | Is the vulnerability public or not. | 
| ThreatStream.IP.Vulnerability.is_system | Boolean | Is the vulnerability in the system or not. | 
| ThreatStream.IP.Vulnerability.modified_ts | Date | When was the vulnerability modified. | 
| ThreatStream.IP.Vulnerability.name | String | The name of the vulnerability. | 
| ThreatStream.IP.Vulnerability.organization_id | Number | The organization ID of the vulnerability. | 
| ThreatStream.IP.Vulnerability.owner_user_id | Unknown | The owner user ID of the vulnerability. | 
| ThreatStream.IP.Vulnerability.publication_status | String | The publication status of the vulnerability. | 
| ThreatStream.IP.Vulnerability.published_ts | Date | When was the vulnerability published. | 
| ThreatStream.IP.Vulnerability.resource_uri | String | The resource uri of the vulnerability. | 
| ThreatStream.IP.Vulnerability.source | String | The source of the vulnerability. | 
| ThreatStream.IP.Vulnerability.source_created | Unknown | The feed ID of the vulnerability. | 
| ThreatStream.IP.Vulnerability.source_modified | Unknown | Was the source modified. | 
| ThreatStream.IP.Vulnerability.tags | String | The tags of the vulnerability. | 
| ThreatStream.IP.Vulnerability.tags_v2.id | String | The id of the tag. | 
| ThreatStream.IP.Vulnerability.tags_v2.name | String | The name of the tag. | 
| ThreatStream.IP.Vulnerability.tlp | String | The tlp of the vulnerability. | 
| ThreatStream.IP.Vulnerability.update_id | Number | The update ID of the vulnerability. | 
| ThreatStream.IP.Vulnerability.uuid | String | The UUID of the vulnerability. | 
| ThreatStream.IP.Campaign.assignee_user | Unknown | The Assignee User of the vulnerability. | 
| ThreatStream.IP.Campaign.association_info.comment | Unknown | The comment in the association info of the vulnerability. | 
| ThreatStream.IP.Campaign.association_info.created | Date | When was the association info created. | 
| ThreatStream.IP.Campaign.association_info.from_id | Number | From which id the association info is related. | 
| ThreatStream.IP.Campaign.can_add_public_tags | Boolean | Can we add a public tags or not to the campaign. | 
| ThreatStream.IP.Campaign.created_ts | Date | When was the campaign created. | 
| ThreatStream.IP.Campaign.end_date | Unknown | The end date of the campaign. | 
| ThreatStream.IP.Campaign.feed_id | Number | The feed ID of the campaign. | 
| ThreatStream.IP.Campaign.id | Number | The ID of the campaign. | 
| ThreatStream.IP.Campaign.is_anonymous | Boolean | Is the campaign anonymus or not. | 
| ThreatStream.IP.Campaign.is_cloneable | String | Is the campaign clonable or not. | 
| ThreatStream.IP.Campaign.is_public | Boolean | Is the campaign public or not. | 
| ThreatStream.IP.Campaign.modified_ts | Date | When was the campain modified. | 
| ThreatStream.IP.Campaign.name | String | The name of the Campaign. | 
| ThreatStream.IP.Campaign.objective | Unknown | The objective of the campaign. | 
| ThreatStream.IP.Campaign.organization_id | Number | The organization ID of the campaign. | 
| ThreatStream.IP.Campaign.owner_user_id | Number | The owner user ID of the campaign. | 
| ThreatStream.IP.Campaign.publication_status | String | The publication status of the campaign | 
| ThreatStream.IP.Campaign.published_ts | Unknown | When was the campaign published. | 
| ThreatStream.IP.Campaign.resource_uri | String | The resource uri of the campaign. | 
| ThreatStream.IP.Campaign.source_created | Date | When was the campaign created. | 
| ThreatStream.IP.Campaign.source_modified | Date | Was the source modified or not. | 
| ThreatStream.IP.Campaign.start_date | Unknown | The start date of the campaign. | 
| ThreatStream.IP.Campaign.status.display_name | String | The display name of the status. | 
| ThreatStream.IP.Campaign.status.id | Number | The id of the status of the campaign. | 
| ThreatStream.IP.Campaign.status.resource_uri | String | The resource uri of the status of the campaign. | 
| ThreatStream.IP.Campaign.tlp | String | The tlp of the campaign. | 
| ThreatStream.IP.Campaign.uuid | String | The UUID of the campaign. | 

#### Command example
```!ip ip=1.1.1.1 threat_model_association=True```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "1.1.1.1",
        "Reliability": "B - Usually reliable",
        "Score": 3,
        "Type": "ip",
        "Vendor": "Anomali ThreatStream v3 May"
    },
    "IP": {
        "Address": "1.1.1.1",
        "Malicious": {
            "Description": null,
            "Vendor": "Anomali ThreatStream v3 May"
        },
        "Relationships": [
            {
                "EntityA": "1.1.1.1",
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
            "Address": "1.1.1.1",
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

>### IP reputation for: 1.1.1.1
>|ASN|Address|Confidence|Country|IType|Modified|Organization|Severity|Source|Status|Tags|Type|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>|  | 1.1.1.1 | 100 |  | apt_ip | 2022-08-01T09:46:41.715Z |  | very-high | Analyst | active | apt, PANW_Test | ip |
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
| threshold | If confidence is greater than the threshold the Domain is considered malicious, otherwise it is considered good. This argument overrides the default Domain threshold defined as a parameter. | Optional | 
| include_inactive | Whether to include results with an inactive status. Possible values are: True, False. | Optional | 
| threat_model_association | Note: if set to true, additional 6 API calls will be performed. Possible values are: True, False. Default is False. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The domain name. | 
| Domain.DNS | String | The IP addresses resolved by DNS. | 
| Domain.WHOIS.CreationDate | Date | The date the domain was created. The date format is: YYYYMMDDThhmmss, where T denotes the start of the value
for time in UTC time. | 
| Domain.WHOIS.UpdatedDate | Date | The date the domain was last updated. The date format is: YYYYMMDDThhmmss, where T denotes the start of the value
for time in UTC time. | 
| Domain.WHOIS.Registrant.Name | String | The registant name. | 
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
| ThreatStream.Domain.IType | String | The iType of the indicator associated with the specified model. | 
| Domain.Tags | Unknown | List of domain tags. | 
| Domain.ThreatTypes | Unknown | Threat types associated with the domain. | 
| ThreatStream.Domain.Actor.assignee_user | Unknown | The Assignee User of the Threat Actor | 
| ThreatStream.Domain.Actor.association_info.comment | Unknown | The comment in the association info of the threat actor. | 
| ThreatStream.Domain.Actor.association_info.created | Date | When was the association info created. | 
| ThreatStream.Domain.Actor.association_info.from_id | Number | From which id the association info is related. | 
| ThreatStream.Domain.Actor.can_add_public_tags | Boolean | Can we add a public tags or not to the threat actor. | 
| ThreatStream.Domain.Actor.created_ts | Date | When was the threat actor cretad. | 
| ThreatStream.Domain.Actor.feed_id | Number | The feed ID of the threat actor. | 
| ThreatStream.Domain.Actor.id | Number | The id of the threat actor. | 
| ThreatStream.Domain.Actor.is_anonymous | Boolean | Is the threat actor anonymus or not. | 
| ThreatStream.Domain.Actor.is_cloneable | String | Is the threat actor clonable or not. | 
| ThreatStream.Domain.Actor.is_public | Boolean | Is the threat actor public or not. | 
| ThreatStream.Domain.Actor.is_team | Boolean | Is the threat actor in a team or not. | 
| ThreatStream.Domain.Actor.modified_ts | Date | When was the threat actor modified. | 
| ThreatStream.Domain.Actor.name | String | The name of the threat actor. | 
| ThreatStream.Domain.Actor.organization_id | Number | The organization ID of the threat actor. | 
| ThreatStream.Domain.Actor.owner_user_id | Number | The owner user ID of the threat actor. | 
| ThreatStream.Domain.Actor.primary_motivation | Unknown | The primary motivation of the threat actor. | 
| ThreatStream.Domain.Actor.publication_status | String | The publication status of the threat actor. | 
| ThreatStream.Domain.Actor.published_ts | Date | When was the threat actor published. | 
| ThreatStream.Domain.Actor.resource_level | Unknown | The resource level of the threat actor. | 
| ThreatStream.Domain.Actor.resource_uri | String | The resource uri of the threat actor. | 
| ThreatStream.Domain.Actor.source_created | Unknown | When was the source created. | 
| ThreatStream.Domain.Actor.source_modified | Unknown | When was the source modified. | 
| ThreatStream.Domain.Actor.start_date | Unknown | The start date. | 
| ThreatStream.Domain.Actor.tags | String | The tags of the threat indicator | 
| ThreatStream.Domain.Actor.tags_v2.id | String | The id of the tag. | 
| ThreatStream.Domain.Actor.tags_v2.name | String | The name of the tag. | 
| ThreatStream.Domain.Actor.tlp | String | The tlp of the threat actor. | 
| ThreatStream.Domain.Actor.uuid | String | The uuid of the threat actor. | 
| ThreatStream.Domain.Signature.assignee_user | Unknown | The Assignee User of the signature | 
| ThreatStream.Domain.Signature.association_info.comment | Unknown | The comment in the association info of the signature. | 
| ThreatStream.Domain.Signature.association_info.created | Date | When was the association info created. | 
| ThreatStream.Domain.Signature.association_info.from_id | Number | From which id the association info is related. | 
| ThreatStream.Domain.Signature.can_add_public_tags | Boolean | Can we add a public tags or not to the signature. | 
| ThreatStream.Domain.Signature.created_ts | Date | When was the signature cretad. | 
| ThreatStream.Domain.Signature.feed_id | Number | The feed ID of the signature. | 
| ThreatStream.Domain.Signature.id | Number | The id of the signature. | 
| ThreatStream.Domain.Signature.is_anonymous | Boolean | Is the signature anonymus or not. | 
| ThreatStream.Domain.Signature.is_cloneable | String | Is the signature clonable or not. | 
| ThreatStream.Domain.Signature.is_public | Boolean | Is the signature public or not. | 
| ThreatStream.Domain.Signature.is_team | Boolean | Is the signature in a team or not. | 
| ThreatStream.Domain.Signature.modified_ts | Date | When was the signature modified. | 
| ThreatStream.Domain.Signature.name | String | The name of the signature. | 
| ThreatStream.Domain.Signature.organization_id | Number | The organization ID of the signature. | 
| ThreatStream.Domain.Signature.owner_user_id | Number | The owner user ID of the signature. | 
| ThreatStream.Domain.Signature.primary_motivation | Unknown | The primary motivation of the signature. | 
| ThreatStream.Domain.Signature.publication_status | String | The publication status of the signature. | 
| ThreatStream.Domain.Signature.published_ts | Date | When was the signature published. | 
| ThreatStream.Domain.Signature.resource_level | Unknown | The resource level of the signature. | 
| ThreatStream.Domain.Signature.resource_uri | String | The resource uri of the signature. | 
| ThreatStream.Domain.Signature.source_created | Unknown | When was the source created. | 
| ThreatStream.Domain.Signature.source_modified | Unknown | When was the source modified. | 
| ThreatStream.Domain.Signature.start_date | Unknown | The start date. | 
| ThreatStream.Domain.Signature.tags | String | The tags of the threat indicator | 
| ThreatStream.Domain.Signature.tags_v2.id | String | The id of the tag. | 
| ThreatStream.Domain.Signature.tags_v2.name | String | The name of the tag. | 
| ThreatStream.Domain.Signature.tlp | String | The tlp of the signature. | 
| ThreatStream.Domain.Signature.uuid | String | The uuid of the signature. | 
| ThreatStream.Domain.ThreatBulletin.all_circles_visible | Boolean | Are all of the circles visible. | 
| ThreatStream.Domain.ThreatBulletin.assignee_org | String | The assignee organization. | 
| ThreatStream.Domain.ThreatBulletin.assignee_org_id | String | The assignee organization ID. | 
| ThreatStream.Domain.ThreatBulletin.assignee_org_name | String | The assignee organization name. | 
| ThreatStream.Domain.ThreatBulletin.assignee_user | String | The assignee user. | 
| ThreatStream.Domain.ThreatBulletin.assignee_user_id | String | The assignee user ID. | 
| ThreatStream.Domain.ThreatBulletin.assignee_user_name | Unknown | The assignee user name. | 
| ThreatStream.Domain.ThreatBulletin.association_info.comment | Unknown | The comment in the association info of the threat actor. | 
| ThreatStream.Domain.ThreatBulletin.association_info.created | Date | When was the association info created. | 
| ThreatStream.Domain.ThreatBulletin.association_info.from_id | String | From which id the association info is related. | 
| ThreatStream.Domain.ThreatBulletin.body_content_type | String | The body content type. | 
| ThreatStream.Domain.ThreatBulletin.campaign | Unknown | The campaign of the threat bulletin. | 
| ThreatStream.Domain.ThreatBulletin.can_add_public_tags | Boolean | Can we add public tags. | 
| ThreatStream.Domain.ThreatBulletin.created_ts | Date | When was the threat bulletin created. | 
| ThreatStream.Domain.ThreatBulletin.feed_id | Number | The feed ID of the threat bulletin. | 
| ThreatStream.Domain.ThreatBulletin.id | String | The ID of the threat bulletin. | 
| ThreatStream.Domain.ThreatBulletin.is_anonymous | Boolean | Is the threat bulletin anonymous. | 
| ThreatStream.Domain.ThreatBulletin.is_cloneable | String | Is the threat bulletin cloneble. | 
| ThreatStream.Domain.ThreatBulletin.is_editable | Boolean | Is the threat bulletin editable. | 
| ThreatStream.Domain.ThreatBulletin.is_email | Boolean | Is the threat bulletin an email. | 
| ThreatStream.Domain.ThreatBulletin.is_public | Boolean | Is the threat bulletin public. | 
| ThreatStream.Domain.ThreatBulletin.modified_ts | Date | When was the threat bulletin modified. | 
| ThreatStream.Domain.ThreatBulletin.name | String | The name of the threat bulletin. | 
| ThreatStream.Domain.ThreatBulletin.original_source | String | The original source of the threat bulletin. | 
| ThreatStream.Domain.ThreatBulletin.original_source_id | Unknown | The original source ID of the threat bulletin. | 
| ThreatStream.Domain.ThreatBulletin.owner_org.id | String | The owner organizetion ID. | 
| ThreatStream.Domain.ThreatBulletin.owner_org.name | String | The owner organizetion name. | 
| ThreatStream.Domain.ThreatBulletin.owner_org.resource_uri | String | The owner organizetion uri. | 
| ThreatStream.Domain.ThreatBulletin.owner_org_id | Number | The id of the owner user. | 
| ThreatStream.Domain.ThreatBulletin.owner_org_name | String | The name of the owner organization. | 
| ThreatStream.Domain.ThreatBulletin.owner_user.avatar_s3_url | Unknown | The url of the owner user. | 
| ThreatStream.Domain.ThreatBulletin.owner_user.can_share_intelligence | Boolean | Can we share intelligence or not. | 
| ThreatStream.Domain.ThreatBulletin.owner_user.email | String | The email of the owner user. | 
| ThreatStream.Domain.ThreatBulletin.owner_user.id | String | The ID of the owner user. | 
| ThreatStream.Domain.ThreatBulletin.owner_user.is_active | Boolean | Is the owner user active. | 
| ThreatStream.Domain.ThreatBulletin.owner_user.is_readonly | Boolean | Is the owner user read only. | 
| ThreatStream.Domain.ThreatBulletin.owner_user.must_change_password | Boolean | Does the owner user must change password. | 
| ThreatStream.Domain.ThreatBulletin.owner_user.name | String | The owner user name. | 
| ThreatStream.Domain.ThreatBulletin.owner_user.nickname | String | The owner user nickname | 
| ThreatStream.Domain.ThreatBulletin.owner_user.organization.id | String | The ID of the owner user organization. | 
| ThreatStream.Domain.ThreatBulletin.owner_user.organization.name | String | The name of the owner user organization. | 
| ThreatStream.Domain.ThreatBulletin.owner_user.organization.resource_uri | String | The resource uri of the owner user organization. | 
| ThreatStream.Domain.ThreatBulletin.owner_user.resource_uri | String | The resource uri of the owner user. | 
| ThreatStream.Domain.ThreatBulletin.owner_user_id | Number | The owner user ID of the threat bulletin. | 
| ThreatStream.Domain.ThreatBulletin.owner_user_name | String | The owner user name of the threat bulletin. | 
| ThreatStream.Domain.ThreatBulletin.parent | Unknown | The parent of the threat bulletin. | 
| ThreatStream.Domain.ThreatBulletin.published_ts | Unknown | When was the threat bulletin published. | 
| ThreatStream.Domain.ThreatBulletin.resource_uri | String | The resource uri of the threat bulletin. | 
| ThreatStream.Domain.ThreatBulletin.source | Unknown | The source of the threat bulletin. | 
| ThreatStream.Domain.ThreatBulletin.source_created | Unknown | When was the source created. | 
| ThreatStream.Domain.ThreatBulletin.source_modified | Unknown | When was the source modified. | 
| ThreatStream.Domain.ThreatBulletin.starred_by_me | Boolean | Was the threat bulletin started bt me. | 
| ThreatStream.Domain.ThreatBulletin.starred_total_count | Number | The total count of times the threat bulletin was starred. | 
| ThreatStream.Domain.ThreatBulletin.status | String | The status of the threat bulletin. | 
| ThreatStream.Domain.ThreatBulletin.threat_actor | Unknown | The threat actor of the threat bulletin. | 
| ThreatStream.Domain.ThreatBulletin.tlp | Unknown | The TLP of the threat bulletin. | 
| ThreatStream.Domain.ThreatBulletin.ttp | Unknown | The TTP of the threat bulletin. | 
| ThreatStream.Domain.ThreatBulletin.uuid | String | The UUID of the threat bulletin. | 
| ThreatStream.Domain.ThreatBulletin.votes.me | Unknown | How nany votes by me. | 
| ThreatStream.Domain.ThreatBulletin.votes.total | Number | How many votes total. | 
| ThreatStream.Domain.ThreatBulletin.watched_by_me | Boolean | Was the threat bulletin watched by me? | 
| ThreatStream.Domain.ThreatBulletin.watched_total_count | Number | The total count of watchers. | 
| ThreatStream.Domain.TTP.assignee_user | Unknown | The Assignee User of the TTP. | 
| ThreatStream.Domain.TTP.association_info.comment | Unknown | The comment in the association info of the TTP. | 
| ThreatStream.Domain.TTP.association_info.created | Date | When was the association info created. | 
| ThreatStream.Domain.TTP.association_info.from_id | Number | From which id the association info is related. | 
| ThreatStream.Domain.TTP.can_add_public_tags | Boolean | Can we add a public tags or not to the TTP. | 
| ThreatStream.Domain.TTP.created_ts | Date | When was the TTP cretad. | 
| ThreatStream.Domain.TTP.feed_id | Number | The feed ID of the TTP. | 
| ThreatStream.Domain.TTP.id | Number | The id of the TTP. | 
| ThreatStream.Domain.TTP.is_anonymous | Boolean | Is the TTP anonymus or not. | 
| ThreatStream.Domain.TTP.is_cloneable | String | Is the TTP clonable or not. | 
| ThreatStream.Domain.TTP.is_public | Boolean | Is the TTP public or not. | 
| ThreatStream.Domain.TTP.is_team | Boolean | Is the TTP in a team or not. | 
| ThreatStream.Domain.TTP.modified_ts | Date | When was the TTP modified. | 
| ThreatStream.Domain.TTP.name | String | The name of the TTP. | 
| ThreatStream.Domain.TTP.organization_id | Number | The organization ID of the TTP. | 
| ThreatStream.Domain.TTP.owner_user_id | Number | The owner user ID of the TTP. | 
| ThreatStream.Domain.TTP.primary_motivation | Unknown | The primary motivation of the TTP. | 
| ThreatStream.Domain.TTP.publication_status | String | The publication status of the TTP. | 
| ThreatStream.Domain.TTP.published_ts | Date | When was the TTP published. | 
| ThreatStream.Domain.TTP.resource_level | Unknown | The resource level of the TTP. | 
| ThreatStream.Domain.TTP.resource_uri | String | The resource uri of the TTP. | 
| ThreatStream.Domain.TTP.source_created | Unknown | When was the source created. | 
| ThreatStream.Domain.TTP.source_modified | Unknown | When was the source modified. | 
| ThreatStream.Domain.TTP.start_date | Unknown | The start date. | 
| ThreatStream.Domain.TTP.tags | String | The tags of the threat indicator | 
| ThreatStream.Domain.TTP.tags_v2.id | String | The id of the tag. | 
| ThreatStream.Domain.TTP.tags_v2.name | String | The name of the tag. | 
| ThreatStream.Domain.TTP.tlp | String | The tlp of the TTP. | 
| ThreatStream.Domain.TTP.uuid | String | The uuid of the TTP. | 
| ThreatStream.Domain.Vulnerability.assignee_user | Unknown | The Assignee User of the vulnerability. | 
| ThreatStream.Domain.Vulnerability.association_info.comment | Unknown | The comment in the association info of the vulnerability. | 
| ThreatStream.Domain.Vulnerability.association_info.created | Date | When was the association info created. | 
| ThreatStream.Domain.Vulnerability.association_info.from_id | Number | From which id the association info is related. | 
| ThreatStream.Domain.Vulnerability.can_add_public_tags | Boolean | Can we add a public tags or not to the vulnerability. | 
| ThreatStream.Domain.Vulnerability.circles.id | String | The ID of the circle. | 
| ThreatStream.Domain.Vulnerability.circles.name | String | The name of the circle. | 
| ThreatStream.Domain.Vulnerability.circles.resource_uri | String | The resource uri of the circle. | 
| ThreatStream.Domain.Vulnerability.created_ts | Date | When was the vulnerability created. | 
| ThreatStream.Domain.Vulnerability.feed_id | Number | The feed ID of the vulnerability. | 
| ThreatStream.Domain.Vulnerability.id | Number | The ID of the vulnerability. | 
| ThreatStream.Domain.Vulnerability.is_anonymous | Boolean | Is the vulnerability anonymus or not. | 
| ThreatStream.Domain.Vulnerability.is_cloneable | String | Is the vulnerability clonable or not. | 
| ThreatStream.Domain.Vulnerability.is_public | Boolean | Is the vulnerability public or not. | 
| ThreatStream.Domain.Vulnerability.is_system | Boolean | Is the vulnerability in the system or not. | 
| ThreatStream.Domain.Vulnerability.modified_ts | Date | When was the vulnerability modified. | 
| ThreatStream.Domain.Vulnerability.name | String | The name of the vulnerability. | 
| ThreatStream.Domain.Vulnerability.organization_id | Number | The organization ID of the vulnerability. | 
| ThreatStream.Domain.Vulnerability.owner_user_id | Unknown | The owner user ID of the vulnerability. | 
| ThreatStream.Domain.Vulnerability.publication_status | String | The publication status of the vulnerability. | 
| ThreatStream.Domain.Vulnerability.published_ts | Date | When was the vulnerability published. | 
| ThreatStream.Domain.Vulnerability.resource_uri | String | The resource uri of the vulnerability. | 
| ThreatStream.Domain.Vulnerability.source | String | The source of the vulnerability. | 
| ThreatStream.Domain.Vulnerability.source_created | Unknown | The feed ID of the vulnerability. | 
| ThreatStream.Domain.Vulnerability.source_modified | Unknown | Was the source modified. | 
| ThreatStream.Domain.Vulnerability.tags | String | The tags of the vulnerability. | 
| ThreatStream.Domain.Vulnerability.tags_v2.id | String | The id of the tag. | 
| ThreatStream.Domain.Vulnerability.tags_v2.name | String | The name of the tag. | 
| ThreatStream.Domain.Vulnerability.tlp | String | The tlp of the vulnerability. | 
| ThreatStream.Domain.Vulnerability.update_id | Number | The update ID of the vulnerability. | 
| ThreatStream.Domain.Vulnerability.uuid | String | The UUID of the vulnerability. | 
| ThreatStream.Domain.Campaign.assignee_user | Unknown | The Assignee User of the vulnerability. | 
| ThreatStream.Domain.Campaign.association_info.comment | Unknown | The comment in the association info of the vulnerability. | 
| ThreatStream.Domain.Campaign.association_info.created | Date | When was the association info created. | 
| ThreatStream.Domain.Campaign.association_info.from_id | Number | From which id the association info is related. | 
| ThreatStream.Domain.Campaign.can_add_public_tags | Boolean | Can we add a public tags or not to the campaign. | 
| ThreatStream.Domain.Campaign.created_ts | Date | When was the campaign created. | 
| ThreatStream.Domain.Campaign.end_date | Unknown | The end date of the campaign. | 
| ThreatStream.Domain.Campaign.feed_id | Number | The feed ID of the campaign. | 
| ThreatStream.Domain.Campaign.id | Number | The ID of the campaign. | 
| ThreatStream.Domain.Campaign.is_anonymous | Boolean | Is the campaign anonymus or not. | 
| ThreatStream.Domain.Campaign.is_cloneable | String | Is the campaign clonable or not. | 
| ThreatStream.Domain.Campaign.is_public | Boolean | Is the campaign public or not. | 
| ThreatStream.Domain.Campaign.modified_ts | Date | When was the campain modified. | 
| ThreatStream.Domain.Campaign.name | String | The name of the Campaign. | 
| ThreatStream.Domain.Campaign.objective | Unknown | The objective of the campaign. | 
| ThreatStream.Domain.Campaign.organization_id | Number | The organization ID of the campaign. | 
| ThreatStream.Domain.Campaign.owner_user_id | Number | The owner user ID of the campaign. | 
| ThreatStream.Domain.Campaign.publication_status | String | The publication status of the campaign | 
| ThreatStream.Domain.Campaign.published_ts | Unknown | When was the campaign published. | 
| ThreatStream.Domain.Campaign.resource_uri | String | The resource uri of the campaign. | 
| ThreatStream.Domain.Campaign.source_created | Date | When was the campaign created. | 
| ThreatStream.Domain.Campaign.source_modified | Date | Was the source modified or not. | 
| ThreatStream.Domain.Campaign.start_date | Unknown | The start date of the campaign. | 
| ThreatStream.Domain.Campaign.status.display_name | String | The display name of the status. | 
| ThreatStream.Domain.Campaign.status.id | Number | The id of the status of the campaign. | 
| ThreatStream.Domain.Campaign.status.resource_uri | String | The resource uri of the status of the campaign. | 
| ThreatStream.Domain.Campaign.tlp | String | The tlp of the campaign. | 
| ThreatStream.Domain.Campaign.uuid | String | The UUID of the campaign. | 

#### Command example
```!domain domain=y.gp threat_model_association=True```
#### Context Example
```json
{
    "DBotScore": [
        {
            "Indicator": "y.gp",
            "Reliability": "C - Fairly reliable",
            "Score": 1,
            "Type": "domain",
            "Vendor": "VirusTotal"
        },
        {
            "Indicator": "y.gp",
            "Reliability": "B - Usually reliable",
            "Score": 2,
            "Type": "domain",
            "Vendor": "Anomali ThreatStream v3 May"
        }
    ],
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
        "VirusTotal": {
            "CommunicatingHashes": [],
            "DetectedURLs": [
                {
                    "positives": 1,
                    "scan_date": "2019-11-03 20:08:55",
                    "total": 71,
                    "url": "url"
                }
            ],
            "DownloadedHashes": [],
            "ReferrerHashes": [
                {
                    "date": "2020-07-21 07:51:14",
                    "positives": 57,
                    "sha256": "38e44d856a42e005551efc9b2e65bb9fc682295708f6cb7a8a9051f3428811ec",
                    "total": 76
                },
                {
                    "date": "2020-07-21 07:40:25",
                    "positives": 1,
                    "sha256": "ea8bf8c76fe922527659c076d215244393117d36408c031301eaecd7431a63a5",
                    "total": 75
                },
                {
                    "date": "2020-07-21 07:33:18",
                    "positives": 60,
                    "sha256": "a5c7766c4f593165febf5f91c44f20a3f55b4b8a7dca8a7c4278fb9533cb8ed1",
                    "total": 76
                },
                {
                    "date": "2020-07-21 07:00:20",
                    "positives": 58,
                    "sha256": "8315cee7ed484c88015438c1bd231e06c031f2be5eb94d27fdedcaf624ed6a94",
                    "total": 76
                },
                {
                    "date": "2020-07-21 07:00:48",
                    "positives": 5,
                    "sha256": "688373e408481000936895e0d41c190daff31d895f8f01d19236d0d9b763a8a0",
                    "total": 76
                },
                {
                    "date": "2020-07-21 06:22:47",
                    "positives": 4,
                    "sha256": "dde7a799951c54f69e4cce7472e04f6a077eb316bb3fc2d24e82380d1eb69245",
                    "total": 74
                },
                {
                    "date": "2020-07-21 06:19:33",
                    "positives": 33,
                    "sha256": "6b512568470d4a7fc74088a1b86dc8e59ed4423e4ff359e87a95297584651de4",
                    "total": 76
                },
                {
                    "date": "2020-07-21 06:16:19",
                    "positives": 46,
                    "sha256": "b0b9670a52f052b884ca5887c02cb7005da6503d956c91be6e15756f8785dcb3",
                    "total": 75
                },
                {
                    "date": "2020-07-21 06:07:26",
                    "positives": 15,
                    "sha256": "41e8e51202c0b6f338b19ec4513aba79a6726e21a914325ecf39339b201f5935",
                    "total": 75
                },
                {
                    "date": "2020-07-21 05:31:14",
                    "positives": 45,
                    "sha256": "bbda1a77c25f4c72f3d6a7a57ce50fa856f2ede82ed369a8d02ff30d41c0a7e8",
                    "total": 75
                },
                {
                    "date": "2020-07-21 05:13:53",
                    "positives": 61,
                    "sha256": "da0e055d4968086bb3064d7a9bd7405ab1becfd8e1910637475d5e06479e8e01",
                    "total": 75
                },
                {
                    "date": "2020-07-21 05:06:47",
                    "positives": 62,
                    "sha256": "8a375cb74d8f14a0c236c8fe695bc02c417c466a0b6e39d30e0d442c2fe7429e",
                    "total": 76
                },
                {
                    "date": "2020-07-21 04:15:10",
                    "positives": 50,
                    "sha256": "3117df7d25aee63df17ae6e85aef5da8348caae23d3cb7840601f2385c4be09c",
                    "total": 75
                },
                {
                    "date": "2020-07-21 03:57:39",
                    "positives": 61,
                    "sha256": "9c72aa3c8cc39616ae7350add253ff64db9d9519e57bf9c6b5342661a59d4dd8",
                    "total": 75
                },
                {
                    "date": "2020-07-21 03:32:27",
                    "positives": 3,
                    "sha256": "f69034de0afd70b1e08711d1b0ce661764e8d390382f4b8a9b4f094dd41d3347",
                    "total": 74
                },
                {
                    "date": "2020-07-21 02:48:23",
                    "positives": 30,
                    "sha256": "09dcfa8608b7007b6ef899a9b88529afab34aac35d683b57ce6c7ea800eea752",
                    "total": 75
                },
                {
                    "date": "2020-07-21 02:41:13",
                    "positives": 1,
                    "sha256": "9eea0b747df7b8f3663920b0b577ea27b093afb36f0e298f6ae6a697dadb8950",
                    "total": 75
                },
                {
                    "date": "2020-07-21 02:11:28",
                    "positives": 61,
                    "sha256": "142ba3121b2409cc68888d58800276153c517e816a338a02dfb3b1e457cfb915",
                    "total": 76
                },
                {
                    "date": "2020-07-21 02:03:27",
                    "positives": 14,
                    "sha256": "ef8d40961195079c435b19c548bbd616f599baf5b9706f90314c55957e8c79d0",
                    "total": 75
                },
                {
                    "date": "2020-07-21 01:58:55",
                    "positives": 58,
                    "sha256": "29ded3d62a91270d4bf4f36fd6f7a7f212a1dfef97da9b3bacd7553586662597",
                    "total": 75
                },
                {
                    "date": "2020-07-21 01:45:22",
                    "positives": 43,
                    "sha256": "6f7891ab76f373aa4f263f4c91fccb1641540e687bb799558d3e6748b28872c1",
                    "total": 76
                },
                {
                    "date": "2020-07-21 01:24:33",
                    "positives": 34,
                    "sha256": "cb4d1e23a939e4617465ce387758801190cccca7b310313886836c545a4d4c78",
                    "total": 75
                },
                {
                    "date": "2020-07-21 01:21:53",
                    "positives": 24,
                    "sha256": "88c6284ccae675623a13e1c3dc1418d755c069d1d6c0314bfa16d00fd0140948",
                    "total": 76
                },
                {
                    "date": "2020-07-21 01:07:25",
                    "positives": 61,
                    "sha256": "e19c17a6b0a2ed0a5ed6d56e283eea007d96e63d32b70e3f014a36082605f5f7",
                    "total": 74
                },
                {
                    "date": "2020-07-21 00:33:54",
                    "positives": 60,
                    "sha256": "a651eafa8f0c73696454d2e89ff90120645b0455e86f5814cd239237efd91d93",
                    "total": 76
                },
                {
                    "date": "2020-07-21 00:25:35",
                    "positives": 60,
                    "sha256": "fc032be6efa534d82643782cef7e0fdf92af66fdec53c4722d70ef9ebbb94db6",
                    "total": 76
                },
                {
                    "date": "2020-07-20 23:20:10",
                    "positives": 27,
                    "sha256": "e1d504bc56ed17a9d87ba9f42f742cbf57971de32176850daf5a2ca6ede5ab42",
                    "total": 75
                },
                {
                    "date": "2020-07-20 23:07:24",
                    "positives": 13,
                    "sha256": "26a02fc095e50f146eb5c2421db6188fe4030e241840537ac0c2bef54cfcdf01",
                    "total": 75
                },
                {
                    "date": "2020-07-20 22:12:48",
                    "positives": 1,
                    "sha256": "c7e4fecd0608380fab4f185a50670d8079295207a9cdece313ecf2e988270bc7",
                    "total": 75
                },
                {
                    "date": "2020-07-20 21:49:53",
                    "positives": 1,
                    "sha256": "e1f18c19bf79eee673632d919476e278c62f544c8da8bf071ce1af8bf16150a0",
                    "total": 76
                },
                {
                    "date": "2020-07-20 20:50:25",
                    "positives": 1,
                    "sha256": "e3cf52fbf25270f12eeacd3bd7dd61fbb702b6e0e6d5152cb984acd2a49804b9",
                    "total": 75
                },
                {
                    "date": "2020-07-20 19:37:21",
                    "positives": 15,
                    "sha256": "5b64f1eea6d7bcc8c4a59f75219759fcfeaf174721605d98cac814ee86bd6c23",
                    "total": 75
                },
                {
                    "date": "2020-07-20 18:49:12",
                    "positives": 1,
                    "sha256": "9fd16829a22a79ad1a278990d320001e801af4e4e322b553d170124642465ba4",
                    "total": 75
                },
                {
                    "date": "2020-07-20 18:17:27",
                    "positives": 2,
                    "sha256": "85ed0e94e14d3458bd87975e3d10f2950c9fe30d014dacfcd10a4c816134cac7",
                    "total": 74
                },
                {
                    "date": "2020-07-20 18:12:35",
                    "positives": 4,
                    "sha256": "b04f57e504a0bb1a832f6891d08e330b3049c3a03dfdf6aae806a121d37d571e",
                    "total": 76
                },
                {
                    "date": "2020-07-20 17:04:01",
                    "positives": 1,
                    "sha256": "975c382cd0bbde210843a7678dc48ea805f1ea59d2a85308497bb0a41cfd03e3",
                    "total": 75
                },
                {
                    "date": "2020-07-20 16:53:46",
                    "positives": 8,
                    "sha256": "b2504387a808ea3cdf00b91f84574a25e7ccb1ea5560158a74943ab0a7f06d0b",
                    "total": 75
                },
                {
                    "date": "2020-07-20 16:48:19",
                    "positives": 3,
                    "sha256": "59328ba228a5eb8ab06ed522cd8b66fa97ff6809edd5e1ba902e701d4cf5b083",
                    "total": 75
                },
                {
                    "date": "2020-07-20 16:38:11",
                    "positives": 59,
                    "sha256": "40bb46a4853a6e9259d6dabbe267c6f7fc5a4d814339c1c24c98468b71265006",
                    "total": 75
                },
                {
                    "date": "2020-07-20 16:14:02",
                    "positives": 4,
                    "sha256": "980fbfc7e13ddca6820bcf2243d1b8b899b4741b718bd1a8f39cc4cab056480c",
                    "total": 75
                },
                {
                    "date": "2020-07-20 15:27:47",
                    "positives": 56,
                    "sha256": "a24179263671de2a3a1af87af0f9b7a3fcd5826ec4f0ae35cac344929860b3fc",
                    "total": 74
                },
                {
                    "date": "2020-07-20 15:07:39",
                    "positives": 60,
                    "sha256": "8dec1faf0bb98f8c8ed6df0661e550b8fa8c2cc9902e3a2b5360ad4ba2cb581a",
                    "total": 74
                },
                {
                    "date": "2020-07-20 15:05:28",
                    "positives": 61,
                    "sha256": "b6b51b92a5d341428f7b435d51845237e8ceb9ffeb9a70dd99cf032030441716",
                    "total": 75
                },
                {
                    "date": "2020-07-20 14:55:27",
                    "positives": 1,
                    "sha256": "fa35cb3b953717405bcb03a4b4a8bab85cabc1b27ee91d82e3868150df207da8",
                    "total": 74
                },
                {
                    "date": "2020-07-20 14:47:02",
                    "positives": 57,
                    "sha256": "30cd0a633ac8e60d7e6cde497a114323f70a90f521415da32ec3914d3e75c05a",
                    "total": 75
                },
                {
                    "date": "2020-07-20 14:37:24",
                    "positives": 1,
                    "sha256": "8df6713d8273c2ff6447de5b868757ce72c30379c0fe7c2e25377cbf9055ac6e",
                    "total": 75
                },
                {
                    "date": "2020-07-20 14:21:09",
                    "positives": 8,
                    "sha256": "39d024b58a446c326583fef47f9988d1fe83436926573e8d9b04aea5ad769dd1",
                    "total": 74
                },
                {
                    "date": "2020-07-20 14:02:51",
                    "positives": 7,
                    "sha256": "e13c136f469058797076e43a69beed0cd023592c4dbe8c39e4bd6952c0b77bdc",
                    "total": 75
                },
                {
                    "date": "2020-07-20 14:01:09",
                    "positives": 56,
                    "sha256": "1d462a45b1869bb35afe0405aa9cbfe455d573f25d0041c252776cbc5b3ac8ad",
                    "total": 75
                },
                {
                    "date": "2020-07-20 13:42:44",
                    "positives": 60,
                    "sha256": "15d5dd484c313eda4823bc130faeed1e0a375d72da787106116491efbb2664a1",
                    "total": 75
                }
            ],
            "Resolutions": [
                {
                    "ip_address": "1.1.1.1",
                    "last_resolved": "2022-02-25 08:37:14"
                },
                {
                    "ip_address": "1.1.1.1",
                    "last_resolved": "2019-12-12 23:53:56"
                },
                {
                    "ip_address": "1.1.1.1",
                    "last_resolved": "2013-04-14 00:00:00"
                }
            ],
            "Subdomains": [],
            "UnAVDetectedCommunicatingHashes": [],
            "UnAVDetectedDownloadedHashes": [],
            "UnAVDetectedReferrerHashes": [
                {
                    "date": "2020-07-21 07:48:17",
                    "positives": 0,
                    "sha256": "2eed3146a5a6a6794fc6da57a32df0037f0e5299f1de09ee8a29bb105c51d63c",
                    "total": 75
                },
                {
                    "date": "2020-07-21 07:41:37",
                    "positives": 0,
                    "sha256": "8e7ea5d20ca45433207f1a84397ce84a9b4351b14fa183fd1e74eb8b79577375",
                    "total": 75
                },
                {
                    "date": "2020-07-21 07:36:24",
                    "positives": 0,
                    "sha256": "a56eac7cf96b9d66748ba421f4af659895a4e9199635a9964b94fb9e43ec23cb",
                    "total": 76
                },
                {
                    "date": "2020-07-21 07:21:34",
                    "positives": 0,
                    "sha256": "c623a1f63c20cfba9fd4ee3801eb590259977f2118d3fb5f1569870a062fe3ee",
                    "total": 75
                },
                {
                    "date": "2020-07-21 07:14:58",
                    "positives": 0,
                    "sha256": "0f47dceee53890fd463fe3569bc2a145cd6124e924269e7932e6c21ed3a820d6",
                    "total": 75
                },
                {
                    "date": "2020-07-21 07:11:49",
                    "positives": 0,
                    "sha256": "d00f209c2275c21cae7176311622617ff4dfb9fbccc6271c81bf3388ee592b80",
                    "total": 74
                },
                {
                    "date": "2020-07-21 07:05:56",
                    "positives": 0,
                    "sha256": "fa15e0f921078235038b6bccd19b825690339209b5cafbcfc505a47b236a5d56",
                    "total": 76
                },
                {
                    "date": "2020-07-21 06:54:12",
                    "positives": 0,
                    "sha256": "45388258bab9dc326784463aee485eb9ee19fe79090f1ddc154bc01675a7b790",
                    "total": 76
                },
                {
                    "date": "2020-07-21 06:52:12",
                    "positives": 0,
                    "sha256": "be8c1d5fb0f757d0ac97680588bf016fe75068fc8cf58bc85c183b5410943619",
                    "total": 76
                },
                {
                    "date": "2020-07-21 06:35:09",
                    "positives": 0,
                    "sha256": "3c6bda12fc86afcfffb5c7e7c6c5ddbfed3629f3f30dbbb0dac46e8aebb34f6b",
                    "total": 75
                },
                {
                    "date": "2020-07-21 06:23:21",
                    "positives": 0,
                    "sha256": "5ed650ed9d21399c107c5be9f4035b28b061afac571851e1d73890a39f843f4a",
                    "total": 76
                },
                {
                    "date": "2020-07-21 06:08:49",
                    "positives": 0,
                    "sha256": "536114cc45166ef74af0acae9143213bbf3ca844f3c8a39fb1f53e601ce17e5c",
                    "total": 75
                },
                {
                    "date": "2020-07-21 06:06:20",
                    "positives": 0,
                    "sha256": "cc3087d45cada72ca1241210c9a9589e0b4c41f18485975f6b40d56c1e6166c7",
                    "total": 76
                },
                {
                    "date": "2020-07-21 06:03:09",
                    "positives": 0,
                    "sha256": "1a14e3fd64d47b0a5cbc4d1203cb34bbf246d63961d9d055ec9b3cdd45c23d88",
                    "total": 76
                },
                {
                    "date": "2020-07-21 05:49:48",
                    "positives": 0,
                    "sha256": "74158bf36feec06a52b3bef9d1bdb06fa0a920a5d31b5a80bd8c6ffacd616058",
                    "total": 75
                },
                {
                    "date": "2020-07-21 05:46:10",
                    "positives": 0,
                    "sha256": "3ecf8f9b54c777283c29bf8f2d6c1456fca127d4814c259b8e1c8b1b1be559d8",
                    "total": 75
                },
                {
                    "date": "2020-07-21 05:42:25",
                    "positives": 0,
                    "sha256": "da20ac768e05b5b7c1fc3ff02d7e256d88534a2c49a6ff6fb0363b61fdacff71",
                    "total": 76
                },
                {
                    "date": "2020-07-21 05:24:11",
                    "positives": 0,
                    "sha256": "9e71ac47c099ec81f9750f8bc46858df7ec89393ace8cdba22c6b9d7efdae7de",
                    "total": 75
                },
                {
                    "date": "2020-07-21 05:22:38",
                    "positives": 0,
                    "sha256": "01778ea7cd0c371988c4c979d40c3f283a892dab568d05c430f9bd06de088475",
                    "total": 76
                },
                {
                    "date": "2020-07-21 05:15:41",
                    "positives": 0,
                    "sha256": "bae74e0f6a8eed3997fcbb58f019989036121c0aa5a93e5b6257d0e847d8b1b5",
                    "total": 76
                },
                {
                    "date": "2020-07-21 04:56:35",
                    "positives": 0,
                    "sha256": "17368d13f91a86bcba0969f22ed076fb4e0e82310488845f638c7c894e51131d",
                    "total": 75
                },
                {
                    "date": "2020-07-21 04:53:27",
                    "positives": 0,
                    "sha256": "ae90d63751eda1fec9d47df56d5d940f8d019eb0ddf73131cc52e233479d9939",
                    "total": 76
                },
                {
                    "date": "2020-07-21 04:48:25",
                    "positives": 0,
                    "sha256": "0dbcf00b5348983460cb7a7b1245636ee1f40284ca510e65776803a967a2e82a",
                    "total": 76
                },
                {
                    "date": "2020-07-21 04:42:04",
                    "positives": 0,
                    "sha256": "6f5368bac2966e32a338fd61bfc902eed3a8f758cda388961d71bd38dba56304",
                    "total": 75
                },
                {
                    "date": "2020-07-21 04:32:54",
                    "positives": 0,
                    "sha256": "a9ec8c79b92ed8fc892c09bb5a379dc3e0d07169ef3451288a9c638ac8d82088",
                    "total": 75
                },
                {
                    "date": "2020-07-21 03:59:56",
                    "positives": 0,
                    "sha256": "20568f972dc5da9afdfa98b6d28b83b535479109cdfb772b8d6cdfc52645cd6d",
                    "total": 75
                },
                {
                    "date": "2020-07-21 03:55:46",
                    "positives": 0,
                    "sha256": "31bb44e510c39b216c61cc8c7cb5c9b2f638ff49f2fd650381c392126993af29",
                    "total": 76
                },
                {
                    "date": "2020-07-21 03:41:18",
                    "positives": 0,
                    "sha256": "582892344e5499e696e2ab56d5a6e94a7e6a936d161983213502fc46a901a86d",
                    "total": 75
                },
                {
                    "date": "2020-07-21 03:26:16",
                    "positives": 0,
                    "sha256": "77aa166fdd585d4fd911811e39b87b6582748c075918a8d0b03141f6a180f5e0",
                    "total": 76
                },
                {
                    "date": "2020-07-21 03:17:19",
                    "positives": 0,
                    "sha256": "756f61c76b007399002e62efe8be771140e88b442cba2cae3d7bd8b9ba92ed08",
                    "total": 75
                },
                {
                    "date": "2020-07-21 02:00:38",
                    "positives": 0,
                    "sha256": "334520339f03801a290c6e2a53dc59ccc6c4001c2e22db6ad4fcb8baa8f7100d",
                    "total": 76
                },
                {
                    "date": "2020-07-21 01:44:03",
                    "positives": 0,
                    "sha256": "8bcde9a31ff5ebf8bd695f16d644931d12845c4f5ec8b65ba82ce31331742160",
                    "total": 75
                },
                {
                    "date": "2020-07-21 01:02:52",
                    "positives": 0,
                    "sha256": "bf77385b51edf7b11a37374e6ac21f1f1b22a95da171b7c91cfc94737d84b2d3",
                    "total": 75
                },
                {
                    "date": "2020-07-21 00:23:41",
                    "positives": 0,
                    "sha256": "105803336debfd961e843814fd73816c65042beba413c32121e2588a290b0076",
                    "total": 76
                },
                {
                    "date": "2020-07-21 00:31:44",
                    "positives": 0,
                    "sha256": "fde97ce2779b5a69a5e078db2f43a26eb24fab7cccdcd7b626f1765705ec4aa6",
                    "total": 75
                },
                {
                    "date": "2020-07-21 00:08:54",
                    "positives": 0,
                    "sha256": "d700f46b4a2ff13fc8ab8bb65ad4456c9b7178d28fb259ec1fbf27d6d825ac45",
                    "total": 75
                },
                {
                    "date": "2020-07-21 00:01:11",
                    "positives": 0,
                    "sha256": "356fc1c01af315ec95b1dc88003aa101624fbb0e1c9161cbb09297cc8fd5a3f3",
                    "total": 75
                },
                {
                    "date": "2020-07-20 23:47:21",
                    "positives": 0,
                    "sha256": "48abfa5dffb8022eea8aad24f87ab829c4dd3c8611daec8e00bd30da8409b2d5",
                    "total": 76
                },
                {
                    "date": "2020-07-20 23:37:34",
                    "positives": 0,
                    "sha256": "5d4f1dee3b4b7bec7f1d9671c3fd8046bff8180f5a85ff56b62cf3037af93119",
                    "total": 75
                },
                {
                    "date": "2020-07-20 23:23:16",
                    "positives": 0,
                    "sha256": "165c6bf214fb425024714b38c59fcbadaa93c181b8f8ddabd502998950ffd8c2",
                    "total": 75
                },
                {
                    "date": "2020-07-20 23:12:16",
                    "positives": 0,
                    "sha256": "f36b7a5e10f0ed67d39e330ab7f5f8c111530db67f2c511d246837ed3fa651a2",
                    "total": 73
                },
                {
                    "date": "2020-07-20 23:07:08",
                    "positives": 0,
                    "sha256": "34356b2c9f6f7d27abae2ea6d9e3abadb8fffdd95e51e009328ac1585885b902",
                    "total": 76
                },
                {
                    "date": "2020-07-20 23:01:24",
                    "positives": 0,
                    "sha256": "fb7d80dd5699d4bac790993a27852d4be79e8ad496f55c3a7fc7260c5f5fd96a",
                    "total": 76
                },
                {
                    "date": "2020-07-20 22:45:54",
                    "positives": 0,
                    "sha256": "065b7020c8d74871c6d9bc079bb21b2b5383d59a9d33e56673e032cd024a16fa",
                    "total": 75
                },
                {
                    "date": "2020-07-20 22:29:23",
                    "positives": 0,
                    "sha256": "b7e4cd539837beebc48e46f50bd426e0e67660b5ab2f73e41d2f9b8859aca9b0",
                    "total": 76
                },
                {
                    "date": "2020-07-20 22:03:41",
                    "positives": 0,
                    "sha256": "2fed6a844074b7e03d550a0c2ca72bf4eacf8432005ed4d406bf3c70fe9c06d4",
                    "total": 76
                },
                {
                    "date": "2020-07-20 21:43:36",
                    "positives": 0,
                    "sha256": "912094dc2de6311183956c7868cc30b76c7bcdbc327de367f9455636f5a20717",
                    "total": 76
                },
                {
                    "date": "2020-07-20 21:24:15",
                    "positives": 0,
                    "sha256": "89c3ac5a060314dc5d0461591d5ce4380b72eabe37e2016b5a49e6a5104d2815",
                    "total": 76
                },
                {
                    "date": "2020-07-20 21:11:50",
                    "positives": 0,
                    "sha256": "816091db6305e02f284c3daec892c977cf7b25451dd662548d6ff6a845ca470d",
                    "total": 76
                },
                {
                    "date": "2020-07-20 21:11:54",
                    "positives": 0,
                    "sha256": "d3cc94accdcceec37778ed665d9aaf356db9c046a61ea030baa611f9729e66ae",
                    "total": 76
                }
            ],
            "Whois": "Admin Email : mail"
        },
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
| threat_model_association | Note: if set to true, additional 6 API calls will be performed. Possible values are: True, False. Default is False. | Optional | 


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
| ThreatStream.File.IType | String | The iType of the indicator associated with the specified model. | 
| File.Tags | Unknown | List of file tags. | 
| File.ThreatTypes | Unknown | Threat types associated with the file. | 
| ThreatStream.File.Actor.assignee_user | Unknown | The Assignee User of the Threat Actor | 
| ThreatStream.File.Actor.association_info.comment | Unknown | The comment in the association info of the threat actor. | 
| ThreatStream.File.Actor.association_info.created | Date | When was the association info created. | 
| ThreatStream.File.Actor.association_info.from_id | Number | From which id the association info is related. | 
| ThreatStream.File.Actor.can_add_public_tags | Boolean | Can we add a public tags or not to the threat actor. | 
| ThreatStream.File.Actor.created_ts | Date | When was the threat actor cretad. | 
| ThreatStream.File.Actor.feed_id | Number | The feed ID of the threat actor. | 
| ThreatStream.File.Actor.id | Number | The id of the threat actor. | 
| ThreatStream.File.Actor.is_anonymous | Boolean | Is the threat actor anonymus or not. | 
| ThreatStream.File.Actor.is_cloneable | String | Is the threat actor clonable or not. | 
| ThreatStream.File.Actor.is_public | Boolean | Is the threat actor public or not. | 
| ThreatStream.File.Actor.is_team | Boolean | Is the threat actor in a team or not. | 
| ThreatStream.File.Actor.modified_ts | Date | When was the threat actor modified. | 
| ThreatStream.File.Actor.name | String | The name of the threat actor. | 
| ThreatStream.File.Actor.organization_id | Number | The organization ID of the threat actor. | 
| ThreatStream.File.Actor.owner_user_id | Number | The owner user ID of the threat actor. | 
| ThreatStream.File.Actor.primary_motivation | Unknown | The primary motivation of the threat actor. | 
| ThreatStream.File.Actor.publication_status | String | The publication status of the threat actor. | 
| ThreatStream.File.Actor.published_ts | Date | When was the threat actor published. | 
| ThreatStream.File.Actor.resource_level | Unknown | The resource level of the threat actor. | 
| ThreatStream.File.Actor.resource_uri | String | The resource uri of the threat actor. | 
| ThreatStream.File.Actor.source_created | Unknown | When was the source created. | 
| ThreatStream.File.Actor.source_modified | Unknown | When was the source modified. | 
| ThreatStream.File.Actor.start_date | Unknown | The start date. | 
| ThreatStream.File.Actor.tags | String | The tags of the threat indicator | 
| ThreatStream.File.Actor.tags_v2.id | String | The id of the tag. | 
| ThreatStream.File.Actor.tags_v2.name | String | The name of the tag. | 
| ThreatStream.File.Actor.tlp | String | The tlp of the threat actor. | 
| ThreatStream.File.Actor.uuid | String | The uuid of the threat actor. | 
| ThreatStream.File.Signature.assignee_user | Unknown | The Assignee User of the signature | 
| ThreatStream.File.Signature.association_info.comment | Unknown | The comment in the association info of the signature. | 
| ThreatStream.File.Signature.association_info.created | Date | When was the association info created. | 
| ThreatStream.File.Signature.association_info.from_id | Number | From which id the association info is related. | 
| ThreatStream.File.Signature.can_add_public_tags | Boolean | Can we add a public tags or not to the signature. | 
| ThreatStream.File.Signature.created_ts | Date | When was the signature cretad. | 
| ThreatStream.File.Signature.feed_id | Number | The feed ID of the signature. | 
| ThreatStream.File.Signature.id | Number | The id of the signature. | 
| ThreatStream.File.Signature.is_anonymous | Boolean | Is the signature anonymus or not. | 
| ThreatStream.File.Signature.is_cloneable | String | Is the signature clonable or not. | 
| ThreatStream.File.Signature.is_public | Boolean | Is the signature public or not. | 
| ThreatStream.File.Signature.is_team | Boolean | Is the signature in a team or not. | 
| ThreatStream.File.Signature.modified_ts | Date | When was the signature modified. | 
| ThreatStream.File.Signature.name | String | The name of the signature. | 
| ThreatStream.File.Signature.organization_id | Number | The organization ID of the signature. | 
| ThreatStream.File.Signature.owner_user_id | Number | The owner user ID of the signature. | 
| ThreatStream.File.Signature.primary_motivation | Unknown | The primary motivation of the signature. | 
| ThreatStream.File.Signature.publication_status | String | The publication status of the signature. | 
| ThreatStream.File.Signature.published_ts | Date | When was the signature published. | 
| ThreatStream.File.Signature.resource_level | Unknown | The resource level of the signature. | 
| ThreatStream.File.Signature.resource_uri | String | The resource uri of the signature. | 
| ThreatStream.File.Signature.source_created | Unknown | When was the source created. | 
| ThreatStream.File.Signature.source_modified | Unknown | When was the source modified. | 
| ThreatStream.File.Signature.start_date | Unknown | The start date. | 
| ThreatStream.File.Signature.tags | String | The tags of the threat indicator | 
| ThreatStream.File.Signature.tags_v2.id | String | The id of the tag. | 
| ThreatStream.File.Signature.tags_v2.name | String | The name of the tag. | 
| ThreatStream.File.Signature.tlp | String | The tlp of the signature. | 
| ThreatStream.File.Signature.uuid | String | The uuid of the signature. | 
| ThreatStream.File.ThreatBulletin.all_circles_visible | Boolean | Are all of the circles visible. | 
| ThreatStream.File.ThreatBulletin.assignee_org | String | The assignee organization. | 
| ThreatStream.File.ThreatBulletin.assignee_org_id | String | The assignee organization ID. | 
| ThreatStream.File.ThreatBulletin.assignee_org_name | String | The assignee organization name. | 
| ThreatStream.File.ThreatBulletin.assignee_user | String | The assignee user. | 
| ThreatStream.File.ThreatBulletin.assignee_user_id | String | The assignee user ID. | 
| ThreatStream.File.ThreatBulletin.assignee_user_name | Unknown | The assignee user name. | 
| ThreatStream.File.ThreatBulletin.association_info.comment | Unknown | The comment in the association info of the threat actor. | 
| ThreatStream.File.ThreatBulletin.association_info.created | Date | When was the association info created. | 
| ThreatStream.File.ThreatBulletin.association_info.from_id | String | From which id the association info is related. | 
| ThreatStream.File.ThreatBulletin.body_content_type | String | The body content type. | 
| ThreatStream.File.ThreatBulletin.campaign | Unknown | The campaign of the threat bulletin. | 
| ThreatStream.File.ThreatBulletin.can_add_public_tags | Boolean | Can we add public tags. | 
| ThreatStream.File.ThreatBulletin.created_ts | Date | When was the threat bulletin created. | 
| ThreatStream.File.ThreatBulletin.feed_id | Number | The feed ID of the threat bulletin. | 
| ThreatStream.File.ThreatBulletin.id | String | The ID of the threat bulletin. | 
| ThreatStream.File.ThreatBulletin.is_anonymous | Boolean | Is the threat bulletin anonymous. | 
| ThreatStream.File.ThreatBulletin.is_cloneable | String | Is the threat bulletin cloneble. | 
| ThreatStream.File.ThreatBulletin.is_editable | Boolean | Is the threat bulletin editable. | 
| ThreatStream.File.ThreatBulletin.is_email | Boolean | Is the threat bulletin an email. | 
| ThreatStream.File.ThreatBulletin.is_public | Boolean | Is the threat bulletin public. | 
| ThreatStream.File.ThreatBulletin.modified_ts | Date | When was the threat bulletin modified. | 
| ThreatStream.File.ThreatBulletin.name | String | The name of the threat bulletin. | 
| ThreatStream.File.ThreatBulletin.original_source | String | The original source of the threat bulletin. | 
| ThreatStream.File.ThreatBulletin.original_source_id | Unknown | The original source ID of the threat bulletin. | 
| ThreatStream.File.ThreatBulletin.owner_org.id | String | The owner organizetion ID. | 
| ThreatStream.File.ThreatBulletin.owner_org.name | String | The owner organizetion name. | 
| ThreatStream.File.ThreatBulletin.owner_org.resource_uri | String | The owner organizetion uri. | 
| ThreatStream.File.ThreatBulletin.owner_org_id | Number | The id of the owner user. | 
| ThreatStream.File.ThreatBulletin.owner_org_name | String | The name of the owner organization. | 
| ThreatStream.File.ThreatBulletin.owner_user.avatar_s3_url | Unknown | The url of the owner user. | 
| ThreatStream.File.ThreatBulletin.owner_user.can_share_intelligence | Boolean | Can we share intelligence or not. | 
| ThreatStream.File.ThreatBulletin.owner_user.email | String | The email of the owner user. | 
| ThreatStream.File.ThreatBulletin.owner_user.id | String | The ID of the owner user. | 
| ThreatStream.File.ThreatBulletin.owner_user.is_active | Boolean | Is the owner user active. | 
| ThreatStream.File.ThreatBulletin.owner_user.is_readonly | Boolean | Is the owner user read only. | 
| ThreatStream.File.ThreatBulletin.owner_user.must_change_password | Boolean | Does the owner user must change password. | 
| ThreatStream.File.ThreatBulletin.owner_user.name | String | The owner user name. | 
| ThreatStream.File.ThreatBulletin.owner_user.nickname | String | The owner user nickname | 
| ThreatStream.File.ThreatBulletin.owner_user.organization.id | String | The ID of the owner user organization. | 
| ThreatStream.File.ThreatBulletin.owner_user.organization.name | String | The name of the owner user organization. | 
| ThreatStream.File.ThreatBulletin.owner_user.organization.resource_uri | String | The resource uri of the owner user organization. | 
| ThreatStream.File.ThreatBulletin.owner_user.resource_uri | String | The resource uri of the owner user. | 
| ThreatStream.File.ThreatBulletin.owner_user_id | Number | The owner user ID of the threat bulletin. | 
| ThreatStream.File.ThreatBulletin.owner_user_name | String | The owner user name of the threat bulletin. | 
| ThreatStream.File.ThreatBulletin.parent | Unknown | The parent of the threat bulletin. | 
| ThreatStream.File.ThreatBulletin.published_ts | Unknown | When was the threat bulletin published. | 
| ThreatStream.File.ThreatBulletin.resource_uri | String | The resource uri of the threat bulletin. | 
| ThreatStream.File.ThreatBulletin.source | Unknown | The source of the threat bulletin. | 
| ThreatStream.File.ThreatBulletin.source_created | Unknown | When was the source created. | 
| ThreatStream.File.ThreatBulletin.source_modified | Unknown | When was the source modified. | 
| ThreatStream.File.ThreatBulletin.starred_by_me | Boolean | Was the threat bulletin started bt me. | 
| ThreatStream.File.ThreatBulletin.starred_total_count | Number | The total count of times the threat bulletin was starred. | 
| ThreatStream.File.ThreatBulletin.status | String | The status of the threat bulletin. | 
| ThreatStream.File.ThreatBulletin.threat_actor | Unknown | The threat actor of the threat bulletin. | 
| ThreatStream.File.ThreatBulletin.tlp | Unknown | The TLP of the threat bulletin. | 
| ThreatStream.File.ThreatBulletin.ttp | Unknown | The TTP of the threat bulletin. | 
| ThreatStream.File.ThreatBulletin.uuid | String | The UUID of the threat bulletin. | 
| ThreatStream.File.ThreatBulletin.votes.me | Unknown | How nany votes by me. | 
| ThreatStream.File.ThreatBulletin.votes.total | Number | How many votes total. | 
| ThreatStream.File.ThreatBulletin.watched_by_me | Boolean | Was the threat bulletin watched by me? | 
| ThreatStream.File.ThreatBulletin.watched_total_count | Number | The total count of watchers. | 
| ThreatStream.File.TTP.assignee_user | Unknown | The Assignee User of the TTP. | 
| ThreatStream.File.TTP.association_info.comment | Unknown | The comment in the association info of the TTP. | 
| ThreatStream.File.TTP.association_info.created | Date | When was the association info created. | 
| ThreatStream.File.TTP.association_info.from_id | Number | From which id the association info is related. | 
| ThreatStream.File.TTP.can_add_public_tags | Boolean | Can we add a public tags or not to the TTP. | 
| ThreatStream.File.TTP.created_ts | Date | When was the TTP cretad. | 
| ThreatStream.File.TTP.feed_id | Number | The feed ID of the TTP. | 
| ThreatStream.File.TTP.id | Number | The id of the TTP. | 
| ThreatStream.File.TTP.is_anonymous | Boolean | Is the TTP anonymus or not. | 
| ThreatStream.File.TTP.is_cloneable | String | Is the TTP clonable or not. | 
| ThreatStream.File.TTP.is_public | Boolean | Is the TTP public or not. | 
| ThreatStream.File.TTP.is_team | Boolean | Is the TTP in a team or not. | 
| ThreatStream.File.TTP.modified_ts | Date | When was the TTP modified. | 
| ThreatStream.File.TTP.name | String | The name of the TTP. | 
| ThreatStream.File.TTP.organization_id | Number | The organization ID of the TTP. | 
| ThreatStream.File.TTP.owner_user_id | Number | The owner user ID of the TTP. | 
| ThreatStream.File.TTP.primary_motivation | Unknown | The primary motivation of the TTP. | 
| ThreatStream.File.TTP.publication_status | String | The publication status of the TTP. | 
| ThreatStream.File.TTP.published_ts | Date | When was the TTP published. | 
| ThreatStream.File.TTP.resource_level | Unknown | The resource level of the TTP. | 
| ThreatStream.File.TTP.resource_uri | String | The resource uri of the TTP. | 
| ThreatStream.File.TTP.source_created | Unknown | When was the source created. | 
| ThreatStream.File.TTP.source_modified | Unknown | When was the source modified. | 
| ThreatStream.File.TTP.start_date | Unknown | The start date. | 
| ThreatStream.File.TTP.tags | String | The tags of the threat indicator | 
| ThreatStream.File.TTP.tags_v2.id | String | The id of the tag. | 
| ThreatStream.File.TTP.tags_v2.name | String | The name of the tag. | 
| ThreatStream.File.TTP.tlp | String | The tlp of the TTP. | 
| ThreatStream.File.TTP.uuid | String | The uuid of the TTP. | 
| ThreatStream.File.Vulnerability.assignee_user | Unknown | The Assignee User of the vulnerability. | 
| ThreatStream.File.Vulnerability.association_info.comment | Unknown | The comment in the association info of the vulnerability. | 
| ThreatStream.File.Vulnerability.association_info.created | Date | When was the association info created. | 
| ThreatStream.File.Vulnerability.association_info.from_id | Number | From which id the association info is related. | 
| ThreatStream.File.Vulnerability.can_add_public_tags | Boolean | Can we add a public tags or not to the vulnerability. | 
| ThreatStream.File.Vulnerability.circles.id | String | The ID of the circle. | 
| ThreatStream.File.Vulnerability.circles.name | String | The name of the circle. | 
| ThreatStream.File.Vulnerability.circles.resource_uri | String | The resource uri of the circle. | 
| ThreatStream.File.Vulnerability.created_ts | Date | When was the vulnerability created. | 
| ThreatStream.File.Vulnerability.feed_id | Number | The feed ID of the vulnerability. | 
| ThreatStream.File.Vulnerability.id | Number | The ID of the vulnerability. | 
| ThreatStream.File.Vulnerability.is_anonymous | Boolean | Is the vulnerability anonymus or not. | 
| ThreatStream.File.Vulnerability.is_cloneable | String | Is the vulnerability clonable or not. | 
| ThreatStream.File.Vulnerability.is_public | Boolean | Is the vulnerability public or not. | 
| ThreatStream.File.Vulnerability.is_system | Boolean | Is the vulnerability in the system or not. | 
| ThreatStream.File.Vulnerability.modified_ts | Date | When was the vulnerability modified. | 
| ThreatStream.File.Vulnerability.name | String | The name of the vulnerability. | 
| ThreatStream.File.Vulnerability.organization_id | Number | The organization ID of the vulnerability. | 
| ThreatStream.File.Vulnerability.owner_user_id | Unknown | The owner user ID of the vulnerability. | 
| ThreatStream.File.Vulnerability.publication_status | String | The publication status of the vulnerability. | 
| ThreatStream.File.Vulnerability.published_ts | Date | When was the vulnerability published. | 
| ThreatStream.File.Vulnerability.resource_uri | String | The resource uri of the vulnerability. | 
| ThreatStream.File.Vulnerability.source | String | The source of the vulnerability. | 
| ThreatStream.File.Vulnerability.source_created | Unknown | The feed ID of the vulnerability. | 
| ThreatStream.File.Vulnerability.source_modified | Unknown | Was the source modified. | 
| ThreatStream.File.Vulnerability.tags | String | The tags of the vulnerability. | 
| ThreatStream.File.Vulnerability.tags_v2.id | String | The id of the tag. | 
| ThreatStream.File.Vulnerability.tags_v2.name | String | The name of the tag. | 
| ThreatStream.File.Vulnerability.tlp | String | The tlp of the vulnerability. | 
| ThreatStream.File.Vulnerability.update_id | Number | The update ID of the vulnerability. | 
| ThreatStream.File.Vulnerability.uuid | String | The UUID of the vulnerability. | 
| ThreatStream.File.Campaign.assignee_user | Unknown | The Assignee User of the vulnerability. | 
| ThreatStream.File.Campaign.association_info.comment | Unknown | The comment in the association info of the vulnerability. | 
| ThreatStream.File.Campaign.association_info.created | Date | When was the association info created. | 
| ThreatStream.File.Campaign.association_info.from_id | Number | From which id the association info is related. | 
| ThreatStream.File.Campaign.can_add_public_tags | Boolean | Can we add a public tags or not to the campaign. | 
| ThreatStream.File.Campaign.created_ts | Date | When was the campaign created. | 
| ThreatStream.File.Campaign.end_date | Unknown | The end date of the campaign. | 
| ThreatStream.File.Campaign.feed_id | Number | The feed ID of the campaign. | 
| ThreatStream.File.Campaign.id | Number | The ID of the campaign. | 
| ThreatStream.File.Campaign.is_anonymous | Boolean | Is the campaign anonymus or not. | 
| ThreatStream.File.Campaign.is_cloneable | String | Is the campaign clonable or not. | 
| ThreatStream.File.Campaign.is_public | Boolean | Is the campaign public or not. | 
| ThreatStream.File.Campaign.modified_ts | Date | When was the campain modified. | 
| ThreatStream.File.Campaign.name | String | The name of the Campaign. | 
| ThreatStream.File.Campaign.objective | Unknown | The objective of the campaign. | 
| ThreatStream.File.Campaign.organization_id | Number | The organization ID of the campaign. | 
| ThreatStream.File.Campaign.owner_user_id | Number | The owner user ID of the campaign. | 
| ThreatStream.File.Campaign.publication_status | String | The publication status of the campaign | 
| ThreatStream.File.Campaign.published_ts | Unknown | When was the campaign published. | 
| ThreatStream.File.Campaign.resource_uri | String | The resource uri of the campaign. | 
| ThreatStream.File.Campaign.source_created | Date | When was the campaign created. | 
| ThreatStream.File.Campaign.source_modified | Date | Was the source modified or not. | 
| ThreatStream.File.Campaign.start_date | Unknown | The start date of the campaign. | 
| ThreatStream.File.Campaign.status.display_name | String | The display name of the status. | 
| ThreatStream.File.Campaign.status.id | Number | The id of the status of the campaign. | 
| ThreatStream.File.Campaign.status.resource_uri | String | The resource uri of the status of the campaign. | 
| ThreatStream.File.Campaign.tlp | String | The tlp of the campaign. | 
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
            },
            {
                "EntityA": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                "EntityAType": "File",
                "EntityB": "Feeds SDK 2.0: Signature Carbon Black Query test 1",
                "EntityBType": "Signature",
                "Relationship": "related-to"
            },
            {
                "EntityA": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                "EntityAType": "File",
                "EntityB": "FleaHopper TTP",
                "EntityBType": "Attack Pattern",
                "Relationship": "related-to"
            },
            {
                "EntityA": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                "EntityAType": "File",
                "EntityB": "CVE-2022-31098",
                "EntityBType": "CVE",
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
                        "actor_tag1",
                        "sdk_tag2"
                    ],
                    "tags_v2": [
                        {
                            "id": "igh",
                            "name": "actor_tag1"
                        },
                        {
                            "id": "99r",
                            "name": "sdk_tag2"
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
                    "UdpDestination": "8.8.8.8",
                    "UdpPort": 53,
                    "UdpSource": "192.168.2.4"
                },
                {
                    "TcpDestination": "78.78.78.67",
                    "TcpPort": 443,
                    "TcpSource": "78.78.78.67"
                },
                {
                    "TcpDestination": "78.78.78.67",
                    "TcpPort": 443,
                    "TcpSource": "78.78.78.67"
                },
                {
                    "HttpsDestination": "78.78.78.67",
                    "HttpsPort": 443,
                    "HttpsSource": "78.78.78.67"
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
| threat_model_association | Note: if set to true, additional 6 API calls will be performed. Possible values are: True, False. Default is False. | Optional | 


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
| ThreatStream.URL.IType | String | The iType of the indicator associated with the specified model. | 
| URL.Tags | Unknown | List of URL tags. | 
| URL.ThreatTypes | Unknown | Threat types associated with the url. | 
| ThreatStream.URL.Actor.assignee_user | Unknown | The Assignee User of the Threat Actor | 
| ThreatStream.URL.Actor.association_info.comment | Unknown | The comment in the association info of the threat actor. | 
| ThreatStream.URL.Actor.association_info.created | Date | When was the association info created. | 
| ThreatStream.URL.Actor.association_info.from_id | Number | From which id the association info is related. | 
| ThreatStream.URL.Actor.can_add_public_tags | Boolean | Can we add a public tags or not to the threat actor. | 
| ThreatStream.URL.Actor.created_ts | Date | When was the threat actor cretad. | 
| ThreatStream.URL.Actor.feed_id | Number | The feed ID of the threat actor. | 
| ThreatStream.URL.Actor.id | Number | The id of the threat actor. | 
| ThreatStream.URL.Actor.is_anonymous | Boolean | Is the threat actor anonymus or not. | 
| ThreatStream.URL.Actor.is_cloneable | String | Is the threat actor clonable or not. | 
| ThreatStream.URL.Actor.is_public | Boolean | Is the threat actor public or not. | 
| ThreatStream.URL.Actor.is_team | Boolean | Is the threat actor in a team or not. | 
| ThreatStream.URL.Actor.modified_ts | Date | When was the threat actor modified. | 
| ThreatStream.URL.Actor.name | String | The name of the threat actor. | 
| ThreatStream.URL.Actor.organization_id | Number | The organization ID of the threat actor. | 
| ThreatStream.URL.Actor.owner_user_id | Number | The owner user ID of the threat actor. | 
| ThreatStream.URL.Actor.primary_motivation | Unknown | The primary motivation of the threat actor. | 
| ThreatStream.URL.Actor.publication_status | String | The publication status of the threat actor. | 
| ThreatStream.URL.Actor.published_ts | Date | When was the threat actor published. | 
| ThreatStream.URL.Actor.resource_level | Unknown | The resource level of the threat actor. | 
| ThreatStream.URL.Actor.resource_uri | String | The resource uri of the threat actor. | 
| ThreatStream.URL.Actor.source_created | Unknown | When was the source created. | 
| ThreatStream.URL.Actor.source_modified | Unknown | When was the source modified. | 
| ThreatStream.URL.Actor.start_date | Unknown | The start date. | 
| ThreatStream.URL.Actor.tags | String | The tags of the threat indicator | 
| ThreatStream.URL.Actor.tags_v2.id | String | The id of the tag. | 
| ThreatStream.URL.Actor.tags_v2.name | String | The name of the tag. | 
| ThreatStream.URL.Actor.tlp | String | The tlp of the threat actor. | 
| ThreatStream.URL.Actor.uuid | String | The uuid of the threat actor. | 
| ThreatStream.URL.Signature.assignee_user | Unknown | The Assignee User of the signature | 
| ThreatStream.URL.Signature.association_info.comment | Unknown | The comment in the association info of the signature. | 
| ThreatStream.URL.Signature.association_info.created | Date | When was the association info created. | 
| ThreatStream.URL.Signature.association_info.from_id | Number | From which id the association info is related. | 
| ThreatStream.URL.Signature.can_add_public_tags | Boolean | Can we add a public tags or not to the signature. | 
| ThreatStream.URL.Signature.created_ts | Date | When was the signature cretad. | 
| ThreatStream.URL.Signature.feed_id | Number | The feed ID of the signature. | 
| ThreatStream.URL.Signature.id | Number | The id of the signature. | 
| ThreatStream.URL.Signature.is_anonymous | Boolean | Is the signature anonymus or not. | 
| ThreatStream.URL.Signature.is_cloneable | String | Is the signature clonable or not. | 
| ThreatStream.URL.Signature.is_public | Boolean | Is the signature public or not. | 
| ThreatStream.URL.Signature.is_team | Boolean | Is the signature in a team or not. | 
| ThreatStream.URL.Signature.modified_ts | Date | When was the signature modified. | 
| ThreatStream.URL.Signature.name | String | The name of the signature. | 
| ThreatStream.URL.Signature.organization_id | Number | The organization ID of the signature. | 
| ThreatStream.URL.Signature.owner_user_id | Number | The owner user ID of the signature. | 
| ThreatStream.URL.Signature.primary_motivation | Unknown | The primary motivation of the signature. | 
| ThreatStream.URL.Signature.publication_status | String | The publication status of the signature. | 
| ThreatStream.URL.Signature.published_ts | Date | When was the signature published. | 
| ThreatStream.URL.Signature.resource_level | Unknown | The resource level of the signature. | 
| ThreatStream.URL.Signature.resource_uri | String | The resource uri of the signature. | 
| ThreatStream.URL.Signature.source_created | Unknown | When was the source created. | 
| ThreatStream.URL.Signature.source_modified | Unknown | When was the source modified. | 
| ThreatStream.URL.Signature.start_date | Unknown | The start date. | 
| ThreatStream.URL.Signature.tags | String | The tags of the threat indicator | 
| ThreatStream.URL.Signature.tags_v2.id | String | The id of the tag. | 
| ThreatStream.URL.Signature.tags_v2.name | String | The name of the tag. | 
| ThreatStream.URL.Signature.tlp | String | The tlp of the signature. | 
| ThreatStream.URL.Signature.uuid | String | The uuid of the signature. | 
| ThreatStream.URL.ThreatBulletin.all_circles_visible | Boolean | Are all of the circles visible. | 
| ThreatStream.URL.ThreatBulletin.assignee_org | String | The assignee organization. | 
| ThreatStream.URL.ThreatBulletin.assignee_org_id | String | The assignee organization ID. | 
| ThreatStream.URL.ThreatBulletin.assignee_org_name | String | The assignee organization name. | 
| ThreatStream.URL.ThreatBulletin.assignee_user | String | The assignee user. | 
| ThreatStream.URL.ThreatBulletin.assignee_user_id | String | The assignee user ID. | 
| ThreatStream.URL.ThreatBulletin.assignee_user_name | Unknown | The assignee user name. | 
| ThreatStream.URL.ThreatBulletin.association_info.comment | Unknown | The comment in the association info of the threat actor. | 
| ThreatStream.URL.ThreatBulletin.association_info.created | Date | When was the association info created. | 
| ThreatStream.URL.ThreatBulletin.association_info.from_id | String | From which id the association info is related. | 
| ThreatStream.URL.ThreatBulletin.body_content_type | String | The body content type. | 
| ThreatStream.URL.ThreatBulletin.campaign | Unknown | The campaign of the threat bulletin. | 
| ThreatStream.URL.ThreatBulletin.can_add_public_tags | Boolean | Can we add public tags. | 
| ThreatStream.URL.ThreatBulletin.created_ts | Date | When was the threat bulletin created. | 
| ThreatStream.URL.ThreatBulletin.feed_id | Number | The feed ID of the threat bulletin. | 
| ThreatStream.URL.ThreatBulletin.id | String | The ID of the threat bulletin. | 
| ThreatStream.URL.ThreatBulletin.is_anonymous | Boolean | Is the threat bulletin anonymous. | 
| ThreatStream.URL.ThreatBulletin.is_cloneable | String | Is the threat bulletin cloneble. | 
| ThreatStream.URL.ThreatBulletin.is_editable | Boolean | Is the threat bulletin editable. | 
| ThreatStream.URL.ThreatBulletin.is_email | Boolean | Is the threat bulletin an email. | 
| ThreatStream.URL.ThreatBulletin.is_public | Boolean | Is the threat bulletin public. | 
| ThreatStream.URL.ThreatBulletin.modified_ts | Date | When was the threat bulletin modified. | 
| ThreatStream.URL.ThreatBulletin.name | String | The name of the threat bulletin. | 
| ThreatStream.URL.ThreatBulletin.original_source | String | The original source of the threat bulletin. | 
| ThreatStream.URL.ThreatBulletin.original_source_id | Unknown | The original source ID of the threat bulletin. | 
| ThreatStream.URL.ThreatBulletin.owner_org.id | String | The owner organizetion ID. | 
| ThreatStream.URL.ThreatBulletin.owner_org.name | String | The owner organizetion name. | 
| ThreatStream.URL.ThreatBulletin.owner_org.resource_uri | String | The owner organizetion uri. | 
| ThreatStream.URL.ThreatBulletin.owner_org_id | Number | The id of the owner user. | 
| ThreatStream.URL.ThreatBulletin.owner_org_name | String | The name of the owner organization. | 
| ThreatStream.URL.ThreatBulletin.owner_user.avatar_s3_url | Unknown | The url of the owner user. | 
| ThreatStream.URL.ThreatBulletin.owner_user.can_share_intelligence | Boolean | Can we share intelligence or not. | 
| ThreatStream.URL.ThreatBulletin.owner_user.email | String | The email of the owner user. | 
| ThreatStream.URL.ThreatBulletin.owner_user.id | String | The ID of the owner user. | 
| ThreatStream.URL.ThreatBulletin.owner_user.is_active | Boolean | Is the owner user active. | 
| ThreatStream.URL.ThreatBulletin.owner_user.is_readonly | Boolean | Is the owner user read only. | 
| ThreatStream.URL.ThreatBulletin.owner_user.must_change_password | Boolean | Does the owner user must change password. | 
| ThreatStream.URL.ThreatBulletin.owner_user.name | String | The owner user name. | 
| ThreatStream.URL.ThreatBulletin.owner_user.nickname | String | The owner user nickname | 
| ThreatStream.URL.ThreatBulletin.owner_user.organization.id | String | The ID of the owner user organization. | 
| ThreatStream.URL.ThreatBulletin.owner_user.organization.name | String | The name of the owner user organization. | 
| ThreatStream.URL.ThreatBulletin.owner_user.organization.resource_uri | String | The resource uri of the owner user organization. | 
| ThreatStream.URL.ThreatBulletin.owner_user.resource_uri | String | The resource uri of the owner user. | 
| ThreatStream.URL.ThreatBulletin.owner_user_id | Number | The owner user ID of the threat bulletin. | 
| ThreatStream.URL.ThreatBulletin.owner_user_name | String | The owner user name of the threat bulletin. | 
| ThreatStream.URL.ThreatBulletin.parent | Unknown | The parent of the threat bulletin. | 
| ThreatStream.URL.ThreatBulletin.published_ts | Unknown | When was the threat bulletin published. | 
| ThreatStream.URL.ThreatBulletin.resource_uri | String | The resource uri of the threat bulletin. | 
| ThreatStream.URL.ThreatBulletin.source | Unknown | The source of the threat bulletin. | 
| ThreatStream.URL.ThreatBulletin.source_created | Unknown | When was the source created. | 
| ThreatStream.URL.ThreatBulletin.source_modified | Unknown | When was the source modified. | 
| ThreatStream.URL.ThreatBulletin.starred_by_me | Boolean | Was the threat bulletin started bt me. | 
| ThreatStream.URL.ThreatBulletin.starred_total_count | Number | The total count of times the threat bulletin was starred. | 
| ThreatStream.URL.ThreatBulletin.status | String | The status of the threat bulletin. | 
| ThreatStream.URL.ThreatBulletin.threat_actor | Unknown | The threat actor of the threat bulletin. | 
| ThreatStream.URL.ThreatBulletin.tlp | Unknown | The TLP of the threat bulletin. | 
| ThreatStream.URL.ThreatBulletin.ttp | Unknown | The TTP of the threat bulletin. | 
| ThreatStream.URL.ThreatBulletin.uuid | String | The UUID of the threat bulletin. | 
| ThreatStream.URL.ThreatBulletin.votes.me | Unknown | How nany votes by me. | 
| ThreatStream.URL.ThreatBulletin.votes.total | Number | How many votes total. | 
| ThreatStream.URL.ThreatBulletin.watched_by_me | Boolean | Was the threat bulletin watched by me? | 
| ThreatStream.URL.ThreatBulletin.watched_total_count | Number | The total count of watchers. | 
| ThreatStream.URL.TTP.assignee_user | Unknown | The Assignee User of the TTP. | 
| ThreatStream.URL.TTP.association_info.comment | Unknown | The comment in the association info of the TTP. | 
| ThreatStream.URL.TTP.association_info.created | Date | When was the association info created. | 
| ThreatStream.URL.TTP.association_info.from_id | Number | From which id the association info is related. | 
| ThreatStream.URL.TTP.can_add_public_tags | Boolean | Can we add a public tags or not to the TTP. | 
| ThreatStream.URL.TTP.created_ts | Date | When was the TTP cretad. | 
| ThreatStream.URL.TTP.feed_id | Number | The feed ID of the TTP. | 
| ThreatStream.URL.TTP.id | Number | The id of the TTP. | 
| ThreatStream.URL.TTP.is_anonymous | Boolean | Is the TTP anonymus or not. | 
| ThreatStream.URL.TTP.is_cloneable | String | Is the TTP clonable or not. | 
| ThreatStream.URL.TTP.is_public | Boolean | Is the TTP public or not. | 
| ThreatStream.URL.TTP.is_team | Boolean | Is the TTP in a team or not. | 
| ThreatStream.URL.TTP.modified_ts | Date | When was the TTP modified. | 
| ThreatStream.URL.TTP.name | String | The name of the TTP. | 
| ThreatStream.URL.TTP.organization_id | Number | The organization ID of the TTP. | 
| ThreatStream.URL.TTP.owner_user_id | Number | The owner user ID of the TTP. | 
| ThreatStream.URL.TTP.primary_motivation | Unknown | The primary motivation of the TTP. | 
| ThreatStream.URL.TTP.publication_status | String | The publication status of the TTP. | 
| ThreatStream.URL.TTP.published_ts | Date | When was the TTP published. | 
| ThreatStream.URL.TTP.resource_level | Unknown | The resource level of the TTP. | 
| ThreatStream.URL.TTP.resource_uri | String | The resource uri of the TTP. | 
| ThreatStream.URL.TTP.source_created | Unknown | When was the source created. | 
| ThreatStream.URL.TTP.source_modified | Unknown | When was the source modified. | 
| ThreatStream.URL.TTP.start_date | Unknown | The start date. | 
| ThreatStream.URL.TTP.tags | String | The tags of the threat indicator | 
| ThreatStream.URL.TTP.tags_v2.id | String | The id of the tag. | 
| ThreatStream.URL.TTP.tags_v2.name | String | The name of the tag. | 
| ThreatStream.URL.TTP.tlp | String | The tlp of the TTP. | 
| ThreatStream.URL.TTP.uuid | String | The uuid of the TTP. | 
| ThreatStream.URL.Vulnerability.assignee_user | Unknown | The Assignee User of the vulnerability. | 
| ThreatStream.URL.Vulnerability.association_info.comment | Unknown | The comment in the association info of the vulnerability. | 
| ThreatStream.URL.Vulnerability.association_info.created | Date | When was the association info created. | 
| ThreatStream.URL.Vulnerability.association_info.from_id | Number | From which id the association info is related. | 
| ThreatStream.URL.Vulnerability.can_add_public_tags | Boolean | Can we add a public tags or not to the vulnerability. | 
| ThreatStream.URL.Vulnerability.circles.id | String | The ID of the circle. | 
| ThreatStream.URL.Vulnerability.circles.name | String | The name of the circle. | 
| ThreatStream.URL.Vulnerability.circles.resource_uri | String | The resource uri of the circle. | 
| ThreatStream.URL.Vulnerability.created_ts | Date | When was the vulnerability created. | 
| ThreatStream.URL.Vulnerability.feed_id | Number | The feed ID of the vulnerability. | 
| ThreatStream.URL.Vulnerability.id | Number | The ID of the vulnerability. | 
| ThreatStream.URL.Vulnerability.is_anonymous | Boolean | Is the vulnerability anonymus or not. | 
| ThreatStream.URL.Vulnerability.is_cloneable | String | Is the vulnerability clonable or not. | 
| ThreatStream.URL.Vulnerability.is_public | Boolean | Is the vulnerability public or not. | 
| ThreatStream.URL.Vulnerability.is_system | Boolean | Is the vulnerability in the system or not. | 
| ThreatStream.URL.Vulnerability.modified_ts | Date | When was the vulnerability modified. | 
| ThreatStream.URL.Vulnerability.name | String | The name of the vulnerability. | 
| ThreatStream.URL.Vulnerability.organization_id | Number | The organization ID of the vulnerability. | 
| ThreatStream.URL.Vulnerability.owner_user_id | Unknown | The owner user ID of the vulnerability. | 
| ThreatStream.URL.Vulnerability.publication_status | String | The publication status of the vulnerability. | 
| ThreatStream.URL.Vulnerability.published_ts | Date | When was the vulnerability published. | 
| ThreatStream.URL.Vulnerability.resource_uri | String | The resource uri of the vulnerability. | 
| ThreatStream.URL.Vulnerability.source | String | The source of the vulnerability. | 
| ThreatStream.URL.Vulnerability.source_created | Unknown | The feed ID of the vulnerability. | 
| ThreatStream.URL.Vulnerability.source_modified | Unknown | Was the source modified. | 
| ThreatStream.URL.Vulnerability.tags | String | The tags of the vulnerability. | 
| ThreatStream.URL.Vulnerability.tags_v2.id | String | The id of the tag. | 
| ThreatStream.URL.Vulnerability.tags_v2.name | String | The name of the tag. | 
| ThreatStream.URL.Vulnerability.tlp | String | The tlp of the vulnerability. | 
| ThreatStream.URL.Vulnerability.update_id | Number | The update ID of the vulnerability. | 
| ThreatStream.URL.Vulnerability.uuid | String | The UUID of the vulnerability. | 
| ThreatStream.URL.Campaign.assignee_user | Unknown | The Assignee User of the vulnerability. | 
| ThreatStream.URL.Campaign.association_info.comment | Unknown | The comment in the association info of the vulnerability. | 
| ThreatStream.URL.Campaign.association_info.created | Date | When was the association info created. | 
| ThreatStream.URL.Campaign.association_info.from_id | Number | From which id the association info is related. | 
| ThreatStream.URL.Campaign.can_add_public_tags | Boolean | Can we add a public tags or not to the campaign. | 
| ThreatStream.URL.Campaign.created_ts | Date | When was the campaign created. | 
| ThreatStream.URL.Campaign.end_date | Unknown | The end date of the campaign. | 
| ThreatStream.URL.Campaign.feed_id | Number | The feed ID of the campaign. | 
| ThreatStream.URL.Campaign.id | Number | The ID of the campaign. | 
| ThreatStream.URL.Campaign.is_anonymous | Boolean | Is the campaign anonymus or not. | 
| ThreatStream.URL.Campaign.is_cloneable | String | Is the campaign clonable or not. | 
| ThreatStream.URL.Campaign.is_public | Boolean | Is the campaign public or not. | 
| ThreatStream.URL.Campaign.modified_ts | Date | When was the campain modified. | 
| ThreatStream.URL.Campaign.name | String | The name of the Campaign. | 
| ThreatStream.URL.Campaign.objective | Unknown | The objective of the campaign. | 
| ThreatStream.URL.Campaign.organization_id | Number | The organization ID of the campaign. | 
| ThreatStream.URL.Campaign.owner_user_id | Number | The owner user ID of the campaign. | 
| ThreatStream.URL.Campaign.publication_status | String | The publication status of the campaign | 
| ThreatStream.URL.Campaign.published_ts | Unknown | When was the campaign published. | 
| ThreatStream.URL.Campaign.resource_uri | String | The resource uri of the campaign. | 
| ThreatStream.URL.Campaign.source_created | Date | When was the campaign created. | 
| ThreatStream.URL.Campaign.source_modified | Date | Was the source modified or not. | 
| ThreatStream.URL.Campaign.start_date | Unknown | The start date of the campaign. | 
| ThreatStream.URL.Campaign.status.display_name | String | The display name of the status. | 
| ThreatStream.URL.Campaign.status.id | Number | The id of the status of the campaign. | 
| ThreatStream.URL.Campaign.status.resource_uri | String | The resource uri of the status of the campaign. | 
| ThreatStream.URL.Campaign.tlp | String | The tlp of the campaign. | 
| ThreatStream.URL.Campaign.uuid | String | The UUID of the campaign. | 

#### Command example
```!url url=http://www.ujhy1.com/ threat_model_association=True```
#### Context Example
```json
{
    "DBotScore": [
        {
            "Indicator": "http://www.ujhy1.com/",
            "Reliability": "C - Fairly reliable",
            "Score": 1,
            "Type": "url",
            "Vendor": "VirusTotal"
        },
        {
            "Indicator": "http://www.ujhy1.com/",
            "Message": "No results found.",
            "Reliability": "B - Usually reliable",
            "Score": 0,
            "Type": "url",
            "Vendor": "Anomali ThreatStream v3 May"
        }
    ],
    "URL": {
        "Data": "http://www.ujhy1.com/",
        "DetectionEngines": 88,
        "PositiveDetections": 0,
        "VirusTotal": {
            "ScanID": "264ffc62c96d2672a4b3b1e2641067bf7c1b9928f672573f40e0aecd137d7dca-1626005775",
            "vtLink": "link"
        }
    }
}
```


## Additional Considerations for this version
- Remove the **default_threshold** integration parameter.
- Add integration parameter for global threshold in ***ip***, ***domain***, ***file***, ***url***, and ***threatstream-email-reputation*** commands. 
- Add ***Include inactive results*** checkbox in integration settings for the ability to get inactive results.
### threatstream-search-intelligence
***
Return filtered intelligence from ThreatStream. If a query is defined, it overrides all other arguments that were passed to the command.


#### Base Command

`threatstream-search-intelligence`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| value | The value of an intelligence. | Optional | 
| uuid | The uuid of an intelligence. When several uuids stated, an “OR” operator is used. | Optional | 
| type | The type of an intelligence. Possible values are: domain, email, ip, md5, string, url. | Optional | 
| itype | The itype of an intelligence. | Optional | 
| status | The status of an intelligence. Possible values are: active, inactive, falsepos. | Optional | 
| tags | The tags of an intelligence. Comma-seperated list. When several tags stated, an “OR” operator is used. | Optional | 
| asn | The ASN of an intelligence. | Optional | 
| confidence | The confidence of an intelligence. Input will be operator then value, I.e. “gt 65” or “lt 85”. If only value is stated, then we use exact. | Optional | 
| threat_type | The threat type of an intelligence. | Optional | 
| is_public | Is the intelligence public or not. | Optional | 
| query | Query that overrides all other arguments. The filter operators used for the filter language query are the symbolic form (=, &lt;, &gt;, and so on) and not the descriptive form (exact, lt, gt, and so on). For more information, see page 19 in API documentation. | Optional | 
| update_id_gt | If specified, then it is recommended to use order_by=update_id. | Optional | 
| order_by | How to order the results. | Optional | 
| limit | The maximum number of results to return from ThreatStream. Default is 50. Default is 50. | Optional | 
| page | Page number to get result from. Needs to be used with page_size argument. | Optional | 
| page_size | The page size of the returned results. Needs to be used with the page argument. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatStream.Intelligence.SourceCreated | String | The Source from which the intelligence was created. | 
| ThreatStream.Intelligence.Status | String | The status of the intelligence. | 
| ThreatStream.Intelligence.IType | String | The itype of the intelligence. | 
| ThreatStream.Intelligence.ExpirationTS | String | The Expiration timestamp  of the intelligence. | 
| ThreatStream.Intelligence.IP | String | The IP  of the intelligence. | 
| ThreatStream.Intelligence.IsEditable | Boolean | Is the Intelligence editable. | 
| ThreatStream.Intelligence.FeedID | String | The feed ID of the Intelligence. | 
| ThreatStream.Intelligence.UpdateID | String | The update ID of the Intelligence | 
| ThreatStream.Intelligence.Value | String | The value of the Intelligence. | 
| ThreatStream.Intelligence.IsPublic | Boolean | Is the Intelligence public. | 
| ThreatStream.Intelligence.ThreatType | String | The threat type of the Intelligence. | 
| ThreatStream.Intelligence.WorkGroups | String | The work groups of the Intelligence. | 
| ThreatStream.Intelligence.Confidence | String | The confidence of the Intelligence. | 
| ThreatStream.Intelligence.UUID | String | The uuid of the Intelligence. | 
| ThreatStream.Intelligence.RetinaConfidence | String | The retina confidence of the Intelligence. | 
| ThreatStream.Intelligence.TrustedCircleIDs | String | The trusted circleIDs of the Intelligence. | 
| ThreatStream.Intelligence.ID | String | The id of the Intelligence. | 
| ThreatStream.Intelligence.Source | String | The source of the Intelligence. | 
| ThreatStream.Intelligence.OwnerOrganizationID | String | The owner organization ID of the intelligence. | 
| ThreatStream.Intelligence.ImportSessionID | String | The ImportSessionID of the Intelligence. | 
| ThreatStream.Intelligence.SourceModified | Boolean | Is the source modified or not. | 
| ThreatStream.Intelligence.Type | String | The type of the Intelligence. | 
| ThreatStream.Intelligence.Description | String | The description of the Intelligence. | 
| ThreatStream.Intelligence.Tags | String | The tags of the Intelligence. | 
| ThreatStream.Intelligence.Threatscore | String | The threat score of the Intelligence. | 
| ThreatStream.Intelligence.Latitude | String | The latitude of the Intelligence. | 
| ThreatStream.Intelligence.Longitude | String | The longitude of the Intelligence. | 
| ThreatStream.Intelligence.Modified | String | When was the intelligence modified. | 
| ThreatStream.Intelligence.Organization | String | the organization of the Intelligence. | 
| ThreatStream.Intelligence.ASN | Number | The ASN of the intelligence. | 
| ThreatStream.Intelligence.CreatedTime | String | When was the intelligence created. | 
| ThreatStream.Intelligence.TLP | String | The TLP of the intelligence. | 
| ThreatStream.Intelligence.IsAnonymous | Boolean | Is the intelligence anonymous. | 
| ThreatStream.Intelligence.Country | String | The country of the intelligence. | 
| ThreatStream.Intelligence.SourceReportedConfidence | String | The confidence of the reported source. | 
| ThreatStream.Intelligence.Subtype | String | The subtype of the intelligence. | 
| ThreatStream.Intelligence.ResourceURI | String | The resource URI of the intelligence | 
| ThreatStream.Intelligence.Severity | String | The severity of the intelligence. | 

#### Command example
```!threatstream-search-intelligence limit=2 status=inactive value=1.1.1.1```
#### Context Example
```json
{
    "ThreatStream": {
        "Intelligence": [
            {
                "ASN": "",
                "Confidence": 100,
                "Country": null,
                "CreatedTime": "2022-04-21T14:27:51.242Z",
                "Description": null,
                "ExpirationTS": "2022-07-20T14:27:51.041Z",
                "FeedID": 0,
                "ID": 355250247,
                "IP": "1.1.1.1",
                "IType": "c2_ip",
                "ImportSessionID": null,
                "IsAnonymous": false,
                "IsEditable": false,
                "IsPublic": true,
                "Latitude": null,
                "Longitude": null,
                "Modified": "2022-07-20T14:30:02.307Z",
                "Organization": "",
                "OwnerOrganizationID": 67,
                "ResourceURI": "/api/v2/intelligence/355250247/",
                "RetinaConfidence": -1,
                "Severity": "medium",
                "Source": "Analyst",
                "SourceCreated": null,
                "SourceModified": null,
                "SourceReportedConfidence": 100,
                "Status": "inactive",
                "Subtype": null,
                "TLP": null,
                "Tags": "abc,feb3fbcf-d18c-4a1a-89af-fbe054e16f6c,Playboook_source_without_approval_on_cloud",
                "ThreatType": "c2",
                "Threatscore": 70,
                "TrustedCircleIDs": null,
                "Type": "ip",
                "UUID": "3e141a49-6fc9-4567-8efb-919565a39752",
                "UpdateID": 940700580,
                "Value": "1.1.1.1",
                "WorkGroups": []
            },
            {
                "ASN": "",
                "Confidence": 100,
                "Country": null,
                "CreatedTime": "2022-04-21T14:18:13.074Z",
                "Description": null,
                "ExpirationTS": "2022-07-20T14:18:13.044Z",
                "FeedID": 0,
                "ID": 355250241,
                "IP": "1.1.1.1",
                "IType": "c2_ip",
                "ImportSessionID": null,
                "IsAnonymous": false,
                "IsEditable": false,
                "IsPublic": true,
                "Latitude": null,
                "Longitude": null,
                "Modified": "2022-07-20T14:20:02.201Z",
                "Organization": "",
                "OwnerOrganizationID": 70,
                "ResourceURI": "/api/v2/intelligence/355250241/",
                "RetinaConfidence": -1,
                "Severity": "high",
                "Source": "Analyst",
                "SourceCreated": null,
                "SourceModified": null,
                "SourceReportedConfidence": 100,
                "Status": "inactive",
                "Subtype": null,
                "TLP": null,
                "Tags": "Playboook_source_without_approval_on_cloud",
                "ThreatType": "c2",
                "Threatscore": 70,
                "TrustedCircleIDs": null,
                "Type": "ip",
                "UUID": "15cb41a2-3a0a-4bbf-b056-a0b87232807c",
                "UpdateID": 940700059,
                "Value": "1.1.1.1",
                "WorkGroups": []
            }
        ]
    }
}
```

#### Human Readable Output

>### The intelligence results
>|Confidence|CreatedTime|ExpirationTS|FeedID|ID|IP|IType|IsAnonymous|IsEditable|IsPublic|Modified|OwnerOrganizationID|ResourceURI|RetinaConfidence|Severity|Source|SourceReportedConfidence|Status|Tags|ThreatType|Threatscore|Type|UUID|UpdateID|Value|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 100 | 2022-04-21T14:27:51.242Z | 2022-07-20T14:27:51.041Z | 0 | 355250247 | 1.1.1.1 | c2_ip | false | false | true | 2022-07-20T14:30:02.307Z | 67 | /api/v2/intelligence/355250247/ | -1 | medium | Analyst | 100 | inactive | abc,feb3fbcf-d18c-4a1a-89af-fbe054e16f6c,Playboook_source_without_approval_on_cloud | c2 | 70 | ip | 3e141a49-6fc9-4567-8efb-919565a39752 | 940700580 | 1.1.1.1 |
>| 100 | 2022-04-21T14:18:13.074Z | 2022-07-20T14:18:13.044Z | 0 | 355250241 | 1.1.1.1 | c2_ip | false | false | true | 2022-07-20T14:20:02.201Z | 70 | /api/v2/intelligence/355250241/ | -1 | high | Analyst | 100 | inactive | Playboook_source_without_approval_on_cloud | c2 | 70 | ip | 15cb41a2-3a0a-4bbf-b056-a0b87232807c | 940700059 | 1.1.1.1 |

