Given CSV strings read from lists, builds a JSON list named *salesforce-provisioning-settings* that is used for Salesforce Provisioning process.

## Requirements for CSV lists
* Column headers that are part of lookup key should be all lower case and match with indicator fields.
* Column headers that are part of Salesforce profile should exactly match with SFDC corresponding attribute name.
* Column headers that are neither can be in any format - there is no restriction, e.g.: profileDescription
* If there is a default mapping for the org, include a role with all keys as "default"..
* If the attribute needs to be defaulted to manager's data, include the value as "default_to_manager".
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |
| Cortex XSOAR Version | 5.5.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| orgunit_mapping_csv_list | Name of the list where Salesforce CSV Org Unit mapping is stored |
| city_mapping_csv_list | Name of the list where Salesforce CSV City mapping is stored |
| location_region_mapping_csv_list | Name of the list where Salesforce CSV city mapping is stored |

## Outputs
---
There are no outputs for this script. However, the script generates the *salesforce-provisioning-settings* list.


## Example
Given the following lists stored on your XSOAR instance:
1. *salesforce-csv-city-mapping*
    ```
    city,Support_Engineer_Location__c,TimeZoneSidKey
    Santa Clara,Santa Clara,America/Los_Angeles
    Singapore,Singapore,Asia/Singapore
    Tel Aviv - Yafo,Israel,Asia/Jerusalem
    ```
2. *salesforce-csv-locationRegion-mapping*
    ```
    locationRegion,theatre
    Americas,NAM
    Asia Pacific,APAC
    "Europe, Middle East & Africa",EMEA
    Japan,JP
    ```
3. *salesforce-csv-orgunit-mapping*
    ```
    jobfunction,jobfamily,orglevel1,orglevel2,orglevel3,peoplemanagerflag,directorflag,vpflag,locationregion,ProfileId,profileDescription,UserRoleId,roleDescription,CallCenterId,callCenterDescription,My_Sales_Level__c,UserPermissionsSupportUser,UserPermissionsMobileUser,UserPermissionsSFContentUser,permissionSets,permissionSetsNames
    Professional Services Function,Professional Services Engineering,Services COS,Global Customer Support,professional services & focused services,y,n,n,Americas,MOCK_PROFILE_ID_1,Support PS Manager,MOCK_USER_ROLE_ID_1,Professional Services,,,Non-Sales,TRUE,TRUE,TRUE,MOCK_PERMISSION_SET_1,Service_Team_Edit_Access
    Information Technology Function,IT Project Management,Services COS,Global Customer Support,professional services & focused services,y,y,n,Americas,MOCK_PROFILE_ID_2,Support PS Manager,MOCK_USER_ROLE_ID_2,Professional Services,,,Non-Sales,FALSE,TRUE,TRUE,,
    ```

The *salesforce-provisioning-settings* list should be generated as follows:
```
{
    "cityMapping": {
        "santa clara": {
            "Support_Engineer_Location__c": "Santa Clara",
            "TimeZoneSidKey": "America/Los_Angeles"
        },
        "singapore": {
            "Support_Engineer_Location__c": "Singapore",
            "TimeZoneSidKey": "Asia/Singapore"
        },
        "tel aviv - yafo": {
            "Support_Engineer_Location__c": "Israel",
            "TimeZoneSidKey": "Asia/Jerusalem"
        }
    },
    "locationRegionMapping": {
        "americas": {
            "theatre": "NAM"
        },
        "asia pacific": {
            "theatre": "APAC"
        },
        "europe, middle east & africa": {
            "theatre": "EMEA"
        },
        "japan": {
            "theatre": "JP"
        }
    },
    "gcs": {
        "keyFormat": "jobfunction|jobfamily|orglevel1|orglevel2|orglevel3|peoplemanagerflag|directorflag|vpflag|locationregion",
        "profileMappings": {
            "professional services function|professional services engineering|services cos|global customer support|professional services & focused services|y|n|n|americas": {
                "ProfileId": "MOCK_PROFILE_ID_1",
                "profileDescription": "Support PS Manager",
                "UserRoleId": "MOCK_USER_ROLE_ID_1",
                "roleDescription": "Professional Services",
                "CallCenterId": "",
                "callCenterDescription": "",
                "My_Sales_Level__c": "Non-Sales",
                "UserPermissionsSupportUser": true,
                "UserPermissionsMobileUser": true,
                "UserPermissionsSFContentUser": true,
                "permissionSets": [
                    "MOCK_PERMISSION_SET_1"
                ],
                "permissionSetsNames": [
                    "Service_Team_Edit_Access"
                ]
            },
            "information technology function|it project management|services cos|global customer support|professional services & focused services|y|y|n|americas": {
                "ProfileId": "MOCK_PROFILE_ID_2",
                "profileDescription": "Support PS Manager",
                "UserRoleId": "MOCK_USER_ROLE_ID_2",
                "roleDescription": "Professional Services",
                "CallCenterId": "",
                "callCenterDescription": "",
                "My_Sales_Level__c": "Non-Sales",
                "UserPermissionsSupportUser": false,
                "UserPermissionsMobileUser": true,
                "UserPermissionsSFContentUser": true,
                "permissionSets": "",
                "permissionSetsNames": ""
            }
        }
    },
    "field marketing": {
        "keyFormat": "orglevel1|orglevel2|locationregion",
        "profileMappings": {}
    },
    "marketing": {
        "keyFormat": "orglevel1|orglevel2",
        "profileMappings": {}
    },
    "legal": {
        "keyFormat": "jobfunction|jobfamily|orglevel3",
        "profileMappings": {}
    },
    "sales": {
        "keyFormat": "jobfunction|jobfamily|suporglevel2|suporglevel3",
        "profileMappings": {}
    },
    "orgUnitMapping": {
        "gcs": "gcs",
        "field marketing": "field marketing",
        "marketing": "marketing",
        "legal": "legal",
        "sales": "sales"
    }
}
```
