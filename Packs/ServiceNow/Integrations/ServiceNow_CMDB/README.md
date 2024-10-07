ServiceNow CMDB is a service‑centric foundation that proactively
  analyzes service‑impacting changes, identifies issues, and eliminates outages.


## Configure ServiceNow_CMDB in Cortex


### Instance Configuration
The integration supports two types of authorization:
1. Basic authorization using username and password.
2. OAuth 2.0 authorization.

#### OAuth 2.0 Authorization
To use OAuth 2.0 authorization, perform the following steps:
1. Login to your ServiceNow instance and create an endpoint for XSOAR to access your instance (please see [Snow OAuth](https://docs.servicenow.com/bundle/xanadu-platform-security/page/administer/security/concept/c_OAuthApplications.html) for more information). 
2. Copy the **Client Id** and **Client Secret** (press the lock next to the client secret to reveal it) that were automatically generated when creating the endpoint into the **Username** and **Password** fields of the instance configuration.
3. Select the **Use OAuth Login** checkbox and click **Done**.
4. Run the command ***!servicenow-cmdb-oauth-login*** from the XSOAR CLI and fill in the username and password of the ServiceNow instance. This step generates and saves to the integration context a refresh token to the ServiceNow instance and is required only the first time after configuring a new instance in the XSOAR platform.
5. (Optional) Test the created instance by running the ***!servicenow-cmdb-oauth-test*** command.

**Notes:**
1. When running the ***!servicenow-cmdb-oauth-login*** command, a refresh token is generated and will be used to produce new access tokens after the current access token has expired.
2. Every time the refresh token expires you will have to run the ***servicenow-cmdb-oauth-login*** command again. Hence, we recommend to set the **Refresh Token Lifespan** field in the endpoint created in step 1 to a long period (can be set to several years). 
3. The grant type used to get an access token is `Client credentials`. See the [Snow documentation](https://docs.servicenow.com/bundle/xanadu-platform-security/page/administer/security/concept/c_OAuthApplications.html#d25788e201) for more information.


### Using Multi Factor Authentication (MFA)
MFA can be used both when using basic authorization and OAuth 2.0 authorization, however we strongly recommend using OAuth 2.0 when using MFA.
If MFA is enabled for your user, perform the following steps:
1. Open the Google Authenticator application on your mobile device and make note of the number. The number refreshes every 30 seconds.
2. Enter your username and password, and append the One Time Password (OTP) that you currently see on your mobile device to your password without any extra spaces. For example, if your password is **12345** and the current OTP code is **424 058**, enter **12345424058**.

**Notes:**
1. When using basic authorization, you will have to update your password with the current OTP every time the current code expires (30 seconds), therefore, we recommend using OAuth 2.0 authorization.
2. For using OAuth 2.0 see the above instructions. The OTP code should be appended to the password parameter in the ***!servicenow-cmdb-oauth-login*** command.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | ServiceNow URL, in the format https://company.service-now.com/ | True |
| credentials | Username/Client ID | True |
| use_oauth | Use OAuth Login | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### servicenow-cmdb-records-list
***
Query records for a CMDB class.


#### Base Command

`servicenow-cmdb-records-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| class | The name of the class to query. | Required | 
| query | An encoded query string used to filter the results. For more information about querying in ServiceNow, see https://docs.servicenow.com/bundle/paris-servicenow-platform/page/use/common-ui-elements/reference/r_OpAvailableFiltersQueries.html | Optional | 
| limit | The maximum number of results returned per page (default: 50). | Optional | 
| offset | The number of records to exclude from the query (default: 0). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNowCMDB.Class | String | The name of CMDB table that was queried. | 
| ServiceNowCMDB.Records | Unknown | A list of all the records that were found in the CMDB table. | 


#### Command Example
```!servicenow-cmdb-records-list class=cmdb_ci_linux_server limit=3```

#### Context Example
```json
{
    "ServiceNowCMDB": {
        "Class": "cmdb_ci_linux_server",
        "Records": [
            {
                "name": "Test Linux Server 2",
                "sys_id": "0ad329e3db27901026fca015ca9619fb"
            },
            {
                "name": "Update Name Test",
                "sys_id": "18295cefdbd0241026fca015ca9619f7"
            },
            {
                "name": "new design updated name",
                "sys_id": "2a41eb4e1b739810042611b4bd4bcb9d"
            }
        ]
    }
}
```

#### Human Readable Output

>### Found 3 records for class cmdb_ci_linux_server:
>|name|sys_id|
>|---|---|
>| Test Linux Server 2 | 0ad329e3db27901026fca015ca9619fb |
>| Update Name Test | 18295cefdbd0241026fca015ca9619f7 |
>| new design updated name | 2a41eb4e1b739810042611b4bd4bcb9d |


### servicenow-cmdb-record-get-by-id
***
Query attributes and relationship information for a specific record.


#### Base Command

`servicenow-cmdb-record-get-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| class | The name of the class to query. | Required | 
| sys_id | The ID of the record that should be queried. | Required | 
| fields | A comma-separated list of the fields to return for the queried record. | Optional | 
| relation_limit | The maximum number of relations returned (default: 50). | Optional | 
| relation_offset | The number of records to exclude from the relations query (default: 0). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNowCMDB.Record.SysID | String | The sys_id of the record that was queried. | 
| ServiceNowCMDB.Record.Class | String | The name of the class from which the record was queried. | 
| ServiceNowCMDB.Record.Attributes | Unknown | The attributes that were returned in the response for the queried record. | 
| ServiceNowCMDB.Record.OutboundRelations | Unknown | A list of all the outbound relations of the queried record. | 
| ServiceNowCMDB.Record.InboundRelations | Unknown | A list of all the inbound relations of the queried record. | 


#### Command Example
```!servicenow-cmdb-record-get-by-id class=cmdb_ci_linux_server sys_id=a8decc3f1b9c2410042611b4bd4bcb7d```

#### Context Example
```json
{
    "ServiceNowCMDB": {
        "Record": {
            "Attributes": {
                "asset": {
                    "display_value": "Unknown",
                    "link": "https://ven03941.service-now.com/api/now/table/alm_asset/60decc3f1b9c2410042611b4bd4bcb7f",
                    "value": "60decc3f1b9c2410042611b4bd4bcb7f"
                },
                "asset_tag": "",
                "assigned": "",
                "assigned_to": "",
                "assignment_group": "",
                "attributes": "",
                "can_print": "false",
                "category": "Hardware",
                "cd_rom": "false",
                "cd_speed": "",
                "change_control": "",
                "chassis_type": "",
                "checked_in": "",
                "checked_out": "",
                "classification": "Production",
                "comments": "",
                "company": "",
                "correlation_id": "",
                "cost": "",
                "cost_cc": "USD",
                "cost_center": "",
                "cpu_core_count": "",
                "cpu_core_thread": "",
                "cpu_count": "",
                "cpu_manufacturer": "",
                "cpu_name": "",
                "cpu_speed": "",
                "cpu_type": "",
                "default_gateway": "",
                "delivery_date": "",
                "department": "",
                "discovery_source": "ServiceNow",
                "disk_space": "",
                "dns_domain": "",
                "dr_backup": "",
                "due": "",
                "due_in": "",
                "duplicate_of": "",
                "fault_count": "0",
                "firewall_status": "Intranet",
                "first_discovered": "2020-11-12 06:18:25",
                "floppy": "",
                "form_factor": "",
                "fqdn": "",
                "gl_account": "",
                "hardware_status": "installed",
                "hardware_substatus": "",
                "host_name": "",
                "install_date": "",
                "install_status": "1",
                "invoice_number": "",
                "ip_address": "",
                "justification": "",
                "kernel_release": "",
                "last_discovered": "2020-11-12 06:18:25",
                "lease_id": "",
                "location": "",
                "mac_address": "",
                "maintenance_schedule": "",
                "managed_by": "",
                "manufacturer": "",
                "model_id": {
                    "display_value": "Unknown",
                    "link": "https://ven03941.service-now.com/api/now/table/cmdb_model/4ed329e3db27901026fca015ca9619fc",
                    "value": "4ed329e3db27901026fca015ca9619fc"
                },
                "model_number": "",
                "monitor": "false",
                "name": "Record For README",
                "object_id": "",
                "operational_status": "1",
                "order_date": "",
                "os": "",
                "os_address_width": "",
                "os_domain": "",
                "os_service_pack": "",
                "os_version": "",
                "owned_by": "",
                "po_number": "",
                "purchase_date": "",
                "ram": "",
                "schedule": "",
                "serial_number": "",
                "short_description": "",
                "skip_sync": "false",
                "start_date": "",
                "subcategory": "Computer",
                "support_group": "",
                "supported_by": "",
                "sys_class_name": "cmdb_ci_linux_server",
                "sys_class_path": "/!!/!2/!(/!!/!0",
                "sys_created_by": "admin",
                "sys_created_on": "2020-11-12 06:18:25",
                "sys_domain": {
                    "display_value": "global",
                    "link": "https://ven03941.service-now.com/api/now/table/sys_user_group/global",
                    "value": "global"
                },
                "sys_domain_path": "/",
                "sys_id": "a8decc3f1b9c2410042611b4bd4bcb7d",
                "sys_mod_count": "0",
                "sys_tags": "",
                "sys_updated_by": "admin",
                "sys_updated_on": "2020-11-12 06:18:25",
                "unverified": "false",
                "used_for": "Production",
                "vendor": "",
                "virtual": "false",
                "warranty_expiration": ""
            },
            "Class": "cmdb_ci_linux_server",
            "InboundRelations": [
                {
                    "sys_id": "eb3f84331b5c2410042611b4bd4bcbf9",
                    "target": {
                        "display_value": "CMS App FLX",
                        "link": "https://ven03941.service-now.com/api/now/cmdb/instance/cmdb_ci/829e953a0ad3370200af63483498b1ea",
                        "value": "829e953a0ad3370200af63483498b1ea"
                    },
                    "type": {
                        "display_value": "Uses::Used by",
                        "link": "https://ven03941.service-now.com/api/now/table/cmdb_rel_type/cb5592603751200032ff8c00dfbe5d17",
                        "value": "cb5592603751200032ff8c00dfbe5d17"
                    }
                }
            ],
            "OutboundRelations": [],
            "SysID": "a8decc3f1b9c2410042611b4bd4bcb7d"
        }
    }
}
```

#### Human Readable Output

>### Found the following attributes and relations for record a8decc3f1b9c2410042611b4bd4bcb7d:
>### Attributes
>|Name|SysID|
>|---|---|
>| Record For README | a8decc3f1b9c2410042611b4bd4bcb7d |
> ### Inbound Relations
>|SysID|Target Display Value|Type Display Value|
>|---|---|---|
>| eb3f84331b5c2410042611b4bd4bcbf9 | CMS App FLX | Uses::Used by |


### servicenow-cmdb-record-create
***
Create a record with associated relations and attributes.


#### Base Command

`servicenow-cmdb-record-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| class | The name of the class to add the record to. | Required | 
| source | The discovery source value. You can see all available values from sys_choice table with query GOTOelementLIKEdiscovery_source^name=cmdb_ci. (default: "ServiceNow"). | Optional | 
| attributes | A comma-separated list of attributes that should be added to the created record. Input format: attribute=value pairs, e.g., "name=test, ram=1024". | Required | 
| inbound_relations | A comma-separated list of dictionaries. Each dictionary represents an inbound relation that should be added to the created record. | Optional | 
| outbound_relations | A comma-separated list of dictionaries. Each dictionary represents an outbound relation that should be added to the created record. | Optional | 
| fields | A comma-separated list of fields to return for the created record. | Optional | 
| relation_limit | The maximum number of relations returned (default: 50). | Optional | 
| relation_offset | The number of records to exclude from the relations query (default: 0). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNowCMDB.Record.SysID | String | The sys_id of the record that was created. | 
| ServiceNowCMDB.Record.Class | String | The name of the class from which the record was created. | 
| ServiceNowCMDB.Record.Attributes | Unknown | The attributes that were returned in the response for the created record. | 
| ServiceNowCMDB.Record.OutboundRelations | Unknown | A list of all the outbound relations of the created record. | 
| ServiceNowCMDB.Record.InboundRelations | Unknown | A list of all the inbound relations of the created record. | 


#### Command Example
```!servicenow-cmdb-record-create class=cmdb_ci_linux_server attributes="name=README Record"```

#### Context Example
```json
{
    "ServiceNowCMDB": {
        "Record": {
            "Attributes": {
                "asset": {
                    "display_value": "Unknown",
                    "link": "https://ven03941.service-now.com/api/now/table/alm_asset/964098b3db50641026fca015ca9619a8",
                    "value": "964098b3db50641026fca015ca9619a8"
                },
                "asset_tag": "",
                "assigned": "",
                "assigned_to": "",
                "assignment_group": "",
                "attributes": "",
                "can_print": "false",
                "category": "Hardware",
                "cd_rom": "false",
                "cd_speed": "",
                "change_control": "",
                "chassis_type": "",
                "checked_in": "",
                "checked_out": "",
                "classification": "Production",
                "comments": "",
                "company": "",
                "correlation_id": "",
                "cost": "",
                "cost_cc": "USD",
                "cost_center": "",
                "cpu_core_count": "",
                "cpu_core_thread": "",
                "cpu_count": "",
                "cpu_manufacturer": "",
                "cpu_name": "",
                "cpu_speed": "",
                "cpu_type": "",
                "default_gateway": "",
                "delivery_date": "",
                "department": "",
                "discovery_source": "ServiceNow",
                "disk_space": "",
                "dns_domain": "",
                "dr_backup": "",
                "due": "",
                "due_in": "",
                "duplicate_of": "",
                "fault_count": "0",
                "firewall_status": "Intranet",
                "first_discovered": "2020-11-12 06:24:49",
                "floppy": "",
                "form_factor": "",
                "fqdn": "",
                "gl_account": "",
                "hardware_status": "installed",
                "hardware_substatus": "",
                "host_name": "",
                "install_date": "",
                "install_status": "1",
                "invoice_number": "",
                "ip_address": "",
                "justification": "",
                "kernel_release": "",
                "last_discovered": "2020-11-12 06:24:49",
                "lease_id": "",
                "location": "",
                "mac_address": "",
                "maintenance_schedule": "",
                "managed_by": "",
                "manufacturer": "",
                "model_id": {
                    "display_value": "Unknown",
                    "link": "https://ven03941.service-now.com/api/now/table/cmdb_model/4ed329e3db27901026fca015ca9619fc",
                    "value": "4ed329e3db27901026fca015ca9619fc"
                },
                "model_number": "",
                "monitor": "false",
                "name": "README Record",
                "object_id": "",
                "operational_status": "1",
                "order_date": "",
                "os": "",
                "os_address_width": "",
                "os_domain": "",
                "os_service_pack": "",
                "os_version": "",
                "owned_by": "",
                "po_number": "",
                "purchase_date": "",
                "ram": "",
                "schedule": "",
                "serial_number": "",
                "short_description": "",
                "skip_sync": "false",
                "start_date": "",
                "subcategory": "Computer",
                "support_group": "",
                "supported_by": "",
                "sys_class_name": "cmdb_ci_linux_server",
                "sys_class_path": "/!!/!2/!(/!!/!0",
                "sys_created_by": "admin",
                "sys_created_on": "2020-11-12 06:24:49",
                "sys_domain": {
                    "display_value": "global",
                    "link": "https://ven03941.service-now.com/api/now/table/sys_user_group/global",
                    "value": "global"
                },
                "sys_domain_path": "/",
                "sys_id": "d64098b3db50641026fca015ca9619a7",
                "sys_mod_count": "0",
                "sys_tags": "",
                "sys_updated_by": "admin",
                "sys_updated_on": "2020-11-12 06:24:49",
                "unverified": "false",
                "used_for": "Production",
                "vendor": "",
                "virtual": "false",
                "warranty_expiration": ""
            },
            "Class": "cmdb_ci_linux_server",
            "InboundRelations": [],
            "OutboundRelations": [],
            "SysID": "d64098b3db50641026fca015ca9619a7"
        }
    }
}
```

#### Human Readable Output

>### Record d64098b3db50641026fca015ca9619a7 was created successfully.
>### Attributes
>|Name|SysID|
>|---|---|
>| README Record | d64098b3db50641026fca015ca9619a7 |


### servicenow-cmdb-record-update
***
Update a record with the given attributes.


#### Base Command

`servicenow-cmdb-record-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| class | The class name of the record that should be updated. | Required | 
| sys_id | The ID of the record that should be updated. | Required | 
| source | The discovery source value. You can see all available values from sys_choice table with query GOTOelementLIKEdiscovery_source^name=cmdb_ci. (default: "ServiceNow"). | Optional | 
| attributes | A comma-separated list of the attributes that should be updated in the record. Input format: attribute=value pairs, e.g., "name=test,ram=1024". | Required | 
| fields | A comma-separated list of the fields to return for the updated record. | Optional | 
| relation_limit | The maximum number of relations returned (default: 50). | Optional | 
| relation_offset | The number of records to exclude from the relations query (default: 0). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNowCMDB.Record.SysID | String | The sys_id of the record that was updated. | 
| ServiceNowCMDB.Record.Class | String | The class name of the updated record. | 
| ServiceNowCMDB.Record.Attributes | Unknown | The attributes that were returned in the response for the updated record. | 
| ServiceNowCMDB.Record.OutboundRelations | Unknown | A list of all the outbound relations of the updated record. | 
| ServiceNowCMDB.Record.InboundRelations | Unknown | A list of all the inbound relations of the updated record. | 


#### Command Example
```!servicenow-cmdb-record-update class=cmdb_ci_linux_server sys_id=a8decc3f1b9c2410042611b4bd4bcb7d attributes="name=Update Name README"```

#### Context Example
```json
{
    "ServiceNowCMDB": {
        "Record": {
            "Attributes": {
                "asset": {
                    "display_value": "Unknown",
                    "link": "https://ven03941.service-now.com/api/now/table/alm_asset/60decc3f1b9c2410042611b4bd4bcb7f",
                    "value": "60decc3f1b9c2410042611b4bd4bcb7f"
                },
                "asset_tag": "",
                "assigned": "",
                "assigned_to": "",
                "assignment_group": "",
                "attributes": "",
                "can_print": "false",
                "category": "Hardware",
                "cd_rom": "false",
                "cd_speed": "",
                "change_control": "",
                "chassis_type": "",
                "checked_in": "",
                "checked_out": "",
                "classification": "Production",
                "comments": "",
                "company": "",
                "correlation_id": "",
                "cost": "",
                "cost_cc": "USD",
                "cost_center": "",
                "cpu_core_count": "",
                "cpu_core_thread": "",
                "cpu_count": "",
                "cpu_manufacturer": "",
                "cpu_name": "",
                "cpu_speed": "",
                "cpu_type": "",
                "default_gateway": "",
                "delivery_date": "",
                "department": "",
                "discovery_source": "ServiceNow",
                "disk_space": "",
                "dns_domain": "",
                "dr_backup": "",
                "due": "",
                "due_in": "",
                "duplicate_of": "",
                "fault_count": "0",
                "firewall_status": "Intranet",
                "first_discovered": "2020-11-12 06:18:25",
                "floppy": "",
                "form_factor": "",
                "fqdn": "",
                "gl_account": "",
                "hardware_status": "installed",
                "hardware_substatus": "",
                "host_name": "",
                "install_date": "",
                "install_status": "1",
                "invoice_number": "",
                "ip_address": "",
                "justification": "",
                "kernel_release": "",
                "last_discovered": "2020-11-12 06:24:53",
                "lease_id": "",
                "location": "",
                "mac_address": "",
                "maintenance_schedule": "",
                "managed_by": "",
                "manufacturer": "",
                "model_id": {
                    "display_value": "Unknown",
                    "link": "https://ven03941.service-now.com/api/now/table/cmdb_model/4ed329e3db27901026fca015ca9619fc",
                    "value": "4ed329e3db27901026fca015ca9619fc"
                },
                "model_number": "",
                "monitor": "false",
                "name": "Update Name README",
                "object_id": "",
                "operational_status": "1",
                "order_date": "",
                "os": "",
                "os_address_width": "",
                "os_domain": "",
                "os_service_pack": "",
                "os_version": "",
                "owned_by": "",
                "po_number": "",
                "purchase_date": "",
                "ram": "",
                "schedule": "",
                "serial_number": "",
                "short_description": "",
                "skip_sync": "false",
                "start_date": "",
                "subcategory": "Computer",
                "support_group": "",
                "supported_by": "",
                "sys_class_name": "cmdb_ci_linux_server",
                "sys_class_path": "/!!/!2/!(/!!/!0",
                "sys_created_by": "admin",
                "sys_created_on": "2020-11-12 06:18:25",
                "sys_domain": {
                    "display_value": "global",
                    "link": "https://ven03941.service-now.com/api/now/table/sys_user_group/global",
                    "value": "global"
                },
                "sys_domain_path": "/",
                "sys_id": "a8decc3f1b9c2410042611b4bd4bcb7d",
                "sys_mod_count": "1",
                "sys_tags": "",
                "sys_updated_by": "admin",
                "sys_updated_on": "2020-11-12 06:24:53",
                "unverified": "false",
                "used_for": "Production",
                "vendor": "",
                "virtual": "false",
                "warranty_expiration": ""
            },
            "Class": "cmdb_ci_linux_server",
            "InboundRelations": [
                {
                    "sys_id": "eb3f84331b5c2410042611b4bd4bcbf9",
                    "target": {
                        "display_value": "CMS App FLX",
                        "link": "https://ven03941.service-now.com/api/now/cmdb/instance/cmdb_ci/829e953a0ad3370200af63483498b1ea",
                        "value": "829e953a0ad3370200af63483498b1ea"
                    },
                    "type": {
                        "display_value": "Uses::Used by",
                        "link": "https://ven03941.service-now.com/api/now/table/cmdb_rel_type/cb5592603751200032ff8c00dfbe5d17",
                        "value": "cb5592603751200032ff8c00dfbe5d17"
                    }
                }
            ],
            "OutboundRelations": [],
            "SysID": "a8decc3f1b9c2410042611b4bd4bcb7d"
        }
    }
}
```

#### Human Readable Output

>### Updated record a8decc3f1b9c2410042611b4bd4bcb7d successfully.
>### Attributes
>|Name|SysID|
>|---|---|
>| Update Name README | a8decc3f1b9c2410042611b4bd4bcb7d |
> ### Inbound Relations
>|SysID|Target Display Value|Type Display Value|
>|---|---|---|
>| eb3f84331b5c2410042611b4bd4bcbf9 | CMS App FLX | Uses::Used by |


### servicenow-cmdb-record-add-relations
***
Add a new relation to an existing record.


#### Base Command

`servicenow-cmdb-record-add-relations`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| class | The class name of the record. | Required | 
| sys_id | The ID of the record to which the relations should be added. | Required | 
| source | The discovery source value. You can see all available values from sys_choice table with query GOTOelementLIKEdiscovery_source^name=cmdb_ci. (default: "ServiceNow"). | Optional | 
| inbound_relations | A comma-separated list of dictionaries. Each dictionary represents an inbound relation that should be added to the created record. | Optional | 
| outbound_relations | A comma-separated list of dictionaries. Each dictionary represents an outbound relation that should be added to the created record. | Optional | 
| fields | A comma-separated list of the fields to return for the record. | Optional | 
| relation_limit | The maximum number of relations returned (default: 50). | Optional | 
| relation_offset | The number of records to exclude from the relations query (default: 0). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNowCMDB.Record.SysID | String | The sys_id of the record that was updated. | 
| ServiceNowCMDB.Record.Class | String | The class name of the record. | 
| ServiceNowCMDB.Record.Attributes | Unknown | The attributes that were returned in the response for the updated record. | 
| ServiceNowCMDB.Record.OutboundRelations | Unknown | A list of all the outbound relations of the record. | 
| ServiceNowCMDB.Record.InboundRelations | Unknown | A list of all the inbound relations of the record. | 


#### Command Example
```!servicenow-cmdb-record-add-relations class=cmdb_ci_linux_server sys_id=a8decc3f1b9c2410042611b4bd4bcb7d inbound_relations="[{'type': 'cb5592603751200032ff8c00dfbe5d17','target':'829e953a0ad3370200af63483498b1ea','sys_class_name':'cmdb_ci_appl'}]"```

#### Context Example
```json
{
    "ServiceNowCMDB": {
        "Record": {
            "Attributes": {
                "asset": {
                    "display_value": "Unknown",
                    "link": "https://ven03941.service-now.com/api/now/table/alm_asset/60decc3f1b9c2410042611b4bd4bcb7f",
                    "value": "60decc3f1b9c2410042611b4bd4bcb7f"
                },
                "asset_tag": "",
                "assigned": "",
                "assigned_to": "",
                "assignment_group": "",
                "attributes": "",
                "can_print": "false",
                "category": "Hardware",
                "cd_rom": "false",
                "cd_speed": "",
                "change_control": "",
                "chassis_type": "",
                "checked_in": "",
                "checked_out": "",
                "classification": "Production",
                "comments": "",
                "company": "",
                "correlation_id": "",
                "cost": "",
                "cost_cc": "USD",
                "cost_center": "",
                "cpu_core_count": "",
                "cpu_core_thread": "",
                "cpu_count": "",
                "cpu_manufacturer": "",
                "cpu_name": "",
                "cpu_speed": "",
                "cpu_type": "",
                "default_gateway": "",
                "delivery_date": "",
                "department": "",
                "discovery_source": "ServiceNow",
                "disk_space": "",
                "dns_domain": "",
                "dr_backup": "",
                "due": "",
                "due_in": "",
                "duplicate_of": "",
                "fault_count": "0",
                "firewall_status": "Intranet",
                "first_discovered": "2020-11-12 06:18:25",
                "floppy": "",
                "form_factor": "",
                "fqdn": "",
                "gl_account": "",
                "hardware_status": "installed",
                "hardware_substatus": "",
                "host_name": "",
                "install_date": "",
                "install_status": "1",
                "invoice_number": "",
                "ip_address": "",
                "justification": "",
                "kernel_release": "",
                "last_discovered": "2020-11-12 06:24:53",
                "lease_id": "",
                "location": "",
                "mac_address": "",
                "maintenance_schedule": "",
                "managed_by": "",
                "manufacturer": "",
                "model_id": {
                    "display_value": "Unknown",
                    "link": "https://ven03941.service-now.com/api/now/table/cmdb_model/4ed329e3db27901026fca015ca9619fc",
                    "value": "4ed329e3db27901026fca015ca9619fc"
                },
                "model_number": "",
                "monitor": "false",
                "name": "Update Name README",
                "object_id": "",
                "operational_status": "1",
                "order_date": "",
                "os": "",
                "os_address_width": "",
                "os_domain": "",
                "os_service_pack": "",
                "os_version": "",
                "owned_by": "",
                "po_number": "",
                "purchase_date": "",
                "ram": "",
                "schedule": "",
                "serial_number": "",
                "short_description": "",
                "skip_sync": "false",
                "start_date": "",
                "subcategory": "Computer",
                "support_group": "",
                "supported_by": "",
                "sys_class_name": "cmdb_ci_linux_server",
                "sys_class_path": "/!!/!2/!(/!!/!0",
                "sys_created_by": "admin",
                "sys_created_on": "2020-11-12 06:18:25",
                "sys_domain": {
                    "display_value": "global",
                    "link": "https://ven03941.service-now.com/api/now/table/sys_user_group/global",
                    "value": "global"
                },
                "sys_domain_path": "/",
                "sys_id": "a8decc3f1b9c2410042611b4bd4bcb7d",
                "sys_mod_count": "1",
                "sys_tags": "",
                "sys_updated_by": "admin",
                "sys_updated_on": "2020-11-12 06:24:53",
                "unverified": "false",
                "used_for": "Production",
                "vendor": "",
                "virtual": "false",
                "warranty_expiration": ""
            },
            "Class": "cmdb_ci_linux_server",
            "InboundRelations": [
                {
                    "sys_id": "b34050bbdb10641026fca015ca961985",
                    "target": {
                        "display_value": "CMS App FLX",
                        "link": "https://ven03941.service-now.com/api/now/cmdb/instance/cmdb_ci/829e953a0ad3370200af63483498b1ea",
                        "value": "829e953a0ad3370200af63483498b1ea"
                    },
                    "type": {
                        "display_value": "Uses::Used by",
                        "link": "https://ven03941.service-now.com/api/now/table/cmdb_rel_type/cb5592603751200032ff8c00dfbe5d17",
                        "value": "cb5592603751200032ff8c00dfbe5d17"
                    }
                },
                {
                    "sys_id": "eb3f84331b5c2410042611b4bd4bcbf9",
                    "target": {
                        "display_value": "CMS App FLX",
                        "link": "https://ven03941.service-now.com/api/now/cmdb/instance/cmdb_ci/829e953a0ad3370200af63483498b1ea",
                        "value": "829e953a0ad3370200af63483498b1ea"
                    },
                    "type": {
                        "display_value": "Uses::Used by",
                        "link": "https://ven03941.service-now.com/api/now/table/cmdb_rel_type/cb5592603751200032ff8c00dfbe5d17",
                        "value": "cb5592603751200032ff8c00dfbe5d17"
                    }
                }
            ],
            "OutboundRelations": [],
            "SysID": "a8decc3f1b9c2410042611b4bd4bcb7d"
        }
    }
}
```

#### Human Readable Output

>### New relations were added to a8decc3f1b9c2410042611b4bd4bcb7d record successfully.
>### Attributes
>|Name|SysID|
>|---|---|
>| Update Name README | a8decc3f1b9c2410042611b4bd4bcb7d |
> ### Inbound Relations
>|SysID|Target Display Value|Type Display Value|
>|---|---|---|
>| b34050bbdb10641026fca015ca961985,<br/>eb3f84331b5c2410042611b4bd4bcbf9 | CMS App FLX,<br/>CMS App FLX | Uses::Used by,<br/>Uses::Used by |


### servicenow-cmdb-record-delete-relations
***
Delete a relation of an existing record.


#### Base Command

`servicenow-cmdb-record-delete-relations`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| class | The class name of the record. | Required | 
| sys_id | The ID of the record from which a relation should be deleted. | Required | 
| relation_sys_id | The ID of the relation that should be deleted. | Required | 
| fields | A comma-separated list of the fields to return for the record. | Optional | 
| relation_limit | The maximum number of relations returned (default: 50). | Optional | 
| relation_offset | The number of records to exclude from the relations query (default: 0). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ServiceNowCMDB.Record.SysID | String | The sys_id of the record that was updated. | 
| ServiceNowCMDB.Record.Class | String | The class name of the record. | 
| ServiceNowCMDB.Record.Attributes | Unknown | The attributes that were returned in the response for the updated record. | 
| ServiceNowCMDB.Record.OutboundRelations | Unknown | A list of all the outbound relations of the record. | 
| ServiceNowCMDB.Record.InboundRelations | Unknown | A list of all the inbound relations of the record. | 

#### Command Example
```!servicenow-cmdb-record-delete-relations class=cmdb_ci_linux_server relation_sys_id=b376af86dbbf981026fca015ca961981 sys_id=2a41eb4e1b739810042611b4bd4bcb9d```

#### Context Example
```json
{
    "ServiceNowCMDB": {
        "Record": {
            "Attributes": {
                "asset": {
                    "display_value": "Unknown",
                    "link": "https://ven03941.service-now.com/api/now/table/alm_asset/964098b3db50641026fca015ca9619a8",
                    "value": "964098b3db50641026fca015ca9619a8"
                },
                "asset_tag": "",
                "assigned": "",
                "assigned_to": "",
                "assignment_group": "",
                "attributes": "",
                "can_print": "false",
                "category": "Hardware",
                "cd_rom": "false",
                "cd_speed": "",
                "change_control": "",
                "chassis_type": "",
                "checked_in": "",
                "checked_out": "",
                "classification": "Production",
                "comments": "",
                "company": "",
                "correlation_id": "",
                "cost": "",
                "cost_cc": "USD",
                "cost_center": "",
                "cpu_core_count": "",
                "cpu_core_thread": "",
                "cpu_count": "",
                "cpu_manufacturer": "",
                "cpu_name": "",
                "cpu_speed": "",
                "cpu_type": "",
                "default_gateway": "",
                "delivery_date": "",
                "department": "",
                "discovery_source": "ServiceNow",
                "disk_space": "",
                "dns_domain": "",
                "dr_backup": "",
                "due": "",
                "due_in": "",
                "duplicate_of": "",
                "fault_count": "0",
                "firewall_status": "Intranet",
                "first_discovered": "2020-11-12 06:24:49",
                "floppy": "",
                "form_factor": "",
                "fqdn": "",
                "gl_account": "",
                "hardware_status": "installed",
                "hardware_substatus": "",
                "host_name": "",
                "install_date": "",
                "install_status": "1",
                "invoice_number": "",
                "ip_address": "",
                "justification": "",
                "kernel_release": "",
                "last_discovered": "2020-11-12 06:24:49",
                "lease_id": "",
                "location": "",
                "mac_address": "",
                "maintenance_schedule": "",
                "managed_by": "",
                "manufacturer": "",
                "model_id": {
                    "display_value": "Unknown",
                    "link": "https://ven03941.service-now.com/api/now/table/cmdb_model/4ed329e3db27901026fca015ca9619fc",
                    "value": "4ed329e3db27901026fca015ca9619fc"
                },
                "model_number": "",
                "monitor": "false",
                "name": "README Record",
                "object_id": "",
                "operational_status": "1",
                "order_date": "",
                "os": "",
                "os_address_width": "",
                "os_domain": "",
                "os_service_pack": "",
                "os_version": "",
                "owned_by": "",
                "po_number": "",
                "purchase_date": "",
                "ram": "",
                "schedule": "",
                "serial_number": "",
                "short_description": "",
                "skip_sync": "false",
                "start_date": "",
                "subcategory": "Computer",
                "support_group": "",
                "supported_by": "",
                "sys_class_name": "cmdb_ci_linux_server",
                "sys_class_path": "/!!/!2/!(/!!/!0",
                "sys_created_by": "admin",
                "sys_created_on": "2020-11-12 06:24:49",
                "sys_domain": {
                    "display_value": "global",
                    "link": "https://ven03941.service-now.com/api/now/table/sys_user_group/global",
                    "value": "global"
                },
                "sys_domain_path": "/",
                "sys_id": "d64098b3db50641026fca015ca9619a7",
                "sys_mod_count": "0",
                "sys_tags": "",
                "sys_updated_by": "admin",
                "sys_updated_on": "2020-11-12 06:24:49",
                "unverified": "false",
                "used_for": "Production",
                "vendor": "",
                "virtual": "false",
                "warranty_expiration": ""
            },
            "Class": "cmdb_ci_linux_server",
            "InboundRelations": [],
            "OutboundRelations": [],
            "SysID": "2a41eb4e1b739810042611b4bd4bcb9d"
        }
    }
}
```


#### Human Readable Output

>### Deleted relation b376af86dbbf981026fca015ca961981 successfully from 2a41eb4e1b739810042611b4bd4bcb9d record.
>### Attributes
>|Name|SysID|
>|---|---|
>| Update Name README | 2a41eb4e1b739810042611b4bd4bcb9d |


### servicenow-cmdb-oauth-login
***
This function should be used once before running any command when using OAuth authorization.


#### Base Command

`servicenow-cmdb-oauth-login`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username that should be used for login. | Required | 
| password | The password that should be used for login. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!servicenow-cmdb-oauth-login username=username password=password```

#### Human Readable Output
> ###Logged in successfully.
> A refresh token was saved to the integration context. This token will be used to generate a new access token once the current one expires.



### servicenow-cmdb-oauth-test
***
Test the instance configuration when using OAuth authorization.


#### Base Command

`servicenow-cmdb-oauth-test`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!servicenow-cmdb-oauth-test```

#### Human Readable Output
> ###Instance Configured Successfully.

