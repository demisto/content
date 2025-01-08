Use Gem alerts as a trigger for Cortex XSOAR’s custom playbooks, to automate response to specific TTPs.

## Configure Gem in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Incident type |  | False |
| API Endpoint | The API endpoint to use for connection \(US or EU\) | True |
| Service Account ID | The Service Account ID to use for connection | True |
| Service Account Secret | The Service Account Secret to use for connection | True |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |
| Fetch incidents |  | False |
| Maximum number of alerts per fetch |  | False |



## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### gem-list-threats

***
List all threats detected in Gem.

#### Base Command

`gem-list-threats`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The number of alert to fetch. Default is 50. | Optional | 
| time_start | The start time of the threats to return in ISO format. Examples: 2023-01-01, 2023-01-01T01:01:01Z, 2023-01-01T01:01:01+00:00. | Required | 
| time_end | The end time of the threats to return in ISO format. Examples: 2023-01-01, 2023-01-01T01:01:01Z, 2023-01-01T01:01:01+00:00. | Required | 
| ordering | The ordering of the items. Possible values are: -timeframe_start, timeframe_state, -mitre_technique, mitre_technique, -severity, severity, -assignee, assignee, -is_resolved, is_resolved. Default is -timeframe_start. | Optional | 
| status | The status of the threats to return. Possible values are: open, resolved, in_progress. | Optional | 
| ttp_id | The TTP ID of the threats to return. | Optional | 
| title | The title of the threats to return. | Optional | 
| severity | The severity of the threats to return. Possible values are: low, medium, high. | Optional | 
| cloud_provider | The provider of the threats to return. Possible values are: aws, azure, gcp, okta, huawei. | Optional | 
| entity_type | The entity type of the threats to return. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gem.ThreatsList.accounts.account_status | String | Indicates the current status of the account \(e.g., active, suspended\). | 
| Gem.ThreatsList.accounts.cloud_provider | String | Specifies the cloud service provider for the account \(e.g., AWS, Azure\). | 
| Gem.ThreatsList.accounts.display_name | String | The display name associated with the account. | 
| Gem.ThreatsList.accounts.hierarchy_path.id | String | Unique identifier within the account hierarchy path. | 
| Gem.ThreatsList.accounts.hierarchy_path.name | String | Name designation within the account hierarchy path. | 
| Gem.ThreatsList.accounts.id | Number | The unique numerical identifier for the account. | 
| Gem.ThreatsList.accounts.identifier | String | An alternative identifier for the account. | 
| Gem.ThreatsList.accounts.organization_name | String | The name of the organization to which the account belongs. | 
| Gem.ThreatsList.alert_source | String | The source of the alert. | 
| Gem.ThreatsList.alerts.accounts.account_status | String | Indicates the account status related to a specific alert. | 
| Gem.ThreatsList.alerts.accounts.cloud_provider | String | Cloud provider associated with the alert's account. | 
| Gem.ThreatsList.alerts.accounts.display_name | String | Display name of the account related to the alert. | 
| Gem.ThreatsList.alerts.accounts.id | Number | Numerical identifier for the account associated with the alert. | 
| Gem.ThreatsList.alerts.accounts.identifier | String | Identifier for the account related to the alert. | 
| Gem.ThreatsList.alerts.accounts.organization_name | String | Organization name associated with the alert's account. | 
| Gem.ThreatsList.alerts.alert_source | String | The source of individual alerts. | 
| Gem.ThreatsList.alerts.datetime | Date | The date and time when the alert was generated. | 
| Gem.ThreatsList.alerts.description | String | Description of the alert. | 
| Gem.ThreatsList.alerts.entities.activity_by_provider | Unknown | Details about activity by the cloud provider in relation to the alert. | 
| Gem.ThreatsList.alerts.entities.cloud_provider | String | Cloud provider related to the alert entities. | 
| Gem.ThreatsList.alerts.entities.id | String | Unique identifier for the entities related to the alert. | 
| Gem.ThreatsList.alerts.entities.is_main_entity | Boolean | Indicates if the entity is the primary subject of the alert. | 
| Gem.ThreatsList.alerts.entities.is_secondary_entity | Boolean | Indicates if the entity is a secondary subject of the alert. | 
| Gem.ThreatsList.alerts.entities.resource_id | Unknown | Identifier for the resources involved in the alert. | 
| Gem.ThreatsList.alerts.entities.type | String | Type of entities involved in the alert. | 
| Gem.ThreatsList.alerts.id | String | Unique identifier for the alert. | 
| Gem.ThreatsList.alerts.main_alert_id | String | Identifier for the primary alert, if applicable. | 
| Gem.ThreatsList.alerts.mitre_techniques.id | String | Identifier for the MITRE ATT&amp;CK technique associated with the alert. | 
| Gem.ThreatsList.alerts.mitre_techniques.technique_name | String | Name of the MITRE ATT&amp;CK technique related to the alert. | 
| Gem.ThreatsList.alerts.organization_id | String | Identifier for the organization associated with the alert. | 
| Gem.ThreatsList.alerts.severity | Number | Numerical representation of the alert's severity. | 
| Gem.ThreatsList.alerts.severity_text | String | Textual description of the alert's severity. | 
| Gem.ThreatsList.alerts.status | String | Current status of the alert \(e.g., open, resolved. in_progress\). | 
| Gem.ThreatsList.alerts.title | String | Title or summary of the alert. | 
| Gem.ThreatsList.alerts.ttp_id | String | Identifier for the tactics, techniques, and procedures \(TTP\) related to the alert. | 
| Gem.ThreatsList.assignees | Unknown | Information about who is assigned to address the threats. | 
| Gem.ThreatsList.category | String | Classification or category of the threat. | 
| Gem.ThreatsList.datetime | Date | The date and time when the threat was identified or logged. | 
| Gem.ThreatsList.description | String | Detailed description of the threat. | 
| Gem.ThreatsList.entities.activity_by_provider | Unknown | Details about the activity conducted by the cloud provider in relation to the threat. | 
| Gem.ThreatsList.entities.cloud_provider | String | Cloud service provider associated with the entities in the threat. | 
| Gem.ThreatsList.entities.id | String | Unique identifier for the entities involved in the threat. | 
| Gem.ThreatsList.entities.is_main_entity | Boolean | Indicates if the entity is the primary focus of the threat. | 
| Gem.ThreatsList.entities.is_secondary_entity | Boolean | Indicates if the entity plays a secondary role in the context of the threat. | 
| Gem.ThreatsList.entities.resource_id | Unknown | Identifier for the resources targeted or involved in the threat. | 
| Gem.ThreatsList.entities.type | String | Type or nature of the entities involved in the threat. | 
| Gem.ThreatsList.id | String | Unique identifier for the threat list item. | 
| Gem.ThreatsList.main_alert_id | String | Main alert identifier related to the threat. | 
| Gem.ThreatsList.mitre_techniques.id | String | Identifier for MITRE ATT&amp;CK techniques associated with the threat. | 
| Gem.ThreatsList.mitre_techniques.technique_name | String | Name of the MITRE ATT&amp;CK technique associated with the threat. | 
| Gem.ThreatsList.organization_id | String | Identifier of the organization associated with the threat. | 
| Gem.ThreatsList.severity_text | String | Textual description of the overall severity of the threat. | 
| Gem.ThreatsList.status | String | Current status of the threat \(e.g., active, resolved\). | 
| Gem.ThreatsList.title | String | Title or main description of the threat. | 
| Gem.ThreatsList.ttp_id | String | Identifier for the tactics, techniques, and procedures \(TTP\) associated with the threat. | 

### gem-get-threat-details

***
Get details about a specific threat.

#### Base Command

`gem-get-threat-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threat_id | The ID of the threat to get details for. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gem.Threat.accounts.account_status | String | Indicates the current status of the account \(e.g., active, suspended\). | 
| Gem.Threat.accounts.cloud_provider | String | Specifies the cloud service provider for the account \(e.g., AWS, Azure\). | 
| Gem.Threat.accounts.display_name | String | The display name associated with the account. | 
| Gem.Threat.accounts.hierarchy_path.id | String | Unique identifier within the account hierarchy path. | 
| Gem.Threat.accounts.hierarchy_path.name | String | Name designation within the account hierarchy path. | 
| Gem.Threat.accounts.id | Number | The unique numerical identifier for the account. | 
| Gem.Threat.accounts.identifier | String | An alternative identifier for the account. | 
| Gem.Threat.accounts.organization_name | String | The name of the organization to which the account belongs. | 
| Gem.Threat.alert_source | String | The source of the alert. | 
| Gem.Threat.alerts.accounts.account_status | String | Indicates the account status related to a specific alert. | 
| Gem.Threat.alerts.accounts.cloud_provider | String | Cloud provider associated with the alert's account. | 
| Gem.Threat.alerts.accounts.display_name | String | Display name of the account related to the alert. | 
| Gem.Threat.alerts.accounts.id | Number | Numerical identifier for the account associated with the alert. | 
| Gem.Threat.alerts.accounts.identifier | String | Identifier for the account related to the alert. | 
| Gem.Threat.alerts.accounts.organization_name | String | Organization name associated with the alert's account. | 
| Gem.Threat.alerts.alert_source | String | The source of individual alerts. | 
| Gem.Threat.alerts.datetime | Date | The date and time when the alert was generated. | 
| Gem.Threat.alerts.description | String | Description of the alert. | 
| Gem.Threat.alerts.entities.activity_by_provider | Unknown | Details about activity by the cloud provider in relation to the alert. | 
| Gem.Threat.alerts.entities.cloud_provider | String | Cloud provider related to the alert entities. | 
| Gem.Threat.alerts.entities.id | String | Unique identifier for the entities related to the alert. | 
| Gem.Threat.alerts.entities.is_main_entity | Boolean | Indicates if the entity is the primary subject of the alert. | 
| Gem.Threat.alerts.entities.is_secondary_entity | Boolean | Indicates if the entity is a secondary subject of the alert. | 
| Gem.Threat.alerts.entities.resource_id | Unknown | Identifier for the resources involved in the alert. | 
| Gem.Threat.alerts.entities.type | String | Type of entities involved in the alert. | 
| Gem.Threat.alerts.id | String | Unique identifier for the alert. | 
| Gem.Threat.alerts.main_alert_id | String | Identifier for the primary alert, if applicable. | 
| Gem.Threat.alerts.mitre_techniques.id | String | Identifier for the MITRE ATT&amp;CK technique associated with the alert. | 
| Gem.Threat.alerts.mitre_techniques.technique_name | String | Name of the MITRE ATT&amp;CK technique related to the alert. | 
| Gem.Threat.alerts.organization_id | String | Identifier for the organization associated with the alert. | 
| Gem.Threat.alerts.severity | Number | Numerical representation of the alert's severity. | 
| Gem.Threat.alerts.severity_text | String | Textual description of the alert's severity. | 
| Gem.Threat.alerts.status | String | Current status of the alert \(e.g., open, resolved. in_progress\). | 
| Gem.Threat.alerts.title | String | Title or summary of the alert. | 
| Gem.Threat.alerts.ttp_id | String | Identifier for the tactics, techniques, and procedures \(TTP\) related to the alert. | 
| Gem.Threat.assignees | Unknown | Information about who is assigned to address the threats. | 
| Gem.Threat.category | String | Classification or category of the threat. | 
| Gem.Threat.datetime | Date | The date and time when the threat was identified or logged. | 
| Gem.Threat.description | String | Detailed description of the threat. | 
| Gem.Threat.entities.activity_by_provider | Unknown | Details about the activity conducted by the cloud provider in relation to the threat. | 
| Gem.Threat.entities.cloud_provider | String | Cloud service provider associated with the entities in the threat. | 
| Gem.Threat.entities.id | String | Unique identifier for the entities involved in the threat. | 
| Gem.Threat.entities.is_main_entity | Boolean | Indicates if the entity is the primary focus of the threat. | 
| Gem.Threat.entities.is_secondary_entity | Boolean | Indicates if the entity plays a secondary role in the context of the threat. | 
| Gem.Threat.entities.resource_id | Unknown | Identifier for the resources targeted or involved in the threat. | 
| Gem.Threat.entities.type | String | Type or nature of the entities involved in the threat. | 
| Gem.Threat.id | String | Unique identifier for the threat list item. | 
| Gem.Threat.main_alert_id | String | Main alert identifier related to the threat. | 
| Gem.Threat.mitre_techniques.id | String | Identifier for MITRE ATT&amp;CK techniques associated with the threat. | 
| Gem.Threat.mitre_techniques.technique_name | String | Name of the MITRE ATT&amp;CK technique associated with the threat. | 
| Gem.Threat.organization_id | String | Identifier of the organization associated with the threat. | 
| Gem.Threat.severity_text | String | Textual description of the overall severity of the threat. | 
| Gem.Threat.status | String | Current status of the threat \(e.g., active, resolved\). | 
| Gem.Threat.title | String | Title or main description of the threat. | 
| Gem.Threat.ttp_id | String | Identifier for the tactics, techniques, and procedures \(TTP\) associated with the threat. | 

### gem-get-alert-details

***
Get details about a specific alert.

#### Base Command

`gem-get-alert-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The ID of the alert to get details for. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gem.Alert.alert_context.account_db_id | String | Database identifier for the account associated with the alert. | 
| Gem.Alert.alert_context.alert_id | String | Unique identifier for the alert. | 
| Gem.Alert.alert_context.alert_source | String | The source from which the alert originated. | 
| Gem.Alert.alert_context.alert_source_id | String | Identifier for the specific source of the alert. | 
| Gem.Alert.alert_context.alert_source_url | String | URL associated with the alert source. | 
| Gem.Alert.alert_context.cloud_provider | String | The cloud service provider associated with the alert. | 
| Gem.Alert.alert_context.created_at | Date | The timestamp when the alert was created. | 
| Gem.Alert.alert_context.description | String | Detailed description of the alert. | 
| Gem.Alert.alert_context.description_template | String | Template used for generating the alert description. | 
| Gem.Alert.alert_context.general_cloud_provider | String | General classification of the cloud provider related to the alert. | 
| Gem.Alert.alert_context.mitre_techniques.id | String | Identifier for the MITRE ATT&amp;CK technique associated with the alert. | 
| Gem.Alert.alert_context.mitre_techniques.technique_name | String | Name of the MITRE ATT&amp;CK technique related to the alert. | 
| Gem.Alert.alert_context.resolved | Boolean | Indicates whether the alert has been resolved. | 
| Gem.Alert.alert_context.severity | Number | Numerical representation of the alert's severity. | 
| Gem.Alert.alert_context.status | String | Current status of the alert \(e.g., open, resolved, in_progress\). | 
| Gem.Alert.alert_context.timeframe_end | Date | End date and time of the timeframe relevant to the alert. | 
| Gem.Alert.alert_context.timeframe_start | Date | Start date and time of the timeframe relevant to the alert. | 
| Gem.Alert.alert_context.title | String | Title or main description of the alert. | 
| Gem.Alert.alert_context.ttp_id | String | Identifier for the tactics, techniques, and procedures \(TTP\) related to the alert. | 
| Gem.Alert.triage_configuration.analysis | String | Analysis or summary of the triage configuration for the alert. | 
| Gem.Alert.triage_configuration.entities.activity_by_provider | String | Activity details by the cloud provider related to the triage entities. | 
| Gem.Alert.triage_configuration.entities.cloud_provider | String | Cloud provider associated with the triage entities. | 
| Gem.Alert.triage_configuration.entities.id | String | Unique identifier for the entities involved in the triage. | 
| Gem.Alert.triage_configuration.entities.is_main_entity | Boolean | Indicates if the entity is the primary focus in the triage. | 
| Gem.Alert.triage_configuration.entities.is_secondary_entity | Boolean | Indicates if the entity plays a secondary role in the triage. | 
| Gem.Alert.triage_configuration.entities.resource_id | String | Resource identifier associated with the triage entities. | 
| Gem.Alert.triage_configuration.entities.type | String | Type or nature of the entities involved in the triage. | 
| Gem.Alert.triage_configuration.event_groups.description | String | Description of the event groups involved in the triage. | 
| Gem.Alert.triage_configuration.event_groups.end_time | Date | End time for the event groups in the triage. | 
| Gem.Alert.triage_configuration.event_groups.error_code | String | Error code associated with the event groups in the triage. | 
| Gem.Alert.triage_configuration.event_groups.event_name | String | Name of the specific event within the event group related to the triage. | 
| Gem.Alert.triage_configuration.event_groups.event_type | String | Type or category of the event within the event group. | 
| Gem.Alert.triage_configuration.event_groups.events | String | Details of the events that are part of the event group in the triage. | 
| Gem.Alert.triage_configuration.event_groups.start_time | Date | Start time for the event groups involved in the triage. | 
| Gem.Alert.triage_configuration.event_groups.time_indicator_text | String | Textual indicator of the time relevant to the event groups in the triage. | 
| Gem.Alert.triage_configuration.event_groups.timeline_item_type | String | Type of timeline item represented by the event groups in the triage. | 
| Gem.Alert.triage_configuration.event_groups.title | String | Title or main description of the event groups in the triage. | 
| Gem.Alert.triage_configuration.event_groups.type | String | Overall type or classification of the event groups in the triage. | 
| Gem.Alert.triage_configuration.resolve_params.include_data_events | Boolean | Indicates whether data events should be included in the resolution process. | 
| Gem.Alert.triage_configuration.resolve_params.timeframe_lookup_window_hours | Number | Number of hours in the lookup window for timeframe analysis in the resolution process. | 
| Gem.Alert.triage_configuration.state | String | Current state or status of the triage configuration for the alert. | 

### gem-list-inventory-resources

***
List inventory resources in Gem.

#### Base Command

`gem-list-inventory-resources`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The number of items to return. Default is 50. | Optional | 
| include_deleted | Include deleted resources in the response. | Optional | 
| region | The region of the resources to return. | Optional | 
| resource_type | The type of the resources to return. | Optional | 
| search | The search query to use. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gem.InventoryItems.account.account_status | String | Current status of the account associated with the inventory item \(e.g., active, suspended\). | 
| Gem.InventoryItems.account.cloud_provider | String | Name of the cloud service provider for the account associated with the inventory item. | 
| Gem.InventoryItems.account.display_name | String | Display name of the account associated with the inventory item. | 
| Gem.InventoryItems.account.hierarchy_path | String | Hierarchical path in the account structure associated with the inventory item. | 
| Gem.InventoryItems.account.id | Number | Unique numerical identifier for the account associated with the inventory item. | 
| Gem.InventoryItems.account.identifier | String | Alternative identifier for the account associated with the inventory item. | 
| Gem.InventoryItems.account.organization_name | String | Name of the organization to which the account associated with the inventory item belongs. | 
| Gem.InventoryItems.account.tenant | String | Tenant information for the account associated with the inventory item in a multi-tenant environment. | 
| Gem.InventoryItems.categories | String | Categories or types assigned to the inventory item. | 
| Gem.InventoryItems.created_at | Date | Timestamp indicating when the inventory item was created. | 
| Gem.InventoryItems.deleted | Boolean | Indicates whether the inventory item has been marked as deleted. | 
| Gem.InventoryItems.external_url | String | URL linking to external information or resources related to the inventory item. | 
| Gem.InventoryItems.identifiers.name | String | Name associated with the identifier of the inventory item. | 
| Gem.InventoryItems.identifiers.value | String | Value of the identifier assigned to the inventory item. | 
| Gem.InventoryItems.region | String | Geographic region associated with the inventory item. | 
| Gem.InventoryItems.resource_id | String | Unique identifier for the resource that the inventory item represents. | 
| Gem.InventoryItems.resource_type | String | Type of resource that the inventory item represents \(e.g., VM, database\). | 
| Gem.InventoryItems.tags | String | Tags or labels assigned to the inventory item for categorization or identification. | 

### gem-get-resource-details

***
Get details about a specific resource.

#### Base Command

`gem-get-resource-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_id | The ID of the resource to get details for. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gem.InventoryItem.account.account_status | String | Current status of the account associated with the inventory item \(e.g., active, suspended\). | 
| Gem.InventoryItem.account.cloud_provider | String | Name of the cloud service provider for the account associated with the inventory item. | 
| Gem.InventoryItem.account.display_name | String | Display name of the account associated with the inventory item. | 
| Gem.InventoryItem.account.hierarchy_path | String | Hierarchical path in the account structure associated with the inventory item. | 
| Gem.InventoryItem.account.id | Number | Unique numerical identifier for the account associated with the inventory item. | 
| Gem.InventoryItem.account.identifier | String | Alternative identifier for the account associated with the inventory item. | 
| Gem.InventoryItem.account.organization_name | String | Name of the organization to which the account associated with the inventory item belongs. | 
| Gem.InventoryItem.account.tenant | String | Tenant information for the account associated with the inventory item in a multi-tenant environment. | 
| Gem.InventoryItem.categories | String | Categories or types assigned to the inventory item. | 
| Gem.InventoryItem.created_at | Date | Timestamp indicating when the inventory item was created. | 
| Gem.InventoryItem.deleted | Boolean | Indicates whether the inventory item has been marked as deleted. | 
| Gem.InventoryItem.external_url | String | URL linking to external information or resources related to the inventory item. | 
| Gem.InventoryItem.identifiers.name | String | Name associated with the identifier of the inventory item. | 
| Gem.InventoryItem.identifiers.value | String | Value of the identifier assigned to the inventory item. | 
| Gem.InventoryItem.region | String | Geographic region associated with the inventory item. | 
| Gem.InventoryItem.resource_id | String | Unique identifier for the resource that the inventory item represents. | 
| Gem.InventoryItem.resource_type | String | Type of resource that the inventory item represents \(e.g., VM, database\). | 

### gem-list-ips-by-entity

***
List all source IP addresses used by an entity in a specific timeframe. The results are sorted by activity volume.

#### Base Command

`gem-list-ips-by-entity`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_id | Gem ID of the entity. This will usually be the ARN or CSP ID. This property is also available for every resource in the Inventory screen. Example: arn:aws:ec2:us-east-1:112233445566:instance/i-1234567890abcdefg. | Required | 
| entity_type | Type of the entity. See documentation for the full options list. | Required | 
| read_only | Show read-only events. | Optional | 
| start_time | Timeframe start (ISO format). Examples: 2023-01-01, 2023-01-01T01:01:01Z, 2023-01-01T01:01:01+00:00. | Required | 
| end_time | Timeframe end (ISO format). Examples: 2023-01-01, 2023-01-01T01:01:01Z, 2023-01-01T01:01:01+00:00. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gem.IP.AS_NAME | String | Name of the Autonomous System \(AS\) associated with the IP address. | 
| Gem.IP.AS_NUMBER | String | Number of the Autonomous System \(AS\) associated with the IP address. | 
| Gem.IP.CITY | String | City where the IP address is located. | 
| Gem.IP.COUNTRY_CODE | String | Country code corresponding to the location of the IP address. | 
| Gem.IP.COUNTRY_NAME | String | Name of the country where the IP address is located. | 
| Gem.IP.COUNT_SOURCEIP | String | Count of occurrences or references to the source IP address. | 
| Gem.IP.IP_TYPE | String | Type of the IP address \(e.g., IPv4, IPv6\). | 
| Gem.IP.IS_PRIVATE | String | Indicates whether the IP address is private \(e.g., within a local network\). | 
| Gem.IP.LATITUDE | String | Latitude coordinate of the IP address's location. | 
| Gem.IP.LONGITUDE | String | Longitude coordinate of the IP address's location. | 
| Gem.IP.PROVIDER | String | Internet service provider associated with the IP address. | 
| Gem.IP.SOURCEIPADDRESS | String | The actual IP address being referenced or analyzed. | 

### gem-list-services-by-entity

***
List all services accessed by an entity in a specific timeframe. The results are sorted by activity volume.

#### Base Command

`gem-list-services-by-entity`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_id | Gem ID of the entity. This will usually be the ARN or CSP ID. This property is also available for every resource in the Inventory screen. Example: arn:aws:ec2:us-east-1:112233445566:instance/i-1234567890abcdefg. | Required | 
| entity_type | Type of the entity. See documentation for the full options list. | Required | 
| read_only | Show read-only events. | Optional | 
| start_time | Timeframe start (ISO format). Examples: 2023-01-01, 2023-01-01T01:01:01Z, 2023-01-01T01:01:01+00:00. | Required | 
| end_time | Timeframe end (ISO format). Examples: 2023-01-01, 2023-01-01T01:01:01Z, 2023-01-01T01:01:01+00:00. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gem.Entity.By.Services.COUNT_SERVICE | String | Number of times the specified service appears or is utilized within the context. | 
| Gem.Entity.By.Services.SERVICE | String | Name or type of the service being referenced or analyzed. | 

### gem-list-events-by-entity

***
List all events performed by an entity in a specific timeframe. The results are sorted by activity volume.

#### Base Command

`gem-list-events-by-entity`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_id | Gem ID of the entity. This will usually be the ARN or CSP ID. This property is also available for every resource in the Inventory screen. Example: arn:aws:ec2:us-east-1:112233445566:instance/i-1234567890abcdefg. | Required | 
| entity_type | Type of the entity. See documentation for the full options list. | Required | 
| read_only | Show read-only events. | Optional | 
| start_time | Timeframe start (ISO format). Examples: 2023-01-01, 2023-01-01T01:01:01Z, 2023-01-01T01:01:01+00:00. | Required | 
| end_time | Timeframe end (ISO format). Examples: 2023-01-01, 2023-01-01T01:01:01Z, 2023-01-01T01:01:01+00:00. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gem.Entity.By.Events.EVENTNAME | String | Name of the event being referenced or analyzed. | 
| Gem.Entity.By.Events.EVENTNAME_COUNT | String | Count of occurrences or references to the specified event name. | 

### gem-list-accessing-entities

***
List all entities that accessed an entity in a specific timeframe. The results are sorted by activity volume.

#### Base Command

`gem-list-accessing-entities`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_id | Gem ID of the entity. This will usually be the ARN or CSP ID. This property is also available for every resource in the Inventory screen. Example: arn:aws:ec2:us-east-1:112233445566:instance/i-1234567890abcdefg. | Required | 
| entity_type | Type of the entity. See documentation for the full options list. | Required | 
| read_only | Show read-only events. | Optional | 
| start_time | Timeframe start (ISO format). Examples: 2023-01-01, 2023-01-01T01:01:01Z, 2023-01-01T01:01:01+00:00. | Required | 
| end_time | Timeframe end (ISO format). Examples: 2023-01-01, 2023-01-01T01:01:01Z, 2023-01-01T01:01:01+00:00. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gem.Entity.Accessing.USER_COUNT | String | Number of users accessing or interacting with the entity. | 
| Gem.Entity.Accessing.USER_ID | String | Identifier\(s\) of the user\(s\) accessing or interacting with the entity. | 

### gem-list-using-entities

***
List all entities that used an entity in a specific timeframe. The results are sorted by activity volume.

#### Base Command

`gem-list-using-entities`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_id | Gem ID of the entity. This will usually be the ARN or CSP ID. This property is also available for every resource in the Inventory screen. Example: arn:aws:ec2:us-east-1:112233445566:instance/i-1234567890abcdefg. | Required | 
| entity_type | Type of the entity. See documentation for the full options list. | Required | 
| read_only | Show read-only events. | Optional | 
| start_time | Timeframe start (ISO format). Examples: 2023-01-01, 2023-01-01T01:01:01Z, 2023-01-01T01:01:01+00:00. | Required | 
| end_time | Timeframe end (ISO format). Examples: 2023-01-01, 2023-01-01T01:01:01Z, 2023-01-01T01:01:01+00:00. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gem.Entity.Using.ENTITY_COUNT | String | Count of the number of times the entity is used or referenced. | 
| Gem.Entity.Using.ENTITY_ID | String | Unique identifier for the entity being used or referenced. | 

### gem-list-events-on-entity

***
List all events performed on an entity in a specific timeframe. The results are sorted by activity volume.

#### Base Command

`gem-list-events-on-entity`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_id | Gem ID of the entity. This will usually be the ARN or CSP ID. This property is also available for every resource in the Inventory screen. Example: arn:aws:ec2:us-east-1:112233445566:instance/i-1234567890abcdefg. | Required | 
| entity_type | Type of the entity. See documentation for the full options list. | Required | 
| read_only | Show read-only events. | Optional | 
| start_time | Timeframe start (ISO format). Examples: 2023-01-01, 2023-01-01T01:01:01Z, 2023-01-01T01:01:01+00:00. | Required | 
| end_time | Timeframe end (ISO format). Examples: 2023-01-01, 2023-01-01T01:01:01Z, 2023-01-01T01:01:01+00:00. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gem.Entity.On.Events.EVENTNAME | String | Name of the event associated with the entity. | 
| Gem.Entity.On.Events.EVENTNAME_COUNT | String | Count of occurrences or instances of the specified event name related to the entity. | 

### gem-list-accessing-ips

***
List all source IP addresses that accessed an entity in a specific timeframe. The results are sorted by activity volume.

#### Base Command

`gem-list-accessing-ips`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_id | Gem ID of the entity. This will usually be the ARN or CSP ID. This property is also available for every resource in the Inventory screen. Example: arn:aws:ec2:us-east-1:112233445566:instance/i-1234567890abcdefg. | Required | 
| entity_type | Type of the entity. See documentation for the full options list. | Required | 
| read_only | Show read-only events. | Optional | 
| start_time | Timeframe start (ISO format). Examples: 2023-01-01, 2023-01-01T01:01:01Z, 2023-01-01T01:01:01+00:00. | Required | 
| end_time | Timeframe end (ISO format). Examples: 2023-01-01, 2023-01-01T01:01:01Z, 2023-01-01T01:01:01+00:00. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gem.Entity.Accessing.IPs.AS_NAME | String | Name of the Autonomous System \(AS\) associated with the IP address accessing the entity. | 
| Gem.Entity.Accessing.IPs.AS_NUMBER | String | Number of the Autonomous System \(AS\) associated with the IP address accessing the entity. | 
| Gem.Entity.Accessing.IPs.CITY | String | City where the IP address accessing the entity is located. | 
| Gem.Entity.Accessing.IPs.COUNTRY_CODE | String | Country code corresponding to the location of the IP address accessing the entity. | 
| Gem.Entity.Accessing.IPs.COUNTRY_NAME | String | Name of the country where the IP address accessing the entity is located. | 
| Gem.Entity.Accessing.IPs.COUNT_SOURCEIP | String | Count of occurrences or references to the source IP address accessing the entity. | 
| Gem.Entity.Accessing.IPs.IP_TYPE | String | Type of the IP address \(e.g., IPv4, IPv6\) accessing the entity. | 
| Gem.Entity.Accessing.IPs.IS_PRIVATE | String | Indicates whether the IP address accessing the entity is private \(e.g., within a local network\). | 
| Gem.Entity.Accessing.IPs.LATITUDE | String | Latitude coordinate of the IP address's location accessing the entity. | 
| Gem.Entity.Accessing.IPs.LONGITUDE | String | Longitude coordinate of the IP address's location accessing the entity. | 
| Gem.Entity.Accessing.IPs.PROVIDER | String | Internet service provider associated with the IP address accessing the entity. | 
| Gem.Entity.Accessing.IPs.SOURCEIPADDRESS | String | The actual IP address being referenced or analyzed that is accessing the entity. | 

### gem-update-threat-status

***
Set a threat's status to open, in progress or resolved.

#### Base Command

`gem-update-threat-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threat_id | The ID of the threat to update. | Required | 
| status | The new status of the threat (open, in_progress, resolved). Possible values are: open, in_progress, resolved. | Required | 
| verdict | The verdict of the threat. Possible values are: malicious, security_test, planned_action, not_malicious, inconclusive. | Optional | 
| reason | The reason for resolving the threat. | Optional | 

#### Context Output

There is no context output for this command.

### gem-run-action

***
Run an action on an entity.

#### Base Command

`gem-run-action`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | The action to run. | Required | 
| entity_id | The ID of the entity to run the action on. | Required | 
| entity_type | The type of the entity to run the action on. | Required | 
| alert_id | The ID of the alert to run the action on. | Required | 
| resource_id | The ID of the resource to run the action on. | Required | 

#### Context Output

There is no context output for this command.

### gem-add-timeline-event

***
Add a timeline event to a threat.

#### Base Command

`gem-add-timeline-event`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threat_id | The ID of the threat to add the timeline event to. | Required | 
| comment | The comment to add to the timeline event. | Required | 

#### Context Output

There is no context output for this command.