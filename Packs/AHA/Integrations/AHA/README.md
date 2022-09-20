## Configure AHA on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for AHA.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Your server URL |  | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Api Key | API Key to access service REST API  | True |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### aha-get-features
***
will get all features from service


#### Base Command

`aha-get-features`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from_date | Get features from a date. Possible values are: YYYY-MM-DD. Default is 2020-01-01. | Optional | 


#### Context Output

|created_at|id|name|product_id|reference_num|resource|url|
|---|---|---|---|---|---|---|
| 2022-09-11T09:11:33.044Z | 7142047390424612198 | Share places of interest in Italy | 7142047389388652071 | DEMO-30 | https://example.com.aha.io/api/v1/features/DEMO-30 | https://example.com.aha.io/features/DEMO-30 |
#### Command Example 

```!aha-get-features```
```!aha-get-features from_date=2020-01-01```
### aha-get-feature
***
returns a specific feature


#### Base Command

`aha-get-feature`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| feature_name | Get a feature with the name specified. Possible values are: "feature_name". | Required | 


#### Context Output

|assigned_to_user|attachments|belongs_to_release_phase|comments_count|created_at|created_by_user|custom_fields|description|due_date|epic_reference_num|feature_links|feature_only_original_estimate|feature_only_remaining_estimate|feature_only_work_done|full_tags|goals|id|initiative|initiative_reference_num|integration_fields|name|position|product_id|progress|progress_source|reference_num|release|release_reference_num|requirements|resource|score|score_facts|start_date|status_changed_on|tags|updated_at|url|workflow_kind|workflow_status|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
|  |  | id: 7142047392916283333<br>name: Define included features<br>start_on: 2022-09-05<br>end_on: 2022-09-07<br>type: phase<br>release_id: 7142047392704264269<br>created_at: 2022-09-11T09:11:33.213Z<br>updated_at: 2022-09-20T08:48:10.220Z<br>progress: 0<br>progress_source: progress_from_todos<br>duration_source: duration_manual<br>description: {"id": "7142047392942881656", "body": "", "created_at": "2022-09-11T09:11:33.215Z", "attachments": []} | 0 | 2022-09-11T09:11:33.224Z | id: 7142047370286614216<br>name: User<br>email: user@email.com<br>created_at: 2022-09-11T09:11:26.224Z<br>updated_at: 2022-09-14T10:23:24.795Z |  | id: 7142047393165357275<br>body: <p>ddesc</p><br>created_at: 2022-09-11T09:11:33.226Z<br>attachments:  |  |  |  |  |  |  |  | {'id': '7142047387627910934', 'name': 'Most used mobile apps', 'url': 'https://example.com.aha.io/strategic_imperatives/7142047387627910934', 'resource': 'https://example.com.aha.io/api/v1/goals/7142047387627910934', 'created_at': '2022-09-11T09:11:30.399Z', 'description': {'id': '7142047387664021169', 'body': '<p>Increase mobile app downloads to 100,000 total.</p>', 'created_at': '2022-09-11T09:11:30.401Z', 'attachments': []}} | 7142047393121670680 | id: 7142047389806640688<br>reference_num: DEMO-S-3<br>name: Mobile Fredwin Cycling Tracker App upgrades<br>url: https://example.com.aha.io/initiatives/DEMO-S-3<br>resource: https://example.com.aha.io/api/v1/initiatives/DEMO-S-3<br>created_at: 2022-09-11T09:11:33.031Z<br>description: {"id": "7142047389835002618", "body": "<p></p>", "created_at": "2022-09-11T09:11:33.033Z", "attachments": []}<br>integration_fields:  | DEMO-S-3 |  | nname | 3 | 7142047389388652071 |  | progress_manual | DEMO-10 | id: 7142047392704264269<br>reference_num: DEMO-R-3<br>name: iOS v4.23 Release<br>start_date: 2022-09-02<br>release_date: 2022-10-05<br>parking_lot: false<br>created_at: 2022-09-11T09:11:33.199Z<br>product_id: 7142047389388652071<br>integration_fields: <br>url: https://example.com.aha.io/releases/DEMO-R-3<br>resource: https://example.com.aha.io/api/v1/releases/DEMO-R-3<br>owner: {"id": "7142047370286614216", "name": "User", "email": "user@email.com", "created_at": "2022-09-11T09:11:26.224Z", "updated_at": "2022-09-14T10:23:24.795Z"}<br>project: {"id": "7142047389388652071", "reference_prefix": "DEMO", "name": "Fredwin Cycling Product (Demo)", "product_line": false, "created_at": "2022-09-11T09:11:33.020Z", "workspace_type": "product_workspace"} | DEMO-R-3 |  | https://example.com.aha.io/api/v1/features/DEMO-10 | 19 | {'id': '7142047393179266454', 'value': 10, 'name': 'PR/Marketing'},<br>{'id': '7142047393169519956', 'value': 9, 'name': 'Retention of customers'},<br>{'id': '7142047393173908761', 'value': 0, 'name': 'Operational efficiencies'},<br>{'id': '7142047393173803796', 'value': 6, 'name': 'Effort to develop (subtracted)'},<br>{'id': '7142047393162383661', 'value': 6, 'name': 'Sales increase'} |  | 2022-09-20 |  | 2022-09-20T08:48:10.212Z | https://example.com.aha.io/features/DEMO-10 | id: 7142047373244952991<br>name: New | id: 7142047373292237665<br>name: Closed<br>position: 6<br>complete: true<br>color: #689f3b |
#### Command Example 

```!aha-get-feature feature_name=DEMO-10 ```

### aha-edit-feature
***
change value of a field in feature


#### Base Command

`aha-edit-feature`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| feature_name | Select features to edit. Possible values are: . | Required | 
| fields | Possible Fields to edit in a feature are name, description and status.
Status values should match the customized status in workflow_status of your Aha! service.
Write fields in json format.
| Required | 


#### Context Output

|assigned_to_user|attachments|belongs_to_release_phase|comments_count|created_at|created_by_user|custom_fields|description|due_date|epic_reference_num|feature_links|feature_only_original_estimate|feature_only_remaining_estimate|feature_only_work_done|full_tags|goals|id|initiative|initiative_reference_num|integration_fields|name|position|product_id|progress|progress_source|reference_num|release|release_reference_num|requirements|resource|score|score_facts|start_date|status_changed_on|tags|updated_at|url|workflow_kind|workflow_status|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
|  |  | id: 7142047392916283333<br>name: Define included features<br>start_on: 2022-09-05<br>end_on: 2022-09-07<br>type: phase<br>release_id: 7142047392704264269<br>created_at: 2022-09-11T09:11:33.213Z<br>updated_at: 2022-09-20T12:41:15.535Z<br>progress: 0<br>progress_source: progress_from_todos<br>duration_source: duration_manual<br>description: {"id": "7142047392942881656", "body": "", "created_at": "2022-09-11T09:11:33.215Z", "attachments": []} | 0 | 2022-09-11T09:11:33.224Z | id: 7142047370286614216<br>name: User<br>email: user@email.com<br>created_at: 2022-09-11T09:11:26.224Z<br>updated_at: 2022-09-14T10:23:24.795Z |  | id: 7142047393165357275<br>body: ddesc<br>created_at: 2022-09-11T09:11:33.226Z<br>attachments:  |  |  |  |  |  |  |  | {'id': '7142047387627910934', 'name': 'Most used mobile apps', 'url': 'https://example.com.aha.io/strategic_imperatives/7142047387627910934', 'resource': 'https://example.com.aha.io/api/v1/goals/7142047387627910934', 'created_at': '2022-09-11T09:11:30.399Z', 'description': {'id': '7142047387664021169', 'body': '<p>Increase mobile app downloads to 100,000 total.</p>', 'created_at': '2022-09-11T09:11:30.401Z', 'attachments': []}} | 7142047393121670680 | id: 7142047389806640688<br>reference_num: DEMO-S-3<br>name: Mobile Fredwin Cycling Tracker App upgrades<br>url: https://example.com.aha.io/initiatives/DEMO-S-3<br>resource: https://example.com.aha.io/api/v1/initiatives/DEMO-S-3<br>created_at: 2022-09-11T09:11:33.031Z<br>description: {"id": "7142047389835002618", "body": "<p></p>", "created_at": "2022-09-11T09:11:33.033Z", "attachments": []}<br>integration_fields:  | DEMO-S-3 |  | nname | 3 | 7142047389388652071 |  | progress_manual | DEMO-10 | id: 7142047392704264269<br>reference_num: DEMO-R-3<br>name: iOS v4.23 Release<br>start_date: 2022-09-02<br>release_date: 2022-10-05<br>parking_lot: false<br>created_at: 2022-09-11T09:11:33.199Z<br>product_id: 7142047389388652071<br>integration_fields: <br>url: https://example.com.aha.io/releases/DEMO-R-3<br>resource: https://example.com.aha.io/api/v1/releases/DEMO-R-3<br>owner: {"id": "7142047370286614216", "name": "User", "email": "user@email.com", "created_at": "2022-09-11T09:11:26.224Z", "updated_at": "2022-09-14T10:23:24.795Z"}<br>project: {"id": "7142047389388652071", "reference_prefix": "DEMO", "name": "Fredwin Cycling Product (Demo)", "product_line": false, "created_at": "2022-09-11T09:11:33.020Z", "workspace_type": "product_workspace"} | DEMO-R-3 |  | https://example.com.aha.io/api/v1/features/DEMO-10 | 19 | {'id': '7142047393179266454', 'value': 10, 'name': 'PR/Marketing'},<br>{'id': '7142047393169519956', 'value': 9, 'name': 'Retention of customers'},<br>{'id': '7142047393173908761', 'value': 0, 'name': 'Operational efficiencies'},<br>{'id': '7142047393173803796', 'value': 6, 'name': 'Effort to develop (subtracted)'},<br>{'id': '7142047393162383661', 'value': 6, 'name': 'Sales increase'} |  | 2022-09-20 |  | 2022-09-20T12:41:15.526Z | https://example.com.aha.io/features/DEMO-10 | id: 7142047373244952991<br>name: New | id: 7142047373292237665<br>name: Closed<br>position: 6<br>complete: true<br>color: #689f3b |
#### Command Example

```!aha-edit-feature feature_name=DEMO-10 fields={"name":"name", "description":"desc", "status" : "Closed"}```
### aha-close-feature
***
Sets a feature status to closed


#### Base Command

`aha-close-feature`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| feature_name | Select a specific feature to close. Possible values are: . | Required | 


#### Context Output

|assigned_to_user|attachments|belongs_to_release_phase|comments_count|created_at|created_by_user|custom_fields|description|due_date|epic_reference_num|feature_links|feature_only_original_estimate|feature_only_remaining_estimate|feature_only_work_done|full_tags|goals|id|initiative|initiative_reference_num|integration_fields|name|position|product_id|progress|progress_source|reference_num|release|release_reference_num|requirements|resource|score|score_facts|start_date|status_changed_on|tags|updated_at|url|workflow_kind|workflow_status|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
|  |  | id: 7142047392916283333<br>name: Define included features<br>start_on: 2022-09-05<br>end_on: 2022-09-07<br>type: phase<br>release_id: 7142047392704264269<br>created_at: 2022-09-11T09:11:33.213Z<br>updated_at: 2022-09-20T12:41:22.404Z<br>progress: 0<br>progress_source: progress_from_todos<br>duration_source: duration_manual<br>description: {"id": "7142047392942881656", "body": "", "created_at": "2022-09-11T09:11:33.215Z", "attachments": []} | 0 | 2022-09-11T09:11:33.224Z | id: 7142047370286614216<br>name: User<br>email: user@email.com<br>created_at: 2022-09-11T09:11:26.224Z<br>updated_at: 2022-09-14T10:23:24.795Z |  | id: 7142047393165357275<br>body: ddesc<br>created_at: 2022-09-11T09:11:33.226Z<br>attachments:  |  |  |  |  |  |  |  | {'id': '7142047387627910934', 'name': 'Most used mobile apps', 'url': 'https://example.com.aha.io/strategic_imperatives/7142047387627910934', 'resource': 'https://example.com.aha.io/api/v1/goals/7142047387627910934', 'created_at': '2022-09-11T09:11:30.399Z', 'description': {'id': '7142047387664021169', 'body': '<p>Increase mobile app downloads to 100,000 total.</p>', 'created_at': '2022-09-11T09:11:30.401Z', 'attachments': []}} | 7142047393121670680 | id: 7142047389806640688<br>reference_num: DEMO-S-3<br>name: Mobile Fredwin Cycling Tracker App upgrades<br>url: https://example.com.aha.io/initiatives/DEMO-S-3<br>resource: https://example.com.aha.io/api/v1/initiatives/DEMO-S-3<br>created_at: 2022-09-11T09:11:33.031Z<br>description: {"id": "7142047389835002618", "body": "<p></p>", "created_at": "2022-09-11T09:11:33.033Z", "attachments": []}<br>integration_fields:  | DEMO-S-3 |  | nname | 3 | 7142047389388652071 |  | progress_manual | DEMO-10 | id: 7142047392704264269<br>reference_num: DEMO-R-3<br>name: iOS v4.23 Release<br>start_date: 2022-09-02<br>release_date: 2022-10-05<br>parking_lot: false<br>created_at: 2022-09-11T09:11:33.199Z<br>product_id: 7142047389388652071<br>integration_fields: <br>url: https://example.com.aha.io/releases/DEMO-R-3<br>resource: https://example.com.aha.io/api/v1/releases/DEMO-R-3<br>owner: {"id": "7142047370286614216", "name": "User", "email": "user@email.com", "created_at": "2022-09-11T09:11:26.224Z", "updated_at": "2022-09-14T10:23:24.795Z"}<br>project: {"id": "7142047389388652071", "reference_prefix": "DEMO", "name": "Fredwin Cycling Product (Demo)", "product_line": false, "created_at": "2022-09-11T09:11:33.020Z", "workspace_type": "product_workspace"} | DEMO-R-3 |  | https://example.com.aha.io/api/v1/features/DEMO-10 | 19 | {'id': '7142047393179266454', 'value': 10, 'name': 'PR/Marketing'},<br>{'id': '7142047393169519956', 'value': 9, 'name': 'Retention of customers'},<br>{'id': '7142047393173908761', 'value': 0, 'name': 'Operational efficiencies'},<br>{'id': '7142047393173803796', 'value': 6, 'name': 'Effort to develop (subtracted)'},<br>{'id': '7142047393162383661', 'value': 6, 'name': 'Sales increase'} |  | 2022-09-20 |  | 2022-09-20T12:41:22.395Z | https://example.com.aha.io/features/DEMO-10 | id: 7142047373244952991<br>name: New | id: 7142047373292237665<br>name: Closed<br>position: 6<br>complete: true<br>color: #689f3b |

#### Command Example 
```!aha-close-feature feature_name=DEMO-10```
