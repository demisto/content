Agentless, context-aware and full-stack security and compliance for AWS, Azure and GCP.
This integration was integrated and tested with Wiz

## Configure Wiz on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Wiz. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | name | Integration Name. Default: `Wiz_instance_1` | True |
    | said | Service Account ID | True |
    | sasecret | Service Account Secret | True |
    | api_endpoint | API Endpoint. Default: `https://api.us1.app.wiz.io/graphql` <br /> To find your API endpoint URL: <br />1. Log in to Wiz, then open your <a href="https://app.wiz.io/user/profile">user profile</a> <br />2. Copy the **API Endpoint URL** to use here. | True
    | first_fetch | First fetch timestamp \(`<number>` `<time unit>`, e.g., 12 hours, 7 days\) | False |
    | Fetch incidents | Issue Streaming type.<br />Either `Fetch incidents` (to constantly pull Issues) or `Do not fetch` (to push live Issues)| False |
    | max_fetch | Max Issues to fetch | False |

3. Click **Test** to validate the API Endpoint, Service Account and connection.

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook or War Room.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### wiz-get-issues
***
Get the issues on cloud resources

<h4> Base Command </h4>

`wiz-get-issues`

<h4> Input </h4>

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_type | The type of Issue to get. | Optional | 
| resource_id | Get Issues of a specific resource_id.<br />Expected input: `providerId` | Optional | 
| severity | Get Issues of a specific severuty.<br />Expected input: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` or `INFORMATIONAL`.<br />The chosen severity and above will be fetched  | Optional | 
*Either `issue_type` or `resource_id` are required.*

<h4> Context Output </h4>

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wiz.Manager.Issues | String | All Issues | 


#### Command Example
```
!wiz-get-issues issue_type="VIRTUAL_MACHINE"
!wiz-get-issues resource_id="arn:aws:ec2:us-east-2:123456789098:instance/i-0g03j4h5gd123d456"
!wiz-get-issues resource_id="arn:aws:ec2:us-east-2:123456789098:instance/i-0g03j4h5gd123d456" severity=HIGH
```

### wiz-get-resource
***
Get Details of a resource.

<h4> Base Command </h4>

`wiz-get-resource`

<h4> Input </h4>

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_id | Resource provider id | Required | 


<h4> Context Output </h4>

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wiz.Manager.Resource | String | Resource details | 


#### Command Example
```
!wiz-get-resource resource_id="arn:aws:ec2:us-east-2:123456789098:instance/i-0g03j4h5gd123d456"
```

### wiz-issue-in-progress
***
Re-open an Issue.

<h4> Base Command </h4>

`wiz-issue-in-progress`

<h4> Input </h4>

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_id | Issue id | Required | 


<h4> Context Output </h4>

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wiz.Manager.Issue | String | Issue details | 


#### Command Example
```
!wiz-issue-in-progress issue_id="12345678-1234-1234-1234-cc0a24716e0b"
```

### wiz-reopen-issue
***
Re-open an Issue.

<h4> Base Command </h4>

`wiz-reopen-issue`

<h4> Input </h4>

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_id | Issue id | Required | 
| reopen_note | Note for re-opening Issue | Optional | 


<h4> Context Output </h4>

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wiz.Manager.Issue | String | Issue details | 


#### Command Example
```
!wiz-reopen-issue issue_id="12345678-1234-1234-1234-cc0a24716e0b" reopen-note="still an issue"
```

### wiz-reject-issue
***
Re-open an Issue.

<h4> Base Command </h4>

`wiz-reject-issue`

<h4> Input </h4>

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_id | Issue id | Required | 
| reject_reason | Note for re-opening Issue<br />Accepted values: `WONT_FIX`, `FALSE_POSITIVE` and `REJECTED`. | Required | 
| reject_note | Note for re-opening Issue | Required | 


<h4> Context Output </h4>

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Wiz.Manager.Issue | String | Issue details | 


#### Command Example
```
!wiz-reject-issue issue_id="12345678-1234-1234-1234-cc0a24716e0b" reject_reason="WONT_FIX" reject_note="this is by design"
```

### wiz-set-issue-note
***
Set (append) a note to an Issue.

<h4> Base Command </h4>

`wiz-set-issue-note`

<h4> Input </h4>

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_id | Issue id | Required | 
| reject_note | Note for the Issue. Will be appeneded to existing one. | Required | 

#### Command Example
```
!wiz-set-issue-note issue_id="12345678-1234-1234-1234-cc0a24716e0b" note="Checking with owner"
```

### wiz-clear-issue-note
***
Clears a note from an Issue.

<h4> Base Command </h4>

`wiz-clear-issue-note`

<h4> Input </h4>

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_id | Issue id | Required | 

#### Command Example
```
!wiz-clear-issue-note issue_id="12345678-1234-1234-1234-cc0a24716e0b"
```

### wiz-get-issue-evidence
***
Get the evidence from an Issue.

<h4> Base Command </h4>

`wiz-get-issue-evidence`

<h4> Input </h4>

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_id | Issue id | Required | 

#### Command Example
```
!wiz-get-issue-evidence issue_id="12345678-1234-1234-1234-cc0a24716e0b"
```

### wiz-rescan-machine-disk
***
Rescan a VM disk in Wiz.

<h4> Base Command </h4>

`wiz-rescan-machine-disk`

<h4> Input </h4>

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vm_id | VM Cloud Provider id | Required | 

#### Command Example
```
!wiz-rescan-machine-disk vm_id="arn:aws:ec2:us-east-2:123456789098:instance/i-1234abcd123456789"
```

### wiz-set-issue-due-date
***
Set a due date for an Issue.

<h4> Base Command </h4>

`wiz-set-issue-due-date`

<h4> Input </h4>

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_id | Issue id | Required | 
| due_at | Due At Date | Required | 

#### Command Example
```
!wiz-set-issue-due-date issue_id="12345678-1234-1234-1234-cc0a24716e0b" due_at="2022-01-20"
```

### wiz-clear-issue-due-date
***
Clear a due date for an Issue.

<h4> Base Command </h4>

`wiz-clear-issue-due-date`

<h4> Input </h4>

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_id | Issue id | Required | 

#### Command Example
```
!wiz-clear-issue-due-date issue_id="12345678-1234-1234-1234-cc0a24716e0b"
```
