Use the  Prisma Cloud (RedLock) Threat Defense integration to manage alerts from Microsoft Azure, Google Cloud Platform, and AWS.

## Configure the Prisma Cloud (RedLock) Integration on Demisto

1.  Navigate to **Settings** > **Integrations** > **Servers & Services**.
2.  Search for Prisma Cloud (RedLock).
3.  Click **Add instance** to create and configure a new integration instance.  
    *   **Name**: A textual name for the integration instance.
    *   **Server URL**: URL of RedLlock server.
    *   **Username**
    *   **Password**
    *   **Customer name**
    *   **Use system proxy settings**
    *   **Trust any certificate (not secure)**
    *   **Fetch only incidents matching this rule name**
    *   **Fetch only incidents with this severity**
    *   **Fetch Incidents**
    *   **Incident type**
4.  Click **Test** to validate the URLs and token.

## Commands

You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.

1.  Search RedLock alerts: redlock-search-alerts
2.  Get RedLock alert details: redlock-get-alert-details
3.  Dismiss RedLock alerts: redlock-dismiss-alerts
4.  Reopen RedLock alerts: redlock-reopen-alerts
5.  List all Redlock alerts: redlock-list-alert-filters


### 1. Search RedLock alerts

Searches RedLock for all alerts.

##### Base Command

`redlock-search-alerts`

##### Input

|Input Parameter|Description|
|--- |--- |
|time-range-date-from|Search start time (MM/DD/YYYY)|
|time-range-date-to|Search end time (MM/DD/YYYY)|
|time-range-value|Amount of units to go back in time|
|time-range-unit|The search unit. The types login and epoch are only available if timeRangeValue is blank.|
|policy-name|Policy name|
|policy-label|Policy label|
|policy-compliance-standard|Policy compliance standard|
|cloud-account|Cloud account|
|cloud-region|Cloud region|
|alert-rule-name|Name of the alert rule|
|resource-id|Resource ID|
|resource-name|Resource name|
|resource-type|Resource type|
|alert-status|Alert status|
|alert-id|Alert ID|
|cloud-type|Cloud type|
|risk-grade|Risk grade|
|policy-type|Policy type|
|policy-severity|Policy severity|


##### Context Output

|Path|Description|
|--- |--- |
|Redlock.Alert.ID|ID of returned alert|
|Redlock.Alert.Status|Status of returned alert|
|Redlock.Alert.AlertTime|Time of alert|
|Redlock.Alert.Policy.ID|Policy ID|
|Redlock.Alert.Policy.Name|Policy name|
|Redlock.Alert.Policy.Type|Policy type|
|Redlock.Alert.Policy.Severity|Policy severity|
|Redlock.Alert.Policy.Remediable|Whether or not the policy is remediable|
|Redlock.Alert.RiskDetail.Rating|Risk rating|
|Redlock.Alert.RiskDetail.Score|Risk score|
|Redlock.Metadata.CountOfAlerts|Number of alerts found|


##### Command Example

`!redlock-search-alerts time-range-date-from="05/19/2018" time-range-date-to="06/26/2018"`

##### Raw Output
```json
[
	{
		"AlertTime": 1527208131469,
		"ID": "P-120",
		"Policy": {
			"ID": "c2b84f89-7ec8-473e-a6af-404feeeb96c5",
			"Name": "CloudTrail logs are not encrypted using Customer Master Keys (CMKs)",
			"Remediable": false,
			"Severity": "medium",
			"Type": "config"
		},
		"Resource": {
			"Account": "Adrians AWS account",
			"AccountID": "961855366482",
			"ID": "arn:aws:cloudtrail:us-west-1:961855366482:trail/Logs",
			"Name": "Logs"
		},
		"RiskDetail": {
			"Rating": "C",
			"Score": 20
		},
		"Status": "open"
	},
	{
		"AlertTime": 1527208131954,
		"ID": "P-151",
		"Policy": {
			"ID": "b82f90ce-ed8b-4b49-970c-2268b0a6c2e5",
			"Name": "Security Groups allow internet traffic from internet to RDP port (3389)",
			"Remediable": true,
			"Severity": "high",
			"Type": "config"
		},
		"Resource": {
			"Account": "Adrians AWS account",
			"AccountID": "961855366482",
			"ID": "sg-00c2402879388152c",
			"Name": "launch-wizard-1"
		},
		"RiskDetail": {
			"Rating": "F",
			"Score": 80
		},
		"Status": "open"
	},
	{
		"AlertTime": 1527283805892,
		"ID": "P-206",
		"Policy": {
			"ID": "cd94c83e-6f84-4a37-a116-13ccba78a615",
			"Name": "Internet connectivity via tcp over insecure port",
			"Remediable": false,
			"Severity": "high",
			"Type": "network"
		},
		"Resource": {
			"Account": "Adrians AWS account",
			"AccountID": "961855366482",
			"ID": "i-0798ff02acd2cd1cf",
			"Name": "i-0798ff02acd2cd1cf"
		},
		"RiskDetail": {
			"Rating": "F",
			"Score": 80
		},
		"Status": "open"
	},
	{
		"AlertTime": 1527283805839,
		"ID": "P-204",
		"Policy": {
			"ID": "9c7af8a8-5743-420f-a879-8f0f73d678ea",
			"Name": "Internet exposed instances",
			"Remediable": false,
			"Severity": "high",
			"Type": "network"
		},
		"Resource": {
			"Account": "Adrians AWS account",
			"AccountID": "961855366482",
			"ID": "i-0798ff02acd2cd1cf",
			"Name": "i-0798ff02acd2cd1cf"
		},
		"RiskDetail": {
			"Rating": "F",
			"Score": 80
		},
		"Status": "open"
	},
	{
		"AlertTime": 1527202810000,
		"ID": "P-195",
		"Policy": {
			"ID": "e12e210c-3018-11e7-93ae-92361f002671",
			"Name": "Excessive login failures",
			"Remediable": false,
			"Severity": "high",
			"Type": "anomaly"
		},
		"Resource": {
			"Account": "Adrians AWS account",
			"AccountID": "961855366482",
			"ID": "akaylor",
			"Name": "akaylor"
		},
		"RiskDetail": {
			"Rating": "C",
			"Score": 40
		},
		"Status": "open"
	},
	{
		"AlertTime": 1527209282788,
		"ID": "P-192",
		"Policy": {
			"ID": "50af1c0a-ab70-44dd-b6f6-3529e795131f",
			"Name": "MFA not enabled for IAM users",
			"Remediable": false,
			"Severity": "medium",
			"Type": "config"
		},
		"Resource": {
			"Account": "Adrians AWS account",
			"AccountID": "961855366482",
			"ID": "akaylor",
			"Name": "akaylor"
		},
		"RiskDetail": {
			"Rating": "C",
			"Score": 20
		},
		"Status": "open"
	},
	{
		"AlertTime": 1527209282796,
		"ID": "P-193",
		"Policy": {
			"ID": "6a34af3f-21ae-8008-0850-229761d01081",
			"Name": "IAM user has both Console access and Access Keys",
			"Remediable": false,
			"Severity": "medium",
			"Type": "config"
		},
		"Resource": {
			"Account": "Adrians AWS account",
			"AccountID": "961855366482",
			"ID": "akaylor",
			"Name": "akaylor"
		},
		"RiskDetail": {
			"Rating": "C",
			"Score": 20
		},
		"Status": "open"
	},
	{
		"AlertTime": 1527208132072,
		"ID": "P-164",
		"Policy": {
			"ID": "d9b86448-11a2-f9d4-74a5-f6fc590caeef",
			"Name": "IAM policy allow full administrative privileges",
			"Remediable": false,
			"Severity": "low",
			"Type": "config"
		},
		"Resource": {
			"Account": "Adrians AWS account",
			"AccountID": "961855366482",
			"ID": "arn:aws:iam::aws:policy/AdministratorAccess",
			"Name": "AdministratorAccess"
		},
		"RiskDetail": {
			"Rating": "B",
			"Score": 1
		},
		"Status": "open"
	},
	{
		"AlertTime": 1527208132065,
		"ID": "P-163",
		"Policy": {
			"ID": "7913fcbf-b679-5aac-d979-1b6817becb22",
			"Name": "S3 buckets do not have server side encryption",
			"Remediable": false,
			"Severity": "low",
			"Type": "config"
		},
		"Resource": {
			"Account": "Adrians AWS account",
			"AccountID": "961855366482",
			"ID": "tax-returns-and-bitcoin-wallets",
			"Name": "tax-returns-and-bitcoin-wallets"
		},
		"RiskDetail": {
			"Rating": "F",
			"Score": 51
		},
		"Status": "open"
	},
	{
		"AlertTime": 1527208131969,
		"ID": "P-152",
		"Policy": {
			"ID": "630d3779-d932-4fbf-9cce-6e8d793c6916",
			"Name": "S3 buckets are accessible to public",
			"Remediable": true,
			"Severity": "high",
			"Type": "config"
		},
		"Resource": {
			"Account": "Adrians AWS account",
			"AccountID": "961855366482",
			"ID": "tax-returns-and-bitcoin-wallets",
			"Name": "tax-returns-and-bitcoin-wallets"
		},
		"RiskDetail": {
			"Rating": "F",
			"Score": 51
		},
		"Status": "open"
	},
	{
		"AlertTime": 1527208132057,
		"ID": "P-162",
		"Policy": {
			"ID": "7913fcbf-b679-5aac-d979-1b6817becb22",
			"Name": "S3 buckets do not have server side encryption",
			"Remediable": false,
			"Severity": "low",
			"Type": "config"
		},
		"Resource": {
			"Account": "Adrians AWS account",
			"AccountID": "961855366482",
			"ID": "someprivatestuff",
			"Name": "someprivatestuff"
		},
		"RiskDetail": {
			"Rating": "B",
			"Score": 11
		},
		"Status": "open"
	},
	{
		"AlertTime": 1527208131434,
		"ID": "P-118",
		"Policy": {
			"ID": "4daa435b-fa46-457a-9359-6a4b4a43a442",
			"Name": "Access logging not enabled on S3 buckets",
			"Remediable": false,
			"Severity": "medium",
			"Type": "config"
		},
		"Resource": {
			"Account": "Adrians AWS account",
			"AccountID": "961855366482",
			"ID": "lotsologs",
			"Name": "lotsologs"
		},
		"RiskDetail": {
			"Rating": "B",
			"Score": 11
		},
		"Status": "open"
	}
]
```

##### War Room Output

![playground - war room 2018-07-09 15-11-24](https://user-images.githubusercontent.com/39116813/42449980-5bcee498-838b-11e8-81a7-34c2d4650b03.jpg)


### 2. Get RedLock alert details

Get details for RedLock alerts.

##### Base Command

`redlock-get-alert-details`

##### Input

|Input Parameter|Description|
|--- |--- |
|alert-id|Alert ID|
|detailed|Enables retrieving the entire or trimmed alert model|

##### Context Output

|Path|Description|
|--- |--- |
|Redlock.Alert.ID|ID of returned alert|
|Redlock.Alert.Status|Status of returned alert|
|Redlock.Alert.AlertTime|Time of alert|
|Redlock.Alert.Policy.ID|Policy ID|
|Redlock.Alert.Policy.Name|Policy name|
|Redlock.Alert.Policy.Type|Policy type|
|Redlock.Alert.Policy.Severity|Policy severity|
|Redlock.Alert.Policy.Remediable|Whether or not the policy is remediable|
|Redlock.Alert.RiskDetail.Rating|Risk rating|
|Redlock.Alert.RiskDetail.Score|Risk score|


##### Command Example

`!redlock-get-alert-details alert-id="P-120"`

##### Raw Output
```json
{
	"AlertTime": 1527208131469,
	"ID": "P-120",
	"Policy": {
		"ID": "c2b84f89-7ec8-473e-a6af-404feeeb96c5",
		"Name": null,
		"Remediable": false,
		"Severity": null,
		"Type": "config"
	},
	"Resource": {
		"Account": "Adrians AWS account",
		"AccountID": "961855366482",
		"ID": "arn:aws:cloudtrail:us-west-1:961855366482:trail/Logs",
		"Name": "Logs"
	},
	"RiskDetail": {
		"Rating": "C",
		"Score": 20
	},
	"Status": "dismissed"
}
```

##### War Room Output

![playground - artifact viewer 2018-07-09 15-28-04](https://user-images.githubusercontent.com/39116813/42450437-c86ac6d4-838c-11e8-95bb-3358f3ba33e5.jpg)


### 3. Dismiss RedLock alerts

Dismisses the specified RedLock alerts.

##### Base Command

`redlock-dismiss-alerts`

##### Input

|Input Parameter|Description|
|--- |--- |
|alert-id|Alert ID|
|dismissal-note|Reason for dismissal|
|time-range-date-from|Search start time (MM/DD/YYYY)|
|time-range-date-to|Search end time (MM/DD/YYYY)|
|time-range-value|Amount of units to go back in time|
|time-range-unit|The search unit. The types login and epoch are only available if timeRangeValue is blank.|
|policy-name|Policy name|
|policy-label|Policy label|
|policy-compliance-standard|Policy compliance standard|
|cloud-account|Cloud account|
|cloud-region|Cloud region|
|alert-rule-name|Name of the alert rule|
|resource-id|Resource ID|
|resource-name|Resource name|
|resource-type|Resource type|
|alert-status|Alert status|
|cloud-type|Cloud type|
|risk-grade|Risk grade|
|policy-type|Policy type|
|policy-severity|Policy severity|
|policy-id|Policy IDs (comma-separated string)|


##### Context Output

|Path|Description|
|--- |--- |
|Redlock.Alert.ID|ID of the dismissed alerts|


##### Command Example

`!redlock-dismiss-alerts alert-id="P-120" dismissal-note="Dismiss"`

##### Raw Output
```json
[
	"P-120"
]
```

##### War Room Output

Alerts dismissed successfully. Dismissal Note: Dismiss.


### 4. Reopen RedLock alerts: redlock-reopen-alerts

Reopens dismissed alerts.

##### Base Command

`redlock-dismiss-alerts`

##### Input

|Input Parameter|Description|
|--- |--- |
|alert-id|Alert ID|
|time-range-date-from|Search start time (MM/DD/YYYY)|
|time-range-date-to|Search end time (MM/DD/YYYY)|
|time-range-value|Amount of units to go back in time|
|time-range-unit|The search unit. The types login and epoch are only available if timeRangeValue is blank.|
|policy-name|Policy name|
|policy-label|Policy label|
|policy-compliance-standard|Policy compliance standard|
|cloud-account|Cloud account|
|cloud-region|Cloud region|
|alert-rule-name|Name of the alert rule|
|resource-id|Resource ID|
|resource-name|Resource name|
|resource-type|Resource type|
|alert-status|Alert status|
|cloud-type|Cloud type|
|risk-grade|Risk grade|
|policy-type|Policy type|
|policy-severity|Policy severity|


##### Context Output

|Path|Description|
|--- |--- |
|Redlock.Alert.ID|ID of the reopened alerts|


##### Command Example

`!redlock-reopen-alerts alert-id="P-120"`

##### Raw Output
```json
[
	"P-120"
]
```

##### War Room Output

Alerts re-opened successfully.

* * *

### 5. List all RedLock alerts

Lists all RedLock alerts.

##### Base Command

`redlock-list-alert-filters`

##### Input

There is no input for this command.

##### Context Output

There is no context output for this command.

##### War Room Output

![playground - artifact viewer 2018-07-09 15-54-29](https://user-images.githubusercontent.com/39116813/42451747-c934f072-8390-11e8-948d-a6ed094f5b04.jpg)