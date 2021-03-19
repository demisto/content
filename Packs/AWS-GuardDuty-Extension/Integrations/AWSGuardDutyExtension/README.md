Amazon Web Services Guard Duty Service (gd)
Extension aimed to provide aws-gd-list/get-member(s) commands
This integration was integrated and tested with version xx of AWS - GuardDuty - Extension
## Configure AWS - GuardDuty - Extension on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for AWS - GuardDuty - Extension.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | AWS Default Region | False |
    | Role Arn | False |
    | Fetch incidents | False |
    | Incident type | False |
    | Role Session Name | False |
    | Role Session Duration | False |
    | Guard Duty Severity level | False |
    | Incidents Fetch Interval | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### aws-gd-create-detector
***
Create an AWS Guard Duty Detector on the integration instance specified aws account.


#### Base Command

`aws-gd-create-detector`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| enabled | A boolean value that specifies whether the detector is to be enabled. Possible values are: True, False. Default is True. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.GuardDuty.Detectors.DetectorId | string | The unique ID of the created detector. | 


#### Command Example
``` ```

#### Human Readable Output



### aws-gd-delete-detector
***
Deletes a Amazon GuardDuty detector specified by the detector ID.


#### Base Command

`aws-gd-delete-detector`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detectorId | The unique ID that specifies the detector that you want to delete. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### aws-gd-get-detector
***
Retrieves an Amazon GuardDuty detector specified by the detectorId.


#### Base Command

`aws-gd-get-detector`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detectorId | The unique ID of the detector that you want to retrieve. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.GuardDuty.Detectors.DetectorId | string | The unique ID of the created detector. | 
| AWS.GuardDuty.Detectors.CreatedAt | string | The first time a resource was created. | 
| AWS.GuardDuty.Detectors.ServiceRole | string | Customer serviceRole name or ARN for accessing customer resources. | 
| AWS.GuardDuty.Detectors.Status | string | The status of detector. | 
| AWS.GuardDuty.Detectors.UpdatedAt | string | The time a resource was last updated. | 


#### Command Example
``` ```

#### Human Readable Output



### aws-gd-update-detector
***
Updates an Amazon GuardDuty detector specified by the detectorId.


#### Base Command

`aws-gd-update-detector`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detectorId | The unique ID of the detector that you want to update. | Required | 
| enable | Updated boolean value for the detector that specifies whether the detector is enabled. Possible values are: True, False. Default is True. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### aws-gd-create-ip-set
***
A list of trusted IP addresses that have been whitelisted for secure communication with AWS infrastructure and applications.


#### Base Command

`aws-gd-create-ip-set`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| activate | A boolean value that indicates whether GuardDuty is to start using the uploaded IPSet. Possible values are: True, False. Default is True. | Optional | 
| detectorId | The unique ID of the detector that you want to update. | Required | 
| format | The format of the file that contains the IPSet. Possible values are: TXT, STIX, OTX_CSV, ALIEN_VAULT, PROOF_POINT, FIRE_EYE. | Required | 
| location | The URI of the file that contains the IPSet. For example (https://s3.us-west-2.amazonaws.com/my-bucket/my-object-key). | Optional | 
| name | The user friendly name to identify the IPSet. This name is displayed in all findings that are triggered by activity that involves IP addresses included in this IPSet. | Optional | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.GuardDuty.Detectors.IPSet.IpSetId | Unknown | The unique identifier for an IP Set. | 


#### Command Example
``` ```

#### Human Readable Output



### aws-gd-delete-ip-set
***
Deletes the IPSet specified by the IPSet ID.


#### Base Command

`aws-gd-delete-ip-set`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detectorId | The detectorID that specifies the GuardDuty service whose IPSet you want to delete. | Required | 
| ipSetId | The unique ID that specifies the IPSet that you want to delete. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### aws-gd-list-detectors
***
Lists detectorIds of all the existing Amazon GuardDuty detector resources.


#### Base Command

`aws-gd-list-detectors`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.GuardDuty.Detectors.DetectorId | string | The unique identifier for a detector. | 


#### Command Example
``` ```

#### Human Readable Output



### aws-gd-update-ip-set
***
Updates the IPSet specified by the IPSet ID.


#### Base Command

`aws-gd-update-ip-set`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| activate | The updated boolean value that specifies whether the IPSet is active or not. Possible values are: True, False. | Optional | 
| detectorId | The detectorID that specifies the GuardDuty service whose IPSet you want to update. | Required | 
| ipSetId | The unique ID that specifies the IPSet that you want to update. | Required | 
| location | The updated URI of the file that contains the IPSet. For example (https://s3.us-west-2.amazonaws.com/my-bucket/my-object-key). | Optional | 
| name | The user friendly name to identify the IPSet. | Optional | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### aws-gd-get-ip-set
***
Retrieves the IPSet specified by the IPSet ID.


#### Base Command

`aws-gd-get-ip-set`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detectorId | The detectorID that specifies the GuardDuty service whose IPSet you want to retrieve. | Required | 
| ipSetId | The unique ID that specifies the IPSet that you want to describe. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.GuardDuty.Detectors.IPSet.IpSetId | string | The unique ID for the IPSet. | 
| AWS.GuardDuty.Detectors.IPSet.Format | string | The format of the file that contains the IPSet. | 
| AWS.GuardDuty.Detectors.IPSet.Location | string | The URI of the file that contains the IPSet. | 
| AWS.GuardDuty.Detectors.IPSet.Name | string | he user friendly name to identify the IPSet. | 
| AWS.GuardDuty.Detectors.IPSet.Status | string | The status of ipSet file uploaded. | 


#### Command Example
``` ```

#### Human Readable Output



### aws-gd-list-ip-sets
***
Lists the IPSets of the GuardDuty service specified by the detector ID.


#### Base Command

`aws-gd-list-ip-sets`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detectorId | The unique ID of the detector that you want to retrieve. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.GuardDuty.Detectors.IPSet.IpSetId | Unknown | The unique identifier for an IP Set | 


#### Command Example
``` ```

#### Human Readable Output



### aws-gd-create-threatintel-set
***
Create a new ThreatIntelSet. ThreatIntelSets consist of known malicious IP addresses. GuardDuty generates findings based on ThreatIntelSets.


#### Base Command

`aws-gd-create-threatintel-set`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| activate | A boolean value that indicates whether GuardDuty is to start using the uploaded ThreatIntelSet. Possible values are: True, False. Default is True. | Required | 
| detectorId | The unique ID of the detector that you want to update. | Required | 
| format | The format of the file that contains the ThreatIntelSet. Possible values are: TXT, STIX, OTX_CSV, ALIEN_VAULT, PROOF_POINT, FIRE_EYE. | Required | 
| location | The URI of the file that contains the ThreatIntelSet. For example (https://s3.us-west-2.amazonaws.com/my-bucket/my-object-key). | Required | 
| name | A user-friendly ThreatIntelSet name that is displayed in all finding generated by activity that involves IP addresses included in this ThreatIntelSet. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.GuardDuty.Detectors.ThreatIntelSet.ThreatIntelSetId | string | The unique identifier for an threat intel set. | 


#### Command Example
``` ```

#### Human Readable Output



### aws-gd-delete-threatintel-set
***
Deletes ThreatIntelSet specified by the ThreatIntelSet ID.


#### Base Command

`aws-gd-delete-threatintel-set`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detectorId | The detectorID that specifies the GuardDuty service whose ThreatIntelSet you want to delete. | Required | 
| threatIntelSetId | The unique ID that specifies the ThreatIntelSet that you want to delete. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### aws-gd-get-threatintel-set
***
Retrieves the ThreatIntelSet that is specified by the ThreatIntelSet ID.


#### Base Command

`aws-gd-get-threatintel-set`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detectorId | The detectorID that specifies the GuardDuty service whose ThreatIntelSet you want to describe. | Required | 
| threatIntelSetId | The unique ID that specifies the ThreatIntelSet that you want to describe. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.GuardDuty.Detectors.ThreatIntelSet.ThreatIntelSetId | string | The unique ID that specifies the ThreatIntelSet. | 
| AWS.GuardDuty.Detectors.ThreatIntelSet.Format | string | The format of the threatIntelSet. | 
| AWS.GuardDuty.Detectors.ThreatIntelSet.Location | string | The URI of the file that contains the ThreatIntelSet. | 
| AWS.GuardDuty.Detectors.ThreatIntelSet.Name | string | A user-friendly ThreatIntelSet name. | 
| AWS.GuardDuty.Detectors.ThreatIntelSet.Status | string | The status of threatIntelSet file uploaded. | 


#### Command Example
``` ```

#### Human Readable Output



### aws-gd-list-threatintel-sets
***
Lists the ThreatIntelSets of the GuardDuty service specified by the detector ID.


#### Base Command

`aws-gd-list-threatintel-sets`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detectorId | The detectorID that specifies the GuardDuty service whose ThreatIntelSets you want to list. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.GuardDuty.Detectors.ThreatIntelSet.ThreatIntelSetId | string | The unique identifier for an threat intel set | 


#### Command Example
``` ```

#### Human Readable Output



### aws-gd-update-threatintel-set
***
Updates the ThreatIntelSet specified by ThreatIntelSet ID.


#### Base Command

`aws-gd-update-threatintel-set`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detectorId | The detectorID that specifies the GuardDuty service whose ThreatIntelSet you want to update. | Required | 
| threatIntelSetId | The unique ID that specifies the ThreatIntelSet that you want to update. | Optional | 
| activate | The updated boolean value that specifies whether the ThreateIntelSet is active or not. Possible values are: True, False. | Optional | 
| location | The updated URI of the file that contains the ThreateIntelSet. For example (https://s3.us-west-2.amazonaws.com/my-bucket/my-object-key). | Optional | 
| name | The user-friendly ThreatIntelSet name. | Optional | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### aws-gd-list-findings
***
Lists Amazon GuardDuty findings for the specified detector ID.


#### Base Command

`aws-gd-list-findings`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detectorId | The ID of the detector that specifies the GuardDuty service whose findings you want to list. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.GuardDuty.Findings.FindingId | string | The unique identifier for the Finding | 


#### Command Example
``` ```

#### Human Readable Output



### aws-gd-get-findings
***
Describes Amazon GuardDuty findings specified by finding IDs.


#### Base Command

`aws-gd-get-findings`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detectorId | The ID of the detector that specifies the GuardDuty service whose findings you want to retrieve. | Required | 
| findingIds | IDs of the findings that you want to retrieve. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### aws-gd-create-sample-findings
***
Generates example findings of types specified by the list of finding types. If 'NULL' is specified for findingTypes, the API generates example findings of all supported finding types.


#### Base Command

`aws-gd-create-sample-findings`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detectorId | The ID of the detector to create sample findings for. | Required | 
| findingTypes | Types of sample findings that you want to generate. Separated by comma. | Optional | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### aws-gd-archive-findings
***
Archives Amazon GuardDuty findings specified by the list of finding IDs.


#### Base Command

`aws-gd-archive-findings`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detectorId | The ID of the detector that specifies the GuardDuty service whose findings you want to archive. | Required | 
| findingIds | IDs of the findings that you want to archive. Separated by comma. | Optional | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### aws-gd-unarchive-findings
***
Unarchives Amazon GuardDuty findings specified by the list of finding IDs.


#### Base Command

`aws-gd-unarchive-findings`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detectorId | The ID of the detector that specifies the GuardDuty service whose findings you want to unarchive. | Required | 
| findingIds | IDs of the findings that you want to unarchive. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### aws-gd-update-findings-feedback
***
Marks specified Amazon GuardDuty findings as useful or not useful.


#### Base Command

`aws-gd-update-findings-feedback`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detectorId | The ID of the detector that specifies the GuardDuty service whose findings you want to mark as useful or not useful. | Required | 
| findingIds | IDs of the findings that you want to mark as useful or not useful. | Optional | 
| comments | Additional feedback about the GuardDuty findings. | Optional | 
| feedback | Specifi wheter the finding was usful or not. Possible values are: USEFUL, NOT_USEFUL. | Optional | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### aws-gd-list-members
***
Describes Amazon GuardDuty members for the specified detector ID.


#### Base Command

`aws-gd-list-members`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detectorId | The ID of the detector that specifies the GuardDuty service whose members you want to retrieve. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### aws-gd-get-members
***
Describes Amazon GuardDuty members for the specified detector ID & account ID.


#### Base Command

`aws-gd-get-members`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detectorId | The ID of the detector that specifies the GuardDuty service whose members you want to retrieve. | Required | 
| accountIds | The ID of the account that specifies the GuardDuty service whose details you want to retrieve. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.GuardDuty.Members.MemberAccountId | string | The unique account ID of the member. | 
| AWS.GuardDuty.Members.MemberDetectorId | string | The unique detector ID of the member. | 
| AWS.GuardDuty.Members.MemberMasterId | string | The unique detector ID of the master. | 
| AWS.GuardDuty.Members.MemberEmail | string | The email of the member. | 
| AWS.GuardDuty.Members.MemberRelationshipStatus | string | The relationship  status of member. | 
| AWS.GuardDuty.Members.MemberInvitedAt | string | The first time a member was invited. | 
| AWS.GuardDuty.Members.MemberUpdatedAt | string | The time a member was last updated. | 


#### Command Example
``` ```

#### Human Readable Output


