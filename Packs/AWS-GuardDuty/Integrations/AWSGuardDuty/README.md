Use this integration to detect and manage threats to your AWS system. We recommend that you use roles that have the following
bulit-in AWS policies:

* _AmazonGuardDutyFullAccess_
* _AmazonGuardDutyReadOnlyAccess_

For detailed instructions about setting up authentication, see: [AWS Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/aws-integrations---authentication).

## Prerequisies

It is important that you familiarize yourself with and complete all steps detailed in
the [Amazon AWS Integrations Configuration Guide](https://xsoar.pan.dev/docs/reference/articles/aws-integrations---authentication)

## Configure AWS - GuardDuty on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for AWS - GuardDuty.
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
   | Access Key | False |
   | Secret Key | False
   | Timeout | False |
   | Retries | False |

4. Click **Test** to validate the URLs, token, and connection.

## Fetched Incidents Data

* The integration fetches newly created Guard DutyFindings. Findings that are fetched are moved to Guard duty archive. Each
  integration instance can fetch findings from a single AWS Region.
* Each region can have a maximum of 1,000 member accounts that are linked to a guard duty master account. For more information see
  the [Amazon GuardDuty documentation](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_accounts.html).
* You can set the severity level of the findings to be fetched. "Low", "Medium", "High". For example, if you set the severity
  level to "Medium", the integration will only fetch findings with severity level of Medium and higher.
* Findings in archived status will not be retrieved.
* The initial fetch interval is one minute.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully
execute a command, a DBot message appears in the War Room with the command details.

### aws-gd-create-detector

***
Create an AWS Guard Duty Detector on the integration instance specified aws account.

##### AWS IAM Policy Permission

Effect: _Allow_<br/>
Action: _guardduty:CreateDetector_

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

```!aws-gd-create-detector enabled=True region=eu-west-2```

### aws-gd-delete-detector

***
Deletes a Amazon GuardDuty detector specified by the detector ID.

##### AWS IAM Policy Permission

Effect: _Allow_<br/>
Action: _guardduty:DeleteDetector_

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

```!aws-gd-delete-detector detectorId=38b1235ed3fe245279cd0c8e235db0715ac5561eb```

### aws-gd-get-detector

***
Retrieves an Amazon GuardDuty detector specified by the detectorId.

##### AWS IAM Policy Permission

Effect: _Allow_<br/>
Action: _guardduty:GetDetector_

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

```!aws-gd-get-detector detectorId=38b1ed3fe279fdascd0c8edb071dsf5ac5561eb region=eu-west-2```

### aws-gd-update-detector

***
Updates an Amazon GuardDuty detector specified by the detectorId.

##### AWS IAM Policy Permission

Effect: _Allow_<br/>
Action: _guardduty:UpdateDetector_

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

```aws-gd-update-detector detectorId=38b1ed3fe279fdascd0c8edb071dsf5ac5561eb enable=True```

### aws-gd-create-ip-set

***
A list of trusted IP addresses on allow list for secure communication with AWS infrastructure and applications.

##### AWS IAM Policy Permission

Effect: _Allow_<br/>
Action: _guardduty:CreateIPSet_

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
| AWS.GuardDuty.Detectors.IPSet.IpSetId | unknown | The unique identifier for an IP Set. | 

#### Command Example

```!aws-gd-create-ip-set format=TXT location=https://s3.eu-central-1.amazonaws.com/test/ipset.txt activate=True detectorId=38b1ed3fe279czvasdd0c8edb0715azdsfc5561eb name=test region=eu-west-2```

### aws-gd-delete-ip-set

***
Deletes the IPSet specified by the IPSet ID.

##### AWS IAM Policy Permission

Effect: _Allow_<br/>
Action: _guardduty:DeleteIPSet_

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

```!aws-gd-delete-ip-set detectorId=38b1ed3fe279cd0c8edb0715ac5561eb ipSetId=7eb1f440be5931f168280b574a26d44d region=eu-west-2```

### aws-gd-list-detectors

***
Lists detectorIds of all the existing Amazon GuardDuty detector resources.

##### AWS IAM Policy Permission

Effect: _Allow_<br/>
Action: _guardduty:ListDetectors_

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

```!aws-gd-list-detectors region=eu-west-2```

### aws-gd-update-ip-set

***
Updates the IPSet specified by the IPSet ID.

##### AWS IAM Policy Permission

Effect: _Allow_<br/>
Action: _guardduty:UpdateIPSet_

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

```!aws-gd-update-ip-set detectorId=38b1ed3fe279cd0c8edb0715ac5561eb ipSetId=7eb1f440be5931f168280b574a26d44d activate=False region=eu-west-2```

### aws-gd-get-ip-set

***
Retrieves the IPSet specified by the IPSet ID.

##### AWS IAM Policy Permission

Effect: _Allow_<br/>
Action: _guardduty:GetIPSet_

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

```!aws-gd-get-ip-set detectorId=38b1ed3fesdf279cd0c8edbdsf071sdgfac5561eb ipSetId=7eb1sdff440be5931f1682adf80b574a26d44d region=eu-west-2```

### aws-gd-list-ip-sets

***
Lists the IPSets of the GuardDuty service specified by the detector ID.

##### AWS IAM Policy Permission

Effect: _Allow_<br/>
Action: _guardduty:ListIPSet_

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
| AWS.GuardDuty.Detectors.IPSet.IpSetId | unknown | The unique identifier for an IP Set | 

#### Command Example

```!aws-gd-list-ip-sets detectorId=38b1ed3fesdf279cd0c8edbdsf071sdgfac5561eb region=eu-west-2```

### aws-gd-create-threatintel-set

***
Create a new ThreatIntelSet. ThreatIntelSets consist of known malicious IP addresses. GuardDuty generates findings based on
ThreatIntelSets.

##### AWS IAM Policy Permission

Effect: _Allow_<br/>
Action: _guardduty:CreateThreatIntelSet_

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

```!aws-gd-create-threatintel-set format=TXT location=https://s3.eu-central-1.amazonaws.com/test/threatintel.txt activate=True detectorId=38b1ed3fe279czvasdd0c8edb0715azdsfc5561eb name=test region=eu-west-2```

### aws-gd-delete-threatintel-set

***
Deletes ThreatIntelSet specified by the ThreatIntelSet ID.

##### AWS IAM Policy Permission

Effect: _Allow_<br/>
Action: _guardduty:DeleteThreatIntelSet_

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

```!aws-gd-delete-threatintel-set detectorId=38b1ed3fe279cd0c8edb0715ac5561eb threatIntelSetId=7eb1f440be5931f168280b574a26d44d region=eu-west-2```

### aws-gd-get-threatintel-set

***
Retrieves the ThreatIntelSet that is specified by the ThreatIntelSet ID.

##### AWS IAM Policy Permission

Effect: _Allow_<br/>
Action: _guardduty:GetThreatIntelSet_

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

```!aws-gd-get-threatintel-set detectorId=38b1ed3fe279cd0c8edb0715ac5561eb threatIntelSetId=7eb1f440be5931f168280b574a26d44d region=eu-west-2```

### aws-gd-list-threatintel-sets

***
Lists the ThreatIntelSets of the GuardDuty service specified by the detector ID.

##### AWS IAM Policy Permission

Effect: _Allow_<br/>
Action: _guardduty:ListThreatIntelSet_

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

```!aws-gd-list-threatintel-sets detectorId=38b1ed3fe279cd0c8edb0715ac5561eb region=eu-west-2```

### aws-gd-update-threatintel-set

***
Updates the ThreatIntelSet specified by ThreatIntelSet ID.

##### AWS IAM Policy Permission

Effect: _Allow_<br/>
Action: _guardduty:UpdateThreatIntelSet_

#### Base Command

`aws-gd-update-threatintel-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detectorId | The detectorID that specifies the GuardDuty service whose ThreatIntelSet you want to update. | Required | 
| threatIntelSetId | The unique ID that specifies the ThreatIntelSet that you want to update. | Optional | 
| activate | The updated boolean value that specifies whether the ThreatIntelSet is active or not. Possible values are: True, False. | Optional | 
| location | The updated URI of the file that contains the ThreatIntelSet. For example (https://s3.us-west-2.amazonaws.com/my-bucket/my-object-key). | Optional | 
| name | The user-friendly ThreatIntelSet name. | Optional | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

There is no context output for this command.

#### Command Example

```!aws-gd-update-threatintel-set detectorId=38b1ed3fe279cd0c8edb0715ac5561eb threatIntelSetId=7eb1f440be5931f168280b574a26d44d activate=False region=eu-west-2```

### aws-gd-list-findings

***
Lists Amazon GuardDuty findings for the specified detector ID.

##### AWS IAM Policy Permission

Effect: _Allow_<br/>
Action: _guardduty:ListFindings_

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

```!aws-gd-list-findings detectorId=38b1ed3fe279cd0c8edb0715ac5561eb region=eu-west-2```

### aws-gd-get-findings

***
Describes Amazon GuardDuty findings specified by finding IDs.

##### AWS IAM Policy Permission

Effect: _Allow_<br/>
Action: _guardduty:GetFindings_

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

```!aws-gd-get-findings detectorIds=4f1fc7cd7dsg26sdf4328d8dc813 findingIds=96b1ac608sdf00e5183c3dds115c36aac328b,0ab180f5801sdg954418f3806c2a45282c9```

### aws-gd-create-sample-findings

***
Generates example findings of types specified by the list of finding types. If 'NULL' is specified for findingTypes, the API
generates example findings of all supported finding types.

##### AWS IAM Policy Permission

Effect: _Allow_<br/>
Action: _guardduty:CreateSampleFindings_

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

```!aws-gd-create-sample-findings detectorId=4f1fc7cd7dsg2adf6sdf4328d8dc813 findingTypes=NULL region=eu-central-1```

### aws-gd-archive-findings

***
Archives Amazon GuardDuty findings specified by the list of finding IDs.

##### AWS IAM Policy Permission

Effect: _Allow_<br/>
Action: _guardduty:ArchiveFindings_

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

```!aws-gd-archive-findings detectorIds=4f1fc7cd7dsg26sdf4328d8dc813 findingIds=96b1ac608sdf00e5183c3dds115c36aac328b,0ab180f5801sdg954418f3806c2a45282c9```

### aws-gd-unarchive-findings

***
Unarchives Amazon GuardDuty findings specified by the list of finding IDs.

##### AWS IAM Policy Permission

Effect: _Allow_<br/>
Action: _guardduty:UnarchiveFindings_

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

```!aws-gd-unarchive-findings detectorIds=4f1fc7cd7dsg26sdf4328d8dc813 findingIds=96b1ac608sdf00e5183c3dds115c36aac328b,0ab180f5801sdg954418f3806c2a45282c9```

### aws-gd-update-findings-feedback

***
Marks specified Amazon GuardDuty findings as useful or not useful.

##### AWS IAM Policy Permission

Effect: _Allow_<br/>
Action: _guardduty:UpdateFindingsFeedback_

#### Base Command

`aws-gd-update-findings-feedback`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detectorId | The ID of the detector that specifies the GuardDuty service whose findings you want to mark as useful or not useful. | Required | 
| findingIds | IDs of the findings that you want to mark as useful or not useful. | Optional | 
| comments | Additional feedback about the GuardDuty findings. | Optional | 
| feedback | Specify whether the finding was useful or not. Possible values are: USEFUL, NOT_USEFUL. | Optional | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 

#### Context Output

There is no context output for this command.

#### Command Example

```!aws-gd-update-findings-feedback detectorIds=4f1fc7cd7dsg26sdf4328d8dc813 findingIds=96b1ac608sdf00e5183c3dds115c36aac328b comments=Good Job feedback=USEFUL```

### aws-gd-list-members

***
Describes Amazon GuardDuty members for the specified detector ID.

##### AWS IAM Policy Permission

Effect: _Allow_<br/>
Action: _guardduty:ListMembers_

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

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.GuardDuty.Members.AccountId | string | The unique account ID of the member. | 
| AWS.GuardDuty.Members.DetectorId | string | The unique detector ID of the member. | 
| AWS.GuardDuty.Members.MasterId | string | The unique detector ID of the master. | 
| AWS.GuardDuty.Members.Email | string | The email of the member. | 
| AWS.GuardDuty.Members.RelationshipStatus | string | The relationship  status of member. | 
| AWS.GuardDuty.Members.InvitedAt | string | The first time a member was invited. | 
| AWS.GuardDuty.Members.UpdatedAt | string | The time a member was last updated. | 

#### Command Example

```!aws-gd-list-members detectorIds=4f1fc7cd7dsg26sdf4328d8dc813```

### aws-gd-get-members

***
Describes Amazon GuardDuty members for the specified detector ID & account ID.

##### AWS IAM Policy Permission

Effect: _Allow_<br/>
Action: _guardduty:GetMembers_

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
| AWS.GuardDuty.Members.AccountId | string | The unique account ID of the member. | 
| AWS.GuardDuty.Members.DetectorId | string | The unique detector ID of the member. | 
| AWS.GuardDuty.Members.MasterId | string | The unique detector ID of the master. | 
| AWS.GuardDuty.Members.Email | string | The email of the member. | 
| AWS.GuardDuty.Members.RelationshipStatus | string | The relationship  status of member. | 
| AWS.GuardDuty.Members.InvitedAt | string | The first time a member was invited. | 
| AWS.GuardDuty.Members.UpdatedAt | string | The time a member was last updated. | 

#### Command Example

```!aws-gd-get-members detectorIds=4f1fc7cd7dsg26sdf4328d8dc813 accountIds=1f3fc2cd1dag26sdf4338d8aa813```




