Analyze a host or a URL. 
## Configure SSL Labs (Community Contribution) in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Registered Email Address | The registered email address that will be used to access SSL Labs.  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### ssl-labs-register-email

***
Register for Scan API initiation and result fetching

#### Base Command

`ssl-labs-register-email`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| firstName | Users First Name. | Required | 
| lastName | Users Last Name. | Required | 
| email | Users Email Address. Email services such as Gmail, Yahoo, or Hotmail are not allowed. | Required | 
| organization | Name of the organization using the service. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SslLabs.Registation.message | string | Registration message response | 
| SslLabs.Registation.status | string | Either success or failure | 

### ssl-labs-info

***
Check the availability of the SSL Labs servers, retrieve the engine and criteria version, and initialize the maximum number of concurrent assessments.

#### Base Command

`ssl-labs-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SslLabs.Info.criteriaVersion | string | Rating criteria version as a string \(e.g., "2009f"\) | 
| SslLabs.Info.currentAssessments | number | The number of ongoing assessments submitted by this client. | 
| SslLabs.Info.engineVersion | string | SSL Labs software version as a string \(e.g., "2.2.0"\) | 
| SslLabs.Info.maxAssessments | number | The maximum number of concurrent assessments the client is allowed to initiate. | 
| SslLabs.Info.newAssessmentCoolOff | number | The cool-off period after each new assessment, in milliseconds; you're not allowed to submit a new assessment before the cool-off expires, otherwise you'll get a 429. | 
| SslLabs.Info.messages | string | A list of messages \(strings\). Messages can be public \(sent to everyone\) and private \(sent only to the invoking client\). Private messages are prefixed with "\[Private\]" | 

### ssl-labs-analyze

***
Invoke assessments. 

#### Base Command

`ssl-labs-analyze`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | Provide hostname or URL. | Required | 
| publish | Set to on if assessment results needs to be published on the public results boards. Default: off. Possible values are: off, on. Default is off. | Optional | 
| startNew | If on setting is enabled, a new assessment is started, even if there is a cached assessment in progress. However, if an assessment is in progress, its status is returned instead of starting a new assessment. Note: This parameter should only be used once to start a new assessment; any additional use may cause an assessment loop. Possible values are: off, on. Default is off. | Optional | 
| fromCache | Delivers cached assessment reports if available. This parameter is intended for API consumers who do not wish to wait for assessment results and cannot be used simultaneously with the startNew parameter. Default: off. Possible values are: off, on. Default is off. | Optional | 
| maxAge | Maximum report age in hours if retrieving from cache (fromCache parameter). | Optional | 
| all | When the parameter is set to on, full information will be returned. When the parameter is set to done, full information will be returned only if the assessment is complete (status is READY or ERROR). Possible values are: off, on. Default is on. | Optional | 
| ignoreMismatch | Ignores the mismatch if server certificate doesn't match the assessment hostname and proceeds with assessments if set to on. Default: off Note: This parameter is ignored if a cached report is returned. Possible values are: off, on. Default is off. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SslLabs.Analyze.host | string | Assessment host, which can be a hostname or an IP address | 
| SslLabs.Analyze.port | number | Assessment port \(e.g., 443\) | 
| SslLabs.Analyze.protocol | string | Protocol \(e.g., HTTP\) | 
| SslLabs.Analyze.isPublic | boolean | true if this assessment is publicly available \(listed on the SSL Labs assessment boards\) | 
| SslLabs.Analyze.status | string | Assessment status; possible values: DNS, ERROR, IN_PROGRESS, and READY. | 
| SslLabs.Analyze.startTime | number | Assessment starting time, in milliseconds since 1970 | 
| SslLabs.Analyze.testTime | number | Assessment completion time, in milliseconds since 1970 | 
| SslLabs.Analyze.engineVersion | string | Assessment engine version \(e.g., "2.2.0"\) | 
| SslLabs.Analyze.criteriaVersion | string | Grading criteria version \(e.g., "2009l"\) | 
| SslLabs.Analyze.cacheExpiryTime | number | When will the assessment results expire from the cache \(typically set only for assessment with errors; otherwise the results stay in the cache for as long as there's sufficient room\) | 
| SslLabs.Analyze.certHostnames | unknown | The list of certificate hostnames collected from the certificates seen during assessment. The hostnames may not be valid. This field is available only if the server certificate doesn't match the requested hostname. In that case, this field saves you some time as you don't have to inspect the certificates yourself to find out what valid hostnames might be. | 
| SslLabs.Analyze.endpoints | unknown | list of Endpoint objects | 
| SslLabs.Analyze.certs | unknown | a list of Cert object, representing the chain certificates in the order in which they were retrieved from the server. | 