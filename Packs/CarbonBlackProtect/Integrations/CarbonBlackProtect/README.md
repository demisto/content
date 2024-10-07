VMware Carbon Black App Control (formerly known as Carbon Black Enterprise Protection) is a next-generation endpoint threat prevention solution to deliver a portfolio of protection policies, real-time visibility across environments, and comprehensive compliance rule sets in a single platform. This integration only supports Carbon Black on-premise APIs.

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration-vmware-carbon-black-app-control-v2).

## Configure VMware Carbon Black App Control v2 in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL (e.g. https://192.168.0.1) | True |
| API Token | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) | False |
| Max incidents per fetch | False |
| Fetch query | False |
| API Token | False |
| Fetch incidents | False |
| Incident type | False |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cbp-fileCatalog-search
***
Search for file catalogs. See more: https://developer.carbonblack.com/reference/enterprise-protection/8.0/rest-api/#filecatalog


#### Base Command

`cbp-fileCatalog-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group | Grouping is optional and can be defined with a single attribute: &amp;group=xyz. There can be only one grouping field. Example: group=osShortName. | Optional | 
| limit | (Int) Is maximum number of results to retrieve. If not specified: First 1000 results will be returned. If set to -1: Only result count will be returned, without actual results. Offset parameter is ignored in this case. If set to 0: All results will be returned. Offset parameter is ignored in this case. Note that some result sets could be very large, resulting in query timeout. Therefore, unless you know that query will not return more than 1000 results, it is recommended to retrieve data in chunks using offset and limit. | Optional | 
| offset | (Int) Offset in data set. | Optional | 
| query | A condition contains three parts: name, operator, and value. Name is any valid field in the object that is being queried. Operator (: LIKE, ! NOT LIKE, &lt; Less than, &gt; Greater than, + logical AND, - logical OR, \| separating values) is any of valid operators (see below). All operators consist of a single character. Value is compared with operator and depends on field type. See more: https://developer.carbonblack.com/reference/enterprise-protection/8.0/rest-api/#searching. | Optional | 
| sort | Sorting is optional and can be defined with a single attribute: &amp;sort=xyz [ASC\|DESC]. There can be only one sorting field. Default sort order (if omitted) is ASC. xyz is field name from the result set. | Optional | 
| fileName | Name of the file under which this unique hash was first seen. | Optional | 
| fileType | Type of the file. | Optional | 
| computerId | Id of computer where this file was first seen. You can get this by executing cbp-computer-search command. | Optional | 
| threat | Threat of this file. Can be one of:<br/>-1=Unknown<br/>0=Clean<br/>50=Potential risk<br/>100=Malicious. Possible values are: Unknown, Clean, Potential risk, Malicious. | Optional | 
| fileState | File state of this hash. Can be one of:<br/>1=Unapproved<br/>2=Approved<br/>3=Banned<br/>4=Approved by Policy<br/>5=Banned by Policy. Possible values are: Unapproved, Approved, Banned, Approved by Policy, Banned by Polic. | Optional | 
| hash | Hash of the file. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | Unknown | Size of the file. | 
| File.Path | String | Path on the found hostname. | 
| File.Name | String | Name of the file. | 
| File.Type | String | File type. | 
| File.ProductName | String | The name of the product to which this file belongs. | 
| File.ID | String | Unique fileCatalog ID. | 
| File.Publisher | String | The publisher of the file. | 
| File.Company | String | The company for the product. | 
| File.Extension | String | Extension of the file. | 

### cbp-computer-search
***
Search for computers. For more information, see the Carbon Black documentation: https://developer.carbonblack.com/reference/enterprise-protection/8.0/rest-api/#computer


#### Base Command

`cbp-computer-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | A condition contains three parts: name, operator, and value. Name is any valid field in the object that is being queried. Operator (: LIKE, ! NOT LIKE, &lt; Less than, &gt; Greater than, + logical AND, - logical OR, \| separating values) is any of valid operators (see below). All operators consist of a single character. Value is compared with an operator and depends on field type. See more: https://developer.carbonblack.com/reference/enterprise-protection/8.0/rest-api/#searching. | Optional | 
| offset | (Int) Offset in data set. | Optional | 
| group | Grouping is optional and can be defined with a single attribute: &amp;group=xyz. There can be only one grouping field, for example: group=osShortName. | Optional | 
| sort | Sorting is optional and can be defined with a single attribute: &amp;sort=xyz [ASC\|DESC]. There can be only one sorting field. Default sort order (if omitted) is ascending (ASC). xyz is field name from the result set. | Optional | 
| limit | Maximum number of results to retrieve (Int). If not specified, the first 1000 results will be returned. If set to "-1", only the result count will be returned, without actual results, and the Offset parameter is ignored. If set to "0", all results will be returned, and the Offset parameter is ignored. Some result sets might be very large, resulting in query timeout. Therefore, unless you know that query will not return more than 1000 results, it is recommended to retrieve data in chunks using offset and limit. | Optional | 
| name | Computer name. | Optional | 
| ipAddress | Last known IP address of this computer. | Optional | 
| macAddress | MAC address of adapter used to connect to the CB Protection Server. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Endpoint.OS | String | The short OS name running on the endpoint. | 
| Memory | Number | Amount of memory for the endpoint. | 

### cbp-computer-update
***
Updates computer objects. Note that some computer properties can be changed only if specific boolean parameters are set. For more information, see the Carbon Black documentation: https://developer.carbonblack.com/reference/enterprise-protection/8.0/rest-api/#computer


#### Base Command

`cbp-computer-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | (Int) Unique computer ID. | Required | 
| name | (String) Computer name can be changed only if computer is a template. | Optional | 
| computerTag | (String) Custom computer tag. | Optional | 
| description | (String) Description of this computer. | Optional | 
| policyId | (Int) New ID of the policy for this computer. PolicyId is ignored if either automaticPolicy is "True" or localApproval is "True". | Optional | 
| automaticPolicy | (Boolean) "True" if this policy is assigned automatically through AD. If localApproval is "True", this argument must be "False". Possible values are: True, False. | Optional | 
| localApproval | (Boolean) "True" if this computer is currently in local approval mode. If automaticPolicy is "True", this argument must be "False". Possible values are: True, False. | Optional | 
| refreshFlags | (Int) Change refresh flags for this agent. Can be a combination of: 0x01=Complete resynch of agent NAB and installer table is requested 0x02=Rescan of programs installed on the computer is requested 0x20=Tell agent to refresh config list 0x40=Force this agent to reregister with new cookie 0x200=Trigger agent Reboot. 0x1000=Tell agent to refresh config list from the file 0x4000 Boost the priority of this agent over all others permanently (until it is de-prioritized). | Optional | 
| prioritized | (Boolean) Set to "True" to prioritize this computer. Possible values are: True, False. | Optional | 
| debugLevel | (Int) Current debug level of the agent. Range is from 0 (none) to 8 (verbose). This value can be changed only if the "changeDiagnostics" request parameter is set to "True". | Optional | 
| kernelDebugLevel | (Int) Current kernel debug level of the agent. Range is from 0 (none) to 5 (verbose). This value can be changed only if the "changeDiagnostics" request parameter is set to "True". | Optional | 
| debugFlags | (Int) Debug flags. Can be 0 or combination of: 0x01 = Upload debug files now 0x10 = Enable full memory dumps 0x20 = Copy agent cache 0x40 = Delete debug files 0x80 = Upload agent cache 0x200 = Save verbose debug info + counters to the cache when copied/uploaded 0x400 = Generate and upload an analysis.bt9 file that contains various constraint violation analysis information 0x800 = Run a health check and send results to server. This value can be changed only if the "changeDiagnostics" request parameter is set to "True". | Optional | 
| debugDuration | (Int) Debug duration in minutes. This value can be changed only if the "changeDiagnostics" request parameter is set to "True". | Optional | 
| cCLevel | (Int) Cache consistency check level set for the agent. Can be one of: 0 = None 1 = Quick verification 2 = Rescan known files Full scan for new files. This value can be changed only if the "changeDiagnostics" request parameter is set to "True". | Optional | 
| cCFlags | (Int) Cache consistency check flags set for agent. Can be 0 or combination of: 0x0001 = Whether this is just a test run or not 0x0002 = Should the state of invalid files be preserved 0x0004 = Should new files found be locally approved or not 0x0008 = Should we re-evaluate whether a file’s certificate information is still valid or not 0x0010 = Whether the check was scheduled or not 0x0020 = Whether the agent should run constraint checks to test for invalid results 0x0040 = Whether we are only searching for new script types as a result of a change to what ‘IsScript’ means 0x0080 = Whether we are doing a level 3 check for initialization 0x0100 = This cache check is to remediate CR# 18041 0x0200 = Force the re-evaluation of the IsCrawlable state and archive type. | Optional | 
| forceUpgrade | (Boolean) Set to "True" to force an upgrade for this computer. Possible values are: True, False. | Optional | 
| template | (Boolean) "True" if the computer is a VDI template. This value can be changed only if the "changeTemplate" request parameter is set to "True". Possible values are: True, False. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Endpoint.Processors | Number | The number of processors. | 
| Endpoint.OS | String | The short OS name running on the endpoint. | 
| Endpoint.MACAddress | String | MAC address of the endpoint. | 
| Endpoint.Model | String | The machine model, if available. | 
| Endpoint.IPAddress | String | IP address of the endpoint. | 
| Endpoint.Processor | String | Model of the processor. | 
| Endpoint.Hostname | String | Hostname of the endpoint. | 
| Endpoint.OSVersion | String | The full OS name running on the endpoint. | 
| Endpoint.ID | String | The unique ID within the tool retreiving the endpoint. | 

### cbp-computer-get
***
Returns information for a computer. For more information, see the Carbon Black documentation: https://developer.carbonblack.com/reference/enterprise-protection/8.0/rest-api/#computer


#### Base Command

`cbp-computer-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | (Int) Unique computer ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Endpoint.Processors | Number | The number of processors. | 
| Endpoint.OS | String | The short OS name running on the endpoint. | 
| Endpoint.MACAddress | String | MAC address of the endpoint. | 
| Endpoint.Model | String | The machine model, if available. | 
| Endpoint.IPAddress | String | IP address of the endpoint. | 
| Endpoint.Processor | String | Model of the processor. | 
| Endpoint.Hostname | String | Hostname of the endpoint. | 
| Endpoint.OSVersion | String | The full OS name running on the endpoint. | 
| Endpoint.ID | String | The unique ID within the tool retreiving the endpoint. | 

### cbp-fileInstance-search
***
Search for file instances. For more information, see the Carbon Black documentation: https://developer.carbonblack.com/reference/enterprise-protection/8.0/rest-api/#fileinstance


#### Base Command

`cbp-fileInstance-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | A condition contains three parts: name, operator and value. Name is any valid field in the object that is being queried. Operator (: LIKE, ! NOT LIKE, &lt; Less than, &gt; Greater than, + logical AND, - logical OR, \| separating values) is any of valid operators (see below). All operators consist of a single character. Value is compared with operator and depends on field type. For more information, see the Carbon Black documentation: https://developer.carbonblack.com/reference/enterprise-protection/8.0/rest-api/#searching. | Optional | 
| limit | (Int) Maximum number of results to retrieve. If not specified the first 1000 results will be returned. If set to "-1", only the result count will be returned, without actual results, and the "offset" parameter is ignored. If set to "0", all results will be returned, and the "offset" parameter is ignored. Note that some result sets might be very large, resulting in query timeout. Therefore, unless you know that query will not return more than 1000 results, it is recommended to retrieve data in chunks using offset and limit. | Optional | 
| offset | (Int) Offset in the data set. | Optional | 
| group | Grouping is optional and can be defined with a single attribute: &amp;group=xyz. There can be only one grouping field, for example: group=osShortName. | Optional | 
| sort | Sorting is optional and can be defined with a single attribute, where xyz is the field name from the result set: &amp;sort=xyz [ASC\|DESC]. There can be only one sorting field. Default sort order is ascending (ASC). . | Optional | 
| computerId | Id of computer associated with this fileInstance. | Optional | 
| fileName | Name of the file on the agent. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CBP.FileInstance.CatalogID | String | The file ID in the file catalog. | 
| CBP.FileInstance.ComputerID | String | The computer ID on which the file was found. | 
| CBP.FileInstance.ID | String | CBP internal ID of the file instance. | 
| CBP.FileInstance.Name | String | Name of the file. | 
| CBP.FileInstance.Path | String | Path on the found hostname. | 

### cbp-event-search
***
Search for events. For more information, see the Carbon Black documentation: https://developer.carbonblack.com/reference/enterprise-protection/8.0/rest-api/#event


#### Base Command

`cbp-event-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | A condition contains three parts: name, operator and value. Name is any valid field in the object that is being queried. Operator (: LIKE, ! NOT LIKE, &lt; Less than, &gt; Greater than, + logical AND, - logical OR, \| separating values) is any of valid operators (see below). All operators consist of a single character. Value is compared with operator and depends on field type. For more information, see the Carbon Black documentation: https://developer.carbonblack.com/reference/enterprise-protection/8.0/rest-api/#searching. | Optional | 
| limit | (Int) Maximum number of results to retrieve. If not specified, the first 1000 results will be returned. If set to "-1", only the result count will be returned, without actual results, and the "offset" parameter is ignored. If set to "0", all results will be returned, and the "offset" parameter is ignored. Note that some result sets might be very large, resulting in query timeout. Therefore, unless you know that query will not return more than 1000 results, it is recommended to retrieve data in chunks using offset and limit. | Optional | 
| offset | (Int) Offset in the data set. | Optional | 
| group | Grouping is optional and can be defined with a single attribute: &amp;group=xyz. There can be only one grouping field, for example: group=osShortName. | Optional | 
| sort | Sorting is optional and can be defined with a single attribute, where xyz is field name from the result set: &amp;sort=xyz [ASC\|DESC]. There can be only one sorting field. Default sort order is ascending (ASC). . | Optional | 
| type | Event type. Can be one of:<br/>0 = Server Management<br/>1 = Session Management<br/>2 = Computer Management<br/>3 = Policy Management<br/>4 = Policy Enforcement<br/>5 = Discovery<br/>6 = General Management<br/>8 = Internal Events. Possible values are: Server Management, Session Management, Computer Management, Policy Management, Policy Enforcement, Discovery, General Management, Internal Events. | Optional | 
| computerId | Id of computer associated with this event. You can get this by executing cbp-computer-search command. | Optional | 
| ipAddress | IP address associated with this event. | Optional | 
| fileName | Name of the file associated with this event. | Optional | 
| severity | Event severity. Can be one of:<br/>2 = Critical<br/>3 = Error<br/>4 = Warning<br/>5 = Notice<br/>6 = Info<br/>7 = Debug. Possible values are: Critical, Error, Warning, Notice, Info, Debug. | Optional | 
| userName | User name associated with this event. | Optional | 
| fileCatalogId | Id of fileCatalog entry associated with this fileRule. Can be null if file hasn’t been seen on any endpoints yet. You can get this by executing cbp-fileCatalog-search. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CBP.Event.FilePath | String | File path of the event. | 
| CBP.Event.Param1 | String | First event parameter. | 
| CBP.Event.Param2 | String | Second event parameter. | 
| CBP.Event.Param3 | String | Third event parameter. | 
| CBP.Event.SubTypeName | String | Name of the subtype. | 
| CBP.Event.ComputerName | String | Name of the computer related to the event. | 
| CBP.Event.FileName | String | Name of the file related to the event. | 
| CBP.Event.RuleName | String | Name of the rule related to the event. | 
| CBP.Event.ProcessFileCatalogID | String | ID of the process file catalog ID. | 
| CBP.Event.StringID | String | ID of the event string. | 
| CBP.Event.IPAddress | String | IP address of the event. | 
| CBP.Event.PolicyID | String | Policy ID of the event. | 
| CBP.Event.Timestamp | Date | Timestamp of the event. | 
| CBP.Event.Username | String | Username related to the event. | 
| CBP.Event.ComputerID | String | ID of the event computer. | 
| CBP.Event.ProcessFileName | String | File name of the process. | 
| CBP.Event.FileCatalogID | String | ID of the file catalog. | 
| CBP.Event.ProcessFileName | String | File name of the process. | 
| CBP.Event.IndicatorName | String | Indicator name of the event. | 
| CBP.Event.SubType | Number | ID of the subtype. | 
| CBP.Event.Type | Number | Type of the event. | 
| CBP.Event.ID | Number | ID of the event. | 
| CBP.Event.Description | String | Description of the event. | 
| CBP.Event.Severity | String | Severity of the event. | 
| CBP.Event.CommandLine | String | Command line executed in the event. | 
| CBP.Event.ProcessPathName | String | Path name of the process. | 

### cbp-approvalRequest-search
***
Search for approval requests. For more information, see the Carbon Black documentation: https://developer.carbonblack.com/reference/enterprise-protection/8.0/rest-api/#approvalrequest


#### Base Command

`cbp-approvalRequest-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | A condition contains three parts: name, operator and value. Name is any valid field in the object that is being queried. Operator (: LIKE, ! NOT LIKE, &lt; Less than, &gt; Greater than, + logical AND, - logical OR, \| separating values) is any of valid operators (see below). All operators consist of a single character. Value is compared with operator and depends on field type. For more information, see the Carbon Black documentation: https://developer.carbonblack.com/reference/enterprise-protection/8.0/rest-api/#searching. | Optional | 
| limit | (Int) Maximum number of results to retrieve. If not specified, the first 1000 results will be returned. If set to "-1", only the result count will be returned, without actual results, and the "offset" parameter is ignored. If set to "0", all results will be returned, and the "offset" parameter is ignored. Note that some result sets might be very large, resulting in query timeout. Therefore, unless you know that query will not return more than 1000 results, it is recommended to retrieve data in chunks using offset and limit. | Optional | 
| offset | (Int) Offset in the data set. | Optional | 
| group | Grouping is optional and can be defined with a single attribute: &amp;group=xyz. There can be only one grouping field. Example: group=osShortName. | Optional | 
| sort | Sorting is optional and can be defined with a single attribute, where xyz is field name from the result set: &amp;sort=xyz [ASC\|DESC]. There can be only one sorting field. Default sort order is ascending (ASC). . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CBP.ApprovalRequest.ID | Number | ID of the approval request. | 
| CBP.ApprovalRequest.ResolutionComments | String | Comments added by the request resolver. | 
| CBP.ApprovalRequest.Resolution | Number | Resolution of the request. Can be one of: 0=Not Resolved, 1=Rejected, 2=Resolved - Approved, 3=Resolved - Rule Change, 4=Resolved - Installer, 5=Resolved - Updater, 6=Resolved - Publisher, 7=Resolved - Other. | 
| CBP.ApprovalRequest.Status | Number | Request status. Can be one of: 1=New, 2=Open, 3=Closed, 4=Escalated. | 
| CBP.ApprovalRequest.FileCatalogID | Number | ID of the fileCatalog entry associated with file for this event. | 
| CBP.ApprovalRequest.ComputerID | Number | ID of the computer entry associated with this analysis. | 
| CBP.ApprovalRequest.ComputerName | String | Name of the computer associated with this event. | 
| CBP.ApprovalRequest.DateCreated | Date | Date/time when the notifier was created \(UTC\). | 
| CBP.ApprovalRequest.CreatedBy | String | User that created this notifier. | 
| CBP.ApprovalRequest.EnforcementLevel | Number | Enforcement level of the agent at the time of the request. Can be one of: 20=High \(Block Unapproved\), 30=Medium \(Prompt Unapproved\), 40=Low \(Monitor Unapproved\), 60=None \(Visibility\), 80=None \(Disabled\). | 
| CBP.ApprovalRequest.RequestorEmail | String | Email address of the user that created this request. | 
| CBP.ApprovalRequest.Priority | Number | Priority of this request. Can be one of: 0=High, 1=Medium, 2=Low. | 
| CBP.ApprovalRequest.FileName | String | Name of the file on the agent. | 
| CBP.ApprovalRequest.PathName | String | Path of the file on the agent. | 
| CBP.ApprovalRequest.Process | String | Process that attempted to execute the file on the agent \(the full process path\). | 
| CBP.ApprovalRequest.Platform | String | Platform of this approval request. | 

### cbp-fileRule-search
***
Search for file rules. For more information, see the Carbon Black documentation: https://developer.carbonblack.com/reference/enterprise-protection/8.0/rest-api/#filerule


#### Base Command

`cbp-fileRule-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | A condition contains three parts: name, operator and value. Name is any valid field in the object that is being queried. Operator (: LIKE, ! NOT LIKE, &lt; Less than, &gt; Greater than, + logical AND, - logical OR, \| separating values) is any of valid operators (see below). All operators consist of a single character. Value is compared with operator and depends on field type. For more information, see the Carbon Black documentation: https://developer.carbonblack.com/reference/enterprise-protection/8.0/rest-api/#searching. | Optional | 
| limit | (Int) Maximum number of results to retrieve. If not specified, the first 1000 results will be returned. If set to "-1", only the result count will be returned, without actual results, and the "offset" parameter is ignored. If set to "0", all results will be returned, and the offset parameter is ignored. Note that some result sets might be very large, resulting in query timeout. Therefore, unless you know that query will not return more than 1000 results, it is recommended to retrieve data in chunks using offset and limit. | Optional | 
| offset | (Int) Offset in the data set. | Optional | 
| group | Grouping is optional and can be defined with a single attribute: &amp;group=xyz. There can be only one grouping field, for example: group=osShortName. | Optional | 
| sort | Sorting is optional and can be defined with a single attribute where xyz is field name from the result set: &amp;sort=xyz [ASC\|DESC]. There can be only one sorting field. Default sort order is ascending (ASC). . | Optional | 
| fileCatalogId | Id of fileCatalog entry associated with this fileRule. Can be null if file hasn’t been seen on any endpoints yet. You can get this by executing cbp-fileCatalog-search. | Optional | 
| name | Name of this rule. | Optional | 
| fileState | File state for this rule. Can be one of:<br/>1=Unapproved<br/>2=Approved<br/>3=Banned. Possible values are: Unapproved, Approved, Banned. | Optional | 
| sourceType | Mechanism that created this rule. Can be one of: <br/>1 = Manual<br/>2 = Trusted Directory<br/>3 = Reputation<br/>4 = Imported<br/>5 = External (API)<br/>6 = Event Rule<br/>7 = Application Template<br/>8 = Unified Management. Possible values are: Manual, Trusted Directory, Reputation, Imported, External (API), Event Rule, Application Template, Unified Management. | Optional | 
| hash | Hash associated with this rule. Note that hash will be available only if rule was created through md5 or sha-1 hash. If rule was created through fileCatalogId or sha-256 hash that exists in the catalog, this field will be empty. | Optional | 
| fileName | File name associated with this rule. Note that file name will be available only if rule was created through file name. If rule was created through fileCatalogId or hash, this field will be empty. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CBP.FileRule.CatalogID | String | The file catalog ID for the rule. | 
| CBP.FileRule.Description | String | Description of the rule. | 
| CBP.FileRule.FileState | String | The file state for the rule. | 
| CBP.FileRule.Hash | String | Hash for the rule. | 
| CBP.FileRule.ID | String | ID of the rule. | 
| CBP.FileRule.Name | String | Name of the rule. | 
| CBP.FileRule.PolicyIDs | String | Policies of which this rule is a part. | 
| CBP.FileRule.ReportOnly | String | Whether this rule is "reporting only, or also "enforcing". | 

### cbp-fileRule-get
***
Gets the file rule. For more information, see the Carbon Black documentation: https://developer.carbonblack.com/reference/enterprise-protection/8.0/rest-api/#filerule


#### Base Command

`cbp-fileRule-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | (Int) Unique ID of the file rule. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CBP.FileRule.CatalogID | String | The file catalog ID for the rule. | 
| CBP.FileRule.Description | String | Description of the rule. | 
| CBP.FileRule.FileState | String | The file state for the rule. | 
| CBP.FileRule.Hash | String | Hash for the rule. | 
| CBP.FileRule.ID | String | ID of the rule. | 
| CBP.FileRule.Name | String | Name of the rule. | 
| CBP.FileRule.PolicyIDs | String | Policies of which this rule is a part. | 
| CBP.FileRule.ReportOnly | String | Whether this rule is "reporting only, or also "enforcing". | 

### cbp-fileRule-delete
***
Deletes the file rule. For more information, see the Carbon Black documentation: https://developer.carbonblack.com/reference/enterprise-protection/8.0/rest-api/#filerule


#### Base Command

`cbp-fileRule-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | (Int) Unique id of this fileRule. | Required | 


#### Context Output

There is no context output for this command.
### cbp-policy-search
***
Search for policies. For more information, see the Carbon Black documentation: https://developer.carbonblack.com/reference/enterprise-protection/8.0/rest-api/#policy


#### Base Command

`cbp-policy-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | A condition contains three parts: name, operator and value. Name is any valid field in the object that is being queried. Operator (: LIKE, ! NOT LIKE, &lt; Less than, &gt; Greater than, + logical AND, - logical OR, \| separating values) is any of valid operators (see below). All operators consist of a single character. Value is compared with operator and depends on field type. For more information, see the Carbon Black documentation: https://developer.carbonblack.com/reference/enterprise-protection/8.0/rest-api/#searching. | Optional | 
| limit | (Int) Maximum number of results to retrieve. If not specified, the first 1000 results will be returned. If set to "-1", only the result count will be returned, without actual results, and the "offset" parameter is ignored. If set to "0", all results will be returned, and the "offset" parameter is ignored. Note that some result sets might be very large, resulting in query timeout. Therefore, unless you know that query will not return more than 1000 results, it is recommended to retrieve data in chunks using offset and limit. | Optional | 
| offset | (Int) Offset in the data set. | Optional | 
| group | Grouping is optional and can be defined with a single attribute: &amp;group=xyz. There can be only one grouping field, for example: group=osShortName. | Optional | 
| sort | Sorting is optional and can be defined with a single attribute where xyz is field name from the result set: &amp;sort=xyz [ASC\|DESC]. There can be only one sorting field. Default sort order is ascending (ASC). . | Optional | 
| enforcementLevel | Target enforcement level. Can be one of:<br/>20=High (Block Unapproved)<br/>30=Medium (Prompt Unapproved)<br/>40=Low (Monitor Unapproved)<br/>60=None (Visibility)<br/>80=None (Disabled). Possible values are: High (Block Unapproved), Medium (Prompt Unapproved), Low (Monitor Unapproved), None (Visibility), None (Disabled). | Optional | 
| disconnectedEnforcementLevel | Target enforcement level for disconnected computers. Can be one of:<br/>20=High (Block Unapproved)<br/>30=Medium (Prompt Unapproved)<br/>40=Low (Monitor Unapproved)<br/>60=None (Visibility)<br/>80=None (Disabled). Possible values are: High (Block Unapproved), Medium (Prompt Unapproved), Low (Monitor Unapproved), None (Visibility), None (Disabled). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CBP.Policy.ReadOnly | Boolean | Whether the policy "read-only". | 
| CBP.Policy.EnforcementLevel | String | The level of enforcement of the policy. | 
| CBP.Policy.ReputationEnabled | Boolean | Whether the reputation for the policy is enabled. | 
| CBP.Policy.AtEnforcementComputers | Number | Number of enforced computers. | 
| CBP.Policy.Automatic | Boolean | Whether the policy is automatic. | 
| CBP.Policy.Name | String | Name of the policy. | 
| CBP.Policy.FileTrackingEnabled | Boolean | Whether file tracking enabled for the policy. | 
| CBP.Policy.ConnectedComputers | Number | Number of connected computers associated with the policy. | 
| CBP.Policy.PackageName | String | Package name of the policy. | 
| CBP.Policy.AllowAgentUpgrades | Boolean | Whether the policy allows agent upgrades. | 
| CBP.Policy.TotalComputers | Number | Number of computers associated with the policy. | 
| CBP.Policy.LoadAgentInSafeMode | Boolean | Whether the agent should load in safe mode. | 
| CBP.Policy.AutomaticApprovalsOnTransition | String | Approve on transition. | 
| CBP.Policy.ID | String | CBP internal ID of the policy. | 
| CBP.Policy.Description | String | Description of the policy. | 
| CBP.Policy.DisconnectedEnforcementLevel | String | The level of enforcement of the policy when disconnected. | 

### cbp-serverConfig-search
***
Search in server configurations. For more information, see the Carbon Black documentation: https://developer.carbonblack.com/reference/enterprise-protection/8.0/rest-api/#serverconfig.


#### Base Command

`cbp-serverConfig-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | A condition contains three parts: name, operator and value. Name is any valid field in the object that is being queried. Operator (: LIKE, ! NOT LIKE, &lt; Less than, &gt; Greater than, + logical AND, - logical OR, \| separating values) is any of valid operators (see below). All operators consist of a single character. Value is compared with operator and depends on field type. For more information, see the Carbon Black documentation: https://developer.carbonblack.com/reference/enterprise-protection/8.0/rest-api/#searching. | Optional | 
| limit | (Int) Maximum number of results to retrieve. If not specified, the first 1000 results will be returned. If set to "-1", only the result count will be returned, without actual results, and the "offset" parameter is ignored. If set to "0", all results will be returned, and the "offset" parameter is ignored. Note that some result sets might be very large, resulting in query timeout. Therefore, unless you know that query will not return more than 1000 results, it is recommended to retrieve data in chunks using offset and limit. | Optional | 
| offset | (Int) Offset in the data set. | Optional | 
| group | Grouping is optional and can be defined with a single attribute: &amp;group=xyz. There can be only one grouping field, for example: group=osShortName. | Optional | 
| sort | Sorting is optional and can be defined with a single attribute where xyz is field name from the result set: &amp;sort=xyz [ASC\|DESC]. There can be only one sorting field. Default sort order is ascending (ASC). . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CBP.ServerConfig.ID | String | CBP internal ID of the server configuration. | 
| CBP.ServerConfig.Name | String | Name of the server configuration. | 
| CBP.ServerConfig.Value | String | Value of the server configuration. | 

### cbp-publisher-search
***
Search for publishers. For more information, see the Carbon Black documentation: https://developer.carbonblack.com/reference/enterprise-protection/8.0/rest-api/#publisher.


#### Base Command

`cbp-publisher-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | A condition contains three parts: name, operator and value. Name is any valid field in the object that is being queried. Operator (: LIKE, ! NOT LIKE, &lt; Less than, &gt; Greater than, + logical AND, - logical OR, \| separating values) is any of valid operators (see below). All operators consist of a single character. Value is compared with operator and depends on field type. For more information, see the Carbon Black documentation: https://developer.carbonblack.com/reference/enterprise-protection/8.0/rest-api/#searching. | Optional | 
| limit | (Int) Maximum number of results to retrieve. If not specified, the first 1000 results will be returned. If set to "-1", only the result count will be returned, without actual results, and the "offset" parameter is ignored. If set to "0", all results will be returned, and the "offset" parameter is ignored. Note that some result sets might be very large, resulting in query timeout. Therefore, unless you know that query will not return more than 1000 results, it is recommended to retrieve data in chunks using offset and limit. | Optional | 
| offset | (Int) Offset in the data set. | Optional | 
| group | Grouping is optional and can be defined with a single attribute: &amp;group=xyz. There can be only one grouping field, for example: group=osShortName. | Optional | 
| sort | Sorting is optional and can be defined with a single attribute where xyz is field name from the result set: &amp;sort=xyz [ASC\|DESC]. There can be only one sorting field. Default sort order is ascending (ASC). . | Optional | 
| name | Subject name of leaf certificate for this publisher. | Optional | 
| publisherReputation | Reputation of this publisher. Can be one of:<br/>0=Not trusted (Unknown)<br/>1=Low<br/>2=Medium<br/>3=High. Possible values are: Not trusted (Unknown), Low, Medium, High. | Optional | 
| publisherState | State for this publisher. Can be one of:<br/>1=Unapproved<br/>2=Approved<br/>3=Banned<br/>4=Approved By Policy<br/>5=Banned By Policy. Possible values are: Unapproved, Approved, Banned, Approved By Policy, Banned By Policy. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CBP.Publisher.Description | String | Description of the publisher. | 
| CBP.Publisher.ID | String | CBP internal ID of the publisher. | 
| CBP.Publisher.Name | String | Name of the publisher. | 
| CBP.Publisher.Reputation | String | Reputation of the publisher. | 
| CBP.Publisher.SignedCertificatesCount | Number | Number of certificates from the publisher. | 
| CBP.Publisher.SignedFilesCount | Number | Number of signed files from publisher. | 
| CBP.Publisher.State | String | The state of the publisher. | 

### cbp-fileAnalysis-get
***
Returns the object instance of this class.


#### Base Command

`cbp-fileAnalysis-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | (Int) Unique fileAnalysis ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CBP.FileAnalysis.Priority | Number | File analysis priority.  Valid range is \[-2, 2\], where 2 is highest priority. Default priority is "0". | 
| CBP.FileAnalysis.PathName | String | Path of the file on the endpoint. | 
| CBP.FileAnalysis.ComputerId | String | ID of the computer entry associated with this analysis. | 
| CBP.FileAnalysis.DateModified | Date | Date/time when the fileAnalysis request was last modified \(UTC\). | 
| CBP.FileAnalysis.ID | String | Unique fileAnalysis ID. | 
| CBP.FileAnalysis.FileCatalogId | String | ID of the fileCatalog entry associated with this analysis. | 
| CBP.FileAnalysis.DateCreated | Date | Date/time when the fileAnalysis request was created \(UTC\). | 
| CBP.FileAnalysis.CreatedBy | String | User that requested the analysis. | 
| File.FileCatalogId | String | ID ofthe fileCatalog entry associated with this analysis. | 
| CBP.FileAnalysis.FileName | String | Name of the file on the endpoint. | 
| File.Malicious | String | Vendor and description of the malicious file. | 
| File.PathName | Unknown | Path of the file on the endpoint. | 
| File.Name | String |  Full file name, for example: "data.xls".  | 
| File.SHA1 | String | SHA1 hash of the file. | 
| File.SHA256 | String | SHA256 hash of the file. | 
| File.MD5 | String | MD5 hash of the file. | 
| DBotScore.Indicator | string | The indicator. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The DBot score vendor. | 
| DBotScore.Score | number | The DBot score | 

### cbp-fileAnalysis-createOrUpdate
***
Creates or updates a file analysis request.


#### Base Command

`cbp-fileAnalysis-createOrUpdate`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fileCatalogId | (Int) ID of the fileCatalog entry for which analysis is requested. This value can be fetched via cbp-fileCatalog-search command. | Required | 
| connectorId | (Int) ID of the target connector for the analysis. This value can be fetched via cbp-connector-search command. | Required | 
| computerId | (Int) ID of the computer from which to upload the file. If "0", the system will identify the best computer from which to get the file. This value can be fetched via cbp-computer-search command. Default is 0. | Optional | 
| priority | (Int) The analysis priority (valid range: -2, 2), where "2" is highest priority. Default priority is "0". Possible values are: -2, -1, 0, 1, 2. Default is 0. | Optional | 
| analysisStatus | (Int) Status of the analysis. The status of an analysis that is in progress can be changed to "5" (Cancelled). | Optional | 
| analysisTarget | (String) Target of the analysis. It has to be one of possible analysisTarget options defined for the given connector object, or empty for connectors without defined analysisTargets. | Optional | 
| id | If specified, will try to update the file analysis with this ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CBP.FileAnalysis.Priority | Number | File analysis priority in range \(valid range: -2, 2\), where "2" is highest priority. Default priority is "0". | 
| CBP.FileAnalysis.PathName | String | Path of the file where the file exists on the endpoint. | 
| CBP.FileAnalysis.ComputerID | String | ID of the computer entry associated with this analysis. | 
| CBP.FileAnalysis.DateModified | Date | Date/time when the fileAnalysis request was last modified \(UTC\). | 
| CBP.FileAnalysis.FileCatalogId | String | ID of the fileCatalog entry associated with this analysis. | 
| CBP.FileAnalysis.DateCreated | Date | Date/time when the fileAnalysis request was created \(UTC\). | 
| CBP.FileAnalysis.ID | String | Unique fileAnalysis ID. | 
| CBP.FileAnalysis.CreatedBy | String | User that requested the analysis. | 

### cbp-fileAnalysis-search
***
Returns objects that match the specified criteria.


#### Base Command

`cbp-fileAnalysis-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | A condition contains three parts: name, operator and value. Name is any valid field in the object that is being queried. Operator (: LIKE, ! NOT LIKE, &lt; Less than, &gt; Greater than, + logical AND, - logical OR, \| separating values) is any of valid operators (see below). All operators consist of a single character. Value is compared with operator and depends on field type. For more informatoin, see the Carbon Black documentation: https://developer.carbonblack.com/reference/enterprise-protection/8.0/rest-api/#searching. | Optional | 
| limit | (Int) Maximum number of results to retrieve. If not specified, the first 1000 results will be returned. If set to "-1", only the result count will be returned, without actual results, and the offset parameter is ignored. If set to "0", all results will be returned, and the offset parameter is ignored. Note that some result sets might be very large, resulting in query timeout. Therefore, unless you know that query will not return more than 1000 results, it is recommended to retrieve data in chunks using offset and limit. | Optional | 
| offset | (Int) Offset in the data set. | Optional | 
| group | Grouping is optional and can be defined with a single attribute: &amp;group=xyz. There can be only one grouping field, for example: group=osShortName. | Optional | 
| sort | Sorting is optional and can be defined with a single attribute: &amp;sort=xyz [ASC\|DESC], where xyz is the field name from the result set. There can be only one sorting field. Default sort order is ascending (ASC). . | Optional | 
| fileCatalogId | Id of fileCatalog entry associated with this analysis. You can get this by executing cbp-fileCatalog-search. | Optional | 
| connectorId | Id of connector associated with this analysis. You can get this by executing cbp-connector-search. | Optional | 
| fileName | Name of the file where file exists on the endpoint<br/>. | Optional | 
| analysisStatus | Status of analysis. Can be one of:<br/>0 = scheduled<br/>1 = submitted (file is sent for analysis)<br/>2 = processed (file is processed but results are not available yet)<br/>3 = analyzed (file is processed and results are available)<br/>4 = error<br/>5 = cancelled. Possible values are: scheduled, submitted (file is sent for analysis), processed (file is processed but results are not available yet), analyzed (file is processed and results are available), error, cancelled. | Optional | 
| analysisResult | Result of the analysis. Can be one of:<br/>0 = Not yet available<br/>1 = File is clean<br/>2 = File is a potential threat<br/>3 = File is malicious. Possible values are: Not yet available, File is clean, File is a potential threat, File is malicious. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CBP.FileAnalysis.Priority | Number | File analysis priority in range \(valid range: -2, 2\), where "2" is highest priority. Default priority is "0". | 
| CBP.FileAnalysis.PathName | String | Path of the file where the file exists on the endpoint. | 
| CBP.FileAnalysis.ComputerID | String | ID of the computer entry associated with this analysis. | 
| CBP.FileAnalysis.DateModified | Date | Date/time when the fileAnalysis request was last modified \(UTC\). | 
| CBP.FileAnalysis.FileCatalogId | String | ID of the fileCatalog entry associated with this analysis. | 
| CBP.FileAnalysis.DateCreated | Date | Date/time when the fileAnalysis request was created \(UTC\). | 
| CBP.FileAnalysis.ID | String | Unique fileAnalysis ID. | 
| CBP.FileAnalysis.CreatedBy | String | User that requested this analysis. | 

### cbp-fileUpload-get
***
Returns the object instance of this class.


#### Base Command

`cbp-fileUpload-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | (Int) Unique ID of this fileUpload. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CBP.FileUpload.Priority | Number | File analysis priority in range \(valid range: -2, 2\), where "2" is highest priority. Default priority is "0". | 
| CBP.FileUpload.FileName | String | Name of the file where the file exists on the endpoint. | 
| CBP.FileUpload.UploadPath | String | Local upload path for the file on the server \(can be a shared network path\). Note that the file is compressed in a ZIP archive. | 
| CBP.FileUpload.ComputerId | String | ID of the computer entry associated with this analysis. | 
| CBP.FileUpload.DateModified | Date | Date/time when the fileAnalysis request was last modified \(UTC\). | 
| CBP.FileUpload.ID | String | Unique fileAnalysis ID. | 
| CBP.FileUpload.FileCatalogId | String | ID of the fileCatalog entry associated with this analysis. | 
| CBP.FileUpload.DateCreated | Date | Date/time when the fileAnalysis request was created \(UTC\). | 
| CBP.FileUpload.PathName | String | Path of the file where there file exists on the endpoint. | 
| CBP.FileUpload.UploadStatus | Number | Status of the upload \(valid range: 0-6\). | 
| CBP.FileUpload.UploadedFileSize | String | Size of the uploaded file. The file size will be 0 unless the uploadStatus is "3" \(Completed\). | 
| CBP.FileUpload.CreatedBy | String | User that requested the analysis. | 

### cbp-fileUpload-download
***
Returns the bject instance of this class.


#### Base Command

`cbp-fileUpload-download`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | (Int) Unique ID of the fileUpload. | Required | 


#### Context Output

There is no context output for this command.
### cbp-fileUpload-createOrUpdate
***
Creates or updates a file upload request.


#### Base Command

`cbp-fileUpload-createOrUpdate`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fileCatalogId | (Int) ID of the fileCatalog entry for file to upload. This value can be fetched via cbp-fileCatalog-search command. | Required | 
| computerId | (Int) ID of the computer entry associated with this analysis. This value can be fetched via cbp-computer-search command. Default is 0. | Optional | 
| priority | File analysis priority in range (valid range: -2, 2), where "2" is highest priority. Default priority is "0". Possible values are: -2, -1, 0, 1, 2. | Optional | 
| uploadStatus | (Int)Status of upload. The status of "upload in progress" can be changed to "5" (Cancelled). Any upload can be changed to "6" (Deleted). | Optional | 
| id | ID of the file upload to update. If omitted, will create a new file upload. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CBP.FileUpload.Priority | Number | File analysis priority in range \(valid range: -2, 2\), where "2" is highest priority. Default priority is "0". | 
| CBP.FileUpload.CreatedByUserId | String | ID of the user that requested the analysis. | 
| CBP.FileUpload.UploadPath | String | Local upload path for this file on the server \(can be a shared network path\). Note that the file is compressed in a ZIP archive. | 
| CBP.FileUpload.FileName | String | Name of the file where the file exists on the endpoint. | 
| CBP.FileUpload.PathName | String | Path of the file where the file exists on the endpoint. | 
| CBP.FileUpload.UploadStatus | Number | Status of the upload \(valid range: 0-6\). | 
| CBP.FileUpload.ComputerID | String | ID of the computer entry associated with this analysis. | 
| CBP.FileUpload.DateModified | Date | Date/time when the fileAnalysis request was last modified \(UTC\). | 
| CBP.FileUpload.FileCatalogId | String | ID of the fileCatalog entry associated with this analysis. | 
| CBP.FileUpload.DateCreated | Date | Date/time when the fileAnalysis request was created \(UTC\). | 
| CBP.FileUpload.ID | String | Unique fileAnalysis ID. | 
| CBP.FileUpload.UploadedFileSize | Number | Size of uploaded file. The file size will be 0 unless the uploadStatus is "3" \(Completed\). | 

### cbp-fileUpload-search
***
Returns objects that match the specified criteria.


#### Base Command

`cbp-fileUpload-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | A condition contains three parts: name, operator and value. Name is any valid field in the object that is being queried. Operator (: LIKE, ! NOT LIKE, &lt; Less than, &gt; Greater than, + logical AND, - logical OR, \| separating values) is any of valid operators (see below). All operators consist of a single character. Value is compared with operator and depends on field type. For more information, see the Carbon Black documentation: https://developer.carbonblack.com/reference/enterprise-protection/8.0/rest-api/#searching. | Optional | 
| limit | (Int) Maximum number of results to retrieve. If not specified, the first 1000 results will be returned. If set to "-1", only the result count will be returned, without actual results, and the offset parameter is ignored. If set to "0", all results will be returned, and the offset parameter is ignored. Note that some result sets might be very large, resulting in query timeout. Therefore, unless you know that query will not return more than 1000 results, it is recommended to retrieve data in chunks using offset and limit. | Optional | 
| offset | (Int) Offset in the data set. | Optional | 
| group | Grouping is optional and can be defined with a single attribute: &amp;group=xyz. There can be only one grouping field, for example: group=osShortName. | Optional | 
| sort | Sorting is optional and can be defined with a single attribute: &amp;sort=xyz [ASC\|DESC], where xyz is the field name from the result set. There can be only one sorting field. Default sort order is ascending (ASC). | Optional | 
| computerId | Id of computer entry associated with this analysis. This can be fetched via cbp-computer-search. | Optional | 
| fileCatalogId | Id of fileCatalog entry associated with this upload. This can be fetched via cbp-fileCatalog-search. | Optional | 
| fileName | Name of the file where file exists on the endpoint. | Optional | 
| uploadStatus | Status of upload. Can be one of:<br/>0 = Queued<br/>1 = Initiated<br/>2 = Uploading<br/>3 = Completed<br/>4 = Error<br/>5 = Cancelled<br/>6 = Deleted. Possible values are: Queued, Initiated, Uploading, Completed, Error, Cancelled, Deleted. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CBP.FileUpload.Priority | Number | File analysis priority in range \(valid range: -2, 2\), where "2" is highest priority. Default priority is "0". | 
| CBP.FileUpload.CreatedByUserId | String | ID of the user that requested the analysis. | 
| CBP.FileUpload.UploadPath | String | Local upload path for this file on the server \(can be a shared network path\). Note that the file is compressed in a ZIP archive. | 
| CBP.FileUpload.FileName | String | Name of the file where the file exists on the endpoint. | 
| CBP.FileUpload.PathName | String | Path of the file where the file exists on the endpoint. | 
| CBP.FileUpload.UploadStatus | Number | Status of upload \(valid range: 0-6\). | 
| CBP.FileUpload.ComputerID | String | ID of the computer entry associated with this analysis. | 
| CBP.FileUpload.DateModified | Date | Date/time when the fileAnalysis request was last modified \(UTC\). | 
| CBP.FileUpload.FileCatalogId | String | ID of the fileCatalog entry associated with this analysis. | 
| CBP.FileUpload.DateCreated | Date | Date/time when the fileAnalysis request was created \(UTC\). | 
| CBP.FileUpload.ID | String | Unique fileAnalysis ID. | 
| CBP.FileUpload.UploadedFileSize | Number | Size of the uploaded file. The file size will be 0 unless the uploadStatus is "3" \(Completed\). | 

### cbp-connector-get
***
Returns the object instance of this class.


#### Base Command

`cbp-connector-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | (Int) Unique connector ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CBP.Connector.AnalysisEnabled | Boolean | "True" if the analysis component of this connector is enabled. "False" if the analysis component of this connector is disabled. | 
| CBP.Connector.AnalysisName | String | Name for the analysis component of the connector \(can be same as the name field\). | 
| CBP.Connector.AnalysisTargets | String | Array of possible analysis targets. Analysis targets are required when creating a new fileAnalysis. They usualy represent different OS and configurations and are available only for some internal connectors. | 
| CBP.Connector.CanAnalyze | Boolean | "True" if this connector can analyze files. "False" if this connector cannot analyze files. | 
| CBP.Connector.ConnectorVersion | String | Version of this connector. | 
| CBP.Connector.Enabled | Boolean | "True" if the connector is enabled. "False" if the connector is disabled. | 
| CBP.Connector.ID | String | Unique fileAnalysis ID. | 

### cbp-connector-search
***
Returns objects that match the specified criteria.


#### Base Command

`cbp-connector-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | A condition contains three parts: name, operator and value. Name is any valid field in the object that is being queried. Operator (: LIKE, ! NOT LIKE, &lt; Less than, &gt; Greater than, + logical AND, - logical OR, \| separating values) is any of valid operators (see below). All operators consist of a single character. Value is compared with operator and depends on field type. For more information, see the Carbon Black documentation: https://developer.carbonblack.com/reference/enterprise-protection/8.0/rest-api/#searching. | Optional | 
| limit | (Int) Maximum number of results to retrieve. If not specified, the first 1000 results will be returned. If set to "-1", only the result count will be returned, without actual results, and the offset parameter is ignored. If set to "0", all results will be returned, and the offset parameter is ignored. Note that some result sets might be very large, resulting in query timeout. Therefore, unless you know that query will not return more than 1000 results, it is recommended to retrieve data in chunks using offset and limit. | Optional | 
| offset | (Int) Offset in the data set. | Optional | 
| group | Grouping is optional and can be defined with a single attribute: &amp;group=xyz. There can be only one grouping field, for example: group=osShortName. | Optional | 
| sort | Sorting is optional and can be defined with a single attribute where xyz is the field name from the result set: &amp;sort=xyz [ASC\|DESC]. There can be only one sorting field. Default sort order is ascending (ASC). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CBP.Connector.AnalysisEnabled | Boolean | "True" if the analysis component of this connector is enabled. "False" if the analysis component of this connector is disabled. | 
| CBP.Connector.AnalysisName | String | Name for the analysis component of the connector \(can be same as the name field\). | 
| CBP.Connector.AnalysisTargets | String | Array of possible analysis targets. Analysis targets are required when creating a new fileAnalysis. They usualy represent different OS and configurations and are available only for some internal connectors. | 
| CBP.Connector.CanAnalyze | Boolean | "True" if this connector can analyze files. "False" if this connector cannot analyze files. | 
| CBP.Connector.ConnectorVersion | String | Version of this connector. | 
| CBP.Connector.Enabled | Boolean | "True" if the connector is enabled. "False" if the connector is disabled. | 
| CBP.Connector.ID | String | Unique fileAnalysis ID. | 

### cbp-approvalRequest-resolve
***
Resolves a file approval request.


#### Base Command

`cbp-approvalRequest-resolve`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the approval request to update. | Required | 
| resolution | Resolution of the request. Resolution can be changed for open requests or<br/>closed requests only. It can be one of:<br/>0=Not Resolved<br/>1=Rejected<br/>2=Resolved - Approved<br/>3=Resolved - Rule Change4=Resolved - Installer<br/>5=Resolved - Updater<br/>6=Resolved - Publisher<br/>7=Resolved - Other. Possible values are: Rejected, Resolved - Approved, Resolved - Rule Change4=Resolved - Installer, Resolved - Updater, Resolved - Publisher, Resolved - Other. | Required | 
| requestorEmail | Email address of the user that created this request. | Optional | 
| resolutionComments | Comments added by the user that resolved the request. | Optional | 
| status | Request status. Can be one of: 1=New, 2=Open, 3=Closed, 4=Escalated. Prohibited transitions are from any status back to 0 or 1. Possible values are: New, Open, Closed, Escalated. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CBP.ApprovalRequest.ID | Number | ID of the approval request. | 
| CBP.ApprovalRequest.ResolutionComments | String | Comments added by the user that resolved the request. | 
| CBP.ApprovalRequest.Resolution | Number | Resolution of request. Can be one of: 0=Not Resolved, 1=Rejected, 2=Resolved - Approved, 3=Resolved - Rule Change, 4=Resolved - Installer, 5=Resolved - Updater, 6=Resolved - Publisher, 7=Resolved - Other | 
| CBP.ApprovalRequest.Status | Number | Request status. Can be one of: 1=New, 2=Open, 3=Closed, 4=Escalated | 

### cbp-fileRule-createOrUpdate
***
Creates or updates a file rule. For more information, see the Carbon Black documentation: https://developer.carbonblack.com/reference/enterprise-protection/8.0/rest-api/#filerule


#### Base Command

`cbp-fileRule-createOrUpdate`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | (String) Hash associated with this rule. This parameter is not required if the fileCatalogId is supplied. | Optional | 
| fileState | (Int) File state for this rule. Can be one of: 1=Unapproved 2=Approved 3=Banned. Possible values are: 1, 2, 3. | Required | 
| id | (Int) Unique ID of this fileRule. | Optional | 
| fileCatalogId | (Int) ID of the fileCatalog entry associated with this fileRule. Can be "0" if creating or modifying the rule based on the hash or file name. This value can be fetched via cbp-fileCatalog-search command. | Optional | 
| name | (String) Name of this rule. | Optional | 
| description | (String) Description of this rule. | Optional | 
| reportOnly | (Boolean) Set to "true" to create a report-only ban. Note: fileState has to be set to "1" (unapproved) before this flag can be set. Possible values are: true, false. | Optional | 
| reputationApprovalsEnabled | (Boolean) "True" if reputation approvals are enabled for this file. "False" if reputation approvals are disabled for this file. Possible values are: true, false. | Optional | 
| forceInstaller | (Boolean) "True" if this file is forced to act as installer, even if the product detected it as ‘not installer’. Possible values are: true, false. | Optional | 
| forceNotInstaller | (Boolean) "True" if this file is forced to act as ‘not installer’, even if the product detected it as installer. Possible values are: true, false. | Optional | 
| policyIds | (String) List of IDs of policies to which this rule applies. Set to "0" if this is a global rule. | Optional | 
| platformFlags | (Int) Set of platform flags where this file rule will be valid. combination of: 1 = Windows 2 = Mac 4 = Linux. | Optional | 
| headers | Headers to present of the returned table. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CBP.FileRule.CatalogID | String | The file catalog ID for the rule. | 
| CBP.FileRule.Description | String | The rule description. | 
| CBP.FileRule.FileState | String | The file state for the rule. | 
| CBP.FileRule.Hash | String | The hash for the rule. | 
| CBP.FileRule.ID | String | The rule ID. | 
| CBP.FileRule.Name | String | The rule name. | 
| CBP.FileRule.PolicyIDs | String | The policies this rule belongs to. | 
| CBP.FileRule.ReportOnly | String | Is this rule "reporting only" or is it also "enforcing". | 
