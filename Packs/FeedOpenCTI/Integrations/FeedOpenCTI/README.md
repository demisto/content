Ingest indicator feeds from OpenCTI. 
Compatible with OpenCTI v3 instances. For v4.* and grater OpenCTI versions use the OpenCTI Feed 4.X integration.
## Configure OpenCTI Feed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| apikey | API Key | True |
| base_url | Base URL | True |
| indicator_types | Indicators Type to fetch | True |
| max_indicator_to_fetch | Max. indicators per fetch \(default is 500\) | False |
| feed | Fetch indicators | False |
| feedReputation | Indicator Reputation | False |
| feedReliability | Source Reliability | True |
| feedExpirationPolicy |  | False |
| feedExpirationInterval |  | False |
| feedFetchInterval | Feed Fetch Interval | False |
| feedTags | Tags | False |
| feedBypassExclusionList | Bypass exclusion list | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

#### Indicator type parameter
Possible values that are supported in XSOAR and will be generated out of the box:

| **Types** |
| --- |
| ALL |
| User-Account |
| Domain |
| Email-Address| 
| File-md5| 
|File-sha1| |
|File-sha256|
|HostName| 
|IPV4-Addr|
|IPV6-Addr| 
|Registry-Key-Value|
|URL|
 
The following types are supported in OpenCTI but are not supported out of the box in XSOAR. To pull these indicator types from OpenCTI you will need to either create dedicated [classification and mapping](https://xsoar.pan.dev/docs/incidents/incident-classification-mapping) and/or create corresponding indicator types in your XSOAR system.


| **Types** |
| --- |
|autonomous-system|
|cryptographic-key|
|cryptocurrency-wallet|
|email-subject|
|directory|
|file-name|
|file-path|
|mac-addr|
|mutex|
|pdb-path|
|process|
|registry-key-value|
|user-agent|
|windows-service-name|
|windows-service-display-name|
|windows-scheduled-task|
|x509-certificate-issuer|
|x509-certificate-serial-number|


## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### opencti-get-indicators
***
Gets indicators from the feed.


#### Base Command

`opencti-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to return per fetch. The default value is "50". | Optional | 
| indicator_types | The indicator types to fetch. Out of the box indicator types supported in XSOAR are: "User-Account", "Domain", "Email-Address", "File-md5", "File-sha1", "File-sha256", "HostName", "IPV4-Addr", "IPV6-Addr", "Registry-Key-Value", and "URL". The rest will not cause automatic indicator creation in XSOAR. Please refer to the integration documentation for more information. The default is "ALL". | Optional | 
| last_id | The last ID from the previous call from which to begin pagination for this call. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.Indicators.type | String | Indicator type. | 
| OpenCTI.Indicators.value | String | Indicator value. | 
| OpenCTI.LastRunID | String | the id of the last fetch to use pagination. | 


#### Command Example
```!opencti-get-indicators limit=2 indicator_types=domain```

#### Context Example
```
{
    "OpenCTI": {
        "Indicators": [
            {
                "type": "Domain",
                "value": "test.com"
            },
            {
                "type": "Domain",
                "value": "test1.com"
            }
        ],
        "LastRunID": "YXJyYXljb25uZWN0aW9uOjI="
    }
}
```

#### Human Readable Output

>### Indicators from OpenCTI
>|type|value|
>|---|---|
>| Domain | test.com |
>| Domain | test.com |


### opencti-reset-fetch-indicators
***
WARNING: This command will reset your fetch history.


#### Base Command

`opencti-reset-fetch-indicators`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!opencti-reset-fetch-indicators```

#### Context Example
```
{}
```

#### Human Readable Output

>Fetch history deleted successfully