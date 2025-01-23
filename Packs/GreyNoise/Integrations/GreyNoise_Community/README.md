GreyNoise tells security analysts what not to worry about. We do this by curating data on IPs that saturate security
tools with noise. This unique perspective helps analysts confidently ignore irrelevant or harmless activity, creating
more time to uncover and investigate true threats. The Action allows IP enrichment via the GreyNoise Community API.

This Integration is design specifically for GreyNoise Community users and only provides the subset of intel available 
via the GreyNoise Community API.  
The [GreyNoise Integration](https://github.com/demisto/content/tree/master/Packs/GreyNoise/Integrations/GreyNoise) 
should be used by customers with a paid subscription to GreyNoise.

This integration was integrated and tested with version 0.8.0 of GreyNoise Python SDK.
Supported Cortex XSOAR versions: 5.5.0 and later.

## Configure GreyNoise in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| api_key | GreyNoise API Key | True |
| proxy | Use system proxy settings | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### greynoise-community-lookup

***
Queries IPs in the GreyNoise Community API.


#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | List of IPs. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| IP.address | string | IP address. |
| IP.Malicious.Description | string | Description of Malicious IP. |
| IP.Malicious.Vendor | string | Vendor Identifying IP as Malicious. |
| GreyNoise.IP.address | string | The IP address of the scanning device IP. |
| GreyNoise.IP.classification | string | Whether the device has been categorized as unknown, benign, or malicious. |
| GreyNoise.IP.last_seen | date | The date the device was last observed by GreyNoise. Format is ISO8601. |
| GreyNoise.IP.link | string | Link to the GreyNoise Visualizer record. |
| GreyNoise.IP.noise | boolean | Has the IP been seen scanning the Internet |
| GreyNoise.IP.riot | boolean | Is the IP part of a known benign service |
| GreyNoise.IP.name | string | The overt actor the device has been associated with. |
| GreyNoise.IP.message | string | Additional Information from API. |
| IP.Address | string | IP address. |


#### Command Example

``` !greynoise-community-lookup ips=1.2.3.4 ```

#### Human Readable Output

### IP: 71.6.135.131 found with Reputation: Good

### GreyNoise Community IP Response

|IP|Noise|RIOT|Classification|Name|Link|Last Seen
|---|---|---|---|---|---|---|
| 71.6.135.131 | true | false | benign | Shodan.io | <https://viz.greynoise.io/ip/71.6.135.131> | 2021-02-03 |