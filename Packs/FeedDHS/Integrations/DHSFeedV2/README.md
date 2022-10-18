The Cybersecurity and Infrastructure Security Agency’s (CISA’s) free Automated Indicator Sharing (AIS) capability enables the exchange of cyber threat indicators, at machine speed, to the Federal Government community.

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration-dhs-feed-v2).

## Configure DHS Feed v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for DHS Feed v2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Fetch indicators |  | False |
    | Discovery Service URL (e.g. https://ais2.cisa.dhs.gov/taxii2/) |  | True |
    | Key File as Text | For more information, visit https://us-cert.cisa.gov/ais. | True |
    | Certificate File as Text | For more information, visit https://us-cert.cisa.gov/ais. | True |
    | Default API Root to use | The default API Root to use \(e.g. default, public\). If left empty, the server default API root will be used. When the server has no default root, the first available API root will be used instead. The user must be authorized to reach the chosen API root. | False |
    | Collection Name To Fetch Indicators From | Indicators will be fetched from this collection. Run "dhs-get-collections" command to get a valid value. If left empty, the instance will try to fetch from all the collections in the given discovery service. | False |
    | Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
    | Source Reliability | Reliability of the source providing the intelligence data. | True |
    | Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |
    | Feed Fetch Interval |  | False |
    | First Fetch Time | The time interval for the first fetch \(retroactive\). &amp;lt;number&amp;gt; &amp;lt;time unit&amp;gt; of type minute/hour/day/year. For example, 1 minute, 12 hour. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
    | Max Indicators Per Fetch | The maximum number of indicators that can be fetched per fetch. If this field is left empty, there will be no limit on the number of indicators fetched. | False |
    | STIX Objects To Fetch |  | False |
    | Max STIX Objects Per Poll | Set the number of stix object that will be requested with each taxii poll \(http request\). A single fetch is made of several taxii polls. Changing this setting can help speed up fetches, or fix issues on slower networks. Please note server restrictions may apply, overriding and limiting the requested limit. | False |
    | Complex Observation Mode | Choose how to handle complex observations. Two or more Observation Expressions MAY be combined using a complex observation operator such as "AND", "OR". e.g. \`\[ IP = 'b' \] AND \[ URL = 'd' \]\` | False |
    | Tags | Supports CSV values. | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### dhs-get-indicators
***
Allows you to test your feed and to make sure you can fetch indicators successfuly.


#### Base Command

`dhs-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| raw | Will return only the rawJSON of the indicator object. Possible values are: true, false. Default is false. | Optional | 
| limit | Maximum number of indicators to return. Default is 10. | Optional | 
| added_after | Fetch only indicators that were added to the server after the given time. Please provide a &lt;number&gt; and &lt;time unit&gt; of type minute/hour/day. For example, 1 minute, 12 hour, 24 days. Default is 20 days. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DHS.Indicators.value | String | Indicator value. | 
| DHS.Indicators.type | String | Indicator type. | 
| DHS.Indicators.rawJSON | String | Indicator rawJSON. | 

### dhs-get-collections
***
Gets the list of collections from the discovery service.


#### Base Command

`dhs-get-collections`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DHS.Collections.ID | String | Collection ID. | 
| DHS.Collections.Name | String | Collection Name. | 

## Breaking changes from the previous version of this integration - DHS Feed v2
### Arguments
#### The following arguments were removed in this version:

In the *dhs-get-indicators* command:
* *tlp_color* - this argument was removed.

#### The behavior of the following arguments was changed:

In the *dhs-get-indicators* command:
* *limit* - The default value changed to '10'.

### Outputs
#### The following outputs were removed in this version:

In the *dhs-get-indicators* command:
* *DHS.type* - this output was replaced by *DHS.Indicators.type*.
* *DHS.value* - this output was replaced by *DHS.Indicators.value*.
* *DHS.tlp* - this output was removed.

## Additional Considerations for this version
* Use this version if your certificate is supporting TAXII 2 protocol.