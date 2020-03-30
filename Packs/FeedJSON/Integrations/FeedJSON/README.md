## Overview
---

Fetch indicators from a JSON feed. The integration allows a great amount of user configuration to support different types of JSON feeds.

## Configure JSON Feed on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for JSON feed.
3. Click __Add instance__ to create and configure a new integration instance.

    | Parameter | Description |
    | --- | --- |
    | Name | A meaningful name for the integration instance. |
    | Fetch indicators | Select this check box to fetch indicators. |
    | Indicator Reputation | The reputation applied to indicators from this integration instance. The default value is Bad. |
    | Source Reliability | Reliability of the source providing the intelligence data. The default value is C - Fairly reliable |
    | Indicator Expiration Method | The method by which to expire indicators from this feed for this integration instance. |
    | Indicator Expiration Interval | How often to expire the indicators from this integration instance (in minutes). Only applies if the feedExpirationPolicy is "interval". The default value is 20160 (two weeks). |
    | Feed Fetch Interval | How often to fetch indicators from the feed for this integration instance (in minutes). The default value is 60. | 
    | URL | URL of the feed. | 
    | Auto detect indicator type | If checked, a type auto detection mechanism will take place for each indicator. |
    | Indicator Type | Type of the indicator in the feed. Relevant only if Auto detect is not checked. | 
    | Username + Password | Credentials to access feeds that require basic authentication. These fields also support the use of API key headers. To use API key headers, specify the header name and value in the following format: `_header:<header_name>` in the **Username** field and the header value in the **Password** field. | 
    | JMESPath Extractor | JMESPath expression for extracting the indicators from. You can check the expression in the [JMESPath site](http://jmespath.org/) to verify this expression will return the following array of objects. |
    | JSON Indicator Attribute | JSON attribute whose value is the indicator. Default is 'indicator'. |
    | Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. |

4. Click __Test__ to validate the URLs and connection.


## Step by step configuration
---

As an example, we'll be looking at the IP ranges from Amazon AWS. This feed will ingest indicators of type CIDR. These are the feed instance configuration parameters for our example.

**URL**: https://ip-ranges.amazonaws.com/ip-ranges.json

**Auto detect indicator type**: Checked.

**Indicator Type** - Leave it empty and let the system identify the indicator type.

**Credentials** - This feed does not require authentication.

From a quick look at the feed in the web browser, we are going to configure the rest of the parameters:

**JMESPath Extractor** - prefixes[?service=='AMAZON'] This means that the desired objects to extract the indicators from is
`prefixes`, and the objects will be filtered by where the field `service` is equal to `AMAZON`.

**JSON Indicator Attribute** - ip_prefix

Now we have successfully configured an instance for the IP ranges from Amazon AWS. After we enable `Fetches indicators` the instance will start pulling indicators.

By clicking `Mapping` in the integration instance, we can map the field names we previously configured to actual indicator fields (except `value` which is the indicator value).
We can use `Set up a new classification rule` using actual data from the feed.

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### Get indicators from the feed: json-get-indicators
---
Gets the feed indicators.

##### Base Command

`!json-get-indicators`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. The default value is 50. | Optional | 


##### Context Output

There is no context output for this command.
