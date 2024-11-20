
Use the JSON feed integration to fetch indicators from a JSON feed. This integration allows for a wide variety of user configuration to support different types of JSON feeds.

## Configure JSON Feed in Cortex
---


| Parameter | Description |
| --- | --- |
| Name | A meaningful name for the integration instance. |
| Fetch indicators | Whether to fetch indicators, if checked. |
| Indicator Reputation | The reputation applied to indicators from this integration instance. The default value is "Bad". |
| Source Reliability | The reliability of the source providing the intelligence data. The default value is "C - Fairly reliable" |
| Traffic Light Protocol Color | The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. More information about the protocol can be found at https://us-cert.cisa.gov/tlp |
| Indicator Expiration Method | The method by which to expire indicators from this feed for this integration instance. |    
| Feed Fetch Interval | How often to fetch indicators from the feed for this integration instance (in minutes). The default value is 60. | 
| URL | The URL of the feed. | 
| Auto detect indicator type | Whether a type auto detection mechanism will take place for each indicator, if checked. |
| Indicator Type | The type of the indicator in the feed. This is relevant only if `Auto detect` is not checked. | 
| Username + Password | The credentials used to access feeds that require basic authentication. These fields also support the use of API key headers. To use API key headers, specify the header name and value in the following format: `_header:<header_name>` in the **Username** field and the header value in the **Password** field. | 
| JMESPath Extractor | The JMESPath expression for extracting the indicators from. You can check the expression in the [JMESPath site](http://jmespath.org/) to verify this expression will return the following array of objects. |    
| JSON Indicator Attribute | The JSON attribute whose value is the indicator. The default is "indicator". |
| POST Data | Send specified data in a POST request. When specified, by default will add the header: `Content-Type: application/x-www-form-urlencoded`. To specify a different Content-Type (for example: application/json) use the **Headers** config param. | 
| Headers | Headers to add to the http request. Specify each header on a single line in the format: `Name: Value`. |
| Include indicator type for mapping | When using a custom classifier and mapper with this feed, use this option to include the indicator type in the raw json used for classification and mapping. The type will be included under the key `_indicator_type`. |
| Bypass Exclusion List | Whether the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. |



## Step-by-step configuration
---

IP address ranges from Amazon AWS will be used as examples. The feed will ingest indicators of the CIDR type. These are the feed instance configuration parameters for our example.

**URL**: https://ip-ranges.amazonaws.com/ip-ranges.json

**Auto detect indicator type**: Checked.

**Indicator Type** - Leave this empty and the system will identify the indicator type.

**Credentials** - This feed does not require authentication.

The following parameters will be configured based on the feed in the web browser.

**JMESPath Extractor** - prefixes[?service=='AMAZON'] This means that the desired objects to extract the indicators from is
`prefixes`, and the objects will be filtered by where the field `service` is equal to `AMAZON`.

**JSON Indicator Attribute** - The `ip_prefix`.

At this point, an instance for the IP ranges from Amazon AWS has been successfully configured. After `Fetches indicators` have been enabled, the instance will start pulling indicators.

By clicking `Mapping` in the integration instance, the field names we previously configured can be mapped to the actual indicator fields (except `value` which is the indicator value).
We can use `Set up a new classification rule` using actual data from the feed.

## Commands
---
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### Get indicators from the feed
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

## Demo Video
<video controls>
    <source src="https://github.com/demisto/content-assets/raw/7982404664dc68c2035b7c701d093ec026628802/Assets/FeedJSON/Json_generic_feed_demo.mp4"
            type="video/mp4"/>
    Sorry, your browser doesn't support embedded videos. You can download the video at: https://github.com/demisto/content-assets/blob/7982404664dc68c2035b7c701d093ec026628802/Assets/FeedJSON/Json_generic_feed_demo.mp4 
</video>