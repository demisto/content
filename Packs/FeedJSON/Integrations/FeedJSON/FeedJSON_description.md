Fetch indicators from a JSON feed. The integration supports a large amount of user configurations to support different types of JSON feeds.

* **URL** - URL of the feed.
* **Auto detect indicator type** - If checked, a type auto detection mechanism will take place for each indicator.
* **Indicator Type** - Type of the indicator in the feed. Relevant only if Auto detect is not checked.
* **Username + Password** - Credentials to access feeds that require basic authentication. 
These fields also support the use of API key headers. To use API key headers, specify the header name and value in the following format:
`_header:<header_name>` in the **Username** field and the header value in the **Password** field.
* **JMESPath Extractor** - JMESPath expression for extracting the indicators from. You can check the expression in 
the [JMESPath site](http://jmespath.org/) to verify this expression will return the following array of objects.
* **JSON Indicator Attribute** - JSON attribute whose value is the indicator. Default is 'indicator'.
* **Headers** - Headers to add to the http request. Specify each header on a single line in the format: 'Name: Value'. For example: `Content-Type: application/json`. 
* **POST Data** - Send specified data in a POST request. When specified, by default will add the header: 'Content-Type: application/x-www-form-urlencoded'. To specify a different Content-Type (for example: application/json) use the **Headers** config param.
* **Include Indicator Type for Mapping** - When using a custom classifier and mapper with this feed, use this option to include the indicator type in the raw json used for classification and mapping. The type will be included under the key `_indicator_type`. 

## Step by step configuration
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
