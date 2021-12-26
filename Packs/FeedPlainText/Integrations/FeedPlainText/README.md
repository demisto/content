## Plain Text Feed Integration

Fetches indicators from a plain text feed. The integration allows a many user configurations to support different types of plain text feeds.

## Configuration

* **Server URL** - URL of the feed.
* **Indicator Type** - The type of indicators in the feed. If the *Custom* option is selected, the *Custom Indicator Type* parameter must be provided.
* **Custom Indicator Type** - The indicator type to be used in case of *Custom* option chosen in the *Indicator Type* field.
* **Username + Password** - Credentials to access feeds that require basic authentication. 
These fields also support the use of API key headers. To use API key headers, specify the header name and value in the following format:
`_header:<header_name>` in the **Username** field and the header value in the **Password** field.
* **Ignore Regex** - Python regular expression for lines that should be ignored.
* **Indicator extraction pattern** - A JSON string of an extraction pattern for the indicator value in the text that consists of a regular expression and a transform template for each regex group. For example:
```json
{
  "regex": "^([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})\\t([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})",
  "transform": "\\1-\\2"
}
```
* **Fields extraction pattern** - A JSON string of an extraction pattern for the additional fields in the text that consists of a regular expression and a transform template for each regex group. For example:
```json
{
  "number_of_attacks":
    {
        "regex": "^.*\\t.*\\t[0-9]+\\t([0-9]+)",
        "transform": "\\1"
    },
  "name":
     {  
        "regex": ",^.*\\t.*\\t[0-9]+\\t[0-9]+\\t([^\\t]+)",
        "transform": "\\1"
     }
}
```

For more information about regular expression extraction, see this [python documentation](https://docs.python.org/3/library/re.html#match-objects).

* **Headers** -  CSV list of headers to send in the HTTP request in the format of "header_name:header_value". For example:

`Content-Type:text/plain,Accept:application/json`


## Step by step configuration
As an example, we'll be looking at the Recommended Block List feed by DShield. This feed will ingest indicators of type CIDR. These are the feed instance configuration parameters for our example.

**Indicator Type** - CIDR.

**Server URL**: https://www.dshield.org/block.txt

**Credentials** - This feed does not require authentication.

From a quick look at the feed in the web browser, we are going to configure the rest of the parameters:

**Ignore Regex** - We are going to need to ignore all the text inside the part enclosed within the `#` character (included) 
so we'll configure `^#` as the regular expression to use to ignore this text.

**Indicator extraction pattern** - We would like to extract the IP range and turn it into a CIDR. For that, we will configure a regular expression to extract both IP addresses in the range into 2 groups,
and transform the 2 groups to an IP range. We will then convert the IP range into a CIDR in the integration code.

This would be our extraction pattern object as a JSON string which we will fill in the field in the instance configuration:
```json
{
  "regex": "^([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})\\t([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})",
  "transform": "\\1-\\2"
}
```

****Fields extraction pattern**** - We want to extract the name and the number of attacks field for each IP range in the feed.
For each field we will configure a regular expression to extract it and then a template to grab the regex group as is.
This would be the JSON string we will use in the integration configuration:
```json
{
  "number_of_attacks":
    {
        "regex": "^.*\\t.*\\t[0-9]+\\t([0-9]+)",
        "transform": "\\1"
    },
  "name":
     {  
        "regex": "^.*\\t.*\\t[0-9]+\\t[0-9]+\\t([^\\t]+)",
        "transform": "\\1"
     }
}
```

Then our indicator will have these 2 additional fields. We can map them to other indicator fields in the system later.


**Headers** - No need for additional headers.

Now we have successfully configured an instance for the DShield Black List feed, once we enable `Fetches indicators` the instance will start pulling indicators.

By clicking `Mapping` in the integration instance, we can map the fields we previously configured to actual indicator fields.
We can use `Set up a new classification rule` to use actual data from the feed.
