## Overview
---


Fetch indicators from a CSV feed. The integration allows a great amount of user configuration to support different types of CSV feeds.


## Configure CSV Feed on Cortex XSOAR
---


1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for CSVFeed.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __URL__: Server URL where the feed is.
    * __Fetch indicators__: boolean flag. If set to true will fetch indicators.
    * __Fetch Interval__: Interval of the fetches.
    * __Reliability__: Reliability of the feed. 
    * __Traffic Light Protocol Color__: The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. More information about the protocol can be found at https://us-cert.cisa.gov/tlp
    * __Username + Password__ - Credentials to access feeds that require basic authentication. 
These fields also support the use of API key headers. To use API key headers, specify the header name and value in the following format:
`_header:<header_name>` in the **Username** field and the header value in the **Password** field.
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
    * __Request Timeout__: Time (in seconds) before HTTP requests timeout.
    * __Ignore Regex__: Python regular expression for lines that should be ignored.
    * __Field Names__: Name of the field names in the CSV. If several are given, will use
    "indicator" as the indicator value field.
    * __Delimiter__: A one-character string used to separate fields.
    * __Double quote__: Controls how instances of quote character appearing inside a field should themselves be quoted. When True, the character is doubled. When False, the escapechar is used as a prefix to the quotechar. It defaults to True.
    * __Escape character__: A one-character string used by the writer to escape the delimiter.
    * __Quote Character__: A one-character string used to quote fields containing special characters.
    * __Skip Initial Space__: When True, whitespace immediately following the delimiter is ignored.
4. Click __Test__ to validate the URLs, token, and connection.


## Step by step configuration
---
As an example, we'll be looking at the SSL BL feed by Abuse. This feed will ingest indicators of type IP. These are the feed isntance configuration parameters for our example.

**Indicator Type** - IP.

**Server URL**: https://sslbl.abuse.ch/blacklist/sslipblacklist.csv.

**Credentials** - This feed does not require authentication.

From a quick look at the feed in the web browser, we are going to configure the rest of the parameters:

**Ignore Regex** - We are going to need to ignore all the text inside the part enclosed by the `#` character (included) 
so we'll configure `^#` as the regular expression to use to ignore this text.

**Field Names** - We have 3 fields in this feed - `Firstseen,DstIP,DstPort`. The integration ignores these headers and we have to configure the field names for each indicator.
Note that the field for the indicator value itself (the IP) must be `value`. So we will configure these field names: `date,value,name`, so that the indicator will be created with these fields.

**Double quote** - No need to double the quote characters, we'll leave this option unchecked.

**Delimiter** - The delimiter between the fields in this feed is `,`, we'll use that as the value for this field.

**Quote Character** - No need to change the quote character, we'll leave that as the default (`"`).

**Escape Character** - No need to change the escape character, we'll leave that empty.

**Skip Initial Space** - No whitespaces between the delimiter and the value, we'll leave the unchecked.

Now we have successfully configured an instance for the Abuse SSL BL feed, once we enable `Fetches indicators` the instance will start pulling indicators.

By clicking `Mapping` in the integration instance, we can map the field names we previously configured to actual indicator fields (except `value` which is the indicator value).
We can use `Set up a new classification rule` using actual data from the feed.


## Demo Video
---
<video controls>
    <source src="https://github.com/demisto/content-assets/raw/7982404664dc68c2035b7c701d093ec026628802/Assets/FeedCSV/CSVFeed_Video.mp4"
            type="video/mp4"/>
    Sorry, your browser doesn't support embedded videos. You can download the video at: https://github.com/demisto/content-assets/blob/7982404664dc68c2035b7c701d093ec026628802/Assets/FeedCSV/CSVFeed_Video.mp4 
</video>
