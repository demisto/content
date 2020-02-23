Fetch indicators from a CSV feed. The integration allows a great amount of user configuration to support different types of CSV feeds.

* **Indicator Type** - The type of indicators in the feed.
* **Server URL** - URL of the feed.
* **Username + Password** - Credentials to access feeds that require basic authentication. 
These fields also support the use of API key headers. To use API key headers, specify the header name and value in the following format:
`_header:<header_name>` in the **Username** field and the header value in the **Password** field.
* **Ignore Regex** - Python regular expression for lines that should be ignored.
* **Field Names** - The names to give the fields in the CSV feed. The name for the field containing the indicator should be "value".
* **Double quote** - Controls how instances of quote character appearing inside a field should themselves be quoted. When True, the character is doubled. When False, the escape character is used as a prefix to the quote characters.
* **Delimiter** -  A one-character string used to separate fields.
* **Quote Character** - A one-character string used to quote fields containing special characters.
* **Escape character** - A one-character string used by the writer to escape the delimiter.
* **Skip Initial Space** - When True, whitespace immediately following the delimiter is ignored.

## Step by step configuration
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
