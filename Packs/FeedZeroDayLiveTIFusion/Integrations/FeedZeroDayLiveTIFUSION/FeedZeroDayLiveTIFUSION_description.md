Fetch indicators from a ZeroDayLive feed.

* **Indicator Type** - The type of indicators in the feed.
* **Server URL** - URL of the feed.
* **Username + Password** - Credentials to access feeds that require basic authentication. 
These fields also support the use of API key headers. To use API key headers, specify the header name and value in the following format:
`_header:<header_name>` in the **Username** field and the header value in the **Password** field.


## Step by step configuration

As an example, we'll be looking at the Palo-Alto-sha256 feed. This feed will ingest indicators of type File. These are the feed instance configuration parameters for our example

**Indicator Type** - File.
**Server URL**: <https://digitalwitness.zeroday.live/exports/download/Palo-Alto-sha256.csv>.
**Credentials** - user: *XXX*, password: *XXX* - need to be obtained from Zero Day Live portal.

The other paramer values can stay with defualt

**Field Names** - There is only single field and that field is the indicator to fetch. So to confgiure that we can leave default `value` as is.
