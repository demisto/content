## Overview

---

Fetch indicators from a ZeroDayLive feed.
Zero Day Live is our threat intelligence platform. It services multiple security vendors within the industry with the latest intelligence in order to prevent cyber attacks.  

## Configure ZeroDayLive Feed on Cortex XSOAR

---


1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Zero Day Live TI FUSION Feed.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __URL__: Server URL where the feed is.
    * __Fetch indicators__: boolean flag. If set to true will fetch indicators.
    * __Fetch Interval__: Interval of the fetches.
    * __Reliability__: Reliability of the feed. 
    * __Traffic Light Protocol Color__: The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. More information about the protocol can be found at <https://us-cert.cisa.gov/tlp>
    * __Username + Password__ - Credentials to access feeds that require basic authentication. 
These fields also support the use of API key headers. To use API key headers, specify the header name and value in the following format:
`_header:<header_name>` in the __Username__ field and the header value in the __Password__ field.
    * __Use system proxy settings__
    * __Request Timeout__: Time (in seconds) before HTTP requests timeout.
    * __Field Names__: Name of the field names in the CSV. If several are given, will use
    "value" as the indicator value field.
4. Click __Test__ to validate the URLs, token, and connection.


## Step by step configuration

As an example, we'll be looking at the Palo-Alto-sha256 feed. This feed will ingest indicators of type File. These are the feed instance configuration parameters for our example

**Indicator Type** - File.
**Server URL**: <https://digitalwitness.zeroday.live/exports/download/Palo-Alto-sha256.csv>.
**Credentials** - user: *XXX*, password: *XXX* - need to be obtained from Zero Day Live portal.

The other paramer values can stay with defualt

**Field Names** - There is only single field and that field is the indicator to fetch. So to confgiure that we can leave default `value` as is.
