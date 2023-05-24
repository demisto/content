## Overview

---

Fetch indicators from a ZeroDayLive feed.
Zero Day Live is our threat intelligence platform. It services multiple security vendors within the industry with the latest intelligence in order to prevent cyber attacks.  

## Configure ZeroDayLive Feed on Cortex XSOAR

---


1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for ZeroDayTIFusion.
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
4. Click __Test__ to validate the URLs, token, and connection.


## Step by step configuration

---

* __Indicator Type__ - The type of indicators in the feed.
* __Server URL__ - URL of the feed.
* __Username + Password__ - Credentials to access feeds that require basic authentication. 

## Step by step configuration

This feed will ingest indicators of type File. These are the feed instance configuration
parameters for our example.

__Indicator Type__ - File.
__Server URL__: <https://digitalwitness.zeroday.live/exports/download/Palo-Alto-sha256.csv>.
__Credentials__ - user: *XXX*, password: *XXX*.
