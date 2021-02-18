## Overview
---

Use the Bambenek Consulting feed integration to fetch indicators from the feed.


## Configure Bambenek Consulting Feed on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Bambenek Consulting Feed.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Services__: Services of Bambenek Consulting to fetch indicators from:
        * C2 IP Feed - Master Feed of known, active, and non-sinkholed C&Cs IP addresses.
        * High-Confidence C2 IP Feed - Master Feed of known, active, and non-sinkholed C&Cs IP addresses (high-confidence only).
        * C2 Domain Feed - Master Feed of known, active, and non-sinkholed C&Cs domain names.
        * High-Confidence C2 Domain Feed - Master Feed of known, active, and non-sinkholed C&Cs domain names (high-confidence only).
        * C2 All Indicator Feed - Master list feed of all current C&C domains using DGAs.
        * High-Confidence C2 All Indicator Feed - Master list feed of all current C&C domains using DGAs (high-confidence only).
        * DGA Domain Feed - Domain feed of known DGA domains from -2 to +3 days.
        * High-Confidence DGA Domain Feed - Domain feed of known DGA domains from -2 to +3 days (high-confidence only).
        * Sinkhole Feed - Manually curated list of IPs known to be sinkholes, provided by Bambenek Consulting. Sinkholing is a technique where security researchers or security companies take over network infrastructure used by malware.
    * **Username + Password** - Credentials to access services that require basic authentication. 
    These fields also support the use of API key headers. To use API key headers, specify the header name and value in the following format:
    `_header:<header_name>` in the **Username** field and the header value in the **Password** field.
    * __Fetch indicators__: boolean flag. If set to true will fetch indicators.
    * __Fetch Interval__: Interval of the fetches.
    * __Reliability__: Reliability of the feed.  
    * __Traffic Light Protocol color__: The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. More information about the protocol can be found at https://us-cert.cisa.gov/tlp 
    * __Skip Exclusion List__: When selected, the exclusion list is ignored for indicators from
    this feed. This means that if an indicator from this feed is on the exclusion
    list, the indicator might still be added to the system. 
    * __Indicator reputation__: Indicators from this integration instance will be marked with this
    reputation.
    * __Request Timeout__: Timeout of the polling request in seconds.
4. Click __Test__ to validate the URLs, token, and connection.

## Troubleshooting  
---
Bambenek Consulting has two license types: Commercial and Non-Commercial, each of which have specific feeds available.

List of commercial feeds:
* DGA Domain Feed
* High-Confidence DGA Domain Feed
* C2 All Indicator Feed
* High-Confidence C2 All Indicator Feed
* Sinkhole Feed

List of non-commercial feeds:
* C2 IP Feed
* High-Confidence C2 IP Feed
* C2 Domain Feed
* High-Confidence C2 Domain Feed

For more information visit [Bambenek Consulting Feeds](https://osint.bambenekconsulting.com/feeds/)
