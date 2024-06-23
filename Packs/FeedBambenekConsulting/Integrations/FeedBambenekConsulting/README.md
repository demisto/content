## Overview

---

Use the Bambenek Consulting feed integration to fetch indicators from the feed.


## Configure Bambenek Consulting Feed on Cortex XSOAR

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
        * DGA Domain Feed - A self-curating feed that monitors malicious networks to observe current criminal activity. All domains are actionable. Live data of between 750 and 1,500 domains. which are used by 65 malware families and nearly 1 million domains. Limited to current relevance.
        * High-Confidence DGA Domain Feed - A self-curating feed that monitors malicious networks to observe current criminal activity. All domains are actionable. Live data of between 750 and 1,500 domains. which are used by 65 malware families and nearly 1 million domains. Limited to current relevance. High-confidence data, extremely low false-positives.
        * Sinkhole Feed - A manually-curated list of over 1,500 known sinkholes. The feed is used to capture traffic headed toward criminal destinations. Catch traffic headed toward them, and you know you have an infected machine.
        * Malware Domains Feed - A feed based on machine learning and analytic methods of DNS telemetry developed in Bambenek Labs. Identifies malware hostnames used primarily for criminal purposes. Data is extremely safe to use to proactively protect networks.
        * Phishing Domains Feed - A feed based on machine learning and analytic methods of DNS telemetry developed in Bambenek Labs. Identifies phishing hostnames used primarily for criminal purposes. Data is extremely safe to use to proactively protect networks.
    * __Username + Password__ - Credentials to access services that require basic authentication. 
    These fields also support the use of API key headers. To use API key headers, specify the header name and value in the following format:
    `_header:<header_name>` in the __Username__ field and the header value in the __Password__ field.
    * __Fetch indicators__: boolean flag. If set to true will fetch indicators.
    * __Fetch Interval__: Interval of the fetches.
    * __Reliability__: Reliability of the feed.  
    * __Traffic Light Protocol color__: The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. More information about the protocol can be found at <https://us-cert.cisa.gov/tlp> 
    * __Skip Exclusion List__: When selected, the exclusion list is ignored for indicators from
    this feed. This means that if an indicator from this feed is on the exclusion
    list, the indicator might still be added to the system. 
    * __Indicator reputation__: Indicators from this integration instance will be marked with this
    reputation.
    * __Request Timeout__: Timeout of the polling request in seconds.
4. Click __Test__ to validate the URLs, token, and connection.

## Gain Access  

Get a quote and subscribe: sales@bambenekconsulting.com