Fetch indicators from URLhaus feed. 

* **Indicator Reputation** - Dropdown select for the reputation of the feed.
* **Feed Source** - The kind of indicators you wish to receive based on the status of the urls.
* **Traffic Light Protocol Color** - The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed.
* **Indicator Expiration Method** - The preferred expiration method.
* **Tags** - Tags for data from the feed.
* **Trust any certificate (not secure)** - Turn on/off secure http access, mark as true if you cannot access the api and you trust it.
* **Indicator Verdict** -  The type of indicator that are returned by the feed.
* **Source Reliability** - Reliability of the source providing the intelligence data.
* **Feed Fetch Interval** - The time to fetch indicators for the feed.

## Step by step configuration
As an example, we'll be looking at the URLhaus feed by Abuse. This feed will ingest indicators of type URL. These are the feed isntance configuration parameters for our example.

**Indicator Reputation** - Malicious
**Feed Source** - Currently Active
**Traffic Light Protocol Color** - WHITE
**Indicator Expiration Method** - Indicator Type 
**Tags** - None
**Trust any certificate (not secure)** - True
**Indicator Verdict** - Malicious
**Source Reliability** - B - Usually reliable
**Feed Fetch Interval** - 01 Hours 
