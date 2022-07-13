## URLhaus
---
URLhaus is a project from abuse.ch with the goal of sharing malicious URLs that are being used for malware distribution.



Fetch indicators from URLhaus feed. 

* *Indicator Reputation* - Dropdown list from which to select the reputation of the feed.
* *Feed Source* - The type of indicators to receive based on the status of the URLs.
* *Traffic Light Protocol Color* - The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed.
* *Indicator Expiration Method* - The preferred expiration method.
* *Tags* - Tags for data from the feed.
* *Trust any certificate (not secure)* - Turn on/off secure HTTP access. Mark as true if you cannot access the API and you trust it.
* *Indicator Verdict* -  The type of indicator that is returned by the feed.
* *Source Reliability* - Reliability of the source providing the intelligence data.
* *Feed Fetch Interval* - The time to fetch indicators for the feed.

## Step by step configuration
As an example, let's look at the URLhaus feed by Abuse. This feed will ingest indicators of type URL. These are the feed instance configuration parameters for our example.

* *Indicator Reputation* - Malicious
* *Feed Source* - Currently Active
* *Traffic Light Protocol Color* - WHITE
* *Indicator Expiration Method* - Indicator Type 
* *Tags* - None
* *Trust any certificate (not secure)* - True
* *Indicator Verdict* - Malicious
* *Source Reliability* - B - Usually reliable
* *Feed Fetch Interval* - 01 Hours 
