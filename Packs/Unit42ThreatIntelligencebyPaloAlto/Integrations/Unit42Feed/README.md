Unit 42 Feed integration provides threat intelligence from Palo Alto Networks Unit 42 research team.
This integration was integrated and tested with version 1.0.0 of Unit 42 Feed.

## Configure Unit 42 Feed in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Fetch indicators |  | False |
| Feed Types |  | True |
| Indicator Types | Comma-separated list of indicator types to fetch \(File, IP, URL, Domain\). If not specified, all indicator types are fetched. | False |
| Feed Fetch Interval | Don't set the feed fetch interval to less than 12 hours. | False |
| Source Reliability | Reliability of the source providing the intelligence data | False |
| Traffic Light Protocol Color (TLP). Indicator's TLP will override default value. |  | False |
| Indicator Reputation |  | False |
| Indicator Expiration Method |  | False |
| Indicator Expiration Interval |  | False |
| Create relationships |  | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |
