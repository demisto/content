## SecneurX Threat Intelligence Feed

SecneurX Threat Intelligence is reliable, human-verified intelligence for actionable defense and strategic planning. SecneurX researchers track emerging trends in APT, ransomware, phishing, research active & most prevalent threats, and supplement highest-priority investigations. Each record in Data Feed is enriched with actionable context (threat names, APT group names, resolved IPs addresses of infected web resources, hashes, popularity etc).

Fetch indicators from SecneurX Threat Intelligence Feed.

In order to access SecneurX Threat Intelligence feeds, Make sure you have your SecneurX API-key. You can obtain the API-key, by sending an email to [support@secneurx.com](support@secneurx.com).

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Feed URL | Input the url of SecneurX Threat Intelligence Feeds. | True |
| API Key | Input the API key for fetching feed from the source. | True |
| Fetch indicators | Select this option if you want this integration instance to fetch indicators from the SecneurX Threat Intelligence feed. | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation | False |
| Tags | Supports CSV values. | False |
| Source Reliability | Reliability of the source providing the intelligence data | True |
| Feed Fetch Interval | How often do fetch indicators from this integration instance. You can specify the interval in days, hours, or minutes. | True |
| Feed Expiration Policy |  | False |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |
| First fetch | First fetch query e.g., 12 hours, 7 days. SecurityScorecard provides a maximum of 7 days back. To ensure no alerts are missed, it's recommended to use a value less than 2 days. | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |