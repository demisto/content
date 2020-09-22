## FireEye Feed
Fetch indicators and reports from FireEye Intelligence Feed.

* **Public Key** - The public key to access the feed's data.
* **Password** - The private key to access the feed's data.
* **Tags** - Will be assigned to the indicators and reports fetched from the feed. Supports CSV values.
* **Traffic Light Protocol Color** - Will be assigned to the indicators and reports fetched from the feed.
* **Malicious Threshold** - The minimum score from the feed in order to to determine whether the indicator is malicious. Default is "70".
* **Reputation Interval** - If this amount of days passed since the indicator was created, then its reputation can be at most "Suspicious". Default is "30".

Examples of reputation calculation:
* Case 1:
    * 'Malicious Threshold' = 60
    * 'Reputation Interval' = 30
    * Indicator publish date < 30 days
    * Indicator confidence = 70
    * **Result = Malicious**

* Case 2:
    * 'Malicious Threshold' = 60
    * 'Reputation Interval' = 30
    * Indicator publish date > 30 days
    * Indicator confidence = 70
    * **Result = Suspicious**