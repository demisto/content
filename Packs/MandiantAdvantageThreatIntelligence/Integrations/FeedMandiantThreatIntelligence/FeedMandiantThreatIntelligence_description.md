## Mandiant Threat Intelligence Feed

### Prerequisites
A Mandiant Advantage Threat Intelligence account.

### Get Credentials
- Log in to `advantage.mandiant.com`.
- Navigate to `Settings`, then scroll down to `APIv4 Access and Key`.
- Click `Get Key ID and Secret`.

### Integration Settings

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Fetch indicators | Whether the integration should check Mandiant for new indicators. | False |
| API Key | Your API Key from Mandiant Advantage Threat Intelligence. | True |
| Secret Key | Your Secret Key from Mandiant Advantage Threat Intelligence. | True |
| Page Size | The number of indicators to request in each page. | True |
| Timeout | API calls timeout. | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Feed Minimum Threat Score | The minimum Threat Score value to import as part of the feed. | True |
| First fetch time | The maximum value allowed is 90 days. | False |
| Feed Exclude Open Source Intelligence | Whether to exclude Open Source Intelligence as part of the feed. | False |
| Traffic Light Protocol Color | The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. | False |
| Tags | Supports CSV values. | False |
| Feed Expiration Policy | Defines how expiration of an indicator created by the feed will be managed. | False |
| Feed Expiration Interval | Defines the expiration date based on the number of days after an indicator is created / updated when the Feed Expiration Policy is set to `interval`. | False |
| Feed Fetch Interval | How frequently the feed should check Mandiant for new indicators. | True |