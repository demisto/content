# Mandiant Threat Intelligence Feed

## Prerequisites
- A Mandiant Advantage Threat Intelligence account

## Get Credentials
- Log into `advantage.mandiant.com`
- Navigate to `Settings`, then scroll down to `APIv4 Access and Key`.
- Click `Get Key ID and Secret`.

## Upgrading from previous versions

Version 1.1 supercedes all previous versions of the Mandiant Advantage Threat Intelligence Integration and splits feed and enrichment capabilities into 2 separate integrations. Customers upgrading from earlier versions should follow these steps:

1. Note the instance name of your existing Mandiant Advantage Threat Intelligence integration instance, this is needed in a later step.
2. Remove all instances of existing Mandiant Advantage Threat Intelligence integrations.
3. Optionally, remove the integration from your Cortex XSOAR server.
4. Remove all indicators created by the previous version. To do this:
    a. Open the Threat Intel page and perform an All Time search using this query `sourceInstances:"<INSTANCE NAME>"`, where `<INSTANCE_NAME>` is the name of your old integration instance collected in step 1.
    b. Select all indicators.
    c. Click **Delete and Exclude**.
    d. In the Delete and Exclude dialog box, check the `Do not add to exclusion list` checkbox and click the **Delete and Exclude** button.
5. Once the indicator deletion process completes, install the new version of the integration and add an instance of the `FeedMandiant` integration  to re-establish the feed.

**NOTE:** To enable enrichment commands, also add an instance of the `Mandiant` integration.

## Integration Settings

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

## Commands

### mandiant-get-indicators

Returns a list of indicators in JSON format.

#### Base Command

`mandiant-get-indicators`

#### Input

| **Argument** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to fetch. | True |

#### Context Output

This command has no context output.