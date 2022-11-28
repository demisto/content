The Cybersecurity and Infrastructure Security Agency’s (CISA’s) free Automated Indicator Sharing (AIS) capability enables the exchange of cyber threat indicators, at machine speed, to the Federal Government community.
Use this version if your certificate supports TAXII 2 protocol.

### Fetching Indicators From Feed Start
When checking **Fetch From Feed Start**, the feed will fetch indicators from all time. Using this method is discouraged, and due to API limitations, will cause the first fetch to take a long time.

To ensure that the fetch will work and will not time out, follow these steps:
1. Make sure **Max Indicators Per Fetch** parameter is left empty.
2. In Cortex XSOAR, go to **Settings > About > Troubleshooting**.
3. In the **Server Configuration** section, click **+ Add Server Configuration**, add the key *dhs feed v2.fetch-indicators.timeout* (with the spaces) and set the value to *20*.
