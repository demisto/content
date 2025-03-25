# Proofpoint TAP
Use the Proofpoint Targeted Attack Protection (TAP) integration to protect against and provide additional visibility into phishing and other malicious email attacks.
Proofpoint TAP detects, analyzes and blocks advanced threats before they reach your inbox. This includes ransomware and other advanced email threats delivered through malicious attachments and URLs.

## What does this pack do?
- Fetches events for all clicks and messages relating to known threats within a specified time period.
- Returns forensics evidence.
- Fetches events for clicks to malicious URLs in a specified time period. 
- Fetches events for messages in a specified time period.
- Fetches events for clicks to malicious URLs permitted and messages delivered containing a known attachment threat within a specified time period.
- Fetches a list of IDs of campaigns active in a specified time period.
- Fetches details for a given campaign.
- Fetches a list of the most attacked users in the organization.
- Fetches a list of the top clickers in the organization for a specified time period.
- Decodes URLs that have been rewritten by TAP to their original, target URL.

The playbook in this pack enriches information about the event forensics.

<~XSIAM>
## Collect Events from Vendor
To configure the collector for "Proofpoint Targeted Attack Protection", follow the XSIAM documentation [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Ingest-Logs-from-Proofpoint-Targeted-Attack-Protection).
The ingested "Proofpoint Tap" logs can be queried in XQL Search using the *`proofpoint_tap_raw`* dataset.

Notes:
- Data normalization capabilities (rules for parsing and modeling) are available for logs ingested via the mentioned above collector.
- Pay attention to the difference between collection via "Proofpoint Targeted Attack Protection" (which is mentioned above) and collection via "Proofpoint TAP".
</~XSIAM>
