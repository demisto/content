## Cortex XDR - IOC
Use the Cortex XDR - IOCs feed integration to sync indicators from XSOAR to XDR.
Cortex XDR is the world's first detection and response app that natively integrates network, endpoint and cloud data to stop sophisticated attacks.

**Note: Only one instance of this integration is supported at a time. If more than one is configured, instances will interrupt one another.**

### Generate an API Key and API Key ID
1. In your Cortex XDR platform, go to **Settings**.
2. Click the **(+) New Key** button in the top-right corner.
3. Generate a key of type **Advanced** with an **Administrator** role.
4. Copy and paste the key.
5. From the ID column, copy the Key ID.

### URL
1. In your Cortex XDR platform, go to **Settings**.
2. Click the **Copy URL** button in the top right corner.

### Severity
The integration sync the severity field (indicator field, set as parameter) between XSOAR and XDR.

The severity field must be one of the following: 
- a textual field, or 
- a single-select field, accepting the following values: `INFO`,`LOW`,`MEDIUM`,`HIGH`,`CRITICAL`. 

Using an invalid field (or one that is not present in the indicator) may cause fetching to stop working.

**Note: Due to XSOAR system limitations, once the severity is manually changed within XSOAR, it is excluded from being updated by the fetching process.**
