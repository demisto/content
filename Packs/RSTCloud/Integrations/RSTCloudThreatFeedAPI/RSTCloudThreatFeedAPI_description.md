### Partner Contributed Integration
#### Integration Author: RST Cloud
Support and maintenance for this integration are provided by the author. Please use the following contact details:
- **URL**: [https://www.rstcloud.net/contact](https://www.rstcloud.net/contact)
***
## RST Threat Feed
- This section explains how to configure the instance of RST Threat Feed API in Cortex XSOAR.
- Provide your API Key
- Set the thresholds for IP, Domain, URL indicator types: below or equal a threshold means that an indicator will be marked as Suspicious, above means it will be marked as Malicious
- Set the limits to mark an indicator as suspicious if it's LastSeen is older than the expiration threshold
- Be mindful of the LastSeen attribute. Most of the indicators tend to be expiring over time.
