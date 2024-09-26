The Cyberwatch integration allows you to manage vulnerabilities on your IT & OT assets. Cyberwatch is a vulnerability management platform that helps you find, prioritize, and fix vulnerabilities on your IT & OT assets. The Cyberwatch integration provides the following capabilities:

  - List CVEs: Get a list of Common Vulnerabilities and Exposures (CVEs) from Cyberwatch.
  - Fetch CVE: Get all details for a CVE from Cyberwatch.
  - List assets: Get a list of assets scanned by Cyberwatch.
  - Fetch asset: Get all details for an asset scanned by Cyberwatch.
  - List security issues: Get a list of security issues from Cyberwatch.
  - Fetch security issue: Get all details for a security issue from Cyberwatch.

To use the Cyberwatch integration, you must have a valid Cyberwatch instance, and a valid Cyberwatch API key. For more information, see the [Cyberwatch documentation](https://docs.cyberwatch.fr/en/).


### SETUP
To use this integration, you need a Cyberwatch instance and a valid license. Your Cortex XSOAR instance **must** be able to send HTTPS requests toward your Cyberwatch instance.

To configure the integration, you will need to enter:
- **Master scanner URL:** The Cyberwatch master scanner URL (e.g. https://192.168.0.1).
- **API Access key:** Your Cyberwatch account API access key.
- **API Secret key:** Your Cyberwatch account API secret key.

To get the API access and secret keys, please log in your Cyberwatch instance with an Administrator account.
Then, go to your profile, and generate new API keys.

### SUPPORT
For any question, please contact support@cyberwatch.fr.