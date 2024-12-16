# Certstream Pack

Certificate transparency logs provide visibility into SSL/TLS certificates issued by certificate authorities. Monitoring these logs allows defenders to detect anomalous certificates that may be used for malicious purposes like phishing or malware command and control.

The Certstream pack consumes certificate transparency log data to detect suspicious TLS certificates in real-time. This pack can help security teams identify phishing campaigns, C2 infrastructure, and other malicious uses of TLS certificates.

What does this pack do?

- Fetches certificate transparency log data from the Certstream API
- Parses certificates and extracts relevant fields like domain names
- Checks certificate domain names against threat intel feeds to identify malicious domains
- Triggers incidents for certificates with high suspicion scores
- Provides analysts with detailed certificate information to investigate incidents

This pack contains a Certstream integration, parsing scripts, threat intel integrations, and a playbook to generate list of domain names to streamline the end-to-end workflow.

## Prerequisites

Before using the Certstream Pack and integration, ensure that you have completed the following steps:

1. **Create Domain's Homographs List**: Run the `Create list for PTH` playbook in playground to generate a list of domains and their homographs or create the list manually in the expected format: 

```json
{
  "domain1": [
    "domain1_homograph1",
    "domain1_homograph2",
    "domain1_homograph2"
  ],
  "domain2": [
    "domain2_homograph1",
    "domain2_homograph2",
    "domain2_homograph3"
  ]
}
```

After the list is created in the valid format, proceed with configuring integration instance.

## Integration Configuration

To configure the Certstream integration in XSOAR, follow these steps:

1. Access the **Settings** tab in XSOAR.
2. Select **Integrations** > **Instances** and search for the Certstream integration.
3. Click on the **Add instance** button and configure the instance by providing the following information:
   - **Homograph list name**: Specify the name of the list generated manually or using the playbook in the prerequisites. This list contains the domains and homographs to be matched against the Certstream Transparency Log.
   - **Homograph list update time interval**: Optionally you can set the time interval for the integration to check for changed in the list.
   - **Levenshtein distance threshold**: Optionally change the default threshold for matching homograph with the certificates' domain name

That's it! Once the integration is properly configured, it will continuously monitor the Certstream Transparency Log for any matches with the provided list of domains and homographs.

## Incident Creation

When a match is found between the Certstream Transparency Log and the list of domains and homographs, a new incident will be automatically created in XSOAR. The incident will contain all the relevant data related to the identified suspicious domain, allowing your team to promptly respond and mitigate any potential threats.

Please note that it is essential to regularly update and maintain the list of domains and homographs to ensure accurate and effective monitoring of potential security risks.

Please consider to download and use the `Suspicious Domain Hunting` pack to automate the handling and investigation this type  of incidents.