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