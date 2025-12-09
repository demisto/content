# Augur Security
Augur is the one and only cybersecurity platform using AI-powered behavioral modeling and automation to reliably predict, decide, and act — not waiting and watching for threats to emerge but blocking threats preemptively.

## How does Augur do it?
Augur integrates seamlessly into your existing stack —SIEM, SOAR, firewall, and EDR — to transform intelligence into immediate, preventative action. Augur analyzes global internet infrastructure to detect the earliest signs of malicious intent, an average of 51 days before attacks go live.

These aren’t retroactive IOCs. The Augur platform will reveal attack infrastructure before it becomes operational. With near-zero false positives (0.007%), Augur delivers high-confidence intelligence your security team can use for instant, automatic enforcement.

## How does it work with XSOAR?
Augur's XSOAR integration leverages Augur API to provide threat intel feed and IOC enrichments.
The daily indicator process will download unique threat intel in the form of IPV4 CIDR (network blocks), malicious hostname, file hashes, urls to XSOAR.  The context endpoint can be used by the XSOAR playbook to enrich suspicious IOCs with context found by Augur. 

## How to get credential / API Key
If you're new to Augur Security. Please contact support@augursecurity.com to receive the API key.
If you have access to Augur Security's dashboard, please navigate to "Integrations" -> "Manage Integrations" -> "SOAR" -> Click on "Settings" for Palo Alto Networks Cortex XSoar -> find the ACCESS TOKEN string.



For more information, please email: support@augursecurity.com

