# CertStream Integration Pack

## Overview

The CertStream integration allows you to leverage the Certificate Transparency Log (CTL) network to get real-time alerts when new TLS/SSL certificates are issued. CertStream provides a stream of certificate transparency log data from dozens of CTL servers around the globe.

By integrating CertStream with Cortex XSOAR, you can build real-time detection and response workflows triggered by the issuance of TLS certificates that match specific criteria.

## Configure CertStream Integration

1. Navigate to **Integrations > CertStream**
2. Click **Add instance** to create a new integration
3. Name your integration instance (e.g. my-certstream)
4. Enter the API endpoint (default is the public CertStream endpoint)
5. Set the Levenshtein distance threshold for matching domains (default is 0.9)
6. Set the Homograph list name of domain permutations to pull from
7. Click **Test** to validate the configuration
8. Click **Done** to save the integration

## Sample Use Cases

- Get real-time alerts when certificates are issued for your brand, trademarks, exec names, etc.
- Detect type-squatting and potential phishing domains targeting your company.
- Monitor certificates issued by public CAs.

## Notifications

- New Certificate Detected - Incident triggered when a new certificate matching defined filters is issued.