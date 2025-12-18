## APIVoid Integration

This integration provides threat intelligence and security analysis using the APIVoid V2 API.

### Configuration

To configure the APIVoid integration in Cortex XSOAR:

1. Navigate to **Settings** > **Integrations** > **Servers & Services**
2. Search for **APIVoid**
3. Click **Add instance** to create and configure a new integration instance

#### Required Parameters

- **API KEY**: Your APIVoid API key
  - Obtain your API key from [APIVoid Dashboard](https://dash.apivoid.com/api-keys/)

#### Optional Parameters

- **Source Reliability**: Reliability of the source (default: C - Fairly reliable)
- **Detection Thresholds**: Configure detection rate thresholds for reputation scoring
  - **Good Threshold**: Maximum detection rate % for good reputation (default: 10%)
  - **Suspicious Threshold**: Detection rate % threshold for suspicious reputation (default: 30%)
  - **Bad Threshold**: Minimum detection rate % for bad reputation (default: 60%)

### Features

The integration supports the following capabilities:

- **IP Reputation**: Check IP addresses against multiple blacklists and threat databases
- **Domain Reputation**: Analyze domain reputation and security status
- **URL Reputation**: Scan URLs for malicious content and phishing indicators
- **Email Verification**: Validate email addresses and detect disposable/suspicious emails
- **DNS Lookup**: Query DNS records (A, AAAA, MX, NS, TXT, etc.)
- **SSL Certificate Info**: Retrieve and validate SSL certificate information
- **Domain Age**: Get domain registration and age information
- **Parked Domain Detection**: Identify parked or inactive domains
- **Site Trustworthiness**: Comprehensive site security and trust analysis
- **Screenshot Capture**: Capture website screenshots
- **URL to PDF**: Convert web pages to PDF documents

### API Rate Limits

Please note that APIVoid has rate limits based on your subscription plan. Refer to your [APIVoid plan details](https://www.apivoid.com/pricing/) for specific limits.

### Support

For issues or questions:
- APIVoid Documentation: https://docs.apivoid.com/
- APIVoid Support: https://www.apivoid.com/contact/