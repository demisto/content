# Unit 42 Intelligence

## Overview

The Unit 42 Intelligence integration provides threat intelligence enrichment capabilities for indicators using Palo Alto Networks Unit 42 threat intelligence data. This integration replaces the deprecated AutoFocus V2 integration and provides enhanced threat intelligence capabilities.

## Features

- **Indicator Enrichment**: Enrich IP addresses, domains, URLs, and file hashes with threat intelligence data
- **Threat Object Associations**: Get associated threat actors, malware families, campaigns, and attack patterns
- **Verdict Information**: Receive malicious, suspicious, benign, or unknown verdicts for indicators
- **Relationship Creation**: Automatically create relationships between indicators and threat objects
- **Comprehensive Metadata**: Access first seen, last seen, and source information

## Configuration

To configure the Unit 42 Intelligence integration:

1. **Server URL**: The base URL for the Unit 42 Intelligence API
2. **API Key**: Your Unit 42 Intelligence API key for authentication
3. **Source Reliability**: Set the reliability level for the intelligence source (default: A - Completely reliable)
4. **Create Relationships**: Enable/disable automatic relationship creation between indicators and threat objects (default: enabled)
5. **Trust any certificate**: Option to ignore SSL certificate verification (not recommended for production)
6. **Use system proxy settings**: Use system proxy configuration if needed

## Commands

### ip

Enrich an IP address with Unit 42 threat intelligence.

**Arguments:**

- `ip` (required): The IP address to enrich

**Example:**

```
!ip ip="192.168.1.1"
```

### domain

Enrich a domain with Unit 42 threat intelligence.

**Arguments:**

- `domain` (required): The domain to enrich

**Example:**

```
!domain domain="malicious.example.com"
```

### url

Enrich a URL with Unit 42 threat intelligence.

**Arguments:**

- `url` (required): The URL to enrich

**Example:**

```
!url url="http://malicious.example.com/path"
```

### file

Enrich a file hash with Unit 42 threat intelligence.

**Arguments:**

- `file` (required): The file hash to enrich (supports MD5, SHA1, SHA256)

**Example:**

```
!file file="a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
```

## Context Outputs

### IP Context

- `IP.Address`: The IP address
- `IP.Malicious.Vendor`: The vendor reporting the IP as malicious
- `IP.Malicious.Description`: Description of the malicious IP
- `Unit42.IP.Address`: The IP address
- `Unit42.IP.Verdict`: The verdict for the IP (malicious, suspicious, benign, unknown)
- `Unit42.IP.VerdictCategory`: The verdict category
- `Unit42.IP.FirstSeen`: First seen date
- `Unit42.IP.LastSeen`: Last seen date
- `Unit42.IP.SeenBy`: Sources that have seen this IP
- `Unit42.IP.Tags`: Associated threat tags

### Domain Context

- `Domain.Name`: The domain name
- `Domain.Malicious.Vendor`: The vendor reporting the domain as malicious
- `Domain.Malicious.Description`: Description of the malicious domain
- `Unit42.Domain.Name`: The domain name
- `Unit42.Domain.Verdict`: The verdict for the domain
- `Unit42.Domain.VerdictCategory`: The verdict category
- `Unit42.Domain.FirstSeen`: First seen date
- `Unit42.Domain.LastSeen`: Last seen date
- `Unit42.Domain.SeenBy`: Sources that have seen this domain
- `Unit42.Domain.Tags`: Associated threat tags

### URL Context

- `URL.Data`: The URL
- `URL.Malicious.Vendor`: The vendor reporting the URL as malicious
- `URL.Malicious.Description`: Description of the malicious URL
- `Unit42.URL.Data`: The URL
- `Unit42.URL.Verdict`: The verdict for the URL
- `Unit42.URL.VerdictCategory`: The verdict category
- `Unit42.URL.FirstSeen`: First seen date
- `Unit42.URL.LastSeen`: Last seen date
- `Unit42.URL.SeenBy`: Sources that have seen this URL
- `Unit42.URL.Tags`: Associated threat tags

### File Context

- `File.MD5`: The MD5 hash of the file
- `File.SHA1`: The SHA1 hash of the file
- `File.SHA256`: The SHA256 hash of the file
- `File.Malicious.Vendor`: The vendor reporting the file as malicious
- `File.Malicious.Description`: Description of the malicious file
- `Unit42.File.Hash`: The file hash
- `Unit42.File.Verdict`: The verdict for the file
- `Unit42.File.VerdictCategory`: The verdict category
- `Unit42.File.FirstSeen`: First seen date
- `Unit42.File.LastSeen`: Last seen date
- `Unit42.File.SeenBy`: Sources that have seen this file
- `Unit42.File.Tags`: Associated threat tags

### DBotScore Context

All commands provide standard DBotScore context:

- `DBotScore.Indicator`: The indicator that was tested
- `DBotScore.Type`: The indicator type
- `DBotScore.Vendor`: The vendor used to calculate the score
- `DBotScore.Score`: The actual score (0=Unknown, 1=Good, 2=Suspicious, 3=Bad)
- `DBotScore.Reliability`: Reliability of the source providing the intelligence data

## Migration from AutoFocus V2

This integration serves as a replacement for the deprecated AutoFocus V2 integration. Key differences include:

1. **Enhanced API**: Uses the new Unit 42 Intelligence API for improved performance and data quality
2. **Simplified Configuration**: Streamlined setup process with fewer configuration options
3. **Better Relationships**: Improved relationship creation between indicators and threat objects
4. **Updated Threat Objects**: Access to current Unit 42 threat intelligence tags and battlecards

### Command Mapping

- AutoFocus V2 `!ip` → Unit 42 Intelligence `!ip`
- AutoFocus V2 `!domain` → Unit 42 Intelligence `!domain`
- AutoFocus V2 `!url` → Unit 42 Intelligence `!url`
- AutoFocus V2 `!file` → Unit 42 Intelligence `!file`

## Troubleshooting

### Common Issues

1. **Authentication Errors**: Verify your API key is correct and has proper permissions
2. **Network Connectivity**: Ensure the XSOAR server can reach the Unit 42 Intelligence API endpoints
3. **Rate Limiting**: The API may have rate limits; consider implementing delays between requests if needed

### Support

For technical support, please contact Palo Alto Networks support or refer to the Cortex XSOAR documentation.

## Version History

- **1.0.0**: Initial release of Unit 42 Intelligence integration
