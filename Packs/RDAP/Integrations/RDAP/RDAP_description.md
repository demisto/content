# RDAP Integration

## Overview
The Registration Data Access Protocol (RDAP) integration enables you to query registration data for internet resources such as domain names, IP addresses, and autonomous system numbers. This integration provides structured information about these resources, including ownership details, registration dates, and nameserver information.

## Configuration
No API key is required for this integration as RDAP is a public protocol that replaces the older WHOIS protocol with structured data responses.

### Integration Settings
- **Base URL**: Use the default RDAP bootstrap server URL or specify a different RDAP server if needed.
- **Trust any certificate**: Select this option to trust any SSL certificate (not recommended for production environments).
- **Use system proxy settings**: Select if your organization uses a proxy to connect to the internet.