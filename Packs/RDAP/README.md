# RDAP Integration Pack

## Overview
The RDAP (Registration Data Access Protocol) Integration Pack allows you to query and retrieve registration data for Internet resources such as IP addresses and domain names.

## Use Cases
- Enrich IP addresses with registration and abuse contact information
- Retrieve domain registration details including creation and expiration dates
- Verify DNSSEC status for domains

## Commands
This pack includes the following commands:

1. `ip`
   Queries RDAP for information about an IP address.

2. `domain`
   Queries RDAP for information about a domain name.

## Configuration
To configure the RDAP integration:

1. Navigate to Settings > Integrations > Servers & Services
2. Search for RDAP
3. Click Add instance to create and configure a new integration instance
4. Configure the instance name and Base URL (default: https://rdap.org)
5. Test the connection to ensure it's working properly

## Troubleshooting
If you encounter any issues:

- Verify that the Base URL is correct and accessible from your Cortex XSOAR instance
- Check the integration's logs for any error messages
- Ensure that the queried IP addresses or domain names are valid

For more information on using this pack, please refer to the RDAP Integration documentation.
