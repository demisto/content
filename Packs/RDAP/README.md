# RDAP Pack

The RDAP (Registration Data Access Protocol) pack allows you to query and retrieve registration data for Internet resources, including domain names, IP addresses, and autonomous system numbers.

## Pack Content

### Integrations

**RDAP**: Allows querying RDAP servers for domain and IP information.

### Playbooks

No playbooks are currently included in this pack.

### Scripts

No scripts are currently included in this pack.

## Use Cases

- Enrichment of domain and IP data for threat intelligence purposes.
- Gathering registration information for domains and IP addresses during investigations.
- Automating the retrieval of WHOIS-like data using the more modern RDAP protocol.

## Additional Information

- This pack uses the RDAP protocol, which is designed to replace the older WHOIS protocol.
- RDAP provides a more standardized and machine-readable format for registration data.
- For more information on RDAP, visit [ICANN's RDAP page](https://www.icann.org/rdap).

## Known Limitations

- The availability and completeness of data may vary depending on the RDAP server being queried.
- Some RDAP servers may have rate limiting in place, which could affect the frequency of queries.

## Troubleshooting

If you encounter any issues:

- Ensure that the integration is correctly configured.
- Check that the queried domain or IP address is valid.
- Verify that you have internet connectivity to reach RDAP servers.

For more information and support, refer to the integration's documentation or contact Cortex XSOAR support.
