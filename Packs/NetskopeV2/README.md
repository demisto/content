# Netskope - Direct to Zero Trust

The Netskope - Direct to Zero Trust content pack provides policy-enforcement and Zero Trust workflows for Cortex XSOAR. It combines Netskope API v2 capabilities with the API v1 file-hash-list operation required for hash-blocking workflows.

## What this pack includes

- URL-list management and URL reputation lookup.
- Device classification tags, device tags, and device lookup.
- Destination Profile and Network Profile lifecycle management.
- Private application (ZTNA/NPA) management and publisher discovery.
- File submission to Netskope Threat Protection and scan-report retrieval.
- File-hash-list updates through Netskope API v1.
- Playbooks for blocking domains and IP addresses, synchronizing threat intelligence, managing private applications, inspecting files, and looking up URLs.
- Helper scripts used by the included playbooks.

## Configuration

Create an instance of **Netskope - Direct to Zero Trust** and configure:

- The URL of the Netskope tenant.
- A Netskope API v2 key for API v2 commands.
- A Netskope API v1 token when using file-hash-list commands.
- Certificate verification and proxy settings appropriate for the environment.

API v1 and API v2 credentials are stored separately because the APIs use different authentication methods.

## Requirements and limitations

Some commands require Netskope features or licenses to be enabled for the tenant, including Device Tags, Network Profiles, URL Lookup, and Threat Protection file scanning. The integration returns the Netskope API error when a required tenant capability is unavailable.

The file-hash-list update command replaces the complete list through API v1. Use the included **Update File Hash List - Netskope** and **Sync Threat Intel to File Hash List - Netskope** playbooks when existing values must be retained between updates.

## Included playbooks

- Block Domain - Netskope
- Block Domain - Destination Profile - Netskope
- Block IP - Network Profile - Netskope
- Manage Private App Segment - Netskope
- Sync Threat Intel to Destination Profile - Netskope
- Sync Threat Intel to File Hash List - Netskope
- Threat Inspection - Netskope
- Update File Hash List - Netskope
- URL Lookup - Netskope
