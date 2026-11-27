# Netskope - Direct to Zero Trust

The Netskope - Direct to Zero Trust content pack provides policy-enforcement and Zero Trust workflows for Cortex XSOAR and Cortex XSIAM. It combines Netskope API v2 capabilities with the API v1 file-hash-list operation required for hash-blocking workflows.

## What does this pack do?

- URL-list management and URL reputation lookup.
- Device classification tags, device tags, and device lookup.
- Destination Profile and Network Profile lifecycle management.
- Private application (ZTNA/NPA) management and publisher discovery.
- File submission to Netskope Threat Protection and scan-report retrieval.
- File-hash-list updates through Netskope API v1.
- Playbooks for blocking domains and IP addresses, synchronizing threat intelligence, managing private applications, inspecting files, and looking up URLs. See the linked playbook documentation below for inputs and workflow details.
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

- [Block Domain - Netskope](https://github.com/demisto/content/blob/master/Packs/NetskopeV2/Playbooks/Block_Domain_-_Netskope_README.md)
- [Block Domain - Destination Profile - Netskope](https://github.com/demisto/content/blob/master/Packs/NetskopeV2/Playbooks/Block_Domain_-_Destination_Profile_-_Netskope_README.md)
- [Block IP - Network Profile - Netskope](https://github.com/demisto/content/blob/master/Packs/NetskopeV2/Playbooks/Block_IP_-_Network_Profile_-_Netskope_README.md)
- [Manage Private App Segment - Netskope](https://github.com/demisto/content/blob/master/Packs/NetskopeV2/Playbooks/Manage_Private_App_Segment_-_Netskope_README.md)
- [Sync Threat Intel to Destination Profile - Netskope](https://github.com/demisto/content/blob/master/Packs/NetskopeV2/Playbooks/Sync_Threat_Intel_to_Destination_Profile_-_Netskope_README.md)
- [Sync Threat Intel to File Hash List - Netskope](https://github.com/demisto/content/blob/master/Packs/NetskopeV2/Playbooks/Sync_Threat_Intel_to_File_Hash_List_-_Netskope_README.md)
- [Threat Inspection - Netskope](https://github.com/demisto/content/blob/master/Packs/NetskopeV2/Playbooks/Threat_Inspection_-_Netskope_README.md)
- [Update File Hash List - Netskope](https://github.com/demisto/content/blob/master/Packs/NetskopeV2/Playbooks/Update_File_Hash_List_-_Netskope_README.md)
- [URL Lookup - Netskope](https://github.com/demisto/content/blob/master/Packs/NetskopeV2/Playbooks/URL_Lookup_-_Netskope_README.md)
