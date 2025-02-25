## Digital Guardian ARC Event Collector Help

**Important:** 
This integration is supported by Palo Alto Networks. 

### Configuration

A maximum of 10,000 events can be retrieved per fetch for each Digital Guardian export profile. To optimize throughput, it is recommended to distribute alerts and events across multiple export profiles and configure the export profile in the Digital Guardian ARC platform to include only relevant alarm and event types.

### How to get the configuration parameters

#### API Client ID

This is the Tenant ID and can be found in the ARC Tenant Settings 

#### API Client Secret

Authentication Token from the ARC Tenant Settings 

#### Gateway Base URL

From DGMC Cloud Services setup screen, Access Gateway Base URL 

#### Auth Server URL

From DGMC Cloud Services setup screen, Authorization server URL 

#### Export Profiles

From the Digital Guardian platform tenant, navigate to **DG ARC > Reports > Export Profiles**.

To confirm the internal document name of an export profile, hover over the 'Link' icon in the URL column in the table. For example, if the export profile URL is `{access_gateway_base_url}/rest/1.0/export_profiles/demisto/export`, the internal document name is `demisto`.
