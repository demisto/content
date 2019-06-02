## Overview
---

Use Ipstack to get location on IPs
## Ipstack Playbook
---

## Use Cases
---
* Get Location info about an IP

## Configure Ipstack on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Ipstack.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __API key__
    * __use system proxy settings__
4. Click __Test__ to validate the URLs, token, and connection.
## Fetched Incidents Data
---

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. ip
### 1. ip
---
query ip in ipstack
##### Base Command

`ip`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP address to query. | Required |


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | string | IP address. |
| IP.Geo.Location | string | Latitude and longitude of the IP address. |
| IP.Geo.Country | string | Country of origin of the IP address. |
| Ipstack.IP.address | string | IP address. |
| Ipstack.IP.type | string | IP type (ipv4 or ipv6). |
| Ipstack.IP.continent_name | string | Continent of the IP address. |
| Ipstack.IP.latitude | string | Latitude of the IP address. |
| Ipstack.IP.longitude | string | Longitude of the IP address. |


##### Command Example
`!ip using-brand="ipstack" ip=5.79.86.16`

##### Context Example

```
{
  "IP": {
    "Address": "5.79.86.16",
    "Geo": {
      "Location": "52.3824,4.8995",
      "Country": "Netherlands"
    }
  },
  "Ipstack": {
    "ip": {
      "address": "5.79.86.16",
      "type": "ipv4",
      "continent_name": "Europe",
      "latitude": 52.3824,
      "longitude": 4.8995
    }
  }
}
```

##### Human Readable Output


## Additional Information
---
To get Your API Key, go to [Ipstack](https://ipstack.com).
After you login (or sign in), under the dashboard tab You will find Your key.

## Known Limitations
---

## Troubleshooting
---


## Possible Errors (DO NOT PUBLISH ON ZENDESK):
