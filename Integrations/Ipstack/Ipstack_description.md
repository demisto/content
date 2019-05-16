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
    * __apikey__
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
| ip | ip to get info for | Required |


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | string | ip address |
| IP.Geo.Location | string | lat/lon of the ip |
| IP.Geo.Country | string | country of origin |
| Ipstack.ip.Address | string | ip address |
| Ipstack.ip.type | string | ipv4\ipv6 |
| Ipstack.ip.continent_name | string | continent of origin |
| Ipstack.ip.latitude | string | Latitude |
| Ipstack.ip.longitude | string | Longitude |


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
* 'Unable to perform command : {}, Reason: {}'.format(demisto.command, e
