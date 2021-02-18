## Overview
---

search engine for Internet-connected devices
This integration was integrated and tested with version xx of Shodan_v2
## Shodan_v2 Playbook
---

## Use Cases
---

## Configure Shodan_v2 on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Shodan_v2.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Api Key__
    * __Base url to Shodan API__
    * __Trust self-signed certificate (insecure)__
    * __Use system proxy settings__
4. Click __Test__ to validate the URLs, token, and connection.
## Fetched Incidents Data
---

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. search
2. ip
3. shodan-search-count
4. shodan-scan-ip
5. shodan-scan-internet
6. shodan-scan-status
7. shodan-create-network-alert
8. shodan-network-get-alert-by-id
9. shodan-network-get-alerts
10. shodan-network-delete-alert
11. shodan-network-alert-set-trigger
12. shodan-network-alert-remove-trigger
13. shodan-network-alert-whitelist-service
14. shodan-network-alert-remove-service-from-whitelist
### 1. search
---
Search Shodan using the same query syntax as the website and use facets to get summary information for different properties.
##### Base Command

`search`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Shodan search query. The provided string is used to search the database of banners in Shodan, with the additional option to provide filters inside the search query using a "filter:value" format. For example, the following search query would find Apache webservers located in Germany: "apache country:DE" | Required | 
| facets | A comma-separated list of properties to get summary information on. Property names can also be in the format of "property:count", where "count" is the number of facets that will be returned for a property (i.e. "country:100" to get the top 100 countries for a search query) | Optional | 
| page | Result page number to be fetched. Each page contains up to 100 results. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Shodan.Banner.Org | String | The name of the organization that is assigned the IP space for this device | 
| Shodan.Banner.Isp | String | The ISP that is providing the organization with the IP space for this device. Consider this the "parent" of the organization in terms of IP ownership | 
| Shodan.Banner.Transport | String | Either "udp" or "tcp" to indicate which IP transport protocol was used to fetch the information | 
| Shodan.Banner.Asn | String | The autonomous system number (ex. "AS4837"). | 
| Shodan.Banner.IP | String | The IP address of the host as a string | 
| Shodan.Banner.Port | Number | The port number that the service is operating on | 
| Shodan.Banner.Ssl.versions | String | list of SSL versions that are supported by the server. If a version isnt supported the value is prefixed with a "-". Example: ["TLSv1", "-SSLv2"] means that the server supports TLSv1 but doesnt support SSLv2. | 
| Shodan.Banner.Hostnames | String | An array of strings containing all of the hostnames that have been assigned to the IP address for this device. | 
| Shodan.Banner.Location.City | String | The name of the city where the device is located | 
| Shodan.Banner.Location.Longitude | Number | The longitude for the geolocation of the device | 
| Shodan.Banner.Location.Latitude | Number | The latitude for the geolocation of the device | 
| Shodan.Banner.Location.Country | String | The name of the country where the device is located | 
| Shodan.Banner.Timestamp | Date | The timestamp for when the banner was fetched from the device in the UTC timezone | 
| Shodan.Banner.Domains | String | An array of strings containing the top-level domains for the hostnames of the device. This is a utility property in case you want to filter by TLD instead of subdomain. It is smart enough to handle global TLDs with several dots in the domain (ex. "co.uk") | 
| Shodan.Banner.OS | String | The operating system that powers the device | 


##### Command Example
```!search query="country:HK product:Apache"```

##### Human Readable Output


### 2. ip
---
Returns all services that have been found on the given host IP.
##### Base Command

`ip`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | Host IP address | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.ASN | Unknown | Autonomous System Number (ASN) such as IP owner | 
| IP.Address | Unknown | IP Address | 
| IP.Geo.Country | Unknown | Country of given IP | 
| IP.Geo.Description | Unknown | Description of location  | 
| IP.Geo.Location | Unknown | Latitude and longitude of given IP | 
| IP.Hostname | Unknown | Hostname | 
| Shodan.IP.Tags | String | The tags related to the IP | 
| Shodan.IP.Latitude | Number | The latitude for the geolocation of the device | 
| Shodan.IP.Org | String | The name of the organization that is assigned the IP space for this device | 
| Shodan.IP.ASN | String | The autonomous system number (ex. "AS4837"). | 
| Shodan.IP.ISP | String | The ISP that is providing the organization with the IP space for this device. Consider this the "parent" of the organization in terms of IP ownership | 
| Shodan.IP.Longitude | Number | The Longitude for the geolocation of the device | 
| Shodan.IP.LastUpdate | Date | The timestamp for when the banner was fetched from the device in the UTC timezone | 
| Shodan.IP.CountryName | String | The name of the country where the device is located | 
| Shodan.IP.OS | String | The operating system that powers the device | 
| Shodan.IP.Port | Number | The port number that the service is operating on | 
| Shodan.IP.Address | String | The IP address of the host as a string | 


##### Command Example
```!ip ip="8.8.8.8"```

##### Human Readable Output


### 3. shodan-search-count
---
This method behaves identical to "shodan-search" with the only difference that this method does not return any host results, it only returns the total number of results that matched the query and any facet information that was requested. As a result this method does not consume query credits.
##### Base Command

`shodan-search-count`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Shodan search query. The provided string is used to search the database of banners in Shodan, with the additional option to provide filters inside the search query using a "filter:value" format. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Shodan.Search.ResultCount | Number | Number of results generated by the search query | 


##### Command Example
```!shodan-search-count query="country:HK product:Apache"```

##### Human Readable Output


### 4. shodan-scan-ip
---
Use this method to request Shodan to crawl a network.
##### Base Command

`shodan-scan-ip`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ips | A comma-separated list of IPs or netblocks (in CIDR notation) that should get crawled. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Shodan.Scan.ID | String | The unique scan ID that was returned by shodan-scan-ip. | 
| Shodan.Scan.Status | String | The status of the scan job | 


##### Command Example
```!shodan-scan-ip ips="1.1.1.69"```

##### Human Readable Output


### 5. shodan-scan-internet
---
This method is restricted to security researchers and companies with a Shodan Enterprise Data license
##### Base Command

`shodan-scan-internet`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| port | The port that Shodan should crawl the Internet for | Required | 
| protocol | The name of the protocol that should be used to interrogate the port. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Shodan.Scan.ID | String | The id of the scan job | 


##### Command Example
```!shodan-scan-internet port="80" protocol="http"```

##### Human Readable Output


### 6. shodan-scan-status
---
Check the progress of a previously submitted scan request
##### Base Command

`shodan-scan-status`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scanID | The unique scan ID that was returned by shodan-scan. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Shodan.Scan.Id | String | The unique scan ID that was returned by shodan-scan | 
| Shodan.Scan.Status | String | The status of the scan job | 


##### Command Example
```!shodan-scan-status scanID="fnFNYGzNGJFNE8lQ"```

##### Human Readable Output


### 7. shodan-create-network-alert
---
Use this method to create a network alert for a defined IP/ netblock which can be used to subscribe to changes/ events that are discovered within that range.
##### Base Command

`shodan-create-network-alert`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alertName | The name to describe the network alert | Required | 
| ip | A list of IPs or network ranges defined using CIDR notation | Required | 
| expires | Number of seconds that the alert should be active | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Shodan.Alert.ID | String | The id of the alert subscription | 
| Shodan.Alert.Expires | String | Number of seconds that the alert should be active | 


##### Command Example
```!shodan-create-network-alert alertName="test_alert" ip="1.1.1.1"```

##### Human Readable Output


### 8. shodan-network-get-alert-by-id
---
Get the details for a network alert
##### Base Command

`shodan-network-get-alert-by-id`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alertID | AlertID | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Shodan.Alert.ID | String | The id of the alert subscription | 
| Shodan.Alert.Expires | String | Number of seconds that the alert should be active | 


##### Command Example
```!shodan-network-get-alert-by-id alertID="Y6KRMXWQ8FPNSHHY```

##### Human Readable Output


### 9. shodan-network-get-alerts
---
Get a list of all the created alerts
##### Base Command

`shodan-network-get-alerts`
##### Input

There are no input arguments for this command.

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Shodan.Alert.ID | String | The id of the alert subscription | 
| Shodan.Alert.Expires | String | Number of seconds that the alert should be active | 


##### Command Example
```!shodan-network-get-alerts```

##### Human Readable Output


### 10. shodan-network-delete-alert
---
Remove the specified network alert.
##### Base Command

`shodan-network-delete-alert`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alertID | AlertID | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!shodan-network-delete-alert alertID="Y6KRMXWQ8FPNSHHY"```

##### Human Readable Output


### 11. shodan-network-alert-set-trigger
---
Get notifications when the specified trigger is met.
##### Base Command

`shodan-network-alert-set-trigger`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alertID | AlertID | Required | 
| Trigger | Trigger name | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!shodan-network-alert-set-trigger alertID="Y6KRMXWQ8FPNSHHY" Trigger="any"```

##### Human Readable Output


### 12. shodan-network-alert-remove-trigger
---
Stop getting notifications for the specified trigger.
##### Base Command

`shodan-network-alert-remove-trigger`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alertID | AlertID | Required | 
| Trigger | Trigger name | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!shodan-network-alert-remove-trigger alertID="Y6KRMXWQ8FPNSHHY" Trigger="any"```

##### Human Readable Output


### 13. shodan-network-alert-whitelist-service
---
Ignore the specified service when it is matched for the trigger.
##### Base Command

`shodan-network-alert-whitelist-service`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alertID | AlertID | Required | 
| trigger | Trigger name | Required | 
| service | Service specified in the format "ip:port" (ex. "1.1.1.1:80") | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!shodan-network-alert-whitelist-service alertID="Y6KRMXWQ8FPNSHHY" trigger="any" service="1.1.1.1:80"```

##### Human Readable Output


### 14. shodan-network-alert-remove-service-from-whitelist
---
Start getting notifications again for the specified trigger
##### Base Command

`shodan-network-alert-remove-service-from-whitelist`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alertID | AlertID | Required | 
| trigger | Trigger name | Required | 
| service | Service specified in the format "ip:port" (ex. "1.1.1.1:80") | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!shodan-network-alert-remove-service-from-whitelist alertID="Y6KRMXWQ8FPNSHHY" trigger="any" service="1.1.1.1:80"```

##### Human Readable Output



