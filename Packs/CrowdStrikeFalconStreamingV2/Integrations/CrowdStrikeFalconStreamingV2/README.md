## Overview
Use CrowdStrike Falcon Streaming v2 integration to connect to CrowdStrike Falcon stream and fetch events as incidents to demisto.


## Define CrowdStrike API client
In order to use the integration, an API client need to be defined, and its ID and secret should be configured in the integration instance.

Follow [this article](https://www.crowdstrike.com/blog/tech-center/get-access-falcon-apis/) in order to get access to CrowdStrike API, and generate client ID and client secret.

The required scope is Event streams.

## Configure CrowdStrike Falcon Streaming v2 on Demisto
1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for CrowdStrike Falcon Streaming v2
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Cloud Base URL (e.g. https://api.crowdstrike.com)__
    * __Client ID__
    * __Client Secret__
    * __Event type to fetch__
    * __Offset to fetch events from__
    * __Incident type__
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
4. Click __Test__ to validate the URLs, token, and connection.

#### Important Notes
 - If you're using Falcon's commercial cloud, use the default value of the Cloud base URL.
   If you use another CrowdStrike cloud environment, use one of the following:
     - GovCloud: https://api.laggar.gcw.crowdstrike.com
     - EU cloud: https://api.eu-1.crowdstrike.com
 - Offset to fetch events from should have an integer value, in order to fetch all events set it to 0 (as the default value).
   
   Only events starting from this offset will be fetched
   
   For example, if set to 10: the event with offset 9 will not be fetched, and events with offsets 10 and 11 will be fetched.
   
 - Event type to fetch parameter accepts multiple values, so choose as many as you want to fetch.
   
   In order to fetch all events of all types, you can leave it empty.
   
   You can also add event type that is not listed, by entering it in the parameter value.

## Fetched Incidents Data
Event metadata will be fetched as the incident details, which contain the following:
* Type
* Offset
* Creation time
* Used ID 
* Service Name
* Detection Name
* Detection Description
* Severity
