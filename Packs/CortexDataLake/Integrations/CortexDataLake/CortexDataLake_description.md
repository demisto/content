## Overview
---

Palo Alto Networks Cortex Data Lake XSOAR Connector provides cloud-based, centralized log storage and aggregation for your on premise, virtual (private cloud and public cloud) firewalls, for Prisma Access, and for cloud-delivered services such as Cortex XDR.
This integration was integrated and tested with version 2 of Cortex Data Lake XSOAR Connector.



---

## Configure Cortex Data Lake XSOAR Connector on Cortex XSOAR 

---

1. In the War Room, run the command `!GetLicenseID` to get the `license ID`.
2. Go to __Settings__ > __ABOUT__ > __License__ to get the `Customer Name`.
3. Go to the [HUB](https://apps.paloaltonetworks.com/apps) and login using your **Palo Alto Networks** credentials. 
4. Under the `Cortex™ XSOAR` app select the relevant instance. If you don't have an active `Cortex™ XSOAR` app check out the Hub [Docs site](https://docs.paloaltonetworks.com/hub/hub-getting-started) to learn about app activation.
5. Insert the `license ID` and the `Customer Name` in the required fields and complete the authentication process in order  
to get the __Authentication Token__  __Registration ID__ __Encryption Key__
6. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
7. Search for Palo Alto Networks Cortex v2.
8. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Authentication Token__: From the authentication process
    * __Registration ID__: From the authentication process
    * __Encryption Key__: From the authentication process
    * __proxy__: Use system proxy settings
    * __insecure__: Trust any certificate (not secure)
    * __Fetch incidents__: Whether to fetch incidents or not
    * __first_fetch_timestamp__: First fetch time (<number> <time unit>, e.g., 12 hours, 7 days, 3 months, 1 year)
    * __Severity of events to fetch (Firewall)__: Select from all,Critical,High,Medium,Low,Informational,Unused
    * __Subtype of events to fetch (Firewall)__: Select from all,attack,url,virus,spyware,vulnerability,file,scan,flood,packet,resource,data,url-content,wildfire,extpcap,wildfire-virus,http-hdr-insert,http-hdr,email-hdr,spyware-dns,spyware-wildfire-dns,spyware-wpc-dns,spyware-custom-dns,spyware-cloud-dns,spyware-raven,spyware-wildfire-raven,spyware-wpc-raven,wpc-virus,sctp
9. Click __Test__ to validate the URLs, token, and connection.

## CDL Server - API Calls Caching Mechanism
The integration implements a caching mechanism for repetitive error when requesting access token from CDL server.
When the intgeration reaches the limit of allowed calls, the following error will be shown:

```We have found out that your recent attempts to authenticate against the CDL server have failed. Therefore we have limited the number of calls that the CDL integration performs.```

The integration will re-attempt authentication if the command was called under the following cases:

1. First hour - once every minute.
2. First 48 hours - once in 10 minutes.
3. After that every 60 minutes.

If you wish to try authenticating again, run the 'cdl-reset-authentication-timeout' command and retry.