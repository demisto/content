Okta Events collector XSIAM
-
 Collects the events log for authentication and Audit provided by Okta admin API


---

* **Server URL** - The API domain URL for Okta.
* **API key** - The request API key.
* **Number of incidents to fetch per fetch** - The amount of items to retrieve from Okta's API per request (a number between 1 and 1000).
* **First fetch time interval** - The period (in days) to retrieve events from, if no time is saved in the system.


## Step by step configuration

**Server URL** - `https://<domain>.com/api/v1/logs` (where `domain` is your domain name). To get help finding your domain, see:  
https://developer.okta.com/docs/guides/find-your-domain/main/  
**API key** - your API key 
**Number of incidents to fetch per fetch** - 100  
**Events fetch  interval** - 01 Minutes 
**Fetches events** - True 

