Okta Events collector XSIAM
-
 Retrieve log events from Okta using its api


---

* **Server URL** - The api url with your domain for Okta.
* **HTTP Method** - The http method you wish to use to use to send requests to the api in this integration.
* **Headers** - The request headers, should be as a stringify json.
* **Encrypted headers** - The request headers showed as asterisks in the integration settings, should be as a stringify json.
* **Api request limit** - The amount of item to get from Okta's api per request, it should be a number between 1 and 1000.
* **XSIAM update limit per request** - The amount of Okta events to save to XSIAM each run, it should be a number.
* **First fetch time interval** - The time to take events from if no time is saved in the system, it is a number in days.


## Step by step configuration

**Indicator Reputation** - `https://<domain>.com/api/v1/logs` which domain is your domain name, you can get help for finding your domain here:  
https://developer.okta.com/docs/guides/find-your-domain/main/  
**HTTP Method** - Currently Active  
**Headers** - {"Accept": "application/json","Content-Type": "application/json"}  
**Encrypted headers** - {"Authorization": "XXXX"} (XXXX is your api key)  
**Api request limit** - 100  
**SIEM request limit** - 1000  
**Events fetch  interval** - 01 Minutes 
**Fetches events** - True 
