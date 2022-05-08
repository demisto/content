DUO admin api provides programmatic access to the administrative functionality of Duo Security's two-factor authentication platform.

To set up an instance you will need:
API hostname: admin api hostname provided by duo (e.g. api-XXXXXXXX.duosecurity.com)
Integration key: your integration key provided by duo
Secret key: your secret key/password provided by duo

Notice that duo admin api requires different credentials from your regular duo account (i.e. another set of api hostname, integration key and secret key)

For more information please check out the documentation at [https://duo.com/docs/adminapi](https://duo.com/docs/adminapi) #disable-secrets-detection


Okta Events collector XSIAM
-
 Retrieve log events from Okta using its api


---

* **HostL** - The api url for Duo.
* **Log Type** - The kind of log to get from the api.
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