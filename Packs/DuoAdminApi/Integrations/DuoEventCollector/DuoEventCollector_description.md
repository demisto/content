DUO admin api provides programmatic access to the administrative functionality of Duo Security's two-factor authentication platform.

To set up an instance you will need:
API hostname: admin api hostname provided by duo (e.g. api-XXXXXXXX.duosecurity.com)
Integration key: your integration key provided by duo
Secret key: your secret key/password provided by duo

Notice that duo admin api requires different credentials from your regular duo account (i.e. another set of api hostname, integration key and secret key)

For more information please check out the documentation at [https://duo.com/docs/adminapi](https://duo.com/docs/adminapi) #disable-secrets-detection


Duo Events collector XSIAM
-
 Retrieve log events from Duo using its api


---

* **Server Host** - The api url for Duo.
* **API KEY** - The integration key.
* **SECRET KEY** - The secrete key.
* **First fetch from api time** - The time to take events from if no time is saved in the system.
* **XSIAM request limit** - The limit amount of events to retrieve from the api.
* **Request retries** - The number of retries to do to the api(we need it because too frequent request make the api retun a"too many requests 429" error).


## Step by step configuration

**Server Host** - `api-XXXX.duosecurity.com` which XXXX is your admin url:  
**INTEGRATION KEY** - Your integration key
**SECRET KEY** - Your secrete key
**Api request limit** - 100  
**First fetch from api time** - 1 Day  
**XSIAM request limit** - 01 Minutes 
**Request retries** - 5 
