Duo Admin API provides programmatic access to the administrative functionality of Duo Security's two-factor authentication platform.

To set up an instance you will need:
- API hostname: admin API hostname provided by Duo (e.g., api-XXXXXXXX.duosecurity.com).
- Integration key: your integration key provided by Duo.
- Secret key: your secret key/password provided by Duo.

For more information, check out the documentation at [https://duo.com/docs/adminapi](https://duo.com/docs/adminapi).


Duo Events collector XSIAM
-
 Retrieve log events from Duo using its API.


---

* **Server Host** - The API URL for Duo.
* **API KEY** - The integration key.
* **SECRET KEY** - The secret key.
* **First fetch from api time** - The time to take events from if no time is saved in the system.
* **XSIAM request limit** - The maximum amount of events to retrieve from the API.
* **Request retries** - The number of retries to perform in the API. (This is necessary because if there are too many retries, the API will return a "too many requests 429" error).


## Step-by-step configuration

- **Server Host** - `api-XXXX.duosecurity.com` where XXXX is your admin URL.  
- **INTEGRATION KEY** - Your integration key.
- **SECRET KEY** - Your secret key.
- **Api request limit** - 100  
- **First fetch from api time** - 1 Day  
- **XSIAM request limit** - 01 Minutes 
- **Request retries** - 5 
