## Cyren Threat InDepth Threat Intelligence

To configure your instance of a Cyren Threat InDepth indicator feed, please provide the following:

* API URL: Should be pre-filled out for you, but in case you are being told to use a different one
* API Token: Supply your API JWT token that has been issued to you
* Feed name: Choose from the available options to ingest the type of data you are interested in
  * keep in mind that the API token issued to you only corresponds to one of the data types each
  * `ip_reputation` for IP Reputation Intelligence
  * `phishing_urls` for Phishing and Fraud URL Intelligence
  * `malware_urls` for Malware URL Intelligence
  * `malware_files` for Malware File Intelligence
* Maximum number of indicators: This will set the number of indicators fetched for you periodically. Leave this at 100000 if you want the maximum number of indicators fetched every time.

Please head over to [https://www.cyren.com/threat-indepth-demo](https://www.cyren.com/threat-indepth-demo) to get started!
