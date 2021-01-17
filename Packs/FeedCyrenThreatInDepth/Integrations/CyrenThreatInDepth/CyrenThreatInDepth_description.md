## Cyren Threat InDepth Threat Intelligence Feed

To configure your instance of a Cyren Threat InDepth indicator feed, please provide the following:

* API URL: Should be pre-filled out for you, but in case you are being told to use a different one
* API Token: Supply your API JWT token that has been issued to you
* Feed name: Choose from the available options to ingest the type of data you are interested in
  * Keep in mind that the API token issued to you only corresponds to one of the data types each
  * `IP Reputation` for IP Reputation Intelligence
  * `Phishing URLs` for Phishing and Fraud URL Intelligence
  * `Malware URLs` for Malware URL Intelligence
  * `Malware Hashes` for Malware File Intelligence
* Maximum number of indicators: Maximum number of indicators to be fetched each time. The value cannot be higher than 100.000. If you provide a value higher than that it will be capped at 100.000.

The underlying Cyren Threat InDepth API provides you with an incremental feed, meaning it provides new
or modified indicators. It also works with an offset value that keeps track of your currently processed
indicators. Your current offset defaults at the globally known maximum offset on your first setup and
is being stored and updated for you in the integration instance context. The integration then uses the
"Maximum number of indicators" parameter as the count in each request. It is recommended to set it to
a high enough value so that you get all the feed indicators for maximum product value, to handle bursts
etc.(the value cannot be higher than 100.000 and it will be capped at that value if you set a higher one).

Please head over to [https://www.cyren.com/threat-indepth-demo](https://www.cyren.com/threat-indepth-demo) to get started!
