The SecBI integration for Cortex XSOAR requires the configuration of the following parameters:

* SECBI_API_URL - The URL to your SecBI instance which is used to query SecBI, such as: https://<SUBDOMAIN>.secbi.com.
* SECBI_API_KEY - The API key used for authentication with your SecBI instance, which can be obtained from the Settings page of your SecBI instance.

You will have an "insecure" connection if using an IP as your SECBI_API_URL, so ensure that you select the **Trust Any Certificate** checkbox.
