#### OCI Related Parameters
Oracle Cloud Infrastructure SDKs and CLI require basic configuration information, which is achieved by using configuration parameters either with a configuration file or a runtime defined configuration dictionary. This integration uses the runtime defined configuration dictionary.
Read more about OCI configuration [here](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/sdkconfig.htm).

| **Parameter**                                                           | **Description**                                                                           |
|-------------------------------------------------------------------------|-------------------------------------------------------------------------------------------|
| Tenancy OCID                                                              | OCID of your tenancy. To get the value, see [Required Keys and OCIDs](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/apisigningkey.htm#Required_Keys_and_OCIDs). <br>   Example: ocid1.tenancy.oc1..<unique_ID>                                              | 
| User OCID                                                       | OCID of the user calling the API. To get the value, see [Required Keys and OCIDs](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/apisigningkey.htm#Required_Keys_and_OCIDs). <br> Example: ocid1.user.oc1..<unique_ID> | 
| API Key Fingerprint                                                                   | Fingerprint for the public key that was added to this user. To get the value, see [Required Keys and OCIDs](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/apisigningkey.htm#Required_Keys_and_OCIDs).                                                                  | 
| Private Key                                                                 | Private Key for authentication. <br> Important: The key pair must be in PEM format. For instructions on generating a key pair in PEM format, see [Required Keys and OCIDs](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/apisigningkey.htm#Required_Keys_and_OCIDs).                                                                       | 
| Region                                               | An Oracle Cloud Infrastructure region. See [Regions and Availability Domains](https://docs.oracle.com/en-us/iaas/Content/General/Concepts/regions.htm#top). <br> Example: us-ashburn-1          | True         |

#### API References

[Oracle Cloud Infrastructure Audit Logs API documentation](https://docs.oracle.com/en-us/iaas/Content/Logging/Concepts/audit_logs.htm)
<br>
[Oracle Cloud Infrastructure Audit API Endpoints (available Regions)](https://docs.oracle.com/en-us/iaas/api/#/en/audit/20190901)