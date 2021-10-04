Use this content pack to retrieve alerts from F5 Silverline and read/update IP lists.

## Main use cases:
* Retrieve the list of alerts from the F5 Silverline portal so response processes can be built.
* Read or update the IP lists from the F5 Silverline portal so denylists and allowlists can be updated based on the customized workflows.
 
## What does this pack do?
The integration in this pack enables you to:
* Get a dynamic list of threatening IP addresses by the given list type (allowlist or denylist).
* Add a new particular threatening IP address object by its IP address.
* Delete an exising particular threatening IP address object by its object ID.

The F5 Silverline API does not support fetching incidents.
Configure the Syslog instance with your log receiver details to retreive the alerts
   * Click "Fetches incidents".
   * Set the Classifier to "F5 Silverline Classifier". 
   * Set the Mapper to "F5 Silverline Mapper".
   * IP address - specify the IP address of your log receiver host.
   * Port - specify the port of your log receiver host.
   * Protocol - choose TCP or UDP.
   * Format - specify to 'Auto'.
