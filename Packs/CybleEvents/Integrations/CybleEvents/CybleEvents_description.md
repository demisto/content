Cyble Intel is an integration which will help Existing Cyble Vision users. This integration would allow users to access the API avaialable as part of Vision Licensing and integrate the data into XSOAR. 

## Configure Cyble Intel on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Cyble Intel.
3. Click **Add instance** to create and configure a new integration instance.


# Commands
    
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

This integration provides following command(s) which can be used to access the Threat Intelligence

**!cyble-vision-fetch-iocs**
| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| from | Returns records started with given value | False |
| limit | Number of records to return (max 1000). Using a smaller limit will get faster responses. | False |
| start_date | Timeline start date in the format "YYYY-MM-DD". Need to used with end_date as timeline range. | False |
| end_date | Timeline end date in the format "YYYY-MM-DD". Need to used with start_date as timeline range. | False |
| type | Returns record by type like (CIDR, CVE, domain, email, FileHash-IMPHASH, FileHash-MD5, FileHash-PEHASH, FileHash-SHA1, FileHash-SHA256, FilePath, hostname, IPv4, IPv6, Mutex, NIDS, URI, URL, YARA, osquery, Ja3, Bitcoinaddress, Sslcertfingerprint). | False |
| keyword | Returns records for the specified keyword | False|


**!cyble-vision-fetch-events**
| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| from | Returns records for the timeline starting from given indice | True |
| limit | Number of records to return (max 50). Using a smaller limit will get faster responses. | True|
| start_date | Timeline start date in the format "YYYY/MM/DD" | True |
| end_date | Timeline end date in the format "YYYY/MM/DD" | True |
| order_by | Sorting order for alert fetch either Ascending or Descending | True |


**!cyble-vision-fetch-event-detail**
| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| event_type | Event Type of the Incident | True |
| event_id | Event ID of the incident | True |
