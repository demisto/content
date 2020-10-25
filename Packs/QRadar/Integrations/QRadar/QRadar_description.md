# Fetch incidents:
You can apply additional (optional) filters for the fetch-incident query using the `Query to fetch offenses
` integration parameter. For more information on how to use the filter syntax, see the [QRadar filter documentation](https://www.ibm.com/support/knowledgecenter/en/SS42VS_7.3.3/com.ibm.qradar.doc/c_rest_api_filtering.html) and [QRadar offense documentation](https://www.ibm.com/support/knowledgecenter/en/SS42VS_7.3.2/com.ibm.qradar.doc/11.0--siem-offenses-GET.html).
* Full Incident Enrichment - Clear this checkbox to disable QRadar offense enrichment performed in fetch-incidents. This might help if you encounter a timeout while fetching new incidents.

# Required Permissions:
* Assets - Vulnerability Management *or* Assets
* Domains - Admin
* Offenses (Manage Closing Reason) - Manage Offense Closing Reasons
* Offenses (Assign Offenses to Users) - Assign Offenses to Users
* Offenses (Read) - Offenses
* References (Create/Update) - admin
* References (Read) - View Reference Data
