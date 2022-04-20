# CimTrak Integration to SOAR:
  The CimTrak integration with Palo Alto XSOAR allows you further vet and respond to emerging threats to your infrastructure.  CimTrak performs realtime detection of unauthorized modifications to servers and network devices, while also levering CIS Benchmarks to ensure that your key servers and devices are always in a hardened state. In addition, CimTrak can perform advanced remediation actions such as rolling back to a previous version of critical files. By combining CimTrak & Palo Alto XSOAR, via this integration, you now have the power to further analyze certain security events using CimTrak''s rich file assessment engines and/or verify them against a curated allow-list.   In addition, this integration will allow you to leverage CimTrak to integrate your your existing ITSM system such as ServiceNow, BMC Remedy, and Jira.     By unlocking dozens of new capabilities, this integration truly unlocks the orchestration and response capabilities of the Palo Alto SOAR.

1.) Fill in the URL to your App Server
   - Example URL -- https://192.168.1.1
   
2.) Fill the in API Key with your CimTrak API Key
   - To create an API Key, right click the top node in the Tree View
      - Click Properties
      - Click the "CimTrak Repo API Keys" Tab
      - Generate API Key

3.) Fill in Repository IP relative to the CimTrak AppServer (Management Console)
   - Typically they are installed on the same machine and you can use 127.0.0.1
   
4.) Fill in Repository Port
   - Default is 3749
   
5.) Once configured all unreconciled items from each CimTrak FIM Policies will be brought into XSOAR as an Incident as well as the ability to initiate Compliance Scans manually or based off a playbook as part of the Incident investigation.

# Additional CimTrak Resources & Documentation:

If you need any help please do not hesitate to reach out to our support team by submitting a ticket at https://www.cimcor.com/support
You can also call our support team at 1-877-424-6267 or 1-219-736-4400 and then press #2 for support.

You can find CimTrak Installation Guide and User Guide in your primary download package you received in the CimTrak_Enterprise_Server.zip file.

For more information and documentation on the CimTrak API navigate to your Management Console with the example link below:
- Note: Replace 192.168.1.1 with your CimTrak Server IP Address or FQDN
- https://192.168.1.1/cmc/#/apidoc