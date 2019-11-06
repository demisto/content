## Before starting to design an integration
- Find the documentation for the API of your product. It'll help to know what is supported via the API in order to design the commands and outputs for each one.

## Design Guidelines Checklist
- Make sure your integration is categorized correctly. Use cases can be helpful for the categorization as well as looking for similar integrations to the one you are working on. 
- Logo must be under 10kb. Make sure to use the company logo (and not the product’s). Eynav and Ido will help with this. 
- When mapping score to DBOT score stay as close as possible to the vendor’s scoring thresholds and categorization (these are usually documented/can be understood from the UI). Dbot score reputation includes the following scores: 0 – unknown, 1 – good, 2 – suspicious, 3 – bad. Give users a threshold argument in order to let customers override and set another scoring logic.
- Add score thresholds and DBOT score mapping to the integration documentation. 
- Add generic reputation commands such as “!url,ip,file,domain”. 
- Global Context outputs – Don’t forget global context outputs for dbot scoring and global indicators. You can find them [here](https://github.com/demisto/content/tree/master/docs/context_standards)
- Time arguments – When the command supports filtering results by time, use start + end time parameters (if supported by UI), and a timeframe parameter, that accepts inputs such as “4 days ago”, “5 minutes ago”, etc. 
- The data we return should make sense to an analyst (convert EPOCH, decrypt data if needed, If you return IDs, make sure to return the original asset name, category type, group name etc.)
- Make sure the parameters and command descriptions are in fact descriptive. 
- Stay as true to the product as possible- keep the same names as used by the vendor, the UI is a good baseline for what the human readable should look like. 
- Context limitation – If the result can include a lot of data, limit the context size. For example "Fetch Incidents" shouldn't return more than 100 records per fetch.
- Polling playbook & check status command – If the command can take more than a few minutes (vulnerability scan, complex search, detonation, etc) make sure to add a polling playbook. If implemented, do remember to include a “status” command as well. 
- Backwards compatibility – Don’t break it. Few suggested workarounds- keep the old context, add new paths as needed and update the outputs accordingly, if a command needs major changes- deprecate it and add a new one

## Usecases
1. [Analytics and SIEM](https://github.com/demisto/content/tree/master/docs/integration_design/usecases/Analytics_SIEM_usecase)
2. [Authentication](https://github.com/demisto/content/tree/master/docs/integration_design/usecases/Authentication_usecase)
3. [Case Management](https://github.com/demisto/content/tree/master/docs/integration_design/usecases/Case_Management_usecase)
4. [Data Enrichment and Threat Intelligence](https://github.com/demisto/content/tree/master/docs/integration_design/usecases/Data_Enrichment_Threat_Intelligence_usecase)
5. [Email Gateway](https://github.com/demisto/content/tree/master/docs/integration_design/usecases/Email_Gateway_usecase)
6. [Endpoint](https://github.com/demisto/internal-content/blob/master/documentation/design/usecases/Endpoint_usecase/README.MD)
7. [Forensics and Malware](https://github.com/demisto/content/tree/master/docs/integration_design/usecases/forensics_malware_usecase)
8. [Network Security (Firewall)](https://github.com/demisto/content/tree/master/docs/integration_design/usecases/network_security_IDS_IPS_usecase)
9. [Network Security (IDS/IPS)](https://github.com/demisto/content/tree/master/docs/integration_design/usecases/network_security_firewall_usecase)
10. [Vulnerability Management](https://github.com/demisto/content/tree/master/docs/integration_design/usecases/vulnerability_management_usecase)
