## Binalyze AIR Integration SETUP

- Give a name to your instance,
- Type AIR server's URL(do not put a forward-slash at the end),
- Copy and paste the API key that you created in AIR Server,
- Test connection beforehand for the health check,
- Click Save & Exit on the right bottom corner.
---
## USAGE 
You can use the integration in Automation, Playbooks, or Playground.

**Isolation**
- !air-isolate *endpoint*=\<ENDPOINTNAME\> *organization_id*=\<ORGANIZATION ID\> *isolation*=\<ENABLE or DISABLE\>

**Acquisition**
- !air-acquire *endpoint*=\<ENDPOINTNAME\> *profile*=\<DEFINED PROFILE\> *caseid*=\<The Case ID\>

**Defined Profiles:**
- browsing-history
- compromise-assessment
- event-logs
- full
- memory-ram-pagefile
- quick

 ---
For more information, please refer to [View integration documentation](https://kb.binalyze.com/air/integrations/cortex-xsoar-integration).
 
For support, please e-mail us: support@binalyze.com 
