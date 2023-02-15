Use the CyberArk Identity integration to get Audit and Auth logs for an application using REST APIs.

Before you start, you need to get the tenant ID, app ID, username, and password. For more information, see [CyberArk Identity Documentation](https://docs.cyberark.com/Product-Doc/OnlineHelp/Idaptive/Latest/en/Content/Integrations/SIEM-PlatformEvents/Identity%20Platform%20API%20Usage%20Guide%20for%20ArcSight.pdf), **Prerequisite for Accessing INGA Events** section (pages 4-10).

## Configuration Parameters

**Server URL**    
The CyberArk Identity URL to get the logs from. For example, https://{{tenant}}.my.idaptive.app/

**App ID**  
The application ID to fetch the logs from.

**User name and Password** 

The user that was created in CyberArk for XSIAM integration.

**First fetch time**

The period to retrieve events for.
Format: <number> <time unit>, for example 12 hours, 1 day, 3 months.
Default is 3 days.
  
**Maximum number of events per fetch**
  
The maximum number of items to retrieve per request from CyberArk's API.