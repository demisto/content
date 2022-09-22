Use the CyberArk Identity Event Collector integration to get Audit and Auth logs for an application using REST APIs.

Before you start, you need to get the tenant ID, app ID, username, and password. For more information, see [CyberArk Identity Documentation](https://docs.cyberark.com/Product-Doc/OnlineHelp/Idaptive/Latest/en/Content/Integrations/SIEM-PlatformEvents/Identity%20Platform%20API%20Usage%20Guide%20for%20ArcSight.pdf), **Prerequisite for Accessing INGA Events** section (pages 4-10).

## Configuration Parameters

**Server URL**    
The endpoint to get the logs. For example, ``https://{{tenant}}.my.idaptive.app/``.

**App ID**  
The application ID to fetch the logs from.

**User name and Password**    
The SIEM user name and password.

**Vendor name**  
The vendor corresponding to the integration that created the events. This affects the name of the dataset where these events will be inserted {vendor_product_raw}.

**Product name**  
The product corresponding to the integration that created the events. This affects the name of the dataset where the events will be inserted {vendor_product_raw}.
