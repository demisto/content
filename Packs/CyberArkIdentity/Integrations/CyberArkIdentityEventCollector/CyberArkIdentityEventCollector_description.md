Integration with CyberArk Identity using REST API to get the Audit and Auth log for an application.

## To get the configuration parameters please follow this guide
[CyberArk Identity Documentation](https://docs.cyberark.com/Product-Doc/OnlineHelp/Idaptive/Latest/en/Content/Integrations/SIEM-PlatformEvents/Identity%20Platform%20API%20Usage%20Guide%20for%20ArcSight.pdf).

## Configuration Parameters

**Server URL**
Endpoint to get the logs, For example: ``https://{{tenant}}.my.idaptive.app/``.

**App ID**
The application ID from where to fetch the logs.

**User name and Password**  
The siem user name and password.

**The vendor corresponding to the integration that originated the events**
The vendor name who created these events, Affects the name of the dataset where these events will insert {`vendor`_product_raw}

**The product corresponding to the integration that originated the events**
The product name who created the events, Affects the name of the dataset where the events will insert {vendor_`product`_raw}
