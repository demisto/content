# Shodan Banner
 Shodan is a search engine for Internet-connected devices. Unlike traditional search engines that index websites, Shodan indexes information about the devices connected to the internet, such as servers, routers, webcams, and other IoT devices.
<~XSIAM>
 
This pack includes Cortex XSIAM content.

## Configuration on Server Side
To enable the Shodan integration you need to have an API key, 
which you can get for free by creating a Shodan account https://account.shodan.io/register 
Once you have an API key you insert it into the API Key field and click the Test button.

## Configuration on Cortex XSIAM 
&rarr;
1. Navigate to **settings** &rarr; **Configurations** &rarr; **Automation & Feeds**.
2. Search for Shodan v2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | API Key |  | False |
    | Base URL to Shodan API |  | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Source Reliability | Reliability of the source providing the intelligence data. | False |
    | The maximum number of events per fetch |  | False |
</~XSIAM>
