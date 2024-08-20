# Microsoft IIS Web Server

## Configuration on Microsoft IIS

Follow the steps bellow on Microsoft IIS to configure IIS logging at the [*site level*](https://learn.microsoft.com/en-us/iis/manage/provisioning-and-managing-iis/configure-logging-in-iis#configure-logging-at-the-site-level) using the UI.   
For configuring logging [*Per-site*](https://learn.microsoft.com/en-us/iis/manage/provisioning-and-managing-iis/configure-logging-in-iis#configure-per-site-logging-at-the-server-level) or [*Per-server*](https://learn.microsoft.com/en-us/iis/manage/provisioning-and-managing-iis/configure-logging-in-iis#configure-per-server-logging-at-the-server-level) at the server level, refer to the Microsoft [*Configure Logging in IIS*](https://learn.microsoft.com/en-us/iis/manage/provisioning-and-managing-iis/configure-logging-in-iis) docs. 

1. Open the IIS Manager:
![Server Screenshot](https://raw.githubusercontent.com/demisto/content/b33523bbb3666eb18c779b09d38fbf14e4764075/Packs/MicrosoftIISWebServer/doc_imgs/IISManager.png)

1. Under the **Connections** tree view on the left, select the requested website for logging.

2. In **Features View**, click **Logging**:
   ![Server Screenshot](https://raw.githubusercontent.com/demisto/content/b33523bbb3666eb18c779b09d38fbf14e4764075/Packs/MicrosoftIISWebServer/doc_imgs/IISWebsites.png)

3. In the **Log File** section under **Format**, select *W3C*:
   ![Server Screenshot](https://raw.githubusercontent.com/demisto/content/b33523bbb3666eb18c779b09d38fbf14e4764075/Packs/MicrosoftIISWebServer/doc_imgs/IISW3C.png)

4. Click **Select Fields** and ensure all the standard fields are selected:
![Server Screenshot](https://raw.githubusercontent.com/demisto/content/b33523bbb3666eb18c779b09d38fbf14e4764075/Packs/MicrosoftIISWebServer/doc_imgs/IISLogging.png)

### Supported Log Formats
The XDM normalization included in this pack is supported only for the *W3C* format, for logs with the following field list structures: 

####  Access Log 
``` bash
  date time s-sitename s-computername s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs-version cs(User-Agent) cs(Cookie) cs(Referer) cs-host sc-status sc-substatus sc-win32-status sc-bytes cs-bytes time-taken
```
#### Error Log

``` bash
  date time c-ip c-port s-ip s-port cs-version cs-method cs-uri sc-status s-siteid s-reason s-queuename
```

``` bash
  date time c-ip c-port s-ip s-port cs-version cs-method cs-uri streamid sc-status s-siteid s-reason s-queuename
```

``` bash
  date time c-ip c-port s-ip s-port cs-version cs-method cs-uri streamid streamid_ex sc-status s-siteid s-reason s-queuename transport
```


## Configuration on Cortex XSIAM 

### XDRC (XDR Collector) Filebeat Configuration

You will need to use the information described [here](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-pro-admin/cortex-xdr-collectors/xdr-collector-datasets#id7f0fcd4d-b019-4959-a43a-40b03db8a8b2) for Filebeat.

When configuring the *Filebeat Configuration File* (inside the relevant profile under the *XDR Collectors Profiles*) for the IIS collector instance, you can either use the sample configuration file below or select the predefined *IIS* template, and update it as necessary.  

#### IIS Filebeat Configuration File Sample

```yaml
filebeat.modules:
- module: iis
  access:
    enabled: true
    var.paths: ["C:/inetpub/**logs**/LogFiles/*/*.log"]
  error:
    enabled: true
    var.paths: ["C:/Windows/System32/LogFiles/HTTPERR/*.log"]
```