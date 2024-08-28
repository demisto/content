# F5 BIG-IP Advanced WAF
 
This pack includes Cortex XSIAM content.

<~XSIAM>
  
## Configuration on Server Side
You need to configure BIG-IP AWAF to forward Syslog messages.
In order to do so, create a logging profile and set remote logging to the relevant server.

* The product documentation is available [here](https://techdocs.f5.com/kb/en-us/products/big-ip_asm/manuals/product/asm-implementations-11-6-0/14.html). 

### Creating a logging profile
1. On the Main tab, click **Security** &rarr; **Event Logs** &rarr; **Logging Profiles**.
2. Click **Create**.
3. In the *Profile Name* field, type a unique name for the profile.
4. Select the **Application Security** checkbox.
5. On the *Application Security* tab, for *Configuration*, select **Advanced**.
6. Select the **Remote Storage** checkbox.
7. Click **Finished**.

### Setting Remote Logging
1. Connect to the BIG-IP web UI and log in with administrative rights.
2. Navigate to **Security** &rarr; **Event Logs** &rarr; **Logging Profiles**.
3. Click the name of the logging profile for which you want to set up remote logging.
4. Select the **Remote Storage** checkbox.
5. From the *Remote Storage Type* list, select **Remote**.
6. For the *Protocol* setting, select **TCP**.
7. For *Server Addresses*, type the IP Address, Port Number (default is 514), and click **Add**.
8. Click **Finished**. 

### Supported Timestamp Ingestion 
Timestamp ingestion is supported for the format: **%Y-%m-%dT%H:%M:%S%Ez** (yyyy-mm-ddTHH:MM:SS+ZZ:ZZ).
In order to configure the required timestamp for syslog messages, follow these instructions:

* The product documentation is available [here](https://my.f5.com/manage/s/article/K02138840). 

1. Log in to the BIG-IP command line.
2. Use a Linux editor to edit the syslog-ng configuration, in this case using *nano* editor.
```bash 
   nano /etc/syslog-ng/syslog-ng.conf
```
3. Add **ts_format(iso);** at the last line inside **options** section.
```bash 
    options {
        dir_perm(0755);
        perm(0600);
        chain_hostnames(no);
        keep_hostname(yes);
        stats_freq(0);
        log_fifo_size(2048);
        ts_format(iso);    --> !!!
        };
```
4. Restart syslog-ng service.
```bash 
   bigstart restart syslog-ng
```

## Collect Events from Vendor
In order to use the collector, use the [Broker VM](#broker-vm) option.
 
### Broker VM
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).
 
You can configure the specific vendor and product for this instance.
 
1. Navigate to **Settings** &rarr; **Configuration** &rarr; **Data Broker** &rarr; **Broker VMs**.
2. Go to the *Apps* column under the *Brokers* tab and add the *Syslog Collector* app for the relevant broker instance. If the app already exists, hover over it and click **Configure**.
3. Click **Add New** for adding a new syslog data source.
4. When configuring the new syslog data source, set the following values:
   | Parameter     | Value   
   | :---          | :---        
   | `Vendor`      | Enter **f5**.
   | `Product`     | Enter **waf**.
 
</~XSIAM>