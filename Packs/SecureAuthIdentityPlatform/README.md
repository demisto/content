
# SecureAuth Identity Platform
<~XSIAM>
This pack includes Cortex XSIAM content.


## Configuration on Server Side
This section describes the configuration that needs to be done on your on-prem deployment SecureAuth Web Admin interface in order to forward SecureAuth Identity Platform audit logs to Cortex XSIAM Broker VM via syslog. For cloud deployments syslog configuration, contact [SecureAuth Support](https://www.secureauth.com/support/).

1. In the Identity Platform administrative web interface, go to the **Advanced Settings**. 
2. From the advanced settings home page, click **Admin Realm**. 
3. Navigate to the **Logs** tab of the admin (SecureAuth0) realm.
4. Go to the **Log Options** section, and select the **Syslog** checkbox of the **Audit Logs** configuration for enabling syslog forwarding of audit log events. 
5. Go to the **Syslog** section and set the following configurations  -              
   - **`Syslog Server`** - Enter the IP address of the target [Cortex XSIAM Syslog Broker VM](#broker-vm). 
   - **`Syslog Port`** - Enter the syslog service port that the target Cortex XSIAM Broker VM is listening on for receiving forwarded events from SecureAuth Identity Platform. 
   - **`Syslog RFC Spec`** - Select [**RFC5424**](https://datatracker.ietf.org/doc/html/rfc5424). Then provide a Private Enterprise Number ([PEN](https://www.iana.org/assignments/enterprise-numbers/)).
6. Save your changes.

See [SecureAuth Identity Platform Logs Configuration](https://docs.secureauth.com/2307/en/configure-the-admin-realm--secureauth0-.html#logs-tab) for additional details.


## Collect Events from Vendor

In order to use the collector, use the [Broker VM](#broker-vm) option.

### Broker VM
You will need to use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** &rarr; **Configuration** &rarr; **Data Broker** &rarr; **Broker VMs**. 
2. Go to the **APPS** column under the **Brokers** tab and add the **Syslog** app for the relevant broker instance. If the **Syslog** app already exists, hover over it and click **Configure**.
3. Click **Add New**.
3. When configuring the Syslog Collector, set the following parameters:
   | Parameter     | Value    
   | :---          | :---                    
   | `Protocol`    | Select **UDP**.
   | `Port`        | Enter the syslog service port that Cortex XSIAM Broker VM should listen on for receiving forwarded events from SecureAuth Identity Platform. 
   | `Vendor`      | Enter **SecureAuth**. 
   | `Product`     | Enter **IDP**. 
   
</~XSIAM>
 