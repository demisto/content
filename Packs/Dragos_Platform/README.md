<~XSIAM>

### This pack includes:
Log Normalization - XDM mapping for key event types.

***

## Data Collection
To configure Dragos Platform to send logs to Cortex XSIAM, follow the below steps.

### Dragos Platform side
1. Log in to Dragos as an administrator.
2. Navigate to **Admin** &rarr; **Syslog** or browse to "https://\<your-site-store\>/syslog/".
3. Go to the **SERVERS** tab and click **+ ADD SERVER**.
4. Fill the below data:

    | Parameter                             | Value                                                                                 |
    |:--------------------------------------|:--------------------------------------------------------------------------------------|
    | Name                                  | Cortex XSIAM Broker VM.                                                               |
    | Hostname/IP                           | Enter the Broker VM IP address.                                                       |
    | Port                                  | Enter the syslog service port that you want to use for sending logs to the Broker VM. |
    | Protocol                              | TCP/TLS.                                                                              |
    | Source Hostname                       | Leave the default value / set a value of your choice.                                 |
    | Source Process                        | Leave the default value / set a value of your choice.                                 |
    | TLS Protocol Configuration (optional) | If protocol is set to TLS, set all the relevant values.                                  |

5. Check the **RFC 5424 Modern Syslog** checkbox under **Message Format**.
6. Check the **Use newline delimiter for TCP and TLS streams** checkbox under **Message Delimiter**.
7. Click **Next: SET TEMPLATE**.
8. From the **Output Message Format** dropdown, select CEF.
9. Use the recommended CEF template suggested by Dragos documentation, under **Message**.
10. Leave all other fields set to their default state.
11. Click **Save**.

For more information contact Dragos support.

### Cortex XSIAM side
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).

### Broker VM
Follow the below steps to configure the Broker VM to receive Dragos Platform logs.

1. Navigate to **Settings** &rarr; **Configuration** &rarr; **Data Broker** &rarr; **Broker VMs**.
2. Go to the **APPS** column under the **Brokers** tab and add the **Syslog** app for the relevant broker instance. If the **Syslog** app already exists, hover over it and click **Configure**.
3. Click **Add New**.
4. When configuring the Syslog Collector, set the following parameters:

    | Parameter    | Value                                                                                                                                           |
    |:-------------|:------------------------------------------------------------------------------------------------------------------------------------------------|                  
    | `Protocol`   | Select **UDP** for the default forwarding, **TCP** or **Secure TCP** (depends on the protocol you configured in the Dragos Platform configuration). | 
    | `Port`       | Enter the syslog service port that Cortex XSIAM Broker VM should listen on for receiving forwarded events from the Dragos Platform.                 |
    | `Vendor`     | Enter **dragos**.                                                                                                                                   |
    | `Product`    | Enter **platform**.                                                                                                                                 |

</~XSIAM>
