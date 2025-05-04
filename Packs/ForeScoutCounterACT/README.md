<~XSIAM>
 
## Overview
Forescout CounterACT is a network access control (NAC) platform that helps organizations manage and secure devices connected to their network by providing real-time visibility, automated policy enforcement and threat prevention.
 
## This pack includes:

-   This pack includes Log Normalization and a Modeling Rule, enabling you to process ForeScout CounterACT network access control logs into XDM fields.
 
***
 
## Data Collection

### Forescout CounterACT side

1. Create and Configure the CEF Plugin
    -   Navigate to CEF -> Add -> Add a SIEM Server -> enter basic server parameters              
    | `Name`                 | The name of the SIEM server.                                                    |
    | `Address`              | The IP address of the SIEM server.                                              |
    | `Port`                 | The UDP Syslog port used by CEF.                                                |                                                                               
    | `Report time interval` | The frequency with which to update the SIEM server with compliance information. |
    | `Comment`              | Comments regarding the server.                                                  |
    - Enable the plugin and assign it to the appropriate device groups for deployment.

 2. Sending CEF Message
    -   Log in to the CounterACT Console
    -   Select the Policy icon from the Console toolbar
    -   Create or edit a policy.
    -   Navigate to Actions -> Send Compliant CEF message
    -   Add an action -> In the Actions tree, open the Audit group and select the **default** format "Send Compliant CEF message".

For more information [<Link to the official docs>](https://docs.forescout.com/).
 
### Cortex XSIAM side - Broker VMg
To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Configure-the-Broker-VM).
 
Follow the below steps to configure the Broker VM to receive Forescout CounterACT logs.
 
1. Navigate to **Settings** → **Configuration** → **Data Broker** → **Broker VMs**.
2. Go to the **APPS** column under the **Brokers** tab and add the **Syslog** app for the relevant broker instance. If the **Syslog** app already exists, hover over it and click **Configure**.
3. Click **Add New**.
4. When configuring the Syslog Collector, set the following parameters:
 
    | Parameter    | Value                                                                                                                                           |
    |:-------------|:------------------------------------------------------------------------------------------------------------------------------------------------|                 
    | `Protocol`   | Select **UDP** for the default forwarding, **TCP** or **Secure TCP** (depends on the protocol you configured in Forescout CounterACT).            |
    | `Port`       | Enter the syslog service port that Cortex XSIAM Broker VM should listen on for receiving forwarded events from Forescout CounterACT.              |
    | `Vendor`     | Enter forescout.                                                                                                                                 |
    | `Product`    | Enter counteract.                                                                                                                                |
    
</~XSIAM>