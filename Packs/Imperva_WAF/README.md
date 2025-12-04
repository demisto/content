<~XSIAM>

## Overview

Imperva Web Application Firewall (WAF) Gateway protects web applications from cyber attacks.
WAF Gateway continuously adapts to evolving threats, mitigates the risk of online data breaches, prevents account takeover, and addresses regulatory compliance requirements such as PCI DSS 6.6.
Imperva WAF Gateway is a key component of Imperva’s market-leading, full stack application security solution which brings defense-in-depth to a new level.

## This pack includes

Data normalization capabilities:
    *Rules for modeling Imperva SecureSphere CEF logs that are ingested via the Broker VM into Cortex XSIAM.
    * The ingested Imperva SecureSphere logs can be queried in XQL Search using the *`imperva_inc__securesphere_raw`* dataset.

**Supported log categories:** Security Logs

## Data Collection

### Imperva SecureSphere side

#### Create the Action Interface

The first step of the process is to define a new Action Interface.  This is accomplished by navigating to Admin -> System Definitions –> Action Interfaces.

1. Create a new action interface by clicking the red plus sign on the middle of the screen.
2. Expand your newly created action interface and uncheck the boxes next to the protocol, primary host and port, Syslog Log level, Message, and Facility options.
    a. Protocol can be TCP or UDP, matched to the Broker VM service you have created.
    b. Primary host can be either the externally accessible IP address, or the fully qualified domain name, of the Broker VM service you have created.
    c. Port should match the listening port of the Broker VM service you have created.
    d. Syslog Log level can be anything you choose. The default is “INFO”.
    e. The message is the full message format you wish to send to the Broker VM service you have created.
    f. Facility can be whatever you want. The default is “USER”.
3. Click the blue “Save” icon in the upper right corner of the screen to save your new Action Interface.

#### Create the Action Set

Navigate to Main -> Policies -> Action Sets.

1. First, create a new Action Set by clicking the red “Plus” sign in the upper left part of the screen.
2. Highlight the newly created Action Set on the left side of the screen,
and in the middle portion of the screen, send the Action Interface you created in the previous step, up to the top by clicking the green arrow next to it.
3. Name the field.
4. Click the blue “Save” icon in the upper right portion of the screen to save the newly created Action Set.

#### Add the Action Set to a Security Policy

The final step is to add the newly created Action Set to the security policies you wish to send to Broker VM.

1. Select the security policy you wish to have alerts for.
2. Click the blue “Save” icon in the upper right of the screen to save the new policy options.
3. Repeat for each policy you wish to have alerts sent for.

For more [information](https://community.imperva.com/blogs/craig-burlingame1/2020/11/13/steps-for-enabling-imperva-waf-gateway-alert).

### Cortex XSIAM side - Broker VM

To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Set-up-and-configure-Broker-VM#).

Follow the below steps to configure the Broker VM to receive Imperva SecureSphere logs.

1. Navigate to **Settings** → **Configuration** → **Data Broker** → **Broker VMs**.
2. Go to the **APPS** column under the **Brokers** tab and add the **Syslog** app for the relevant broker instance. If the **Syslog** app already exists, hover over it and click **Configure**.
3. Click **Add New**.
4. When configuring the Syslog Collector, set the following parameters:

    | Parameter    | Value                                                                                                                                           |
    |--------------|-------------------------------------------------------------------------------------------------------------------------------------------------|
    | `Protocol`   | Select **UDP** for the default forwarding, **TCP** or **Secure TCP** (depends on the protocol you configured in Imperva SecureSphere).          |
    | `Port`       | Enter the syslog service port that Cortex XSIAM Broker VM should listen on for receiving forwarded events from Imperva SecureSphere.            |
    | `Format`     | Enter CEF.                                                                                                                                      |
    | `Vendor`     | Enter imperva_inc_.                                                                                                                             |
    | `Product`    | Enter securesphere.                                                                                                                             |

</~XSIAM>
