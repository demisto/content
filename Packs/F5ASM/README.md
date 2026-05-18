# F5 ASM

## Overview

F5 ASM is a web application firewall designed to protect web applications from common and advanced attacks, ensuring secure and reliable application traffic.

<~XSIAM>

## This pack includes

- Remote logging manual.
- Modeling Rules for Application Security Manager logs.

## Broker VM

You will need to use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Documentation/Set-up-and-configure-Broker-VM).\
You can configure the specific vendor and product for this instance.

1. Navigate to **Settings** -> **Configuration** -> **Data Broker** -> **Broker VMs**.
2. Right-click, and select **Syslog Collector** -> **Configure**.
3. When configuring the Syslog Collector, set:
   - vendor as F5
   - product as ASM

## Setting up remote logging

1. On the Main tab, click **SecurityEventLogs** -> **Logging**  -> **Profiles**.
The Logging Profiles list screen opens.
2. Click **Create**.
The Create New Logging Profile screen opens.
3. In the **Profile Name** field, type a unique name for the profile.
4. Select the **Application Security** check box.
The screen displays additional fields.
5. On the **Application Security** tab, for **Configuration**, select **Advanced**.
6. From the **Storage Destination** list, select **Remote Storage**.
Additional fields related to remote logging are displayed.
7. From the Logging Format list, select **Common Event Format (ArcSight)**
8. For the Protocol setting, select the protocol that the remote storage server uses: **TCP** (the default setting), **TCP-RFC3195**, or **UDP**.
9. For **Server Addresses**, Type the**IP Address of the Broker VM and Port** (default is 514), and click **Add**.
10. Click **Finished**.

For more information about remote logging, refer to [this documentation](https://techdocs.f5.com/en-us/bigip-14-1-0/big-ip-asm-implementations-14-1-0/logging-application-security-events.html).

</~XSIAM>
