<~XSIAM>

## This pack includes

Data normalization capabilities:

* Rules for parsing and modeling Cisco Catalyst logs that are ingested via the Broker VM (Syslog) on Cortex XSIAM.
  * The ingested Cisco Catalyst logs can be queried in XQL Search using the *`cisco_catalyst_raw`* dataset.

### Supported Timestamp Formats

The timestamp parsing is supported only for timestamps including a time zone - `MMM dd yyyy HH:mm:ss UTC`.

***

## Data Collection

### Cisco Catalyst side

To configure syslog forwarding from Cisco Catalyst to Cortex XSIAM, follow the below steps.

1. Access the switch's command-line interface (CLI) using a terminal emulator or SSH.
2. Access privileged EXEC mode by entering the following command and providing the enable password:

    ```
    enable
    ```

3. Enter global configuration mode:

    ```
    configure terminal
    ```

4. Enter the following command with the IP address of BrokerVM:

    ```
    logging host <BrokerVM IP>
    ```

5. Exit configuration mode:

    ```
    exit
    ```

6. To save the configuration changes run the command:

    ```
    write memory
    ```

More information can be found in the official Cisco Catalyst documentation.

### Cortex XSIAM side - Broker VM

To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Set-up-and-configure-Broker-VM#).

Follow the below steps to configure the Broker VM to receive Cisco Catalyst logs.

1. Navigate to **Settings** → **Configuration** → **Data Broker** → **Broker VMs**.
2. Go to the **APPS** column under the **Brokers** tab and add the **Syslog** app for the relevant broker instance. If the **Syslog** app already exists, hover over it and click **Configure**.
3. Click **Add New**.
4. When configuring the Syslog Collector, set the following parameters:

    | Parameter    | Value                                                                                                                            |
    |:-------------|:---------------------------------------------------------------------------------------------------------------------------------|
    | `Protocol`   | Select **UDP** for the default forwarding, **TCP** or **Secure TCP** (depends on the protocol you configured in Cisco Catalyst). |
    | `Port`       | Enter the syslog service port that Cortex XSIAM Broker VM should listen on for receiving forwarded events from Cisco Catalyst.   |
    | `Format`     | Select RAW.                                                                                                                      |
    | `Vendor`     | Enter cisco.                                                                                                                     |
    | `Product`    | Enter catalyst.                                                                                                                  |

</~XSIAM>
