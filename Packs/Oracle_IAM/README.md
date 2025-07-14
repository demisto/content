<~XSIAM>

## Overview

A robust suite that helps organizations securely manage user identities and control access to critical systems and data. It includes components for authentication, Single Sign-On (SSO), authorization, identity lifecycle management, and federation.

## This pack includes

* Built-in commands for CRUD (create, read, update, and delete) operations for employee lifecycle processes.
* Modeling Rule for Audit Event logs that are ingested via the Broker VM on Cortex XSIAM.
* Parsing Rule for timestamp ingestion.
  * The ingested Oracle OAM logs can be queried in XQL Search using the *`oracle_oam_raw`* dataset.

### Supported Timestamp Formats

Ingestion is conducted according to the **IAU_TSTZORIGINATING** field, in UTC (+0000) format.

***

## Data Collection

### Cortex XSIAM side - Broker VM

To create or configure the Broker VM, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Set-up-and-configure-Broker-VM#).

Follow the below steps to configure the Broker VM to receive Oracle OAM logs.

1. Navigate to **Settings** → **Configuration** → **Data Broker** → **Broker VMs**.
2. Right-click the broker VM and select **DB Collector** -> **Activate**.
3. When configuring the Database Collector, set:

    | Parameter    | Value                                                                                                                                           |
    |:-------------|:------------------------------------------------------------------------------------------------------------------------------------------------|
    | `Rising Column`   | Enter IAU_TSTZORIGINATING            |
    | `Retrieval value`       | Specify the value from where the applet starts querying, e.g; 2025-02-02 10:30:00              |
    | `Vendor`     | Enter oracle.                                                                                                                                 |
    | `Product`    | Enter oam.                                                                                                                                |

You will need to use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Activate-Database-Collector).
When configuring the `Database Connection` the `SQL Query` should look as follows:

``` sql
SELECT * FROM <OAM_TABLE>
WHERE IAU_TSTZORIGINATING > ?
ORDER BY IAU_TSTZORIGINATING ASC
```

Make sure to use the correct value for "Retrieval Value", to match the Rising Column value type.

</~XSIAM>
