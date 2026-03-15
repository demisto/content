### Asimily Insight Integration

#### Configuration

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for **Asimily Insight**.
3. Click **Add instance** to create and configure a new integration instance.
4. Fill in the required fields:
    - **Asimily Portal URL**: Base URL of the Asimily Insight portal. Format: `https://customer-portal.asimily.com`.
    - **API Username** and **Password**: Asimily API user credentials. To create a new user, go to **Settings > Users** and click **Add User** on the Asimily Insight portal.
    - **Fetch incidents**: Enable to fetch incidents from Asimily Insight into Cortex XSOAR.
    - **Classifier and Mapper**: Default Classifier and Mapper provided as `Asimily_Insight - Classifier` and `Asimily_Insight - Incoming Mapper`.
    - **Incident Fetch Interval**: Set how often incidents should be fetched (e.g., `5 minutes`).
    - **Log Level**: Choose a log level from the dropdown.
    - **Single Engine**: Select **No engine**.

#### Incident Types

The integration can fetch the following incident types:

- **Asimily Anomaly** – Represents anomaly alerts.
- **Asimily CVE** – Represents vulnerabilities.

You can enable and filter these incidents with the following options:

- **Fetch Anomaly Alerts**: Enable to fetch anomaly alerts.
- **Fetch Device CVEs**: Enable to fetch device vulnerability incidents.
- **Fetch Anomaly Criticality**: Filter to only fetch anomalies of the selected criticality.
- **Fetch CVE Score**: Filter to only fetch CVEs above the specified score threshold.
- **Device Family Filter for Fetch Operation**: Only fetch incidents for specified device families.
- **Device Tags Filter for Fetch Operation**: Only fetch incidents for devices with specified tags.

#### Resetting the "Last Run" Timestamp

If you modify any of the fetch filters (*Fetch Anomaly Alerts*, *Fetch Device CVEs*, *Device Family Filter*, *Device Tags Filter*, *Fetch Anomaly Criticality*, *Fetch CVE Score*), this means there may be new devices included to fetch incidents or there will be new incidents included for existing devices. It is strongly recommended to **Reset the "last run" timestamp**. 

To reset:

1. Go to the integration instance configuration.
2. Navigate to **Collect > Advanced Settings**.
3. Click **Reset the "last run" timestamp**.
4. Click **Reset Now**.

This ensures that incidents related to newly included devices and updated filters are correctly fetched.

#### Configure Pre-Process Rules
The integration retrieves asset information, anomaly alerts, and CVEs from Asimily Insight—either through scheduled updates or on-demand queries—making it necessary to define a preprocessing rule that discards incoming incidents if they are duplicates.

The integration includes a preprocessing script (**PreProcessAsimilyDedup**) that will drop incoming incidents if it is a duplicate. It will search all past incidents with all status. The script can be used for configuring Pre-Process Rules to avoid duplication.