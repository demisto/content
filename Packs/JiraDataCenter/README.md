<~XSIAM>

## Atlassian Jira Data Center

Atlassian Jira Data Center is a self-managed issue and project tracking platform used by teams to plan, track, and manage work across various use cases.

## This pack includes

- Filebeat log collection manual
- Modeling Rules for 'Audit events'
- Parsing Rules for epoch timestamp to '_time' field

Note: For project level logs use the pack - Jira

***

## Data Collection

### Jira Datacenter side - Filebeat

### Setting the database retention period

You can decide to retain the data in the database for a maximum of 99 years, however, setting long retention periods can increase the size of your DB and affect performance.

To set the retention period:

In the administration area, go to **Settings**.
Adjust the **Database retention period**.
**Save your changes**.

### Selecting events to log

The events that are logged are organized in categories that belong to specific coverage areas.

To adjust the coverage:
In the administration area, go to … > **Settings**.
In the **Coverage level** drop-down, choose the coverage level to log.
Coverage levels reflect the number and frequency of events that are logged.

**Off**: Turns off logging events from this coverage area.

**Base**: Logs low-frequency and some of the high-frequency core events from selected coverage areas.

**Advanced**: Logs everything in Base, plus additional events where available.

**Full**: Logs all the events available in Base and Advanced, plus additional events for a comprehensive audit.

You can find the log file in the ***/your home directory/log/audit*** directory.
On clustered Bitbucket Data Center deployments, each application node will have its own log in the local ***/your home directory/log/audit*** directory.

For more inofrmation use the following guide [here](https://confluence.atlassian.com/adminjiraserver/audit-log-events-in-jira-998879036.html).

### Cortex XSIAM side -

1. Install the jira datacenter content pack from Cortex XSIAM Marketplace.
2. Configure an [XDR Collector](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Manage-XDR-Collectors):
   1. Create an XDR Collector installation package as described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Create-an-XDR-Collector-installation-package).
   2. Install the XDR Collector created installation package on the jira datacenter server:
      - For a *Windows* server see [Install the XDR Collector installation package for Windows](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Install-the-XDR-Collector-installation-package-for-Windows).
      - For a *Linux* server see [Install the XDR Collector installation package for Linux](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Install-the-XDR-Collector-installation-package-for-Linux).
   3. Configure an [XDR Collector Filebeat profile](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/XDR-Collector-profiles):
      - For a *Windows* server see [Add an XDR Collector profile for Windows](https://docs-cortex.pawloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Add-an-XDR-Collector-profile-for-Windows).
      - For a *Linux* server see [Add an XDR Collector profile for Linux](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Add-an-XDR-Collector-profile-for-Linux).
      - Customize the *[paths](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-filestream.html#filestream-input-paths)* parameter in accordance to the path contain your jira datacenter logs.

           ```
                - type: filestream
                    enabled: true
                    id: jira
                    paths: 
                    - <local home directory>/log/audit/
                    processors: 
                    - add_fields: 
                        fields: 
                            vendor: atlassian
                            product: jira
           ```

   4. Apply the configured Filebeat profile to the target jira datacenter server by attaching it to a policy as described on [Apply profiles to collection machine policies](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Apply-profiles-to-collection-machine-policies).

</~XSIAM>
