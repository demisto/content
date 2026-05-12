# Atlassian Bitbucket

Atlassian Bitbucket is a Git-based source code management platform that enables teams to collaborate, review code, and deploy with built-in CI/CD tools

<~XSIAM>

## What does this pack contain?

- Filebeat log collection manual
- Modeling Rules for 'Audit events'
- Parsing Rules for json formated log

## Configuration on Server Side

### Setting the database retention period

You can decide to retain the data in the database for a maximum of 99 years, however, setting long retention periods can increase the size of your DB and affect performance.

To set the retention period:

In the administration area, go to … > **Settings**.
Adjust the **Database retention period**.
**Save your changes**.

### Selecting events to log

The events that are logged are organized in categories that belong to specific coverage areas.
For all coverage areas and events logged in each area, see [Audit log events](https://confluence.atlassian.com/bitbucketserver/audit-log-events-776640423.html).

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

For more inofrmation use the following guide [here](https://confluence.atlassian.com/bitbucketserver/view-and-configure-the-audit-log-776640417.html).

## Filebeat Collection

In order to use the collector, you need to use the following option to collect events from the vendor:

- [XDRC (XDR Collector)](#xdrc-xdr-collector)

You will need to configure the vendor and product for this specific collector.

## XDRC (XDR Collector)

You will need to use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/XDR-Collectors).

You can configure the vendor and product by replacing [vendor]\_[product]\_raw with atlassian_bitbucket_raw

When configuring the instance, you should use a YAML that configures the vendor and product, just as seen in the below configuration for the Atlassian Bitbucket product.

Copy and paste the below YAML in the "Filebeat Configuration File" section (inside the relevant profile under the "XDR Collectors Profiles").

#### Filebeat Configuration file

```commandline
- type: filestream
    enabled: true
    id: bitbucket
    paths: 
    - <local home directory>/log/audit/
    processors: 
      - add_fields: 
          fields: 
            vendor: atlassian
            product: bitbucket
```

This configuration will collect the data into a dataset named `atlassian_bitbucket_raw`.

**Please note**: The above configuration uses the default location of the Message Tracking logs. In case your Exchange server saves the Message Tracking logs under a different location, you would need to change it in the yaml (under the `paths` field).
</~XSIAM>

<~XSOAR>

### What does this pack do?

- Returns a specific project or a list of projects in a workspace.
- Returns a list of the open branches.
- Returns the information of the requested branch.
- Creates or deletes a branch in Bitbucket.
- Creates a new commit in Bitbucket.
- Returns a list of the commits in accordance with the included and excluded branches.
- Deletes a given file from Bitbucket.
- Returns the content of the given file, along with the option to download it.
- Creates or updates an issue in Bitbucket.
- Returns a specific issue or a list of all the issues, according to the limit parameter.
- Creates or updates a pull request in Bitbucket.
- Returns a list of the pull requests.
- Creates, updates, or deletes a comment on an issue in Bitbucket.
- Returns a list of comments on a specific issue.
- Creates, updates or deletes a comment on a pull request.
- Returns a list of comments of a specific pull request.
- Returns a list of all the members in the workspace.
</~XSOAR>
