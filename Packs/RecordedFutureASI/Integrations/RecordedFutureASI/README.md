### What does this pack do?
#### This pack enables security teams to:

- Access a unified risk management from the most popular SOAR platform.
- Visualize to the most critical risks within your organization
- Identify security incidents filtered by severity (critical, medium and low)
- See the full context of the incident, including CVE id, name, description, and affected hostnames.

### Configure RecordedFutureASI in Cortex
#### Get your Project ID
- Log in to SecurityTrails SurfaceBrowser
- Go to the Projects page by clicking the `Projects` link in the top right
- Click on the Project that you want to use in XSOAR
- Copy the ID from the URL (looks like `c1234567-c123-4123-9123-0123456789ab`)

#### Get your API Key
- Log in to SecurityTrails SurfaceBrowser
- Click the username in the top right corner
- Click on Account
- Go to API > API Keys
- Create a new API key with a note that it is being used for the XSOAR Integration

#### Setting up the Integration

| **Parameter**                                                                                      | **Required** |
|----------------------------------------------------------------------------------------------------|--------------|
| API Key                                                                                            | False        |
| Project ID                                                                                         | True         |
| Min Severity                                                                                       | False        |
| Issue Grouping                                                                                     | False        |
| Expand Issues                                                                                      | False        |
| Fetch incidents                                                                                    | False        |
| Incidents Fetch Interval                                                                           | False        |
| Incident type                                                                                      | False        |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year) | False        |
| Max Fetch                                                                                          | False        |


## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### asi-project-issues-fetch
***
Fetches all the current or added issues.


#### Base Command

`asi-project-issues-fetch`
#### Input

| **Argument Name** | **Description**                                     | **Required** |
|-------------------|-----------------------------------------------------| --- |
| issues_start      | Timestamp to get added issues after                 | Optional |
| group_by_host     | Whether to group results by host                    | Optional |
| expand_issues     | Whether to expand grouped host issues by each issue | Optional |


#### Context Output

There is no context output for this command.