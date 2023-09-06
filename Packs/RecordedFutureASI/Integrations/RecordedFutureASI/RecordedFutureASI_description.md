### What does this pack do?
#### This pack enables security teams to:

- Access a unified risk management from the most popular SOAR platform.
- Visualize to the most critical risks within your organization
- Identify security incidents filtered by severity (critical, medium and low)
- See the full context of the incident, including CVE id, name, description, and affected hostnames.

### Configure RecordedFutureASI on Cortex XSOAR
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
1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for RecordedFutureASI.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter**                                                                                      | **Required**  |
|---------------|----------------------------------------------------------------------------------------------------|
| API Key                                                                                            | True          |
| Project ID                                                                                         | True          |
| Min Severity                                                                                       | False         |
| Issue Grouping                                                                                     | False         |
| Expand Issues                                                                                      | False         |
| Fetch incidents                                                                                    | False         |
| Incidents Fetch Interval                                                                           | False         |
| Incident type                                                                                      | False         |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year) | False         |
| Max Fetch                                                                                          | False         |

5. Click **Test** to validate the token and connection.