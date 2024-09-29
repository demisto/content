Collects Auth and Audit events for Duo using the API.

## Configure Duo Event Collector in Cortex


| **Parameter** | **Description**                                                                                          | **Required**  |
|----------------------------------------------------------------------------------------------------------|---------------| --- |
| Server Host               | The URL for the API.                                                                                     | True          |
| First fetch timestamps    | The first time fetch date range, for example: 2 days, 1 month, 3 years.                                  | True          |
| Integration key           | The integration key for the admin API from Duo.                                                           | True          |
| Secret key                | The secret key for the admin API from Duo.                                                               | True          |
| XSIAM request limit       | The maximum number of events to collect from the API in each cycle.                                      | True          |
| Request retries           | The number of times to retry a failed too many requests 429 HTTP error.                                   | False         |
| Use system proxy settings | Enable proxy support for running the collector.                                                          | False         |
| logs_type_array           | The type of APIs that this instance will use in the collector.            | False         |
| End of the fetch window   | The number of minutes to delay when fetching events (to handle events creation delay in the DUO database). The default value is 0 minutes. The recommended value is 5. | False         |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### duo-get-events
***
Manual command to fetch events and display them.


#### Base Command

`duo-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display them. Possible values are: True, False. Default is False. | Required |


## Known Limitations and recommended configuration
- As suggested by the [DUO ADMIN API](https://duo.com/docs/adminapi#authentication-logs:~:text=Administrative%20Units-,Logs,-Authentication%20Logs) documentation "We recommend requesting logs no more than once per minute".
- Recomended fetch time interval 1 minute and limit of up to 1000 per fetch.
- The returned logs are available ranging from the last 180 days up to as recently as two minutes before the API request.
#### Context Output

There is no context output for this command.

## Additional information
* The Duo eventing system is not real-time. It takes a few minutes for the events to be indexed and available for an API call due to consolidation. As a result the parameter "End of the fetch window" to adjust XSIAM to Duo's delay was added.