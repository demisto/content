Allows you to push and pull your external data to and from the KnowBe4 console.

## Configure KnowBe4 KMSAT Event Collector in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Your server URL |  | True |
| API Key | The API Key to use for connection. For more information about how to generate an API Key, refer to https://support.knowbe4.com/hc/en-us/articles/360024863474-User-Event-API| True |
| First fetch time interval | The time range to consider for the initial data fetch. \(&amp;lt;number&amp;gt; &amp;lt;unit&amp;gt;, e.g., 2 days, 2 months, 2 years\). Default is 1 day. | False |
| Events Fetch Interval | The Fetch interval. It is recommended to set it to 5 hours as there are not many events for this API and there's an api-calls daily-limit for the basic API key. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
    


**Important Notes**
The basic API-Key has a daily limit of calls per seat.
Therefore, the default and recommended **Events Fetch Interval** value is 5 hours and 
**First fetch time interval** is 1 day.

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### kms-get-events
Manual command to fetch events and display them.
#### Base Command
`kms-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| occurred_date | Filter by the date the event occurred (YYYY-MM-DD). | Optional | 
| risk_level | Filter by the risk level by  entering a value from -10 (low risk) to 10 (high risk). | Optional | 
| per_page | The number of results to display per page. The maximum and default is 100. | Optional | 
| page | The results page to display. | Optional | 
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display them. If setting to 'False', the returned events will be lost. Possible values are: True, False. Default is False. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| KMSat.Event.id | Number | Event ID. | 
| KMSat.Event.user.email | String | The target mail for this event. | 
| KMSat.Event.user.id | Number | The ID of the user the event is targeted to. | 
| KMSat.Event.user.archived | Boolean | Whether the user is archived or not. | 
| KMSat.Event.external_id | String | The event's external ID. | 
| KMSat.Event.source | String | The source of the event. | 
| KMSat.Event.description | String | The event description. | 
| KMSat.Event.occurred_date | String | The date the event occurred. | 
| KMSat.Event.risk.level | Number | The event's risk level. | 
| KMSat.Event.risk.factor | Number | The event's risk factor. | 
| KMSat.Event.risk.decay_mode | String | The risk's decay mode. | 
| KMSat.Event.risk.expire_date | String | The event's expiration date. | 
| KMSat.Event.event_type.id | Number | The ID of the event type. | 
| KMSat.Event.event_type.name | String | The name of the event type. | 

#### Command example
```!kms-get-events should_push_events=false```

#### Context Example
```json
{
    "KMSat": {
        "Event": [
            {
                "account_id": 52306,
                "description": "My description",
                "event_type": {
                    "description": null,
                    "id": 418927900,
                    "name": "my_custom_event"
                },
                "external_id": null,
                "id": "2b265035-1a12-4e76-bcb1-6c681b86333e",
                "metadata": null,
                "occurred_date": "2022-08-04T14:14:50.917Z",
                "risk": {
                    "decay_mode": 0,
                    "expire_date": null,
                    "level": 5
                },
                "source": null,
                "user": {
                    "archived": false,
                    "email": "example@paloaltonetworks.com",
                    "id": 38651943
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### KnowBe4 KMSAT Logs
>|AccountId|Description|EventType|Id|OccurredDate|Risk|User|
>|---|---|---|---|---|---|---|
>| 52306 | My description lkjhy khl lgf | id: 420899085<br/>name: event_type_55<br/>description: null | 786a515c-1cbd-4a8c-a94a-61ad877c893c | 2022-08-09T10:05:13.890Z | level: 5<br/>decay_mode: 0<br/>expire_date: null | email: maizen@paloaltonetworks.com<br/>id: 38651943<br/>archived: false |
>| 52306 | My description lkjhy khl lgf | id: 420894024<br/>name: event_type_2<br/>description: null | c3081dfc-1bf9-4c56-b6ff-f364f0c13d39 | 2022-08-09T10:01:45.862Z | level: 5<br/>decay_mode: 0<br/>expire_date: null | email: maizen@paloaltonetworks.com<br/>id: 38651943<br/>archived: false |
>| 52306 | My description | id: 418927900<br/>name: my_custom_event<br/>description: null | 2b265035-1a12-4e76-bcb1-6c681b86333e | 2022-08-04T14:14:50.917Z | level: 5<br/>decay_mode: 0<br/>expire_date: null | email: maizen@paloaltonetworks.com<br/>id: 38651943<br/>archived: false |