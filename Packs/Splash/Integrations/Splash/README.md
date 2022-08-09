Welcome to the Splash API! This integration has been assembled to make it easier to navigate the API and access your Splash data.
This integration was integrated and tested with version 2.2 of Splash

## Configure Splash on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Splash.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL | True |
    | Credentials | True |
    | Password | True |
    | Client ID | True |
    | Client Secret | True |
    | Use system proxy settings | False |
    | Trust any certificate (not secure) | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### splash-list-events
***
Retrieve a list of Events.


#### Base Command

`splash-list-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Limits how many events are returned. If no limit is specified, the default is set to 5. | Optional | 
| page | When using a limit, this will allow you to specify which page of results to retrieve. | Optional | 
| search | Use a search string to refine your results. | Optional | 
| sort | Sort the results by a requested field. Possible values are: created_desc, created_asc, event_start_desc, event_start_asc, title_asc, title_desc, modified_asc, modified_desc. | Optional | 
| upcoming | Constrains your results to events with a start date later than 2 days ago. Possible values are: false, true. Default is false. | Optional | 
| past | Include past events. Possible values are: false, true. Default is false. | Optional | 
| tbd | Include or exclude events with TBD dates. Possible values are: false, true. Default is false. | Optional | 
| event_start_after | Only return events that start after a certain date (format: yyyy-mm-dd hh:mm:ss). | Optional | 
| event_start_before | Only return events that start before a certain date (format: yyyy-mm-dd hh:mm:ss). | Optional | 
| tag_names | Search your Splash events by their tags. | Optional | 
| venues | Specify the venues by which you would like to constrain your results. | Optional | 
| event_type_ids | Enter the event types by which you would like to filter. | Optional | 
| include_themes | Include themes in the event list. Possible values are: false, true. Default is false. | Optional | 
| theme_ids | Enter theme IDs to only retrieve events that use that specified theme. | Optional | 
| exclude_ids | Exclude specific event IDs from your request. | Optional | 
| rsvp_events | Limit your request to only RSVP events. Possible values are: false, true. Default is false. | Optional | 
| ticketed_events | Limit your request to only return ticketed events. Possible values are: false, true. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Splash.Event.stats.name | String |  | 
| Splash.Event.stats.count | Number |  | 
| Splash.Event.event_owner_first_name | String |  | 
| Splash.Event.event_owner_last_name | String |  | 
| Splash.Event.event_owner_email | String |  | 
| Splash.Event.registration_updating_enabled | Boolean |  | 
| Splash.Event.registration_updating_deadline | Number |  | 
| Splash.Event.id | Number |  | 
| Splash.Event.event_type.id | Number |  | 
| Splash.Event.event_type.name | String |  | 
| Splash.Event.splash_theme.id | Number |  | 
| Splash.Event.splash_theme.name | String |  | 
| Splash.Event.splash_theme.abbr | String |  | 
| Splash.Event.splash_theme.image_url | String |  | 
| Splash.Event.splash_theme.thumbnail_url | Unknown |  | 
| Splash.Event.splash_theme.sort | Number |  | 
| Splash.Event.splash_theme.active | Boolean |  | 
| Splash.Event.splash_theme.created | Date |  | 
| Splash.Event.event_setting.header_image | String |  | 
| Splash.Event.event_setting.rsvp_open | Boolean |  | 
| Splash.Event.event_setting.wait_list | Boolean |  | 
| Splash.Event.event_setting.id | Number |  | 
| Splash.Event.event_setting.rsvp_method | String |  | 
| Splash.Event.event_setting.lat | String |  | 
| Splash.Event.event_setting.lng | String |  | 
| Splash.Event.event_setting.event_hashtag | String |  | 
| Splash.Event.event_setting.rsvp_max | Number |  | 
| Splash.Event.event_setting.custom_questions.type | String |  | 
| Splash.Event.event_setting.custom_questions.name | String |  | 
| Splash.Event.event_setting.custom_questions.required | Boolean |  | 
| Splash.Event.event_setting.custom_questions.column_name | String |  | 
| Splash.Event.event_setting.event_cards.x1 | String |  | 
| Splash.Event.event_setting.event_cards.x2 | String |  | 
| Splash.Event.event_setting.event_cards.x3 | String |  | 
| Splash.Event.event_setting.venue_tbd | Number |  | 
| Splash.Event.event_setting.rsvp_guest_display | Boolean |  | 
| Splash.Event.event_setting.rsvp_closed_state | String |  | 
| Splash.Event.event_setting.rsvp_closed_at | Date |  | 
| Splash.Event.event_setting.rsvp_closed_team_notified | Boolean |  | 
| Splash.Event.event_setting.page_privacy_type | String |  | 
| Splash.Event.event_setting.event_host | String |  | 
| Splash.Event.statistics | Unknown |  | 
| Splash.Event.group_ids | String |  | 
| Splash.Event.title | String |  | 
| Splash.Event.description | String |  | 
| Splash.Event.description_text | String |  | 
| Splash.Event.event_start | Date |  | 
| Splash.Event.event_end | Date |  | 
| Splash.Event.hide_event_time | Boolean |  | 
| Splash.Event.venue_name | String |  | 
| Splash.Event.address | String |  | 
| Splash.Event.city | String |  | 
| Splash.Event.state | String |  | 
| Splash.Event.zip_code | String |  | 
| Splash.Event.country | String |  | 
| Splash.Event.created_at | Date |  | 
| Splash.Event.modified_at | Date |  | 
| Splash.Event.domain | String |  | 
| Splash.Event.paid_for_domain | Boolean |  | 
| Splash.Event.deleted | Boolean |  | 
| Splash.Event.custom_domain | String |  | 
| Splash.Event.hub | Number |  | 
| Splash.Event.mobility_account_id | String |  | 
| Splash.Event.mobility_wholesaler_id | String |  | 
| Splash.Event.fq_url | String |  | 
| Splash.Event.mobile_check_in_url | String |  | 
| Splash.Event.event_setting.email_settings.cached_maps.wide | String |  | 
| Splash.Event.event_setting.email_settings.cached_maps.square | String |  | 
| Splash.Event.event_setting.email_settings.google_map_url | String |  | 

#### Command example
```!splash-list-events```
#### Human Readable Output

>### All Events:
>**No entries.**


### splash-get-event
***
Retrieve a single event.


#### Base Command

`splash-get-event`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | The ID of the event for which details are needed. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Splash.Event.stats.name | String |  | 
| Splash.Event.stats.count | Number |  | 
| Splash.Event.event_owner_first_name | String |  | 
| Splash.Event.event_owner_last_name | String |  | 
| Splash.Event.event_owner_email | String |  | 
| Splash.Event.registration_updating_enabled | Boolean |  | 
| Splash.Event.registration_updating_deadline | Number |  | 
| Splash.Event.id | Number |  | 
| Splash.Event.event_type.id | Number |  | 
| Splash.Event.event_type.name | String |  | 
| Splash.Event.splash_theme.id | Number |  | 
| Splash.Event.splash_theme.name | String |  | 
| Splash.Event.splash_theme.abbr | String |  | 
| Splash.Event.splash_theme.image_url | String |  | 
| Splash.Event.splash_theme.thumbnail_url | Unknown |  | 
| Splash.Event.splash_theme.sort | Number |  | 
| Splash.Event.splash_theme.active | Boolean |  | 
| Splash.Event.splash_theme.created | Date |  | 
| Splash.Event.event_setting.header_image | String |  | 
| Splash.Event.event_setting.rsvp_open | Boolean |  | 
| Splash.Event.event_setting.wait_list | Boolean |  | 
| Splash.Event.event_setting.id | Number |  | 
| Splash.Event.event_setting.rsvp_method | String |  | 
| Splash.Event.event_setting.lat | String |  | 
| Splash.Event.event_setting.lng | String |  | 
| Splash.Event.event_setting.event_hashtag | String |  | 
| Splash.Event.event_setting.rsvp_max | Number |  | 
| Splash.Event.event_setting.custom_questions.type | String |  | 
| Splash.Event.event_setting.custom_questions.name | String |  | 
| Splash.Event.event_setting.custom_questions.required | Boolean |  | 
| Splash.Event.event_setting.custom_questions.column_name | String |  | 
| Splash.Event.event_setting.event_cards.x1 | String |  | 
| Splash.Event.event_setting.event_cards.x2 | String |  | 
| Splash.Event.event_setting.event_cards.x3 | String |  | 
| Splash.Event.event_setting.venue_tbd | Number |  | 
| Splash.Event.event_setting.rsvp_guest_display | Boolean |  | 
| Splash.Event.event_setting.rsvp_closed_state | String |  | 
| Splash.Event.event_setting.rsvp_closed_at | Date |  | 
| Splash.Event.event_setting.rsvp_closed_team_notified | Boolean |  | 
| Splash.Event.event_setting.page_privacy_type | String |  | 
| Splash.Event.event_setting.event_host | String |  | 
| Splash.Event.statistics | Unknown |  | 
| Splash.Event.group_ids | String |  | 
| Splash.Event.title | String |  | 
| Splash.Event.description | String |  | 
| Splash.Event.description_text | String |  | 
| Splash.Event.event_start | Date |  | 
| Splash.Event.event_end | Date |  | 
| Splash.Event.hide_event_time | Boolean |  | 
| Splash.Event.venue_name | String |  | 
| Splash.Event.address | String |  | 
| Splash.Event.city | String |  | 
| Splash.Event.state | String |  | 
| Splash.Event.zip_code | String |  | 
| Splash.Event.country | String |  | 
| Splash.Event.created_at | Date |  | 
| Splash.Event.modified_at | Date |  | 
| Splash.Event.domain | String |  | 
| Splash.Event.paid_for_domain | Boolean |  | 
| Splash.Event.deleted | Boolean |  | 
| Splash.Event.custom_domain | String |  | 
| Splash.Event.hub | Number |  | 
| Splash.Event.mobility_account_id | String |  | 
| Splash.Event.mobility_wholesaler_id | String |  | 
| Splash.Event.fq_url | String |  | 
| Splash.Event.mobile_check_in_url | String |  | 
| Splash.Event.event_setting.email_settings.cached_maps.wide | String |  | 
| Splash.Event.event_setting.email_settings.cached_maps.square | String |  | 
| Splash.Event.event_setting.email_settings.google_map_url | String |  | 

#### Command example
```!splash-get-event event_id=458498411```
#### Context Example
```json
{
    "Splash": {
        "Event": {
            "address": "",
            "attendance_types": [
                "virtual"
            ],
            "city": "",
            "country": "",
            "created_at": "2022-08-09T06:23:40-04:00",
            "custom_domain": "",
            "deleted": false,
            "description": "",
            "description_text": "<p>Tickets are non-transferrable. All guests must RSVP individually \u2013 no +1s admitted. Coffee will be provided at the door. Breakfast will be served promptly at 8:15am. Please have your RSVP confirmation email available at the door to receive your complimentary breakfast ticket.</p>",
            "domain": "newtestevent123",
            "event_end": "2022-08-31T22:00:00+01:00",
            "event_owner_email": "mail@domain.com",
            "event_owner_first_name": "FirstName",
            "event_owner_last_name": "Lastname",
            "event_setting": {
                "autosave": false,
                "button_closed_message": "",
                "currency": [],
                "custom_questions": [
                    {
                        "column_name": "first_name",
                        "name": "First Name",
                        "required": true,
                        "selected_values": [],
                        "type": "text",
                        "values": []
                    },
                    {
                        "column_name": "last_name",
                        "name": "Last Name",
                        "required": true,
                        "selected_values": [],
                        "type": "text",
                        "values": []
                    },
                    {
                        "column_name": "email",
                        "name": "Email",
                        "required": true,
                        "selected_values": [],
                        "type": "email",
                        "values": []
                    }
                ],
                "email_settings": {
                    "cached_maps": {
                        "square": "https://s3.amazonaws.com/s3.clients.splashthat.com/img/events/id/458/458498411/assets/map-1660040624.200x200.png",
                        "wide": "https://s3.amazonaws.com/s3.clients.splashthat.com/img/events/id/458/458498411/assets/map-1660040622.550x220.png"
                    },
                    "google_map_url": "http://maps.google.com/?q=NaN,NaN",
                    "triggered_emails": [
                        {
                            "active": 1,
                            "event_message_id": null,
                            "event_message_linked_to_theme": 1,
                            "ticket_type_id": null,
                            "trigger": "rsvp-yes"
                        },
                        {
                            "event_message_id": null,
                            "event_message_linked_to_theme": 1,
                            "trigger": "ticket-default"
                        },
                        {
                            "event_message_id": null,
                            "event_message_linked_to_theme": 1,
                            "trigger": "ticket-multi"
                        }
                    ]
                },
                "event_cards": {
                    "x1": "https://s3.amazonaws.com/s3.clients.splashthat.com/img/events/splash/cards/458498411.x1.6c250fc4.png",
                    "x2": "https://s3.amazonaws.com/s3.clients.splashthat.com/img/events/splash/cards/458498411.x2.1222f86e.png",
                    "x3": "https://s3.amazonaws.com/s3.clients.splashthat.com/img/events/splash/cards/458498411.x3.d2daa824.png"
                },
                "event_hashtag": "#castironbreakfast",
                "event_host": "FirstName Lastname",
                "header_image": "https://d24wuq6o951i2g.cloudfront.net/img/events/id/245/2452081/assets/793.friedegg.png",
                "id": 2377224,
                "lat": "NaN",
                "lng": "NaN",
                "page_privacy_type": "none",
                "rsvp_closed_at": null,
                "rsvp_closed_state": "open",
                "rsvp_closed_team_notified": false,
                "rsvp_guest_display": false,
                "rsvp_max": 1,
                "rsvp_method": "collect",
                "rsvp_open": true,
                "venue_tbd": 0,
                "wait_list": false,
                "waitlist_settings": []
            },
            "event_stages": [
                [],
                []
            ],
            "event_start": "2022-08-31T09:00:00+01:00",
            "event_type": {
                "id": 24551,
                "name": "Seminars & Workshops"
            },
            "fq_url": "https://newtestevent123.splashthat.com",
            "group_ids": [
                ""
            ],
            "hide_event_time": true,
            "hub": 0,
            "id": 458498411,
            "mobile_check_in_url": "https://newtestevent123.splashthat.com/checkin/341239896b2954a99e857e8687c8c53d0d9f19ea4a31b9ce0741e894159c0ec6",
            "mobility_account_id": "",
            "mobility_wholesaler_id": "",
            "modified_at": "2022-08-09T12:01:10-04:00",
            "organization": null,
            "paid_for_domain": false,
            "published": true,
            "registration_updating_deadline": 0,
            "registration_updating_enabled": null,
            "splash_theme": {
                "abbr": "Nosh",
                "active": true,
                "created": "2016-02-05T14:19:05-05:00",
                "id": 1201376,
                "image_url": "//d24wuq6o951i2g.cloudfront.net/img/events/id/245/2452081/assets/93b.2019-05-13-18-18-interactive-2.splashthat.com.png",
                "name": "Nosh",
                "sort": 45,
                "thumbnail_url": null
            },
            "state": "",
            "statistics": null,
            "stats": [
                {
                    "count": 0,
                    "name": "invited"
                },
                {
                    "count": 1,
                    "name": "rsvp_yes"
                },
                {
                    "count": 0,
                    "name": "checkin_yes"
                }
            ],
            "ticket_types": [],
            "time_zone": [],
            "title": "a new title",
            "user": [],
            "venue_name": "Virtual",
            "zip_code": ""
        }
    }
}
```

#### Human Readable Output

>### Event ID 458498411:
>|address|attendance_types|city|country|created_at|custom_domain|deleted|description|description_text|domain|event_end|event_owner_email|event_owner_first_name|event_owner_last_name|event_setting|event_stages|event_start|event_type|fq_url|group_ids|hide_event_time|hub|id|mobile_check_in_url|mobility_account_id|mobility_wholesaler_id|modified_at|organization|paid_for_domain|published|registration_updating_deadline|registration_updating_enabled|splash_theme|state|statistics|stats|ticket_types|time_zone|title|user|venue_name|zip_code|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|  | virtual |  |  | 2022-08-09T06:23:40-04:00 |  | false |  | <p>Tickets are non-transferrable. All guests must RSVP individually – no +1s admitted. Coffee will be provided at the door. Breakfast will be served promptly at 8:15am. Please have your RSVP confirmation email available at the door to receive your complimentary breakfast ticket.</p> | newtestevent123 | 2022-08-31T22:00:00+01:00 | mail@domain.com | FirstName | Lastname | id: 2377224<br/>header_image: https:<span>//</span>d24wuq6o951i2g.cloudfront.net/img/events/id/245/2452081/assets/793.friedegg.png<br/>rsvp_open: true<br/>wait_list: false<br/>rsvp_method: collect<br/>lat: NaN<br/>lng: NaN<br/>currency: <br/>event_hashtag: #castironbreakfast<br/>rsvp_max: 1<br/>custom_questions: {'type': 'text', 'name': 'First Name', 'required': True, 'column_name': 'first_name', 'values': [], 'selected_values': []},<br/>{'type': 'text', 'name': 'Last Name', 'required': True, 'column_name': 'last_name', 'values': [], 'selected_values': []},<br/>{'type': 'email', 'name': 'Email', 'required': True, 'column_name': 'email', 'values': [], 'selected_values': []}<br/>event_cards: {"x1": "https:<span>//</span>s3.amazonaws.com/s3.clients.splashthat.com/img/events/splash/cards/458498411.x1.6c250fc4.png", "x2": "https:<span>//</span>s3.amazonaws.com/s3.clients.splashthat.com/img/events/splash/cards/458498411.x2.1222f86e.png", "x3": "https:<span>//</span>s3.amazonaws.com/s3.clients.splashthat.com/img/events/splash/cards/458498411.x3.d2daa824.png"}<br/>venue_tbd: 0<br/>rsvp_guest_display: false<br/>rsvp_closed_state: open<br/>rsvp_closed_at: null<br/>rsvp_closed_team_notified: false<br/>waitlist_settings: <br/>page_privacy_type: none<br/>email_settings: {"triggered_emails": [{"trigger": "rsvp-yes", "active": 1, "event_message_id": null, "event_message_linked_to_theme": 1, "ticket_type_id": null}, {"trigger": "ticket-default", "event_message_id": null, "event_message_linked_to_theme": 1}, {"trigger": "ticket-multi", "event_message_id": null, "event_message_linked_to_theme": 1}], "cached_maps": {"wide": "https:<span>//</span>s3.amazonaws.com/s3.clients.splashthat.com/img/events/id/458/458498411/assets/map-1660040622.550x220.png", "square": "https:<span>//</span>s3.amazonaws.com/s3.clients.splashthat.com/img/events/id/458/458498411/assets/map-1660040624.200x200.png"}, "google_map_url": "http:<span>//</span>maps.google.com/?q=NaN,NaN"}<br/>event_host: FirstName Lastname<br/>button_closed_message: <br/>autosave: false | [],<br/>[] | 2022-08-31T09:00:00+01:00 | id: 24551<br/>name: Seminars & Workshops | https:<span>//</span>newtestevent123.splashthat.com |  | true | 0 | 458498411 | https:<span>//</span>newtestevent123.splashthat.com/checkin/341239896b2954a99e857e8687c8c53d0d9f19ea4a31b9ce0741e894159c0ec6 |  |  | 2022-08-09T12:01:10-04:00 |  | false | true | 0 |  | id: 1201376<br/>name: Nosh<br/>abbr: Nosh<br/>image_url: //d24wuq6o951i2g.cloudfront.net/img/events/id/245/2452081/assets/93b.2019-05-13-18-18-interactive-2.splashthat.com.png<br/>thumbnail_url: null<br/>sort: 45<br/>active: true<br/>created: 2016-02-05T14:19:05-05:00 |  |  | {'name': 'invited', 'count': 0},<br/>{'name': 'rsvp_yes', 'count': 1},<br/>{'name': 'checkin_yes', 'count': 0} |  |  | a new title |  | Virtual |  |


### splash-event-details
***
Some event object fields are not returned in the basic event data. This will return additional details.


#### Base Command

`splash-event-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | The ID of the event for which details are needed. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Splash.Event.title | String |  | 
| Splash.Event.domain | String |  | 
| Splash.Event.custom_domain | String |  | 
| Splash.Event.paid_for_domain | Boolean |  | 
| Splash.Event.white_label | Number |  | 
| Splash.Event.start_time | Date |  | 
| Splash.Event.end_time | Unknown |  | 
| Splash.Event.venue.name | String |  | 
| Splash.Event.venue.address | String |  | 
| Splash.Event.venue.city | String |  | 
| Splash.Event.venue.region | String |  | 
| Splash.Event.venue.country | String |  | 
| Splash.Event.venue.postal_code | String |  | 
| Splash.Event.venue.lat | String |  | 
| Splash.Event.venue.lon | String |  | 
| Splash.Event.type | String |  | 
| Splash.Event.event_host | String |  | 
| Splash.Event.status | String |  | 
| Splash.Event.page_action | String |  | 
| Splash.Event.tags | String |  | 
| Splash.Event.waitlist | Boolean |  | 
| Splash.Event.currency | String |  | 
| Splash.Event.meta_title | Unknown |  | 
| Splash.Event.meta_description | Unknown |  | 
| Splash.Event.meta_calendar_description | Unknown |  | 
| Splash.Event.favicon_url | String |  | 
| Splash.Event.no_index | Boolean |  | 
| Splash.Event.limit_one_per_email | Boolean |  | 
| Splash.Event.is_invite_only | Boolean |  | 
| Splash.Event.page_password | Unknown |  | 
| Splash.Event.page_privacy_type | String |  | 
| Splash.Event.require_captcha | Boolean |  | 
| Splash.Event.facebook_title | Unknown |  | 
| Splash.Event.facebook_description | Unknown |  | 
| Splash.Event.twitter_default | Unknown |  | 
| Splash.Event.linkedin_title | Unknown |  | 
| Splash.Event.linkedin_description | Unknown |  | 
| Splash.Event.hashtag | String |  | 
| Splash.Event.salesforce_campaign_id | String |  | 
| Splash.Event.sessions_overlap | Boolean |  | 
| Splash.Event.share_image_url | String |  | 
| Splash.Event.time_zone_id | Number |  | 
| Splash.Event.invite_link_privacy_bypass | Boolean |  | 
| Splash.Event.registration_updating_enabled | Boolean |  | 
| Splash.Event.registration_updating_deadline | Number |  | 
| Splash.Event.splash_hub_auto_subscribe | Number |  | 
| Splash.Event.form_email_domain_restriction | Unknown |  | 
| Splash.Event.email_white_label_key | Unknown |  | 
| Splash.Event.description_text | String |  | 
| Splash.Event.user.event_types.id | Number |  | 
| Splash.Event.user.event_types.name | String |  | 
| Splash.Event.is_rsvp_open | Boolean |  | 

### splash-update-event
***
Update and make changes to an existing Event with a known ID.


#### Base Command

`splash-update-event`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | Event ID to update. | Required | 
| update_data | The JSON Dict of data to update. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Splash.Event.stats.name | String |  | 
| Splash.Event.stats.count | Number |  | 
| Splash.Event.event_owner_first_name | String |  | 
| Splash.Event.event_owner_last_name | String |  | 
| Splash.Event.event_owner_email | String |  | 
| Splash.Event.registration_updating_enabled | Boolean |  | 
| Splash.Event.registration_updating_deadline | Number |  | 
| Splash.Event.id | Number |  | 
| Splash.Event.event_type.id | Number |  | 
| Splash.Event.event_type.name | String |  | 
| Splash.Event.splash_theme.id | Number |  | 
| Splash.Event.splash_theme.name | String |  | 
| Splash.Event.splash_theme.abbr | String |  | 
| Splash.Event.splash_theme.image_url | String |  | 
| Splash.Event.splash_theme.thumbnail_url | Unknown |  | 
| Splash.Event.splash_theme.sort | Number |  | 
| Splash.Event.splash_theme.active | Boolean |  | 
| Splash.Event.splash_theme.created | Date |  | 
| Splash.Event.event_setting.header_image | String |  | 
| Splash.Event.event_setting.rsvp_open | Boolean |  | 
| Splash.Event.event_setting.wait_list | Boolean |  | 
| Splash.Event.event_setting.id | Number |  | 
| Splash.Event.event_setting.rsvp_method | String |  | 
| Splash.Event.event_setting.lat | String |  | 
| Splash.Event.event_setting.lng | String |  | 
| Splash.Event.event_setting.event_hashtag | String |  | 
| Splash.Event.event_setting.rsvp_max | Number |  | 
| Splash.Event.event_setting.custom_questions.type | String |  | 
| Splash.Event.event_setting.custom_questions.name | String |  | 
| Splash.Event.event_setting.custom_questions.required | Boolean |  | 
| Splash.Event.event_setting.custom_questions.column_name | String |  | 
| Splash.Event.event_setting.event_cards.x1 | String |  | 
| Splash.Event.event_setting.event_cards.x2 | String |  | 
| Splash.Event.event_setting.event_cards.x3 | String |  | 
| Splash.Event.event_setting.venue_tbd | Number |  | 
| Splash.Event.event_setting.rsvp_guest_display | Boolean |  | 
| Splash.Event.event_setting.rsvp_closed_state | String |  | 
| Splash.Event.event_setting.rsvp_closed_at | Date |  | 
| Splash.Event.event_setting.rsvp_closed_team_notified | Boolean |  | 
| Splash.Event.event_setting.page_privacy_type | String |  | 
| Splash.Event.event_setting.event_host | String |  | 
| Splash.Event.statistics | Unknown |  | 
| Splash.Event.group_ids | String |  | 
| Splash.Event.title | String |  | 
| Splash.Event.description | String |  | 
| Splash.Event.description_text | String |  | 
| Splash.Event.event_start | Date |  | 
| Splash.Event.event_end | Date |  | 
| Splash.Event.hide_event_time | Boolean |  | 
| Splash.Event.venue_name | String |  | 
| Splash.Event.address | String |  | 
| Splash.Event.city | String |  | 
| Splash.Event.state | String |  | 
| Splash.Event.zip_code | String |  | 
| Splash.Event.country | String |  | 
| Splash.Event.created_at | Date |  | 
| Splash.Event.modified_at | Date |  | 
| Splash.Event.domain | String |  | 
| Splash.Event.paid_for_domain | Boolean |  | 
| Splash.Event.deleted | Boolean |  | 
| Splash.Event.custom_domain | String |  | 
| Splash.Event.hub | Number |  | 
| Splash.Event.mobility_account_id | String |  | 
| Splash.Event.mobility_wholesaler_id | String |  | 
| Splash.Event.fq_url | String |  | 
| Splash.Event.mobile_check_in_url | String |  | 
| Splash.Event.event_setting.email_settings.cached_maps.wide | String |  | 
| Splash.Event.event_setting.email_settings.cached_maps.square | String |  | 
| Splash.Event.event_setting.email_settings.google_map_url | String |  | 

#### Command example
```!splash-update-event event_id=458498411 update_data="""{"title": "a new title"}"""```
#### Context Example
```json
{
    "Splash": {
        "Event": {
            "attendance_types": [
                "virtual"
            ],
            "autosave": false,
            "button_closed_message": "",
            "currency": "USD",
            "custom_domain": "",
            "description_text": "Tickets are non-transferrable. All guests must RSVP individually \u2013 no +1s admitted. Coffee will be provided at the door. Breakfast will be served promptly at 8:15am. Please have your RSVP confirmation email available at the door to receive your complimentary breakfast ticket.",
            "domain": "newtestevent123",
            "email_white_label_key": null,
            "end_time": "2022-08-31T22:00:00",
            "event_host": "FirstName Lastname",
            "event_workflow": null,
            "facebook_description": null,
            "facebook_title": null,
            "favicon_url": "//d24wuq6o951i2g.cloudfront.net/img/events/id/245/2452081/assets/195.favicon-black.png",
            "form": {
                "isInLibrary": false
            },
            "form_email_domain_restriction": null,
            "has_virtual": false,
            "hashtag": "#castironbreakfast",
            "hide_footer": false,
            "invite_link_privacy_bypass": false,
            "is_invite_only": false,
            "is_rsvp_open": true,
            "limit_one_per_email": true,
            "linkedin_description": null,
            "linkedin_title": null,
            "locale": null,
            "meta_calendar_description": null,
            "meta_description": null,
            "meta_title": null,
            "multisession": false,
            "no_index": false,
            "page_action": "collect",
            "page_password": null,
            "page_privacy_type": "none",
            "paid_for_domain": false,
            "published": true,
            "redirect_to": "",
            "registration_updating_deadline": 0,
            "registration_updating_enabled": false,
            "require_captcha": false,
            "salesforce_campaign_id": "",
            "send_guest_confirmation": false,
            "sessions_overlap": false,
            "share_image_url": "",
            "splash_hub_auto_subscribe": 0,
            "start_time": "2022-08-31T09:00:00",
            "status": "open",
            "tags": [],
            "time_zone_id": 25,
            "title": "a new title",
            "twitter_default": null,
            "type": "Seminars & Workshops",
            "user": {
                "event_types": [
                    {
                        "id": 18867,
                        "name": "Networking Event"
                    },
                    {
                        "id": 18868,
                        "name": "Conference"
                    },
                    {
                        "id": 18870,
                        "name": "Launch Event"
                    },
                    {
                        "id": 18871,
                        "name": "Recruiting Event"
                    },
                    {
                        "id": 18875,
                        "name": "Other"
                    },
                    {
                        "id": 24548,
                        "name": "Happy Hours"
                    },
                    {
                        "id": 24549,
                        "name": "Exhibits & Shows"
                    },
                    {
                        "id": 24551,
                        "name": "Seminars & Workshops"
                    },
                    {
                        "id": 32649,
                        "name": "In-Store Engagement"
                    }
                ],
                "locales": [
                    {
                        "code": "af-na",
                        "name": "Afrikaans (Namibia)"
                    },
                    {
                        "code": "af-za",
                        "name": "Afrikaans (South Africa)"
                    },
                    {
                        "code": "ak-gh",
                        "name": "Akan (Ghana)"
                    },
                    {
                        "code": "sq-al",
                        "name": "Albanian (Albania)"
                    },
                    {
                        "code": "sq-xk",
                        "name": "Albanian (Kosovo)"
                    },
                    {
                        "code": "sq-mk",
                        "name": "Albanian (Macedonia)"
                    },
                    {
                        "code": "am-et",
                        "name": "Amharic (Ethiopia)"
                    },
                    {
                        "code": "ar-dz",
                        "name": "Arabic (Algeria)"
                    },
                    {
                        "code": "ar-bh",
                        "name": "Arabic (Bahrain)"
                    },
                    {
                        "code": "ar-td",
                        "name": "Arabic (Chad)"
                    },
                    {
                        "code": "ar-km",
                        "name": "Arabic (Comoros)"
                    },
                    {
                        "code": "ar-dj",
                        "name": "Arabic (Djibouti)"
                    },
                    {
                        "code": "ar-eg",
                        "name": "Arabic (Egypt)"
                    },
                    {
                        "code": "ar-er",
                        "name": "Arabic (Eritrea)"
                    },
                    {
                        "code": "ar-iq",
                        "name": "Arabic (Iraq)"
                    },
                    {
                        "code": "ar-il",
                        "name": "Arabic (Israel)"
                    },
                    {
                        "code": "ar-jo",
                        "name": "Arabic (Jordan)"
                    },
                    {
                        "code": "ar-kw",
                        "name": "Arabic (Kuwait)"
                    },
                    {
                        "code": "ar-lb",
                        "name": "Arabic (Lebanon)"
                    },
                    {
                        "code": "ar-ly",
                        "name": "Arabic (Libya)"
                    },
                    {
                        "code": "ar-mr",
                        "name": "Arabic (Mauritania)"
                    },
                    {
                        "code": "ar-ma",
                        "name": "Arabic (Morocco)"
                    },
                    {
                        "code": "ar-om",
                        "name": "Arabic (Oman)"
                    },
                    {
                        "code": "ar-ps",
                        "name": "Arabic (Palestinian Territories)"
                    },
                    {
                        "code": "ar-qa",
                        "name": "Arabic (Qatar)"
                    },
                    {
                        "code": "ar-sa",
                        "name": "Arabic (Saudi Arabia)"
                    },
                    {
                        "code": "ar-so",
                        "name": "Arabic (Somalia)"
                    },
                    {
                        "code": "ar-ss",
                        "name": "Arabic (South Sudan)"
                    },
                    {
                        "code": "ar-sd",
                        "name": "Arabic (Sudan)"
                    },
                    {
                        "code": "ar-sy",
                        "name": "Arabic (Syria)"
                    },
                    {
                        "code": "ar-tn",
                        "name": "Arabic (Tunisia)"
                    },
                    {
                        "code": "ar-ae",
                        "name": "Arabic (United Arab Emirates)"
                    },
                    {
                        "code": "ar-eh",
                        "name": "Arabic (Western Sahara)"
                    },
                    {
                        "code": "ar-ye",
                        "name": "Arabic (Yemen)"
                    },
                    {
                        "code": "hy-am",
                        "name": "Armenian (Armenia)"
                    },
                    {
                        "code": "as-in",
                        "name": "Assamese (India)"
                    },
                    {
                        "code": "az-az",
                        "name": "Azerbaijani (Azerbaijan)"
                    },
                    {
                        "code": "az-cyrl",
                        "name": "Azerbaijani (Cyrillic)"
                    },
                    {
                        "code": "az-cyrl-az",
                        "name": "Azerbaijani (Cyrillic, Azerbaijan)"
                    },
                    {
                        "code": "az-latn",
                        "name": "Azerbaijani (Latin)"
                    },
                    {
                        "code": "az-latn-az",
                        "name": "Azerbaijani (Latin, Azerbaijan)"
                    },
                    {
                        "code": "bm-latn",
                        "name": "Bambara (Latin)"
                    },
                    {
                        "code": "bm-latn-ml",
                        "name": "Bambara (Latin, Mali)"
                    },
                    {
                        "code": "eu-es",
                        "name": "Basque (Spain)"
                    },
                    {
                        "code": "be-by",
                        "name": "Belarusian (Belarus)"
                    },
                    {
                        "code": "bn-bd",
                        "name": "Bengali (Bangladesh)"
                    },
                    {
                        "code": "bn-in",
                        "name": "Bengali (India)"
                    },
                    {
                        "code": "bs-ba",
                        "name": "Bosnian (Bosnia & Herzegovina)"
                    },
                    {
                        "code": "bs-cyrl",
                        "name": "Bosnian (Cyrillic)"
                    },
                    {
                        "code": "bs-cyrl-ba",
                        "name": "Bosnian (Cyrillic, Bosnia & Herzegovina)"
                    },
                    {
                        "code": "bs-latn",
                        "name": "Bosnian (Latin)"
                    },
                    {
                        "code": "bs-latn-ba",
                        "name": "Bosnian (Latin, Bosnia & Herzegovina)"
                    },
                    {
                        "code": "br-fr",
                        "name": "Breton (France)"
                    },
                    {
                        "code": "bg-bg",
                        "name": "Bulgarian (Bulgaria)"
                    },
                    {
                        "code": "my-mm",
                        "name": "Burmese (Myanmar (Burma))"
                    },
                    {
                        "code": "ca-ad",
                        "name": "Catalan (Andorra)"
                    },
                    {
                        "code": "ca-fr",
                        "name": "Catalan (France)"
                    },
                    {
                        "code": "ca-it",
                        "name": "Catalan (Italy)"
                    },
                    {
                        "code": "ca-es",
                        "name": "Catalan (Spain)"
                    },
                    {
                        "code": "zh-cn",
                        "name": "Chinese (China)"
                    },
                    {
                        "code": "zh-hk",
                        "name": "Chinese (Hong Kong SAR China)"
                    },
                    {
                        "code": "zh-mo",
                        "name": "Chinese (Macau SAR China)"
                    },
                    {
                        "code": "zh-hans",
                        "name": "Chinese (Simplified)"
                    },
                    {
                        "code": "zh-hans-cn",
                        "name": "Chinese (Simplified, China)"
                    },
                    {
                        "code": "zh-hans-hk",
                        "name": "Chinese (Simplified, Hong Kong SAR China)"
                    },
                    {
                        "code": "zh-hans-mo",
                        "name": "Chinese (Simplified, Macau SAR China)"
                    },
                    {
                        "code": "zh-hans-sg",
                        "name": "Chinese (Simplified, Singapore)"
                    },
                    {
                        "code": "zh-sg",
                        "name": "Chinese (Singapore)"
                    },
                    {
                        "code": "zh-tw",
                        "name": "Chinese (Taiwan)"
                    },
                    {
                        "code": "zh-hant",
                        "name": "Chinese (Traditional)"
                    },
                    {
                        "code": "zh-hant-hk",
                        "name": "Chinese (Traditional, Hong Kong SAR China)"
                    },
                    {
                        "code": "zh-hant-mo",
                        "name": "Chinese (Traditional, Macau SAR China)"
                    },
                    {
                        "code": "zh-hant-tw",
                        "name": "Chinese (Traditional, Taiwan)"
                    },
                    {
                        "code": "kw-gb",
                        "name": "Cornish (United Kingdom)"
                    },
                    {
                        "code": "hr-ba",
                        "name": "Croatian (Bosnia & Herzegovina)"
                    },
                    {
                        "code": "hr-hr",
                        "name": "Croatian (Croatia)"
                    },
                    {
                        "code": "cs-cz",
                        "name": "Czech (Czech Republic)"
                    },
                    {
                        "code": "da-dk",
                        "name": "Danish (Denmark)"
                    },
                    {
                        "code": "da-gl",
                        "name": "Danish (Greenland)"
                    },
                    {
                        "code": "nl-aw",
                        "name": "Dutch (Aruba)"
                    },
                    {
                        "code": "nl-be",
                        "name": "Dutch (Belgium)"
                    },
                    {
                        "code": "nl-bq",
                        "name": "Dutch (Caribbean Netherlands)"
                    },
                    {
                        "code": "nl-cw",
                        "name": "Dutch (Cura\u00e7ao)"
                    },
                    {
                        "code": "nl-nl",
                        "name": "Dutch (Netherlands)"
                    },
                    {
                        "code": "nl-sx",
                        "name": "Dutch (Sint Maarten)"
                    },
                    {
                        "code": "nl-sr",
                        "name": "Dutch (Suriname)"
                    },
                    {
                        "code": "dz-bt",
                        "name": "Dzongkha (Bhutan)"
                    },
                    {
                        "code": "en-as",
                        "name": "English (American Samoa)"
                    },
                    {
                        "code": "en-ai",
                        "name": "English (Anguilla)"
                    },
                    {
                        "code": "en-ag",
                        "name": "English (Antigua & Barbuda)"
                    },
                    {
                        "code": "en-au",
                        "name": "English (Australia)"
                    },
                    {
                        "code": "en-bs",
                        "name": "English (Bahamas)"
                    },
                    {
                        "code": "en-bb",
                        "name": "English (Barbados)"
                    },
                    {
                        "code": "en-be",
                        "name": "English (Belgium)"
                    },
                    {
                        "code": "en-bz",
                        "name": "English (Belize)"
                    },
                    {
                        "code": "en-bm",
                        "name": "English (Bermuda)"
                    },
                    {
                        "code": "en-bw",
                        "name": "English (Botswana)"
                    },
                    {
                        "code": "en-io",
                        "name": "English (British Indian Ocean Territory)"
                    },
                    {
                        "code": "en-vg",
                        "name": "English (British Virgin Islands)"
                    },
                    {
                        "code": "en-cm",
                        "name": "English (Cameroon)"
                    },
                    {
                        "code": "en-ca",
                        "name": "English (Canada)"
                    },
                    {
                        "code": "en-ky",
                        "name": "English (Cayman Islands)"
                    },
                    {
                        "code": "en-cx",
                        "name": "English (Christmas Island)"
                    },
                    {
                        "code": "en-cc",
                        "name": "English (Cocos (Keeling) Islands)"
                    },
                    {
                        "code": "en-ck",
                        "name": "English (Cook Islands)"
                    },
                    {
                        "code": "en-dg",
                        "name": "English (Diego Garcia)"
                    },
                    {
                        "code": "en-dm",
                        "name": "English (Dominica)"
                    },
                    {
                        "code": "en-er",
                        "name": "English (Eritrea)"
                    },
                    {
                        "code": "en-fk",
                        "name": "English (Falkland Islands)"
                    },
                    {
                        "code": "en-fj",
                        "name": "English (Fiji)"
                    },
                    {
                        "code": "en-gm",
                        "name": "English (Gambia)"
                    },
                    {
                        "code": "en-gh",
                        "name": "English (Ghana)"
                    },
                    {
                        "code": "en-gi",
                        "name": "English (Gibraltar)"
                    },
                    {
                        "code": "en-gd",
                        "name": "English (Grenada)"
                    },
                    {
                        "code": "en-gu",
                        "name": "English (Guam)"
                    },
                    {
                        "code": "en-gg",
                        "name": "English (Guernsey)"
                    },
                    {
                        "code": "en-gy",
                        "name": "English (Guyana)"
                    },
                    {
                        "code": "en-hk",
                        "name": "English (Hong Kong SAR China)"
                    },
                    {
                        "code": "en-in",
                        "name": "English (India)"
                    },
                    {
                        "code": "en-ie",
                        "name": "English (Ireland)"
                    },
                    {
                        "code": "en-im",
                        "name": "English (Isle of Man)"
                    },
                    {
                        "code": "en-jm",
                        "name": "English (Jamaica)"
                    },
                    {
                        "code": "en-je",
                        "name": "English (Jersey)"
                    },
                    {
                        "code": "en-ke",
                        "name": "English (Kenya)"
                    },
                    {
                        "code": "en-ki",
                        "name": "English (Kiribati)"
                    },
                    {
                        "code": "en-ls",
                        "name": "English (Lesotho)"
                    },
                    {
                        "code": "en-lr",
                        "name": "English (Liberia)"
                    },
                    {
                        "code": "en-mo",
                        "name": "English (Macau SAR China)"
                    },
                    {
                        "code": "en-mg",
                        "name": "English (Madagascar)"
                    },
                    {
                        "code": "en-mw",
                        "name": "English (Malawi)"
                    },
                    {
                        "code": "en-my",
                        "name": "English (Malaysia)"
                    },
                    {
                        "code": "en-mt",
                        "name": "English (Malta)"
                    },
                    {
                        "code": "en-mh",
                        "name": "English (Marshall Islands)"
                    },
                    {
                        "code": "en-mu",
                        "name": "English (Mauritius)"
                    },
                    {
                        "code": "en-fm",
                        "name": "English (Micronesia)"
                    },
                    {
                        "code": "en-ms",
                        "name": "English (Montserrat)"
                    },
                    {
                        "code": "en-na",
                        "name": "English (Namibia)"
                    },
                    {
                        "code": "en-nr",
                        "name": "English (Nauru)"
                    },
                    {
                        "code": "en-nz",
                        "name": "English (New Zealand)"
                    },
                    {
                        "code": "en-ng",
                        "name": "English (Nigeria)"
                    },
                    {
                        "code": "en-nu",
                        "name": "English (Niue)"
                    },
                    {
                        "code": "en-nf",
                        "name": "English (Norfolk Island)"
                    },
                    {
                        "code": "en-mp",
                        "name": "English (Northern Mariana Islands)"
                    },
                    {
                        "code": "en-pk",
                        "name": "English (Pakistan)"
                    },
                    {
                        "code": "en-pw",
                        "name": "English (Palau)"
                    },
                    {
                        "code": "en-pg",
                        "name": "English (Papua New Guinea)"
                    },
                    {
                        "code": "en-ph",
                        "name": "English (Philippines)"
                    },
                    {
                        "code": "en-pn",
                        "name": "English (Pitcairn Islands)"
                    },
                    {
                        "code": "en-pr",
                        "name": "English (Puerto Rico)"
                    },
                    {
                        "code": "en-rw",
                        "name": "English (Rwanda)"
                    },
                    {
                        "code": "en-ws",
                        "name": "English (Samoa)"
                    },
                    {
                        "code": "en-sc",
                        "name": "English (Seychelles)"
                    },
                    {
                        "code": "en-sl",
                        "name": "English (Sierra Leone)"
                    },
                    {
                        "code": "en-sg",
                        "name": "English (Singapore)"
                    },
                    {
                        "code": "en-sx",
                        "name": "English (Sint Maarten)"
                    },
                    {
                        "code": "en-sb",
                        "name": "English (Solomon Islands)"
                    },
                    {
                        "code": "en-za",
                        "name": "English (South Africa)"
                    },
                    {
                        "code": "en-ss",
                        "name": "English (South Sudan)"
                    },
                    {
                        "code": "en-sh",
                        "name": "English (St. Helena)"
                    },
                    {
                        "code": "en-kn",
                        "name": "English (St. Kitts & Nevis)"
                    },
                    {
                        "code": "en-lc",
                        "name": "English (St. Lucia)"
                    },
                    {
                        "code": "en-vc",
                        "name": "English (St. Vincent & Grenadines)"
                    },
                    {
                        "code": "en-sd",
                        "name": "English (Sudan)"
                    },
                    {
                        "code": "en-sz",
                        "name": "English (Swaziland)"
                    },
                    {
                        "code": "en-tz",
                        "name": "English (Tanzania)"
                    },
                    {
                        "code": "en-tk",
                        "name": "English (Tokelau)"
                    },
                    {
                        "code": "en-to",
                        "name": "English (Tonga)"
                    },
                    {
                        "code": "en-tt",
                        "name": "English (Trinidad & Tobago)"
                    },
                    {
                        "code": "en-tc",
                        "name": "English (Turks & Caicos Islands)"
                    },
                    {
                        "code": "en-tv",
                        "name": "English (Tuvalu)"
                    },
                    {
                        "code": "en-um",
                        "name": "English (U.S. Outlying Islands)"
                    },
                    {
                        "code": "en-vi",
                        "name": "English (U.S. Virgin Islands)"
                    },
                    {
                        "code": "en-ug",
                        "name": "English (Uganda)"
                    },
                    {
                        "code": "en-gb",
                        "name": "English (United Kingdom)"
                    },
                    {
                        "code": "en-us",
                        "name": "English (United States)"
                    },
                    {
                        "code": "en-vu",
                        "name": "English (Vanuatu)"
                    },
                    {
                        "code": "en-zm",
                        "name": "English (Zambia)"
                    },
                    {
                        "code": "en-zw",
                        "name": "English (Zimbabwe)"
                    },
                    {
                        "code": "et-ee",
                        "name": "Estonian (Estonia)"
                    },
                    {
                        "code": "ee-gh",
                        "name": "Ewe (Ghana)"
                    },
                    {
                        "code": "ee-tg",
                        "name": "Ewe (Togo)"
                    },
                    {
                        "code": "fo-fo",
                        "name": "Faroese (Faroe Islands)"
                    },
                    {
                        "code": "fi-fi",
                        "name": "Finnish (Finland)"
                    },
                    {
                        "code": "fr-dz",
                        "name": "French (Algeria)"
                    },
                    {
                        "code": "fr-be",
                        "name": "French (Belgium)"
                    },
                    {
                        "code": "fr-bj",
                        "name": "French (Benin)"
                    },
                    {
                        "code": "fr-bf",
                        "name": "French (Burkina Faso)"
                    },
                    {
                        "code": "fr-bi",
                        "name": "French (Burundi)"
                    },
                    {
                        "code": "fr-cm",
                        "name": "French (Cameroon)"
                    },
                    {
                        "code": "fr-ca",
                        "name": "French (Canada)"
                    },
                    {
                        "code": "fr-cf",
                        "name": "French (Central African Republic)"
                    },
                    {
                        "code": "fr-td",
                        "name": "French (Chad)"
                    },
                    {
                        "code": "fr-km",
                        "name": "French (Comoros)"
                    },
                    {
                        "code": "fr-cg",
                        "name": "French (Congo - Brazzaville)"
                    },
                    {
                        "code": "fr-cd",
                        "name": "French (Congo - Kinshasa)"
                    },
                    {
                        "code": "fr-ci",
                        "name": "French (C\u00f4te d\u0092Ivoire)"
                    },
                    {
                        "code": "fr-dj",
                        "name": "French (Djibouti)"
                    },
                    {
                        "code": "fr-gq",
                        "name": "French (Equatorial Guinea)"
                    },
                    {
                        "code": "fr-fr",
                        "name": "French (France)"
                    },
                    {
                        "code": "fr-gf",
                        "name": "French (French Guiana)"
                    },
                    {
                        "code": "fr-pf",
                        "name": "French (French Polynesia)"
                    },
                    {
                        "code": "fr-ga",
                        "name": "French (Gabon)"
                    },
                    {
                        "code": "fr-gp",
                        "name": "French (Guadeloupe)"
                    },
                    {
                        "code": "fr-gn",
                        "name": "French (Guinea)"
                    },
                    {
                        "code": "fr-ht",
                        "name": "French (Haiti)"
                    },
                    {
                        "code": "fr-lu",
                        "name": "French (Luxembourg)"
                    },
                    {
                        "code": "fr-mg",
                        "name": "French (Madagascar)"
                    },
                    {
                        "code": "fr-ml",
                        "name": "French (Mali)"
                    },
                    {
                        "code": "fr-mq",
                        "name": "French (Martinique)"
                    },
                    {
                        "code": "fr-mr",
                        "name": "French (Mauritania)"
                    },
                    {
                        "code": "fr-mu",
                        "name": "French (Mauritius)"
                    },
                    {
                        "code": "fr-yt",
                        "name": "French (Mayotte)"
                    },
                    {
                        "code": "fr-mc",
                        "name": "French (Monaco)"
                    },
                    {
                        "code": "fr-ma",
                        "name": "French (Morocco)"
                    },
                    {
                        "code": "fr-nc",
                        "name": "French (New Caledonia)"
                    },
                    {
                        "code": "fr-ne",
                        "name": "French (Niger)"
                    },
                    {
                        "code": "fr-rw",
                        "name": "French (Rwanda)"
                    },
                    {
                        "code": "fr-re",
                        "name": "French (R\u00e9union)"
                    },
                    {
                        "code": "fr-sn",
                        "name": "French (Senegal)"
                    },
                    {
                        "code": "fr-sc",
                        "name": "French (Seychelles)"
                    },
                    {
                        "code": "fr-bl",
                        "name": "French (St. Barth\u00e9lemy)"
                    },
                    {
                        "code": "fr-mf",
                        "name": "French (St. Martin)"
                    },
                    {
                        "code": "fr-pm",
                        "name": "French (St. Pierre & Miquelon)"
                    },
                    {
                        "code": "fr-ch",
                        "name": "French (Switzerland)"
                    },
                    {
                        "code": "fr-sy",
                        "name": "French (Syria)"
                    },
                    {
                        "code": "fr-tg",
                        "name": "French (Togo)"
                    },
                    {
                        "code": "fr-tn",
                        "name": "French (Tunisia)"
                    },
                    {
                        "code": "fr-vu",
                        "name": "French (Vanuatu)"
                    },
                    {
                        "code": "fr-wf",
                        "name": "French (Wallis & Futuna)"
                    },
                    {
                        "code": "ff-cm",
                        "name": "Fulah (Cameroon)"
                    },
                    {
                        "code": "ff-gn",
                        "name": "Fulah (Guinea)"
                    },
                    {
                        "code": "ff-mr",
                        "name": "Fulah (Mauritania)"
                    },
                    {
                        "code": "ff-sn",
                        "name": "Fulah (Senegal)"
                    },
                    {
                        "code": "gl-es",
                        "name": "Galician (Spain)"
                    },
                    {
                        "code": "lg-ug",
                        "name": "Ganda (Uganda)"
                    },
                    {
                        "code": "ka-ge",
                        "name": "Georgian (Georgia)"
                    },
                    {
                        "code": "de-at",
                        "name": "German (Austria)"
                    },
                    {
                        "code": "de-be",
                        "name": "German (Belgium)"
                    },
                    {
                        "code": "de-de",
                        "name": "German (Germany)"
                    },
                    {
                        "code": "de-li",
                        "name": "German (Liechtenstein)"
                    },
                    {
                        "code": "de-lu",
                        "name": "German (Luxembourg)"
                    },
                    {
                        "code": "de-ch",
                        "name": "German (Switzerland)"
                    },
                    {
                        "code": "el-cy",
                        "name": "Greek (Cyprus)"
                    },
                    {
                        "code": "el-gr",
                        "name": "Greek (Greece)"
                    },
                    {
                        "code": "gu-in",
                        "name": "Gujarati (India)"
                    },
                    {
                        "code": "ha-gh",
                        "name": "Hausa (Ghana)"
                    },
                    {
                        "code": "ha-latn",
                        "name": "Hausa (Latin)"
                    },
                    {
                        "code": "ha-latn-gh",
                        "name": "Hausa (Latin, Ghana)"
                    },
                    {
                        "code": "ha-latn-ne",
                        "name": "Hausa (Latin, Niger)"
                    },
                    {
                        "code": "ha-latn-ng",
                        "name": "Hausa (Latin, Nigeria)"
                    },
                    {
                        "code": "ha-ne",
                        "name": "Hausa (Niger)"
                    },
                    {
                        "code": "ha-ng",
                        "name": "Hausa (Nigeria)"
                    },
                    {
                        "code": "he-il",
                        "name": "Hebrew (Israel)"
                    },
                    {
                        "code": "hi-in",
                        "name": "Hindi (India)"
                    },
                    {
                        "code": "hu-hu",
                        "name": "Hungarian (Hungary)"
                    },
                    {
                        "code": "is-is",
                        "name": "Icelandic (Iceland)"
                    },
                    {
                        "code": "ig-ng",
                        "name": "Igbo (Nigeria)"
                    },
                    {
                        "code": "id-id",
                        "name": "Indonesian (Indonesia)"
                    },
                    {
                        "code": "ga-ie",
                        "name": "Irish (Ireland)"
                    },
                    {
                        "code": "it-it",
                        "name": "Italian (Italy)"
                    },
                    {
                        "code": "it-sm",
                        "name": "Italian (San Marino)"
                    },
                    {
                        "code": "it-ch",
                        "name": "Italian (Switzerland)"
                    },
                    {
                        "code": "ja-jp",
                        "name": "Japanese (Japan)"
                    },
                    {
                        "code": "kl-gl",
                        "name": "Kalaallisut (Greenland)"
                    },
                    {
                        "code": "kn-in",
                        "name": "Kannada (India)"
                    },
                    {
                        "code": "ks-arab",
                        "name": "Kashmiri (Arabic)"
                    },
                    {
                        "code": "ks-arab-in",
                        "name": "Kashmiri (Arabic, India)"
                    },
                    {
                        "code": "ks-in",
                        "name": "Kashmiri (India)"
                    },
                    {
                        "code": "kk-cyrl",
                        "name": "Kazakh (Cyrillic)"
                    },
                    {
                        "code": "kk-cyrl-kz",
                        "name": "Kazakh (Cyrillic, Kazakhstan)"
                    },
                    {
                        "code": "kk-kz",
                        "name": "Kazakh (Kazakhstan)"
                    },
                    {
                        "code": "km-kh",
                        "name": "Khmer (Cambodia)"
                    },
                    {
                        "code": "ki-ke",
                        "name": "Kikuyu (Kenya)"
                    },
                    {
                        "code": "rw-rw",
                        "name": "Kinyarwanda (Rwanda)"
                    },
                    {
                        "code": "ko-kp",
                        "name": "Korean (North Korea)"
                    },
                    {
                        "code": "ko-kr",
                        "name": "Korean (South Korea)"
                    },
                    {
                        "code": "ky-cyrl",
                        "name": "Kyrgyz (Cyrillic)"
                    },
                    {
                        "code": "ky-cyrl-kg",
                        "name": "Kyrgyz (Cyrillic, Kyrgyzstan)"
                    },
                    {
                        "code": "ky-kg",
                        "name": "Kyrgyz (Kyrgyzstan)"
                    },
                    {
                        "code": "lo-la",
                        "name": "Lao (Laos)"
                    },
                    {
                        "code": "lv-lv",
                        "name": "Latvian (Latvia)"
                    },
                    {
                        "code": "ln-ao",
                        "name": "Lingala (Angola)"
                    },
                    {
                        "code": "ln-cf",
                        "name": "Lingala (Central African Republic)"
                    },
                    {
                        "code": "ln-cg",
                        "name": "Lingala (Congo - Brazzaville)"
                    },
                    {
                        "code": "ln-cd",
                        "name": "Lingala (Congo - Kinshasa)"
                    },
                    {
                        "code": "lt-lt",
                        "name": "Lithuanian (Lithuania)"
                    },
                    {
                        "code": "lu-cd",
                        "name": "Luba-Katanga (Congo - Kinshasa)"
                    },
                    {
                        "code": "lb-lu",
                        "name": "Luxembourgish (Luxembourg)"
                    },
                    {
                        "code": "mk-mk",
                        "name": "Macedonian (Macedonia)"
                    },
                    {
                        "code": "mg-mg",
                        "name": "Malagasy (Madagascar)"
                    },
                    {
                        "code": "ms-bn",
                        "name": "Malay (Brunei)"
                    },
                    {
                        "code": "ms-latn",
                        "name": "Malay (Latin)"
                    },
                    {
                        "code": "ms-latn-bn",
                        "name": "Malay (Latin, Brunei)"
                    },
                    {
                        "code": "ms-latn-my",
                        "name": "Malay (Latin, Malaysia)"
                    },
                    {
                        "code": "ms-latn-sg",
                        "name": "Malay (Latin, Singapore)"
                    },
                    {
                        "code": "ms-my",
                        "name": "Malay (Malaysia)"
                    },
                    {
                        "code": "ms-sg",
                        "name": "Malay (Singapore)"
                    },
                    {
                        "code": "ml-in",
                        "name": "Malayalam (India)"
                    },
                    {
                        "code": "mt-mt",
                        "name": "Maltese (Malta)"
                    },
                    {
                        "code": "gv-im",
                        "name": "Manx (Isle of Man)"
                    },
                    {
                        "code": "mr-in",
                        "name": "Marathi (India)"
                    },
                    {
                        "code": "mn-cyrl",
                        "name": "Mongolian (Cyrillic)"
                    },
                    {
                        "code": "mn-cyrl-mn",
                        "name": "Mongolian (Cyrillic, Mongolia)"
                    },
                    {
                        "code": "mn-mn",
                        "name": "Mongolian (Mongolia)"
                    },
                    {
                        "code": "ne-in",
                        "name": "Nepali (India)"
                    },
                    {
                        "code": "ne-np",
                        "name": "Nepali (Nepal)"
                    },
                    {
                        "code": "nd-zw",
                        "name": "North Ndebele (Zimbabwe)"
                    },
                    {
                        "code": "se-fi",
                        "name": "Northern Sami (Finland)"
                    },
                    {
                        "code": "se-no",
                        "name": "Northern Sami (Norway)"
                    },
                    {
                        "code": "se-se",
                        "name": "Northern Sami (Sweden)"
                    },
                    {
                        "code": "no-no",
                        "name": "Norwegian (Norway)"
                    },
                    {
                        "code": "nb-no",
                        "name": "Norwegian Bokm\u00e5l (Norway)"
                    },
                    {
                        "code": "nb-sj",
                        "name": "Norwegian Bokm\u00e5l (Svalbard & Jan Mayen)"
                    },
                    {
                        "code": "nn-no",
                        "name": "Norwegian Nynorsk (Norway)"
                    },
                    {
                        "code": "or-in",
                        "name": "Oriya (India)"
                    },
                    {
                        "code": "om-et",
                        "name": "Oromo (Ethiopia)"
                    },
                    {
                        "code": "om-ke",
                        "name": "Oromo (Kenya)"
                    },
                    {
                        "code": "os-ge",
                        "name": "Ossetic (Georgia)"
                    },
                    {
                        "code": "os-ru",
                        "name": "Ossetic (Russia)"
                    },
                    {
                        "code": "ps-af",
                        "name": "Pashto (Afghanistan)"
                    },
                    {
                        "code": "fa-af",
                        "name": "Persian (Afghanistan)"
                    },
                    {
                        "code": "fa-ir",
                        "name": "Persian (Iran)"
                    },
                    {
                        "code": "pl-pl",
                        "name": "Polish (Poland)"
                    },
                    {
                        "code": "pt-ao",
                        "name": "Portuguese (Angola)"
                    },
                    {
                        "code": "pt-br",
                        "name": "Portuguese (Brazil)"
                    },
                    {
                        "code": "pt-cv",
                        "name": "Portuguese (Cape Verde)"
                    },
                    {
                        "code": "pt-gw",
                        "name": "Portuguese (Guinea-Bissau)"
                    },
                    {
                        "code": "pt-mo",
                        "name": "Portuguese (Macau SAR China)"
                    },
                    {
                        "code": "pt-mz",
                        "name": "Portuguese (Mozambique)"
                    },
                    {
                        "code": "pt-pt",
                        "name": "Portuguese (Portugal)"
                    },
                    {
                        "code": "pt-st",
                        "name": "Portuguese (S\u00e3o Tom\u00e9 & Pr\u00edncipe)"
                    },
                    {
                        "code": "pt-tl",
                        "name": "Portuguese (Timor-Leste)"
                    },
                    {
                        "code": "pa-arab",
                        "name": "Punjabi (Arabic)"
                    },
                    {
                        "code": "pa-arab-pk",
                        "name": "Punjabi (Arabic, Pakistan)"
                    },
                    {
                        "code": "pa-guru",
                        "name": "Punjabi (Gurmukhi)"
                    },
                    {
                        "code": "pa-guru-in",
                        "name": "Punjabi (Gurmukhi, India)"
                    },
                    {
                        "code": "pa-in",
                        "name": "Punjabi (India)"
                    },
                    {
                        "code": "pa-pk",
                        "name": "Punjabi (Pakistan)"
                    },
                    {
                        "code": "qu-bo",
                        "name": "Quechua (Bolivia)"
                    },
                    {
                        "code": "qu-ec",
                        "name": "Quechua (Ecuador)"
                    },
                    {
                        "code": "qu-pe",
                        "name": "Quechua (Peru)"
                    },
                    {
                        "code": "ro-md",
                        "name": "Romanian (Moldova)"
                    },
                    {
                        "code": "ro-ro",
                        "name": "Romanian (Romania)"
                    },
                    {
                        "code": "rm-ch",
                        "name": "Romansh (Switzerland)"
                    },
                    {
                        "code": "rn-bi",
                        "name": "Rundi (Burundi)"
                    },
                    {
                        "code": "ru-by",
                        "name": "Russian (Belarus)"
                    },
                    {
                        "code": "ru-kz",
                        "name": "Russian (Kazakhstan)"
                    },
                    {
                        "code": "ru-kg",
                        "name": "Russian (Kyrgyzstan)"
                    },
                    {
                        "code": "ru-md",
                        "name": "Russian (Moldova)"
                    },
                    {
                        "code": "ru-ru",
                        "name": "Russian (Russia)"
                    },
                    {
                        "code": "ru-ua",
                        "name": "Russian (Ukraine)"
                    },
                    {
                        "code": "sg-cf",
                        "name": "Sango (Central African Republic)"
                    },
                    {
                        "code": "gd-gb",
                        "name": "Scottish Gaelic (United Kingdom)"
                    },
                    {
                        "code": "sr-ba",
                        "name": "Serbian (Bosnia & Herzegovina)"
                    },
                    {
                        "code": "sr-cyrl",
                        "name": "Serbian (Cyrillic)"
                    },
                    {
                        "code": "sr-cyrl-ba",
                        "name": "Serbian (Cyrillic, Bosnia & Herzegovina)"
                    },
                    {
                        "code": "sr-cyrl-xk",
                        "name": "Serbian (Cyrillic, Kosovo)"
                    },
                    {
                        "code": "sr-cyrl-me",
                        "name": "Serbian (Cyrillic, Montenegro)"
                    },
                    {
                        "code": "sr-cyrl-rs",
                        "name": "Serbian (Cyrillic, Serbia)"
                    },
                    {
                        "code": "sr-xk",
                        "name": "Serbian (Kosovo)"
                    },
                    {
                        "code": "sr-latn",
                        "name": "Serbian (Latin)"
                    },
                    {
                        "code": "sr-latn-ba",
                        "name": "Serbian (Latin, Bosnia & Herzegovina)"
                    },
                    {
                        "code": "sr-latn-xk",
                        "name": "Serbian (Latin, Kosovo)"
                    },
                    {
                        "code": "sr-latn-me",
                        "name": "Serbian (Latin, Montenegro)"
                    },
                    {
                        "code": "sr-latn-rs",
                        "name": "Serbian (Latin, Serbia)"
                    },
                    {
                        "code": "sr-me",
                        "name": "Serbian (Montenegro)"
                    },
                    {
                        "code": "sr-rs",
                        "name": "Serbian (Serbia)"
                    },
                    {
                        "code": "sh-ba",
                        "name": "Serbo-Croatian (Bosnia & Herzegovina)"
                    },
                    {
                        "code": "sn-zw",
                        "name": "Shona (Zimbabwe)"
                    },
                    {
                        "code": "ii-cn",
                        "name": "Sichuan Yi (China)"
                    },
                    {
                        "code": "si-lk",
                        "name": "Sinhala (Sri Lanka)"
                    },
                    {
                        "code": "sk-sk",
                        "name": "Slovak (Slovakia)"
                    },
                    {
                        "code": "sl-si",
                        "name": "Slovenian (Slovenia)"
                    },
                    {
                        "code": "so-dj",
                        "name": "Somali (Djibouti)"
                    },
                    {
                        "code": "so-et",
                        "name": "Somali (Ethiopia)"
                    },
                    {
                        "code": "so-ke",
                        "name": "Somali (Kenya)"
                    },
                    {
                        "code": "so-so",
                        "name": "Somali (Somalia)"
                    },
                    {
                        "code": "es-ar",
                        "name": "Spanish (Argentina)"
                    },
                    {
                        "code": "es-bo",
                        "name": "Spanish (Bolivia)"
                    },
                    {
                        "code": "es-ic",
                        "name": "Spanish (Canary Islands)"
                    },
                    {
                        "code": "es-ea",
                        "name": "Spanish (Ceuta & Melilla)"
                    },
                    {
                        "code": "es-cl",
                        "name": "Spanish (Chile)"
                    },
                    {
                        "code": "es-co",
                        "name": "Spanish (Colombia)"
                    },
                    {
                        "code": "es-cr",
                        "name": "Spanish (Costa Rica)"
                    },
                    {
                        "code": "es-cu",
                        "name": "Spanish (Cuba)"
                    },
                    {
                        "code": "es-do",
                        "name": "Spanish (Dominican Republic)"
                    },
                    {
                        "code": "es-ec",
                        "name": "Spanish (Ecuador)"
                    },
                    {
                        "code": "es-sv",
                        "name": "Spanish (El Salvador)"
                    },
                    {
                        "code": "es-gq",
                        "name": "Spanish (Equatorial Guinea)"
                    },
                    {
                        "code": "es-gt",
                        "name": "Spanish (Guatemala)"
                    },
                    {
                        "code": "es-hn",
                        "name": "Spanish (Honduras)"
                    },
                    {
                        "code": "es-mx",
                        "name": "Spanish (Mexico)"
                    },
                    {
                        "code": "es-ni",
                        "name": "Spanish (Nicaragua)"
                    },
                    {
                        "code": "es-pa",
                        "name": "Spanish (Panama)"
                    },
                    {
                        "code": "es-py",
                        "name": "Spanish (Paraguay)"
                    },
                    {
                        "code": "es-pe",
                        "name": "Spanish (Peru)"
                    },
                    {
                        "code": "es-ph",
                        "name": "Spanish (Philippines)"
                    },
                    {
                        "code": "es-pr",
                        "name": "Spanish (Puerto Rico)"
                    },
                    {
                        "code": "es-es",
                        "name": "Spanish (Spain)"
                    },
                    {
                        "code": "es-us",
                        "name": "Spanish (United States)"
                    },
                    {
                        "code": "es-uy",
                        "name": "Spanish (Uruguay)"
                    },
                    {
                        "code": "es-ve",
                        "name": "Spanish (Venezuela)"
                    },
                    {
                        "code": "sw-ke",
                        "name": "Swahili (Kenya)"
                    },
                    {
                        "code": "sw-tz",
                        "name": "Swahili (Tanzania)"
                    },
                    {
                        "code": "sw-ug",
                        "name": "Swahili (Uganda)"
                    },
                    {
                        "code": "sv-fi",
                        "name": "Swedish (Finland)"
                    },
                    {
                        "code": "sv-se",
                        "name": "Swedish (Sweden)"
                    },
                    {
                        "code": "sv-ax",
                        "name": "Swedish (\u00c5land Islands)"
                    },
                    {
                        "code": "tl-ph",
                        "name": "Tagalog (Philippines)"
                    },
                    {
                        "code": "ta-in",
                        "name": "Tamil (India)"
                    },
                    {
                        "code": "ta-my",
                        "name": "Tamil (Malaysia)"
                    },
                    {
                        "code": "ta-sg",
                        "name": "Tamil (Singapore)"
                    },
                    {
                        "code": "ta-lk",
                        "name": "Tamil (Sri Lanka)"
                    },
                    {
                        "code": "te-in",
                        "name": "Telugu (India)"
                    },
                    {
                        "code": "th-th",
                        "name": "Thai (Thailand)"
                    },
                    {
                        "code": "bo-cn",
                        "name": "Tibetan (China)"
                    },
                    {
                        "code": "bo-in",
                        "name": "Tibetan (India)"
                    },
                    {
                        "code": "ti-er",
                        "name": "Tigrinya (Eritrea)"
                    },
                    {
                        "code": "ti-et",
                        "name": "Tigrinya (Ethiopia)"
                    },
                    {
                        "code": "to-to",
                        "name": "Tongan (Tonga)"
                    },
                    {
                        "code": "tr-cy",
                        "name": "Turkish (Cyprus)"
                    },
                    {
                        "code": "tr-tr",
                        "name": "Turkish (Turkey)"
                    },
                    {
                        "code": "uk-ua",
                        "name": "Ukrainian (Ukraine)"
                    },
                    {
                        "code": "ur-in",
                        "name": "Urdu (India)"
                    },
                    {
                        "code": "ur-pk",
                        "name": "Urdu (Pakistan)"
                    },
                    {
                        "code": "ug-arab",
                        "name": "Uyghur (Arabic)"
                    },
                    {
                        "code": "ug-arab-cn",
                        "name": "Uyghur (Arabic, China)"
                    },
                    {
                        "code": "ug-cn",
                        "name": "Uyghur (China)"
                    },
                    {
                        "code": "uz-af",
                        "name": "Uzbek (Afghanistan)"
                    },
                    {
                        "code": "uz-arab",
                        "name": "Uzbek (Arabic)"
                    },
                    {
                        "code": "uz-arab-af",
                        "name": "Uzbek (Arabic, Afghanistan)"
                    },
                    {
                        "code": "uz-cyrl",
                        "name": "Uzbek (Cyrillic)"
                    },
                    {
                        "code": "uz-cyrl-uz",
                        "name": "Uzbek (Cyrillic, Uzbekistan)"
                    },
                    {
                        "code": "uz-latn",
                        "name": "Uzbek (Latin)"
                    },
                    {
                        "code": "uz-latn-uz",
                        "name": "Uzbek (Latin, Uzbekistan)"
                    },
                    {
                        "code": "uz-uz",
                        "name": "Uzbek (Uzbekistan)"
                    },
                    {
                        "code": "vi-vn",
                        "name": "Vietnamese (Vietnam)"
                    },
                    {
                        "code": "cy-gb",
                        "name": "Welsh (United Kingdom)"
                    },
                    {
                        "code": "fy-nl",
                        "name": "Western Frisian (Netherlands)"
                    },
                    {
                        "code": "yo-bj",
                        "name": "Yoruba (Benin)"
                    },
                    {
                        "code": "yo-ng",
                        "name": "Yoruba (Nigeria)"
                    },
                    {
                        "code": "zu-za",
                        "name": "Zulu (South Africa)"
                    }
                ]
            },
            "venue": {
                "address": "",
                "city": "",
                "country": "",
                "lat": "NaN",
                "lon": "NaN",
                "name": "Virtual",
                "postal_code": "",
                "region": ""
            },
            "waitlist": false,
            "white_label": 0
        }
    }
}
```

#### Human Readable Output

>### Updated Event ID 458498411:
>|attendance_types|autosave|button_closed_message|currency|custom_domain|description_text|domain|email_white_label_key|end_time|event_host|event_workflow|facebook_description|facebook_title|favicon_url|form|form_email_domain_restriction|has_virtual|hashtag|hide_footer|invite_link_privacy_bypass|is_invite_only|is_rsvp_open|limit_one_per_email|linkedin_description|linkedin_title|locale|meta_calendar_description|meta_description|meta_title|multisession|no_index|page_action|page_password|page_privacy_type|paid_for_domain|published|redirect_to|registration_updating_deadline|registration_updating_enabled|require_captcha|salesforce_campaign_id|send_guest_confirmation|sessions_overlap|share_image_url|splash_hub_auto_subscribe|start_time|status|tags|time_zone_id|title|twitter_default|type|user|venue|waitlist|white_label|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| virtual | false |  | USD |  | Tickets are non-transferrable. All guests must RSVP individually – no +1s admitted. Coffee will be provided at the door. Breakfast will be served promptly at 8:15am. Please have your RSVP confirmation email available at the door to receive your complimentary breakfast ticket. | newtestevent123 |  | 2022-08-31T22:00:00 | FirstName Lastname |  |  |  | //d24wuq6o951i2g.cloudfront.net/img/events/id/245/2452081/assets/195.favicon-black.png | isInLibrary: false |  | false | #castironbreakfast | false | false | false | true | true |  |  |  |  |  |  | false | false | collect |  | none | false | true |  | 0 | false | false |  | false | false |  | 0 | 2022-08-31T09:00:00 | open |  | 25 | a new title |  | Seminars & Workshops | event_types: {'id': 18867, 'name': 'Networking Event'},<br/>{'id': 18868, 'name': 'Conference'},<br/>{'id': 18870, 'name': 'Launch Event'},<br/>{'id': 18871, 'name': 'Recruiting Event'},<br/>{'id': 18875, 'name': 'Other'},<br/>{'id': 24548, 'name': 'Happy Hours'},<br/>{'id': 24549, 'name': 'Exhibits & Shows'},<br/>{'id': 24551, 'name': 'Seminars & Workshops'},<br/>{'id': 32649, 'name': 'In-Store Engagement'}<br/>locales: {'code': 'af-na', 'name': 'Afrikaans (Namibia)'},<br/>{'code': 'af-za', 'name': 'Afrikaans (South Africa)'},<br/>{'code': 'ak-gh', 'name': 'Akan (Ghana)'},<br/>{'code': 'sq-al', 'name': 'Albanian (Albania)'},<br/>{'code': 'sq-xk', 'name': 'Albanian (Kosovo)'},<br/>{'code': 'sq-mk', 'name': 'Albanian (Macedonia)'},<br/>{'code': 'am-et', 'name': 'Amharic (Ethiopia)'},<br/>{'code': 'ar-dz', 'name': 'Arabic (Algeria)'},<br/>{'code': 'ar-bh', 'name': 'Arabic (Bahrain)'},<br/>{'code': 'ar-td', 'name': 'Arabic (Chad)'},<br/>{'code': 'ar-km', 'name': 'Arabic (Comoros)'},<br/>{'code': 'ar-dj', 'name': 'Arabic (Djibouti)'},<br/>{'code': 'ar-eg', 'name': 'Arabic (Egypt)'},<br/>{'code': 'ar-er', 'name': 'Arabic (Eritrea)'},<br/>{'code': 'ar-iq', 'name': 'Arabic (Iraq)'},<br/>{'code': 'ar-il', 'name': 'Arabic (Israel)'},<br/>{'code': 'ar-jo', 'name': 'Arabic (Jordan)'},<br/>{'code': 'ar-kw', 'name': 'Arabic (Kuwait)'},<br/>{'code': 'ar-lb', 'name': 'Arabic (Lebanon)'},<br/>{'code': 'ar-ly', 'name': 'Arabic (Libya)'},<br/>{'code': 'ar-mr', 'name': 'Arabic (Mauritania)'},<br/>{'code': 'ar-ma', 'name': 'Arabic (Morocco)'},<br/>{'code': 'ar-om', 'name': 'Arabic (Oman)'},<br/>{'code': 'ar-ps', 'name': 'Arabic (Palestinian Territories)'},<br/>{'code': 'ar-qa', 'name': 'Arabic (Qatar)'},<br/>{'code': 'ar-sa', 'name': 'Arabic (Saudi Arabia)'},<br/>{'code': 'ar-so', 'name': 'Arabic (Somalia)'},<br/>{'code': 'ar-ss', 'name': 'Arabic (South Sudan)'},<br/>{'code': 'ar-sd', 'name': 'Arabic (Sudan)'},<br/>{'code': 'ar-sy', 'name': 'Arabic (Syria)'},<br/>{'code': 'ar-tn', 'name': 'Arabic (Tunisia)'},<br/>{'code': 'ar-ae', 'name': 'Arabic (United Arab Emirates)'},<br/>{'code': 'ar-eh', 'name': 'Arabic (Western Sahara)'},<br/>{'code': 'ar-ye', 'name': 'Arabic (Yemen)'},<br/>{'code': 'hy-am', 'name': 'Armenian (Armenia)'},<br/>{'code': 'as-in', 'name': 'Assamese (India)'},<br/>{'code': 'az-az', 'name': 'Azerbaijani (Azerbaijan)'},<br/>{'code': 'az-cyrl', 'name': 'Azerbaijani (Cyrillic)'},<br/>{'code': 'az-cyrl-az', 'name': 'Azerbaijani (Cyrillic, Azerbaijan)'},<br/>{'code': 'az-latn', 'name': 'Azerbaijani (Latin)'},<br/>{'code': 'az-latn-az', 'name': 'Azerbaijani (Latin, Azerbaijan)'},<br/>{'code': 'bm-latn', 'name': 'Bambara (Latin)'},<br/>{'code': 'bm-latn-ml', 'name': 'Bambara (Latin, Mali)'},<br/>{'code': 'eu-es', 'name': 'Basque (Spain)'},<br/>{'code': 'be-by', 'name': 'Belarusian (Belarus)'},<br/>{'code': 'bn-bd', 'name': 'Bengali (Bangladesh)'},<br/>{'code': 'bn-in', 'name': 'Bengali (India)'},<br/>{'code': 'bs-ba', 'name': 'Bosnian (Bosnia & Herzegovina)'},<br/>{'code': 'bs-cyrl', 'name': 'Bosnian (Cyrillic)'},<br/>{'code': 'bs-cyrl-ba', 'name': 'Bosnian (Cyrillic, Bosnia & Herzegovina)'},<br/>{'code': 'bs-latn', 'name': 'Bosnian (Latin)'},<br/>{'code': 'bs-latn-ba', 'name': 'Bosnian (Latin, Bosnia & Herzegovina)'},<br/>{'code': 'br-fr', 'name': 'Breton (France)'},<br/>{'code': 'bg-bg', 'name': 'Bulgarian (Bulgaria)'},<br/>{'code': 'my-mm', 'name': 'Burmese (Myanmar (Burma))'},<br/>{'code': 'ca-ad', 'name': 'Catalan (Andorra)'},<br/>{'code': 'ca-fr', 'name': 'Catalan (France)'},<br/>{'code': 'ca-it', 'name': 'Catalan (Italy)'},<br/>{'code': 'ca-es', 'name': 'Catalan (Spain)'},<br/>{'code': 'zh-cn', 'name': 'Chinese (China)'},<br/>{'code': 'zh-hk', 'name': 'Chinese (Hong Kong SAR China)'},<br/>{'code': 'zh-mo', 'name': 'Chinese (Macau SAR China)'},<br/>{'code': 'zh-hans', 'name': 'Chinese (Simplified)'},<br/>{'code': 'zh-hans-cn', 'name': 'Chinese (Simplified, China)'},<br/>{'code': 'zh-hans-hk', 'name': 'Chinese (Simplified, Hong Kong SAR China)'},<br/>{'code': 'zh-hans-mo', 'name': 'Chinese (Simplified, Macau SAR China)'},<br/>{'code': 'zh-hans-sg', 'name': 'Chinese (Simplified, Singapore)'},<br/>{'code': 'zh-sg', 'name': 'Chinese (Singapore)'},<br/>{'code': 'zh-tw', 'name': 'Chinese (Taiwan)'},<br/>{'code': 'zh-hant', 'name': 'Chinese (Traditional)'},<br/>{'code': 'zh-hant-hk', 'name': 'Chinese (Traditional, Hong Kong SAR China)'},<br/>{'code': 'zh-hant-mo', 'name': 'Chinese (Traditional, Macau SAR China)'},<br/>{'code': 'zh-hant-tw', 'name': 'Chinese (Traditional, Taiwan)'},<br/>{'code': 'kw-gb', 'name': 'Cornish (United Kingdom)'},<br/>{'code': 'hr-ba', 'name': 'Croatian (Bosnia & Herzegovina)'},<br/>{'code': 'hr-hr', 'name': 'Croatian (Croatia)'},<br/>{'code': 'cs-cz', 'name': 'Czech (Czech Republic)'},<br/>{'code': 'da-dk', 'name': 'Danish (Denmark)'},<br/>{'code': 'da-gl', 'name': 'Danish (Greenland)'},<br/>{'code': 'nl-aw', 'name': 'Dutch (Aruba)'},<br/>{'code': 'nl-be', 'name': 'Dutch (Belgium)'},<br/>{'code': 'nl-bq', 'name': 'Dutch (Caribbean Netherlands)'},<br/>{'code': 'nl-cw', 'name': 'Dutch (Curaçao)'},<br/>{'code': 'nl-nl', 'name': 'Dutch (Netherlands)'},<br/>{'code': 'nl-sx', 'name': 'Dutch (Sint Maarten)'},<br/>{'code': 'nl-sr', 'name': 'Dutch (Suriname)'},<br/>{'code': 'dz-bt', 'name': 'Dzongkha (Bhutan)'},<br/>{'code': 'en-as', 'name': 'English (American Samoa)'},<br/>{'code': 'en-ai', 'name': 'English (Anguilla)'},<br/>{'code': 'en-ag', 'name': 'English (Antigua & Barbuda)'},<br/>{'code': 'en-au', 'name': 'English (Australia)'},<br/>{'code': 'en-bs', 'name': 'English (Bahamas)'},<br/>{'code': 'en-bb', 'name': 'English (Barbados)'},<br/>{'code': 'en-be', 'name': 'English (Belgium)'},<br/>{'code': 'en-bz', 'name': 'English (Belize)'},<br/>{'code': 'en-bm', 'name': 'English (Bermuda)'},<br/>{'code': 'en-bw', 'name': 'English (Botswana)'},<br/>{'code': 'en-io', 'name': 'English (British Indian Ocean Territory)'},<br/>{'code': 'en-vg', 'name': 'English (British Virgin Islands)'},<br/>{'code': 'en-cm', 'name': 'English (Cameroon)'},<br/>{'code': 'en-ca', 'name': 'English (Canada)'},<br/>{'code': 'en-ky', 'name': 'English (Cayman Islands)'},<br/>{'code': 'en-cx', 'name': 'English (Christmas Island)'},<br/>{'code': 'en-cc', 'name': 'English (Cocos (Keeling) Islands)'},<br/>{'code': 'en-ck', 'name': 'English (Cook Islands)'},<br/>{'code': 'en-dg', 'name': 'English (Diego Garcia)'},<br/>{'code': 'en-dm', 'name': 'English (Dominica)'},<br/>{'code': 'en-er', 'name': 'English (Eritrea)'},<br/>{'code': 'en-fk', 'name': 'English (Falkland Islands)'},<br/>{'code': 'en-fj', 'name': 'English (Fiji)'},<br/>{'code': 'en-gm', 'name': 'English (Gambia)'},<br/>{'code': 'en-gh', 'name': 'English (Ghana)'},<br/>{'code': 'en-gi', 'name': 'English (Gibraltar)'},<br/>{'code': 'en-gd', 'name': 'English (Grenada)'},<br/>{'code': 'en-gu', 'name': 'English (Guam)'},<br/>{'code': 'en-gg', 'name': 'English (Guernsey)'},<br/>{'code': 'en-gy', 'name': 'English (Guyana)'},<br/>{'code': 'en-hk', 'name': 'English (Hong Kong SAR China)'},<br/>{'code': 'en-in', 'name': 'English (India)'},<br/>{'code': 'en-ie', 'name': 'English (Ireland)'},<br/>{'code': 'en-im', 'name': 'English (Isle of Man)'},<br/>{'code': 'en-jm', 'name': 'English (Jamaica)'},<br/>{'code': 'en-je', 'name': 'English (Jersey)'},<br/>{'code': 'en-ke', 'name': 'English (Kenya)'},<br/>{'code': 'en-ki', 'name': 'English (Kiribati)'},<br/>{'code': 'en-ls', 'name': 'English (Lesotho)'},<br/>{'code': 'en-lr', 'name': 'English (Liberia)'},<br/>{'code': 'en-mo', 'name': 'English (Macau SAR China)'},<br/>{'code': 'en-mg', 'name': 'English (Madagascar)'},<br/>{'code': 'en-mw', 'name': 'English (Malawi)'},<br/>{'code': 'en-my', 'name': 'English (Malaysia)'},<br/>{'code': 'en-mt', 'name': 'English (Malta)'},<br/>{'code': 'en-mh', 'name': 'English (Marshall Islands)'},<br/>{'code': 'en-mu', 'name': 'English (Mauritius)'},<br/>{'code': 'en-fm', 'name': 'English (Micronesia)'},<br/>{'code': 'en-ms', 'name': 'English (Montserrat)'},<br/>{'code': 'en-na', 'name': 'English (Namibia)'},<br/>{'code': 'en-nr', 'name': 'English (Nauru)'},<br/>{'code': 'en-nz', 'name': 'English (New Zealand)'},<br/>{'code': 'en-ng', 'name': 'English (Nigeria)'},<br/>{'code': 'en-nu', 'name': 'English (Niue)'},<br/>{'code': 'en-nf', 'name': 'English (Norfolk Island)'},<br/>{'code': 'en-mp', 'name': 'English (Northern Mariana Islands)'},<br/>{'code': 'en-pk', 'name': 'English (Pakistan)'},<br/>{'code': 'en-pw', 'name': 'English (Palau)'},<br/>{'code': 'en-pg', 'name': 'English (Papua New Guinea)'},<br/>{'code': 'en-ph', 'name': 'English (Philippines)'},<br/>{'code': 'en-pn', 'name': 'English (Pitcairn Islands)'},<br/>{'code': 'en-pr', 'name': 'English (Puerto Rico)'},<br/>{'code': 'en-rw', 'name': 'English (Rwanda)'},<br/>{'code': 'en-ws', 'name': 'English (Samoa)'},<br/>{'code': 'en-sc', 'name': 'English (Seychelles)'},<br/>{'code': 'en-sl', 'name': 'English (Sierra Leone)'},<br/>{'code': 'en-sg', 'name': 'English (Singapore)'},<br/>{'code': 'en-sx', 'name': 'English (Sint Maarten)'},<br/>{'code': 'en-sb', 'name': 'English (Solomon Islands)'},<br/>{'code': 'en-za', 'name': 'English (South Africa)'},<br/>{'code': 'en-ss', 'name': 'English (South Sudan)'},<br/>{'code': 'en-sh', 'name': 'English (St. Helena)'},<br/>{'code': 'en-kn', 'name': 'English (St. Kitts & Nevis)'},<br/>{'code': 'en-lc', 'name': 'English (St. Lucia)'},<br/>{'code': 'en-vc', 'name': 'English (St. Vincent & Grenadines)'},<br/>{'code': 'en-sd', 'name': 'English (Sudan)'},<br/>{'code': 'en-sz', 'name': 'English (Swaziland)'},<br/>{'code': 'en-tz', 'name': 'English (Tanzania)'},<br/>{'code': 'en-tk', 'name': 'English (Tokelau)'},<br/>{'code': 'en-to', 'name': 'English (Tonga)'},<br/>{'code': 'en-tt', 'name': 'English (Trinidad & Tobago)'},<br/>{'code': 'en-tc', 'name': 'English (Turks & Caicos Islands)'},<br/>{'code': 'en-tv', 'name': 'English (Tuvalu)'},<br/>{'code': 'en-um', 'name': 'English (U.S. Outlying Islands)'},<br/>{'code': 'en-vi', 'name': 'English (U.S. Virgin Islands)'},<br/>{'code': 'en-ug', 'name': 'English (Uganda)'},<br/>{'code': 'en-gb', 'name': 'English (United Kingdom)'},<br/>{'code': 'en-us', 'name': 'English (United States)'},<br/>{'code': 'en-vu', 'name': 'English (Vanuatu)'},<br/>{'code': 'en-zm', 'name': 'English (Zambia)'},<br/>{'code': 'en-zw', 'name': 'English (Zimbabwe)'},<br/>{'code': 'et-ee', 'name': 'Estonian (Estonia)'},<br/>{'code': 'ee-gh', 'name': 'Ewe (Ghana)'},<br/>{'code': 'ee-tg', 'name': 'Ewe (Togo)'},<br/>{'code': 'fo-fo', 'name': 'Faroese (Faroe Islands)'},<br/>{'code': 'fi-fi', 'name': 'Finnish (Finland)'},<br/>{'code': 'fr-dz', 'name': 'French (Algeria)'},<br/>{'code': 'fr-be', 'name': 'French (Belgium)'},<br/>{'code': 'fr-bj', 'name': 'French (Benin)'},<br/>{'code': 'fr-bf', 'name': 'French (Burkina Faso)'},<br/>{'code': 'fr-bi', 'name': 'French (Burundi)'},<br/>{'code': 'fr-cm', 'name': 'French (Cameroon)'},<br/>{'code': 'fr-ca', 'name': 'French (Canada)'},<br/>{'code': 'fr-cf', 'name': 'French (Central African Republic)'},<br/>{'code': 'fr-td', 'name': 'French (Chad)'},<br/>{'code': 'fr-km', 'name': 'French (Comoros)'},<br/>{'code': 'fr-cg', 'name': 'French (Congo - Brazzaville)'},<br/>{'code': 'fr-cd', 'name': 'French (Congo - Kinshasa)'},<br/>{'code': 'fr-ci', 'name': 'French (Côte d\x92Ivoire)'},<br/>{'code': 'fr-dj', 'name': 'French (Djibouti)'},<br/>{'code': 'fr-gq', 'name': 'French (Equatorial Guinea)'},<br/>{'code': 'fr-fr', 'name': 'French (France)'},<br/>{'code': 'fr-gf', 'name': 'French (French Guiana)'},<br/>{'code': 'fr-pf', 'name': 'French (French Polynesia)'},<br/>{'code': 'fr-ga', 'name': 'French (Gabon)'},<br/>{'code': 'fr-gp', 'name': 'French (Guadeloupe)'},<br/>{'code': 'fr-gn', 'name': 'French (Guinea)'},<br/>{'code': 'fr-ht', 'name': 'French (Haiti)'},<br/>{'code': 'fr-lu', 'name': 'French (Luxembourg)'},<br/>{'code': 'fr-mg', 'name': 'French (Madagascar)'},<br/>{'code': 'fr-ml', 'name': 'French (Mali)'},<br/>{'code': 'fr-mq', 'name': 'French (Martinique)'},<br/>{'code': 'fr-mr', 'name': 'French (Mauritania)'},<br/>{'code': 'fr-mu', 'name': 'French (Mauritius)'},<br/>{'code': 'fr-yt', 'name': 'French (Mayotte)'},<br/>{'code': 'fr-mc', 'name': 'French (Monaco)'},<br/>{'code': 'fr-ma', 'name': 'French (Morocco)'},<br/>{'code': 'fr-nc', 'name': 'French (New Caledonia)'},<br/>{'code': 'fr-ne', 'name': 'French (Niger)'},<br/>{'code': 'fr-rw', 'name': 'French (Rwanda)'},<br/>{'code': 'fr-re', 'name': 'French (Réunion)'},<br/>{'code': 'fr-sn', 'name': 'French (Senegal)'},<br/>{'code': 'fr-sc', 'name': 'French (Seychelles)'},<br/>{'code': 'fr-bl', 'name': 'French (St. Barthélemy)'},<br/>{'code': 'fr-mf', 'name': 'French (St. Martin)'},<br/>{'code': 'fr-pm', 'name': 'French (St. Pierre & Miquelon)'},<br/>{'code': 'fr-ch', 'name': 'French (Switzerland)'},<br/>{'code': 'fr-sy', 'name': 'French (Syria)'},<br/>{'code': 'fr-tg', 'name': 'French (Togo)'},<br/>{'code': 'fr-tn', 'name': 'French (Tunisia)'},<br/>{'code': 'fr-vu', 'name': 'French (Vanuatu)'},<br/>{'code': 'fr-wf', 'name': 'French (Wallis & Futuna)'},<br/>{'code': 'ff-cm', 'name': 'Fulah (Cameroon)'},<br/>{'code': 'ff-gn', 'name': 'Fulah (Guinea)'},<br/>{'code': 'ff-mr', 'name': 'Fulah (Mauritania)'},<br/>{'code': 'ff-sn', 'name': 'Fulah (Senegal)'},<br/>{'code': 'gl-es', 'name': 'Galician (Spain)'},<br/>{'code': 'lg-ug', 'name': 'Ganda (Uganda)'},<br/>{'code': 'ka-ge', 'name': 'Georgian (Georgia)'},<br/>{'code': 'de-at', 'name': 'German (Austria)'},<br/>{'code': 'de-be', 'name': 'German (Belgium)'},<br/>{'code': 'de-de', 'name': 'German (Germany)'},<br/>{'code': 'de-li', 'name': 'German (Liechtenstein)'},<br/>{'code': 'de-lu', 'name': 'German (Luxembourg)'},<br/>{'code': 'de-ch', 'name': 'German (Switzerland)'},<br/>{'code': 'el-cy', 'name': 'Greek (Cyprus)'},<br/>{'code': 'el-gr', 'name': 'Greek (Greece)'},<br/>{'code': 'gu-in', 'name': 'Gujarati (India)'},<br/>{'code': 'ha-gh', 'name': 'Hausa (Ghana)'},<br/>{'code': 'ha-latn', 'name': 'Hausa (Latin)'},<br/>{'code': 'ha-latn-gh', 'name': 'Hausa (Latin, Ghana)'},<br/>{'code': 'ha-latn-ne', 'name': 'Hausa (Latin, Niger)'},<br/>{'code': 'ha-latn-ng', 'name': 'Hausa (Latin, Nigeria)'},<br/>{'code': 'ha-ne', 'name': 'Hausa (Niger)'},<br/>{'code': 'ha-ng', 'name': 'Hausa (Nigeria)'},<br/>{'code': 'he-il', 'name': 'Hebrew (Israel)'},<br/>{'code': 'hi-in', 'name': 'Hindi (India)'},<br/>{'code': 'hu-hu', 'name': 'Hungarian (Hungary)'},<br/>{'code': 'is-is', 'name': 'Icelandic (Iceland)'},<br/>{'code': 'ig-ng', 'name': 'Igbo (Nigeria)'},<br/>{'code': 'id-id', 'name': 'Indonesian (Indonesia)'},<br/>{'code': 'ga-ie', 'name': 'Irish (Ireland)'},<br/>{'code': 'it-it', 'name': 'Italian (Italy)'},<br/>{'code': 'it-sm', 'name': 'Italian (San Marino)'},<br/>{'code': 'it-ch', 'name': 'Italian (Switzerland)'},<br/>{'code': 'ja-jp', 'name': 'Japanese (Japan)'},<br/>{'code': 'kl-gl', 'name': 'Kalaallisut (Greenland)'},<br/>{'code': 'kn-in', 'name': 'Kannada (India)'},<br/>{'code': 'ks-arab', 'name': 'Kashmiri (Arabic)'},<br/>{'code': 'ks-arab-in', 'name': 'Kashmiri (Arabic, India)'},<br/>{'code': 'ks-in', 'name': 'Kashmiri (India)'},<br/>{'code': 'kk-cyrl', 'name': 'Kazakh (Cyrillic)'},<br/>{'code': 'kk-cyrl-kz', 'name': 'Kazakh (Cyrillic, Kazakhstan)'},<br/>{'code': 'kk-kz', 'name': 'Kazakh (Kazakhstan)'},<br/>{'code': 'km-kh', 'name': 'Khmer (Cambodia)'},<br/>{'code': 'ki-ke', 'name': 'Kikuyu (Kenya)'},<br/>{'code': 'rw-rw', 'name': 'Kinyarwanda (Rwanda)'},<br/>{'code': 'ko-kp', 'name': 'Korean (North Korea)'},<br/>{'code': 'ko-kr', 'name': 'Korean (South Korea)'},<br/>{'code': 'ky-cyrl', 'name': 'Kyrgyz (Cyrillic)'},<br/>{'code': 'ky-cyrl-kg', 'name': 'Kyrgyz (Cyrillic, Kyrgyzstan)'},<br/>{'code': 'ky-kg', 'name': 'Kyrgyz (Kyrgyzstan)'},<br/>{'code': 'lo-la', 'name': 'Lao (Laos)'},<br/>{'code': 'lv-lv', 'name': 'Latvian (Latvia)'},<br/>{'code': 'ln-ao', 'name': 'Lingala (Angola)'},<br/>{'code': 'ln-cf', 'name': 'Lingala (Central African Republic)'},<br/>{'code': 'ln-cg', 'name': 'Lingala (Congo - Brazzaville)'},<br/>{'code': 'ln-cd', 'name': 'Lingala (Congo - Kinshasa)'},<br/>{'code': 'lt-lt', 'name': 'Lithuanian (Lithuania)'},<br/>{'code': 'lu-cd', 'name': 'Luba-Katanga (Congo - Kinshasa)'},<br/>{'code': 'lb-lu', 'name': 'Luxembourgish (Luxembourg)'},<br/>{'code': 'mk-mk', 'name': 'Macedonian (Macedonia)'},<br/>{'code': 'mg-mg', 'name': 'Malagasy (Madagascar)'},<br/>{'code': 'ms-bn', 'name': 'Malay (Brunei)'},<br/>{'code': 'ms-latn', 'name': 'Malay (Latin)'},<br/>{'code': 'ms-latn-bn', 'name': 'Malay (Latin, Brunei)'},<br/>{'code': 'ms-latn-my', 'name': 'Malay (Latin, Malaysia)'},<br/>{'code': 'ms-latn-sg', 'name': 'Malay (Latin, Singapore)'},<br/>{'code': 'ms-my', 'name': 'Malay (Malaysia)'},<br/>{'code': 'ms-sg', 'name': 'Malay (Singapore)'},<br/>{'code': 'ml-in', 'name': 'Malayalam (India)'},<br/>{'code': 'mt-mt', 'name': 'Maltese (Malta)'},<br/>{'code': 'gv-im', 'name': 'Manx (Isle of Man)'},<br/>{'code': 'mr-in', 'name': 'Marathi (India)'},<br/>{'code': 'mn-cyrl', 'name': 'Mongolian (Cyrillic)'},<br/>{'code': 'mn-cyrl-mn', 'name': 'Mongolian (Cyrillic, Mongolia)'},<br/>{'code': 'mn-mn', 'name': 'Mongolian (Mongolia)'},<br/>{'code': 'ne-in', 'name': 'Nepali (India)'},<br/>{'code': 'ne-np', 'name': 'Nepali (Nepal)'},<br/>{'code': 'nd-zw', 'name': 'North Ndebele (Zimbabwe)'},<br/>{'code': 'se-fi', 'name': 'Northern Sami (Finland)'},<br/>{'code': 'se-no', 'name': 'Northern Sami (Norway)'},<br/>{'code': 'se-se', 'name': 'Northern Sami (Sweden)'},<br/>{'code': 'no-no', 'name': 'Norwegian (Norway)'},<br/>{'code': 'nb-no', 'name': 'Norwegian Bokmål (Norway)'},<br/>{'code': 'nb-sj', 'name': 'Norwegian Bokmål (Svalbard & Jan Mayen)'},<br/>{'code': 'nn-no', 'name': 'Norwegian Nynorsk (Norway)'},<br/>{'code': 'or-in', 'name': 'Oriya (India)'},<br/>{'code': 'om-et', 'name': 'Oromo (Ethiopia)'},<br/>{'code': 'om-ke', 'name': 'Oromo (Kenya)'},<br/>{'code': 'os-ge', 'name': 'Ossetic (Georgia)'},<br/>{'code': 'os-ru', 'name': 'Ossetic (Russia)'},<br/>{'code': 'ps-af', 'name': 'Pashto (Afghanistan)'},<br/>{'code': 'fa-af', 'name': 'Persian (Afghanistan)'},<br/>{'code': 'fa-ir', 'name': 'Persian (Iran)'},<br/>{'code': 'pl-pl', 'name': 'Polish (Poland)'},<br/>{'code': 'pt-ao', 'name': 'Portuguese (Angola)'},<br/>{'code': 'pt-br', 'name': 'Portuguese (Brazil)'},<br/>{'code': 'pt-cv', 'name': 'Portuguese (Cape Verde)'},<br/>{'code': 'pt-gw', 'name': 'Portuguese (Guinea-Bissau)'},<br/>{'code': 'pt-mo', 'name': 'Portuguese (Macau SAR China)'},<br/>{'code': 'pt-mz', 'name': 'Portuguese (Mozambique)'},<br/>{'code': 'pt-pt', 'name': 'Portuguese (Portugal)'},<br/>{'code': 'pt-st', 'name': 'Portuguese (São Tomé & Príncipe)'},<br/>{'code': 'pt-tl', 'name': 'Portuguese (Timor-Leste)'},<br/>{'code': 'pa-arab', 'name': 'Punjabi (Arabic)'},<br/>{'code': 'pa-arab-pk', 'name': 'Punjabi (Arabic, Pakistan)'},<br/>{'code': 'pa-guru', 'name': 'Punjabi (Gurmukhi)'},<br/>{'code': 'pa-guru-in', 'name': 'Punjabi (Gurmukhi, India)'},<br/>{'code': 'pa-in', 'name': 'Punjabi (India)'},<br/>{'code': 'pa-pk', 'name': 'Punjabi (Pakistan)'},<br/>{'code': 'qu-bo', 'name': 'Quechua (Bolivia)'},<br/>{'code': 'qu-ec', 'name': 'Quechua (Ecuador)'},<br/>{'code': 'qu-pe', 'name': 'Quechua (Peru)'},<br/>{'code': 'ro-md', 'name': 'Romanian (Moldova)'},<br/>{'code': 'ro-ro', 'name': 'Romanian (Romania)'},<br/>{'code': 'rm-ch', 'name': 'Romansh (Switzerland)'},<br/>{'code': 'rn-bi', 'name': 'Rundi (Burundi)'},<br/>{'code': 'ru-by', 'name': 'Russian (Belarus)'},<br/>{'code': 'ru-kz', 'name': 'Russian (Kazakhstan)'},<br/>{'code': 'ru-kg', 'name': 'Russian (Kyrgyzstan)'},<br/>{'code': 'ru-md', 'name': 'Russian (Moldova)'},<br/>{'code': 'ru-ru', 'name': 'Russian (Russia)'},<br/>{'code': 'ru-ua', 'name': 'Russian (Ukraine)'},<br/>{'code': 'sg-cf', 'name': 'Sango (Central African Republic)'},<br/>{'code': 'gd-gb', 'name': 'Scottish Gaelic (United Kingdom)'},<br/>{'code': 'sr-ba', 'name': 'Serbian (Bosnia & Herzegovina)'},<br/>{'code': 'sr-cyrl', 'name': 'Serbian (Cyrillic)'},<br/>{'code': 'sr-cyrl-ba', 'name': 'Serbian (Cyrillic, Bosnia & Herzegovina)'},<br/>{'code': 'sr-cyrl-xk', 'name': 'Serbian (Cyrillic, Kosovo)'},<br/>{'code': 'sr-cyrl-me', 'name': 'Serbian (Cyrillic, Montenegro)'},<br/>{'code': 'sr-cyrl-rs', 'name': 'Serbian (Cyrillic, Serbia)'},<br/>{'code': 'sr-xk', 'name': 'Serbian (Kosovo)'},<br/>{'code': 'sr-latn', 'name': 'Serbian (Latin)'},<br/>{'code': 'sr-latn-ba', 'name': 'Serbian (Latin, Bosnia & Herzegovina)'},<br/>{'code': 'sr-latn-xk', 'name': 'Serbian (Latin, Kosovo)'},<br/>{'code': 'sr-latn-me', 'name': 'Serbian (Latin, Montenegro)'},<br/>{'code': 'sr-latn-rs', 'name': 'Serbian (Latin, Serbia)'},<br/>{'code': 'sr-me', 'name': 'Serbian (Montenegro)'},<br/>{'code': 'sr-rs', 'name': 'Serbian (Serbia)'},<br/>{'code': 'sh-ba', 'name': 'Serbo-Croatian (Bosnia & Herzegovina)'},<br/>{'code': 'sn-zw', 'name': 'Shona (Zimbabwe)'},<br/>{'code': 'ii-cn', 'name': 'Sichuan Yi (China)'},<br/>{'code': 'si-lk', 'name': 'Sinhala (Sri Lanka)'},<br/>{'code': 'sk-sk', 'name': 'Slovak (Slovakia)'},<br/>{'code': 'sl-si', 'name': 'Slovenian (Slovenia)'},<br/>{'code': 'so-dj', 'name': 'Somali (Djibouti)'},<br/>{'code': 'so-et', 'name': 'Somali (Ethiopia)'},<br/>{'code': 'so-ke', 'name': 'Somali (Kenya)'},<br/>{'code': 'so-so', 'name': 'Somali (Somalia)'},<br/>{'code': 'es-ar', 'name': 'Spanish (Argentina)'},<br/>{'code': 'es-bo', 'name': 'Spanish (Bolivia)'},<br/>{'code': 'es-ic', 'name': 'Spanish (Canary Islands)'},<br/>{'code': 'es-ea', 'name': 'Spanish (Ceuta & Melilla)'},<br/>{'code': 'es-cl', 'name': 'Spanish (Chile)'},<br/>{'code': 'es-co', 'name': 'Spanish (Colombia)'},<br/>{'code': 'es-cr', 'name': 'Spanish (Costa Rica)'},<br/>{'code': 'es-cu', 'name': 'Spanish (Cuba)'},<br/>{'code': 'es-do', 'name': 'Spanish (Dominican Republic)'},<br/>{'code': 'es-ec', 'name': 'Spanish (Ecuador)'},<br/>{'code': 'es-sv', 'name': 'Spanish (El Salvador)'},<br/>{'code': 'es-gq', 'name': 'Spanish (Equatorial Guinea)'},<br/>{'code': 'es-gt', 'name': 'Spanish (Guatemala)'},<br/>{'code': 'es-hn', 'name': 'Spanish (Honduras)'},<br/>{'code': 'es-mx', 'name': 'Spanish (Mexico)'},<br/>{'code': 'es-ni', 'name': 'Spanish (Nicaragua)'},<br/>{'code': 'es-pa', 'name': 'Spanish (Panama)'},<br/>{'code': 'es-py', 'name': 'Spanish (Paraguay)'},<br/>{'code': 'es-pe', 'name': 'Spanish (Peru)'},<br/>{'code': 'es-ph', 'name': 'Spanish (Philippines)'},<br/>{'code': 'es-pr', 'name': 'Spanish (Puerto Rico)'},<br/>{'code': 'es-es', 'name': 'Spanish (Spain)'},<br/>{'code': 'es-us', 'name': 'Spanish (United States)'},<br/>{'code': 'es-uy', 'name': 'Spanish (Uruguay)'},<br/>{'code': 'es-ve', 'name': 'Spanish (Venezuela)'},<br/>{'code': 'sw-ke', 'name': 'Swahili (Kenya)'},<br/>{'code': 'sw-tz', 'name': 'Swahili (Tanzania)'},<br/>{'code': 'sw-ug', 'name': 'Swahili (Uganda)'},<br/>{'code': 'sv-fi', 'name': 'Swedish (Finland)'},<br/>{'code': 'sv-se', 'name': 'Swedish (Sweden)'},<br/>{'code': 'sv-ax', 'name': 'Swedish (Åland Islands)'},<br/>{'code': 'tl-ph', 'name': 'Tagalog (Philippines)'},<br/>{'code': 'ta-in', 'name': 'Tamil (India)'},<br/>{'code': 'ta-my', 'name': 'Tamil (Malaysia)'},<br/>{'code': 'ta-sg', 'name': 'Tamil (Singapore)'},<br/>{'code': 'ta-lk', 'name': 'Tamil (Sri Lanka)'},<br/>{'code': 'te-in', 'name': 'Telugu (India)'},<br/>{'code': 'th-th', 'name': 'Thai (Thailand)'},<br/>{'code': 'bo-cn', 'name': 'Tibetan (China)'},<br/>{'code': 'bo-in', 'name': 'Tibetan (India)'},<br/>{'code': 'ti-er', 'name': 'Tigrinya (Eritrea)'},<br/>{'code': 'ti-et', 'name': 'Tigrinya (Ethiopia)'},<br/>{'code': 'to-to', 'name': 'Tongan (Tonga)'},<br/>{'code': 'tr-cy', 'name': 'Turkish (Cyprus)'},<br/>{'code': 'tr-tr', 'name': 'Turkish (Turkey)'},<br/>{'code': 'uk-ua', 'name': 'Ukrainian (Ukraine)'},<br/>{'code': 'ur-in', 'name': 'Urdu (India)'},<br/>{'code': 'ur-pk', 'name': 'Urdu (Pakistan)'},<br/>{'code': 'ug-arab', 'name': 'Uyghur (Arabic)'},<br/>{'code': 'ug-arab-cn', 'name': 'Uyghur (Arabic, China)'},<br/>{'code': 'ug-cn', 'name': 'Uyghur (China)'},<br/>{'code': 'uz-af', 'name': 'Uzbek (Afghanistan)'},<br/>{'code': 'uz-arab', 'name': 'Uzbek (Arabic)'},<br/>{'code': 'uz-arab-af', 'name': 'Uzbek (Arabic, Afghanistan)'},<br/>{'code': 'uz-cyrl', 'name': 'Uzbek (Cyrillic)'},<br/>{'code': 'uz-cyrl-uz', 'name': 'Uzbek (Cyrillic, Uzbekistan)'},<br/>{'code': 'uz-latn', 'name': 'Uzbek (Latin)'},<br/>{'code': 'uz-latn-uz', 'name': 'Uzbek (Latin, Uzbekistan)'},<br/>{'code': 'uz-uz', 'name': 'Uzbek (Uzbekistan)'},<br/>{'code': 'vi-vn', 'name': 'Vietnamese (Vietnam)'},<br/>{'code': 'cy-gb', 'name': 'Welsh (United Kingdom)'},<br/>{'code': 'fy-nl', 'name': 'Western Frisian (Netherlands)'},<br/>{'code': 'yo-bj', 'name': 'Yoruba (Benin)'},<br/>{'code': 'yo-ng', 'name': 'Yoruba (Nigeria)'},<br/>{'code': 'zu-za', 'name': 'Zulu (South Africa)'} | name: Virtual<br/>address: <br/>city: <br/>region: <br/>country: <br/>postal_code: <br/>lat: NaN<br/>lon: NaN | false | 0 |


### splash-delete-event
***
Batch delete Events.


#### Base Command

`splash-delete-event`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | CSV of Event IDs to delete. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Splash.DeleteEvent.meta.code | Number |  | 
| Splash.DeleteEvent.data | Unknown |  | 
| Splash.DeleteEvent.success | Boolean |  | 

#### Command example
```!splash-delete-event ids=458498730```
#### Human Readable Output

>Event IDs 458498730 deleted successfully.

### splash-get-event-group-contacts
***
Retrieve the group contacts just for a specific event.


#### Base Command

`splash-get-event-group-contacts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | The ID of the event for which you would like to see the group contacts (attendees). | Required | 
| limit | Limits how many group contacts are returned. If no limit is specified, Splash will default to 5. | Optional | 
| page | When using a limit, this allows you to specify which page of results you would like to retrieve. | Optional | 
| sort | Sort the results by a requested field. | Optional | 
| status | Use this parameter to limit your results by the RSVP status of the attendees. | Optional | 
| text_filter | This parameter can constrain results to those that match a particular text string. | Optional | 
| event_rsvp_conditions | . | Optional | 
| custom_question_ids | . | Optional | 
| statistics | . | Optional | 
| additional_columns | Use this parameter to specify particular columns to be included in the response. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Splash.Event.id | Number |  | 
| Splash.GroupContact.id | Number |  | 
| Splash.GroupContact.contact.id | Number |  | 
| Splash.GroupContact.contact.last_name | String |  | 
| Splash.GroupContact.contact.first_name | String |  | 
| Splash.GroupContact.contact.primary_email | String |  | 
| Splash.GroupContact.contact.title | String |  | 
| Splash.GroupContact.contact.notes | String |  | 
| Splash.GroupContact.contact.organization_name | String |  | 
| Splash.GroupContact.contact.avatar_url | String |  | 
| Splash.GroupContact.contact.phone | String |  | 
| Splash.GroupContact.contact.facebook_url | String |  | 
| Splash.GroupContact.contact.linkedin_url | String |  | 
| Splash.GroupContact.contact.instagram_url | String |  | 
| Splash.GroupContact.contact.createdate | Date |  | 
| Splash.GroupContact.contact.unsubscribed | Boolean |  | 
| Splash.GroupContact.contact.vip | Boolean |  | 
| Splash.GroupContact.contact.salesforce_id | String |  | 
| Splash.GroupContact.contact.bounced | Boolean |  | 
| Splash.GroupContact.contact.invalid_email | Boolean |  | 
| Splash.GroupContact.event_rsvp.event_id | Number |  | 
| Splash.GroupContact.event_rsvp.contact_id | Number |  | 
| Splash.GroupContact.event_rsvp.ticket_sale | Unknown |  | 
| Splash.GroupContact.event_rsvp.tracking_link | Unknown |  | 
| Splash.GroupContact.event_rsvp.parent_event_rsvp | Unknown |  | 
| Splash.GroupContact.event_rsvp.checked_out | Unknown |  | 
| Splash.GroupContact.event_rsvp.id | Number |  | 
| Splash.GroupContact.event_rsvp.first_name | String |  | 
| Splash.GroupContact.event_rsvp.last_name | String |  | 
| Splash.GroupContact.event_rsvp.guest_name | Unknown |  | 
| Splash.GroupContact.event_rsvp.email | String |  | 
| Splash.GroupContact.event_rsvp.plus_one | Number |  | 
| Splash.GroupContact.event_rsvp.created | Date |  | 
| Splash.GroupContact.event_rsvp.modified | Date |  | 
| Splash.GroupContact.event_rsvp.date_rsvped | Date |  | 
| Splash.GroupContact.event_rsvp.ip_address | Unknown |  | 
| Splash.GroupContact.event_rsvp.attending | Boolean |  | 
| Splash.GroupContact.event_rsvp.deleted | Number |  | 
| Splash.GroupContact.event_rsvp.checked_in | Unknown |  | 
| Splash.GroupContact.event_rsvp.unsub_tag | String |  | 
| Splash.GroupContact.event_rsvp.ticket_number | Unknown |  | 
| Splash.GroupContact.event_rsvp.vip | Boolean |  | 
| Splash.GroupContact.event_rsvp.waitlist | Boolean |  | 
| Splash.GroupContact.event_rsvp.qr_url | String |  | 
| Splash.GroupContact.event_rsvp.unsubscribed | Boolean |  | 
| Splash.GroupContact.event_lists | Unknown |  | 
| Splash.GroupContact.status | String |  | 
| Splash.GroupContact.created | Date |  | 
| Splash.GroupContact.modified | Date |  | 
| Splash.GroupContact.deleted | Boolean |  | 
| Splash.GroupContact.salesforce_campaign_member_id | Unknown |  | 
| Splash.GroupContact.event_rsvp | Unknown |  | 

#### Command example
```!splash-get-event-group-contacts event_id=458498411```
#### Context Example
```json
{
    "Splash": {
        "Event": {
            "GroupContacts": [],
            "id": 458498411
        }
    }
}
```

#### Human Readable Output

>### Contacts for Event ID 458498411:
>**No entries.**


### splash-get-group-contact
***
Retrieve a single group contact if their group contact ID is known.


#### Base Command

`splash-get-group-contact`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_contact_id | The group contact ID of the individual for which you would like to retrieve data. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Splash.GroupContact.id | Number |  | 
| Splash.GroupContact.contact.id | Number |  | 
| Splash.GroupContact.contact.last_name | String |  | 
| Splash.GroupContact.contact.first_name | String |  | 
| Splash.GroupContact.contact.primary_email | String |  | 
| Splash.GroupContact.contact.title | String |  | 
| Splash.GroupContact.contact.notes | String |  | 
| Splash.GroupContact.contact.organization_name | String |  | 
| Splash.GroupContact.contact.avatar_url | String |  | 
| Splash.GroupContact.contact.phone | String |  | 
| Splash.GroupContact.contact.facebook_url | String |  | 
| Splash.GroupContact.contact.linkedin_url | String |  | 
| Splash.GroupContact.contact.instagram_url | String |  | 
| Splash.GroupContact.contact.createdate | Date |  | 
| Splash.GroupContact.contact.unsubscribed | Boolean |  | 
| Splash.GroupContact.contact.vip | Boolean |  | 
| Splash.GroupContact.contact.salesforce_id | String |  | 
| Splash.GroupContact.contact.bounced | Boolean |  | 
| Splash.GroupContact.contact.invalid_email | Boolean |  | 
| Splash.GroupContact.event_rsvp.event_id | Number |  | 
| Splash.GroupContact.event_rsvp.contact_id | Number |  | 
| Splash.GroupContact.event_rsvp.ticket_sale | Unknown |  | 
| Splash.GroupContact.event_rsvp.tracking_link | Unknown |  | 
| Splash.GroupContact.event_rsvp.parent_event_rsvp | Unknown |  | 
| Splash.GroupContact.event_rsvp.checked_out | Unknown |  | 
| Splash.GroupContact.event_rsvp.id | Number |  | 
| Splash.GroupContact.event_rsvp.first_name | String |  | 
| Splash.GroupContact.event_rsvp.last_name | String |  | 
| Splash.GroupContact.event_rsvp.guest_name | Unknown |  | 
| Splash.GroupContact.event_rsvp.email | String |  | 
| Splash.GroupContact.event_rsvp.plus_one | Number |  | 
| Splash.GroupContact.event_rsvp.created | Date |  | 
| Splash.GroupContact.event_rsvp.modified | Date |  | 
| Splash.GroupContact.event_rsvp.date_rsvped | Date |  | 
| Splash.GroupContact.event_rsvp.ip_address | Unknown |  | 
| Splash.GroupContact.event_rsvp.attending | Boolean |  | 
| Splash.GroupContact.event_rsvp.deleted | Number |  | 
| Splash.GroupContact.event_rsvp.checked_in | Unknown |  | 
| Splash.GroupContact.event_rsvp.unsub_tag | String |  | 
| Splash.GroupContact.event_rsvp.ticket_number | Unknown |  | 
| Splash.GroupContact.event_rsvp.vip | Boolean |  | 
| Splash.GroupContact.event_rsvp.waitlist | Boolean |  | 
| Splash.GroupContact.event_rsvp.qr_url | String |  | 
| Splash.GroupContact.event_rsvp.unsubscribed | Boolean |  | 
| Splash.GroupContact.event_lists | Unknown |  | 
| Splash.GroupContact.status | String |  | 
| Splash.GroupContact.created | Date |  | 
| Splash.GroupContact.modified | Date |  | 
| Splash.GroupContact.deleted | Boolean |  | 
| Splash.GroupContact.salesforce_campaign_member_id | Unknown |  | 

#### Command example
```!splash-get-group-contact group_contact_id=553715301```
#### Context Example
```json
{
    "Splash": {
        "GroupContact": {
            "answers": [
                {
                    "answer": "8/17/2022",
                    "question_id": 1265490
                }
            ],
            "contact": {
                "avatar_url": "",
                "bounced": false,
                "createdate": "2022-08-09T08:07:17-04:00",
                "deleted": false,
                "facebook_url": "",
                "first_name": "FirstName",
                "id": 141408389,
                "instagram_url": "",
                "invalid_email": false,
                "last_name": "Lastname",
                "linkedin_url": "",
                "notes": "",
                "organization_name": "",
                "phone": "",
                "primary_email": "mail@domain.com",
                "salesforce_id": "",
                "title": "",
                "unsubscribed": false,
                "vip": false
            },
            "created": "2022-08-09T13:07:17+01:00",
            "deleted": true,
            "event_lists": null,
            "event_rsvp": {
                "attending": true,
                "checked_in": null,
                "checked_out": null,
                "contact_id": 141408389,
                "created": "2022-08-09T08:07:17-04:00",
                "date_rsvped": "2022-08-09T13:07:17+01:00",
                "deleted": 1,
                "email": "mail@domain.com",
                "event_id": 458498411,
                "first_name": "FirstName",
                "guest_name": null,
                "id": 508214110,
                "ip_address": "86.155.204.63",
                "last_name": "Lastname",
                "modified": "2022-08-09T11:00:22-04:00",
                "parent_event_rsvp": null,
                "plus_one": 0,
                "qr_url": "newtestevent123.splashthat.com/tc/1cba42a4797a3ffa",
                "ticket_number": null,
                "ticket_sale": null,
                "tracking_link": null,
                "unsub_tag": "1cba42a4797a3ffa",
                "unsubscribed": false,
                "vip": false,
                "waitlist": false
            },
            "id": 553715301,
            "modified": "2022-08-09T16:00:22+01:00",
            "salesforce_campaign_member_id": null,
            "status": "rsvp_yes"
        }
    }
}
```

#### Human Readable Output

>### Group Contact 553715301:
>|answers|contact|created|deleted|event_lists|event_rsvp|id|modified|salesforce_campaign_member_id|status|
>|---|---|---|---|---|---|---|---|---|---|
>| {'question_id': 1265490, 'answer': '8/17/2022'} | id: 141408389<br/>last_name: Lastname<br/>first_name: FirstName<br/>primary_email: mail@domain.com<br/>title: <br/>notes: <br/>organization_name: <br/>avatar_url: <br/>phone: <br/>facebook_url: <br/>linkedin_url: <br/>instagram_url: <br/>createdate: 2022-08-09T08:07:17-04:00<br/>deleted: false<br/>unsubscribed: false<br/>vip: false<br/>salesforce_id: <br/>bounced: false<br/>invalid_email: false | 2022-08-09T13:07:17+01:00 | true |  | id: 508214110<br/>event_id: 458498411<br/>contact_id: 141408389<br/>ticket_sale: null<br/>tracking_link: null<br/>parent_event_rsvp: null<br/>checked_out: null<br/>first_name: FirstName<br/>last_name: Lastname<br/>guest_name: null<br/>email: mail@domain.com<br/>plus_one: 0<br/>created: 2022-08-09T08:07:17-04:00<br/>modified: 2022-08-09T11:00:22-04:00<br/>date_rsvped: 2022-08-09T13:07:17+01:00<br/>ip_address: 86.155.204.63<br/>attending: true<br/>deleted: 1<br/>checked_in: null<br/>unsub_tag: 1cba42a4797a3ffa<br/>ticket_number: null<br/>vip: false<br/>waitlist: false<br/>qr_url: newtestevent123.splashthat.com/tc/1cba42a4797a3ffa<br/>unsubscribed: false | 553715301 | 2022-08-09T16:00:22+01:00 |  | rsvp_yes |


### splash-list-group-contacts
***
List Group Contacts. By excluding an event ID, you can query your entire group contacts database. This can return a large result set, so pagination is highly recommended. You can still apply all of the same search parameters to this call.


#### Base Command

`splash-list-group-contacts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | The ID of the event you would like to see the group contacts (attendees) for. | Optional | 
| limit | Limits how many group contacts are returned. If no limit is specified, Splash will default to 5. | Optional | 
| page | When using a limit, this allows you to specify which page of results you would like to retrieve. | Optional | 
| sort | Sort the results by a requested field. | Optional | 
| status | Use this parameter to limit your results by the RSVP status of the attendees. | Optional | 
| text_filter | This parameter can constrain results to those that match a particular text string. | Optional | 
| event_rsvp_conditions | . | Optional | 
| custom_question_ids | . | Optional | 
| statistics | . | Optional | 
| additional_columns | Use this parameter to specify particular columns to be included in the response. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Splash.GroupContact.id | Number |  | 
| Splash.GroupContact.contact.id | Number |  | 
| Splash.GroupContact.contact.last_name | String |  | 
| Splash.GroupContact.contact.first_name | String |  | 
| Splash.GroupContact.contact.primary_email | String |  | 
| Splash.GroupContact.contact.title | String |  | 
| Splash.GroupContact.contact.notes | String |  | 
| Splash.GroupContact.contact.organization_name | String |  | 
| Splash.GroupContact.contact.avatar_url | String |  | 
| Splash.GroupContact.contact.phone | String |  | 
| Splash.GroupContact.contact.facebook_url | String |  | 
| Splash.GroupContact.contact.linkedin_url | String |  | 
| Splash.GroupContact.contact.instagram_url | String |  | 
| Splash.GroupContact.contact.createdate | Date |  | 
| Splash.GroupContact.contact.unsubscribed | Boolean |  | 
| Splash.GroupContact.contact.vip | Boolean |  | 
| Splash.GroupContact.contact.salesforce_id | String |  | 
| Splash.GroupContact.contact.bounced | Boolean |  | 
| Splash.GroupContact.contact.invalid_email | Boolean |  | 
| Splash.GroupContact.event_rsvp.event_id | Number |  | 
| Splash.GroupContact.event_rsvp.contact_id | Number |  | 
| Splash.GroupContact.event_rsvp.ticket_sale | Unknown |  | 
| Splash.GroupContact.event_rsvp.tracking_link | Unknown |  | 
| Splash.GroupContact.event_rsvp.parent_event_rsvp | Unknown |  | 
| Splash.GroupContact.event_rsvp.checked_out | Unknown |  | 
| Splash.GroupContact.event_rsvp.id | Number |  | 
| Splash.GroupContact.event_rsvp.first_name | String |  | 
| Splash.GroupContact.event_rsvp.last_name | String |  | 
| Splash.GroupContact.event_rsvp.guest_name | Unknown |  | 
| Splash.GroupContact.event_rsvp.email | String |  | 
| Splash.GroupContact.event_rsvp.plus_one | Number |  | 
| Splash.GroupContact.event_rsvp.created | Date |  | 
| Splash.GroupContact.event_rsvp.modified | Date |  | 
| Splash.GroupContact.event_rsvp.date_rsvped | Date |  | 
| Splash.GroupContact.event_rsvp.ip_address | Unknown |  | 
| Splash.GroupContact.event_rsvp.attending | Boolean |  | 
| Splash.GroupContact.event_rsvp.deleted | Number |  | 
| Splash.GroupContact.event_rsvp.checked_in | Date |  | 
| Splash.GroupContact.event_rsvp.unsub_tag | String |  | 
| Splash.GroupContact.event_rsvp.ticket_number | Unknown |  | 
| Splash.GroupContact.event_rsvp.vip | Boolean |  | 
| Splash.GroupContact.event_rsvp.waitlist | Boolean |  | 
| Splash.GroupContact.event_rsvp.qr_url | String |  | 
| Splash.GroupContact.event_rsvp.unsubscribed | Boolean |  | 
| Splash.GroupContact.event_lists | Unknown |  | 
| Splash.GroupContact.status | String |  | 
| Splash.GroupContact.created | Date |  | 
| Splash.GroupContact.modified | Date |  | 
| Splash.GroupContact.deleted | Boolean |  | 
| Splash.GroupContact.salesforce_campaign_member_id | Unknown |  | 
| Splash.GroupContact.event_rsvp | Unknown |  | 
| Splash.AllGroupContacts.pagination.limit | Number |  | 
| Splash.AllGroupContacts.pagination.count | Number |  | 
| Splash.AllGroupContacts.pagination.page | Number |  | 
| Splash.AllGroupContacts.pagination.pages | Number |  | 
| Splash.AllGroupContacts.pagination.cursor | Unknown |  | 
| Splash.AllGroupContacts.limit | Number |  | 
| Splash.AllGroupContacts.count | Number |  | 
| Splash.AllGroupContacts.page | Number |  | 
| Splash.AllGroupContacts.pages | Number |  | 
| Splash.AllGroupContacts.cursor | Unknown |  | 

#### Command example
```!splash-list-group-contacts```
#### Context Example
```json
{
    "Splash": {
        "GroupContact": {
            "count": 0,
            "cursor": null,
            "data": [],
            "limit": 5,
            "meta": {
                "code": 200
            },
            "page": 1,
            "pages": 0,
            "pagination": {
                "count": 0,
                "cursor": null,
                "limit": 5,
                "page": 1,
                "pages": 0
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|count|cursor|data|limit|meta|page|pages|pagination|
>|---|---|---|---|---|---|---|---|
>| 0 |  |  | 5 | code: 200 | 1 | 0 | limit: 5<br/>count: 0<br/>page: 1<br/>pages: 0<br/>cursor: null |


### splash-create-group-contact
***
Create additional group contacts in your events, one-at-a-time. New attendees are defined via a JSON object, which you can find in the example request body. They require an *event_id* field to tell Splash to which event they should be added. Additional fields include *confirmation email, email, first_name, last_name,* and *status.* 

__Note:__ The behavior of this endpoint can vary depending upon the guest's status. If a guest with that email address already has _"added"_ or _"invited"_, they will be updated. Any other status creates a duplicate guest with that email address. As such, we recommend limiting the use of this endpoint to one-off creations of new guests.


#### Base Command

`splash-create-group-contact`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | The event ID to which to add the contact to. | Required | 
| contact_data | A JSON dictionary of the group contact information. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Splash.GroupContact.id | Number |  | 
| Splash.GroupContact.contact.id | Number |  | 
| Splash.GroupContact.contact.last_name | String |  | 
| Splash.GroupContact.contact.first_name | String |  | 
| Splash.GroupContact.contact.primary_email | String |  | 
| Splash.GroupContact.contact.title | Unknown |  | 
| Splash.GroupContact.contact.notes | Unknown |  | 
| Splash.GroupContact.contact.organization_name | Unknown |  | 
| Splash.GroupContact.contact.avatar_url | Unknown |  | 
| Splash.GroupContact.contact.phone | Unknown |  | 
| Splash.GroupContact.contact.facebook_url | Unknown |  | 
| Splash.GroupContact.contact.linkedin_url | Unknown |  | 
| Splash.GroupContact.contact.instagram_url | Unknown |  | 
| Splash.GroupContact.contact.createdate | Date |  | 
| Splash.GroupContact.contact.unsubscribed | Boolean |  | 
| Splash.GroupContact.contact.vip | Boolean |  | 
| Splash.GroupContact.contact.salesforce_id | Unknown |  | 
| Splash.GroupContact.contact.bounced | Boolean |  | 
| Splash.GroupContact.contact.invalid_email | Boolean |  | 
| Splash.GroupContact.event_rsvp | Unknown |  | 
| Splash.GroupContact.status | String |  | 
| Splash.GroupContact.created | Date |  | 
| Splash.GroupContact.modified | Date |  | 
| Splash.GroupContact.deleted | Boolean |  | 
| Splash.GroupContact.salesforce_campaign_member_id | Unknown |  | 

### splash-update-group-contact
***
Updating a group contact is how you can change information about your guests, as well as alter their status - such as checking them in, waitlisting them, etc. Reference the body parameter to see which fields you can alter. Include the fields and values for the ones you would like to change in the JSON body. If you have custom questions for your guests, you can use an array in the "answer" field and include the question ID and the answer for that guest for each custom question. 

Also, know that the guest statuses used by our backend server functions are different than the ones seen on the frontend of the Splash UI. See the table below for a mapping of the front-end statuses to the back-end statuses. 

| Backend Status | Frontend Status | 
|-|-|
| _added_ | _-- (No Status) --_ |
_invited_ | _Awaiting Reply_ |
| _waitlisted_ | _Waitlisted_ |
| _rsvp\_no_ | _Not Attending_ |
| _rsvp\_yes_ | _Attending_ |
| _checkin\_yes_ | _Checked In_ |
| _checkin\_no_ | _Checked Out_ |


#### Base Command

`splash-update-group-contact`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_contact_id | . | Required | 
| update_data | JSON dictionary of the updates. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Splash.GroupContact.id | Number |  | 
| Splash.GroupContact.contact.id | Number |  | 
| Splash.GroupContact.contact.last_name | String |  | 
| Splash.GroupContact.contact.first_name | String |  | 
| Splash.GroupContact.contact.primary_email | String |  | 
| Splash.GroupContact.contact.title | String |  | 
| Splash.GroupContact.contact.notes | String |  | 
| Splash.GroupContact.contact.organization_name | String |  | 
| Splash.GroupContact.contact.avatar_url | String |  | 
| Splash.GroupContact.contact.phone | String |  | 
| Splash.GroupContact.contact.facebook_url | String |  | 
| Splash.GroupContact.contact.linkedin_url | String |  | 
| Splash.GroupContact.contact.instagram_url | String |  | 
| Splash.GroupContact.contact.createdate | Date |  | 
| Splash.GroupContact.contact.unsubscribed | Boolean |  | 
| Splash.GroupContact.contact.vip | Boolean |  | 
| Splash.GroupContact.contact.salesforce_id | String |  | 
| Splash.GroupContact.contact.bounced | Boolean |  | 
| Splash.GroupContact.contact.invalid_email | Boolean |  | 
| Splash.GroupContact.event_rsvp.event_id | Number |  | 
| Splash.GroupContact.event_rsvp.contact_id | Number |  | 
| Splash.GroupContact.event_rsvp.ticket_sale | Unknown |  | 
| Splash.GroupContact.event_rsvp.tracking_link | Unknown |  | 
| Splash.GroupContact.event_rsvp.parent_event_rsvp | Unknown |  | 
| Splash.GroupContact.event_rsvp.checked_out | Unknown |  | 
| Splash.GroupContact.event_rsvp.id | Number |  | 
| Splash.GroupContact.event_rsvp.first_name | String |  | 
| Splash.GroupContact.event_rsvp.last_name | String |  | 
| Splash.GroupContact.event_rsvp.guest_name | Unknown |  | 
| Splash.GroupContact.event_rsvp.email | String |  | 
| Splash.GroupContact.event_rsvp.plus_one | Number |  | 
| Splash.GroupContact.event_rsvp.created | Date |  | 
| Splash.GroupContact.event_rsvp.modified | Date |  | 
| Splash.GroupContact.event_rsvp.date_rsvped | Date |  | 
| Splash.GroupContact.event_rsvp.ip_address | Unknown |  | 
| Splash.GroupContact.event_rsvp.attending | Boolean |  | 
| Splash.GroupContact.event_rsvp.deleted | Number |  | 
| Splash.GroupContact.event_rsvp.checked_in | Unknown |  | 
| Splash.GroupContact.event_rsvp.unsub_tag | String |  | 
| Splash.GroupContact.event_rsvp.ticket_number | Unknown |  | 
| Splash.GroupContact.event_rsvp.vip | Boolean |  | 
| Splash.GroupContact.event_rsvp.waitlist | Boolean |  | 
| Splash.GroupContact.event_rsvp.qr_url | String |  | 
| Splash.GroupContact.event_rsvp.unsubscribed | Boolean |  | 
| Splash.GroupContact.event_lists | Unknown |  | 
| Splash.GroupContact.status | String |  | 
| Splash.GroupContact.created | Date |  | 
| Splash.GroupContact.modified | Date |  | 
| Splash.GroupContact.deleted | Boolean |  | 
| Splash.GroupContact.salesforce_campaign_member_id | Unknown |  | 

### splash-batch-cancel-rsvps
***
To cancel the RSVP of a guest when their *group contact id* number is known, use the DELETE and _id_ to change their status in your event to RSVP No.


#### Base Command

`splash-batch-cancel-rsvps`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_contact_id | . | Optional | 


#### Context Output

There is no context output for this command.
### splash-list-contacts
***
List Contacts.


#### Base Command

`splash-list-contacts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | . | Optional | 
| page | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Splash.Contacts.id | Number |  | 
| Splash.Contacts.last_name | String |  | 
| Splash.Contacts.first_name | String |  | 
| Splash.Contacts.middle_name | String |  | 
| Splash.Contacts.primary_email | String |  | 
| Splash.Contacts.title | String |  | 
| Splash.Contacts.notes | String |  | 
| Splash.Contacts.organization_name | String |  | 
| Splash.Contacts.avatar_url | String |  | 
| Splash.Contacts.profile_image | String |  | 
| Splash.Contacts.street | String |  | 
| Splash.Contacts.city | String |  | 
| Splash.Contacts.state | String |  | 
| Splash.Contacts.zip | String |  | 
| Splash.Contacts.phone | String |  | 
| Splash.Contacts.twitter_display_name | String |  | 
| Splash.Contacts.twitter_url | String |  | 
| Splash.Contacts.facebook_display_name | String |  | 
| Splash.Contacts.facebook_url | String |  | 
| Splash.Contacts.linkedin_display_name | String |  | 
| Splash.Contacts.linkedin_url | String |  | 
| Splash.Contacts.pinterest_display_name | String |  | 
| Splash.Contacts.pinterest_url | String |  | 
| Splash.Contacts.instagram_display_name | String |  | 
| Splash.Contacts.instagram_url | String |  | 
| Splash.Contacts.website | String |  | 
| Splash.Contacts.createdate | Date |  | 
| Splash.Contacts.gender | String |  | 
| Splash.Contacts.unsubscribed | Boolean |  | 
| Splash.Contacts.birthday | String |  | 
| Splash.Contacts.vip | Boolean |  | 
| Splash.Contacts.salesforce_id | String |  | 
| Splash.Contacts.bounced | Boolean |  | 
| Splash.Contacts.invalid_email | Boolean |  | 

#### Command example
```!splash-list-contacts```
#### Context Example
```json
{
    "Splash": {
        "Contact": {
            "avatar_url": "",
            "birthday": "2022-08-17 00:00:00",
            "bounced": false,
            "city": "",
            "createdate": "2022-08-09T08:07:17-04:00",
            "deleted": false,
            "facebook_display_name": "",
            "facebook_url": "",
            "first_name": "FirstName",
            "gender": "",
            "id": 141408389,
            "instagram_display_name": "",
            "instagram_url": "",
            "invalid_email": false,
            "last_name": "Lastname",
            "linkedin_display_name": "",
            "linkedin_url": "",
            "middle_name": "",
            "notes": "",
            "organization_name": "",
            "phone": "",
            "pinterest_display_name": "",
            "pinterest_url": "",
            "primary_email": "mail@domain.com",
            "profile_image": "",
            "salesforce_id": "",
            "state": "",
            "street": "",
            "title": "",
            "twitter_display_name": "",
            "twitter_url": "",
            "unsubscribed": false,
            "vip": false,
            "website": "",
            "zip": ""
        }
    }
}
```

#### Human Readable Output

>### Contacts:
>|avatar_url|birthday|bounced|city|createdate|deleted|facebook_display_name|facebook_url|first_name|gender|id|instagram_display_name|instagram_url|invalid_email|last_name|linkedin_display_name|linkedin_url|middle_name|notes|organization_name|phone|pinterest_display_name|pinterest_url|primary_email|profile_image|salesforce_id|state|street|title|twitter_display_name|twitter_url|unsubscribed|vip|website|zip|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|  | 2022-08-17 00:00:00 | false |  | 2022-08-09T08:07:17-04:00 | false |  |  | FirstName |  | 141408389 |  |  | false | Lastname |  |  |  |  |  |  |  |  | mail@domain.com |  |  |  |  |  |  |  | false | false |  |  |


### splash-get-contact
***
Retrieve the information for an individual contact. The contact you want to retrieve is specified by a *contact ID* in the URL path and is rendered as JSON in the response.


#### Base Command

`splash-get-contact`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| contact_id | . | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Splash.Contact.id | Number |  | 
| Splash.Contact.last_name | String |  | 
| Splash.Contact.first_name | String |  | 
| Splash.Contact.middle_name | String |  | 
| Splash.Contact.primary_email | String |  | 
| Splash.Contact.title | String |  | 
| Splash.Contact.notes | String |  | 
| Splash.Contact.organization_name | String |  | 
| Splash.Contact.avatar_url | String |  | 
| Splash.Contact.profile_image | String |  | 
| Splash.Contact.street | String |  | 
| Splash.Contact.city | String |  | 
| Splash.Contact.state | String |  | 
| Splash.Contact.zip | String |  | 
| Splash.Contact.phone | String |  | 
| Splash.Contact.twitter_display_name | String |  | 
| Splash.Contact.twitter_url | String |  | 
| Splash.Contact.facebook_display_name | String |  | 
| Splash.Contact.facebook_url | String |  | 
| Splash.Contact.linkedin_display_name | String |  | 
| Splash.Contact.linkedin_url | String |  | 
| Splash.Contact.pinterest_display_name | String |  | 
| Splash.Contact.pinterest_url | String |  | 
| Splash.Contact.instagram_display_name | String |  | 
| Splash.Contact.instagram_url | String |  | 
| Splash.Contact.website | String |  | 
| Splash.Contact.createdate | Date |  | 
| Splash.Contact.gender | String |  | 
| Splash.Contact.unsubscribed | Boolean |  | 
| Splash.Contact.birthday | String |  | 
| Splash.Contact.vip | Boolean |  | 
| Splash.Contact.salesforce_id | String |  | 
| Splash.Contact.bounced | Boolean |  | 
| Splash.Contact.invalid_email | Boolean |  | 

#### Command example
```!splash-get-contact contact_id=141408389```
#### Context Example
```json
{
    "Splash": {
        "Contact": {
            "avatar_url": "",
            "birthday": "2022-08-17 00:00:00",
            "bounced": false,
            "city": "",
            "createdate": "2022-08-09T08:07:17-04:00",
            "deleted": false,
            "facebook_display_name": "",
            "facebook_url": "",
            "first_name": "FirstName",
            "gender": "",
            "id": 141408389,
            "instagram_display_name": "",
            "instagram_url": "",
            "invalid_email": false,
            "last_name": "Lastname",
            "linkedin_display_name": "",
            "linkedin_url": "",
            "middle_name": "",
            "notes": "",
            "organization_name": "",
            "phone": "",
            "pinterest_display_name": "",
            "pinterest_url": "",
            "primary_email": "mail@domain.com",
            "profile_image": "",
            "salesforce_id": "",
            "state": "",
            "street": "",
            "title": "",
            "twitter_display_name": "",
            "twitter_url": "",
            "unsubscribed": false,
            "vip": false,
            "website": "",
            "zip": ""
        }
    }
}
```

#### Human Readable Output

>### Contact ID 141408389:
>|avatar_url|birthday|bounced|city|createdate|deleted|facebook_display_name|facebook_url|first_name|gender|id|instagram_display_name|instagram_url|invalid_email|last_name|linkedin_display_name|linkedin_url|middle_name|notes|organization_name|phone|pinterest_display_name|pinterest_url|primary_email|profile_image|salesforce_id|state|street|title|twitter_display_name|twitter_url|unsubscribed|vip|website|zip|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|  | 2022-08-17 00:00:00 | false |  | 2022-08-09T08:07:17-04:00 | false |  |  | FirstName |  | 141408389 |  |  | false | Lastname |  |  |  |  |  |  |  |  | mail@domain.com |  |  |  |  |  |  |  | false | false |  |  |


### splash-get-contact-history
***
Part of privacy compliance is the ability to be transparent about the data you have. The Contact History API call helps meet this compliance necessity by responding to a *contact ID* with a record of the events with which this contact has been associated in Splash.


#### Base Command

`splash-get-contact-history`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| contact_id | . | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Splash.Contact.History.history.history.type | String |  | 
| Splash.Contact.History.history.object.event.user.id | Number |  | 
| Splash.Contact.History.history.object.event.user.email | String |  | 
| Splash.Contact.History.history.object.event.user.first_name | String |  | 
| Splash.Contact.History.history.object.event.user.last_name | String |  | 
| Splash.Contact.History.history.object.event.user.cognito_id | String |  | 
| Splash.Contact.History.history.object.event.event_type.name | String |  | 
| Splash.Contact.History.history.object.event.title | String |  | 
| Splash.Contact.History.history.object.event.domain | String |  | 
| Splash.Contact.History.history.object.ticket_sale | Unknown |  | 
| Splash.Contact.History.history.object.checked_out | Unknown |  | 
| Splash.Contact.History.history.object.id | Number |  | 
| Splash.Contact.History.history.object.email | String |  | 
| Splash.Contact.History.history.object.created | Date |  | 
| Splash.Contact.History.history.object.date_rsvped | Date |  | 
| Splash.Contact.History.history.object.attending | Boolean |  | 
| Splash.Contact.History.history.object.checked_in | Unknown |  | 
| Splash.Contact.History.history.object.vip | Boolean |  | 
| Splash.Contact.History.history.text | String |  | 
| Splash.Contact.History.history.created | Number |  | 
| Splash.Contact.History.custom | List |  | 
| Splash.Contact.History.tags | List |  | 

#### Command example
```!splash-get-contact-history contact_id=141408389```
#### Context Example
```json
{
    "Splash": {
        "Contact": {
            "History": {
                "custom": [],
                "history": [
                    {
                        "created": 1660057268,
                        "object": {
                            "attending": true,
                            "checked_in": null,
                            "checked_out": null,
                            "created": "2022-08-09T11:01:08-04:00",
                            "date_rsvped": "2022-08-09T16:01:08+01:00",
                            "email": "mail@domain.com",
                            "event": {
                                "domain": "newtestevent123",
                                "event_type": {
                                    "name": "Seminars & Workshops"
                                },
                                "title": "a new title",
                                "user": {
                                    "cognito_id": null,
                                    "email": "mail@domain.com",
                                    "first_name": "FirstName",
                                    "id": 637495,
                                    "last_name": "Lastname"
                                }
                            },
                            "id": 508223276,
                            "ticket_sale": null,
                            "vip": false
                        },
                        "text": "RSVP'ed to the event",
                        "type": "rsvp"
                    }
                ],
                "tags": []
            },
            "id": 141408389
        }
    }
}
```

#### Human Readable Output

>### Contact History for ID 141408389:
>|custom|history|tags|
>|---|---|---|
>|  | {'type': 'rsvp', 'object': {'id': 508223276, 'event': {'user': {'id': 637495, 'email': 'mail@domain.com', 'first_name': 'FirstName', 'last_name': 'Lastname', 'cognito_id': None}, 'event_type': {'name': 'Seminars & Workshops'}, 'title': 'a new title', 'domain': 'newtestevent123'}, 'ticket_sale': None, 'checked_out': None, 'email': 'mail@domain.com', 'created': '2022-08-09T11:01:08-04:00', 'date_rsvped': '2022-08-09T16:01:08+01:00', 'attending': True, 'checked_in': None, 'vip': False}, 'text': "RSVP'ed to the event", 'created': 1660057268} |  |


### splash-delete-contact
***
Delete a Contact.   If you know a *contact ID*, it can be used to delete that _Contact_ from your list of _Splash Contacts_. Make certain it is the contact you want to delete and not just an event guest (group contact). Keep in mind this is just a __soft delete__ that makes contacts invisible to Splash users and does not remove them from the Splash database. For GDPR-related use cases and removing personal information, Splash recommends using the anonymize endpoint which is designed to be compliant with privacy laws.


#### Base Command

`splash-delete-contact`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| contact_id | . | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!splash-delete-contact contact_id=141408389```
#### Human Readable Output

>Successfully deleted contact ID 141408389

### splash-anonymize-contact
***
Anonymize Contact. Splash takes compliance with privacy laws very seriously. This directly led to the creation of the anonymize contact endpoint as a GDPR compliance tool. Be absolutely certain you want to do this! Once a contact has been anonymized, it cannot be undone.

**Note:**
Utilizing the Anonymize Contacts endpoint requires special privileges for your API user. Inadequate privileges are indicated by a 403 error when using this endpoint. This privilege is only available to organization admins. Contact your Customer Success Representative to learn how to gain appropriate privileges for access.  
Alternatively, you can use the Incoming Webhook integration to accomplish anonymizations and unsubscribes.


#### Base Command

`splash-anonymize-contact`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| contact_id | This is the contact ID of the person whose information will be anonymized in the Splash database. | Required | 


#### Context Output

There is no context output for this command.
### splash-retrieve-unsubscribe
***
A GET call to the /unsubscribe endpoint can be used to query for a specified unsubscribe. The unsubscribe tag, type of unsubscribe to retrieve, and event ID for the event from which the unsubscribe came are all required values.


#### Base Command

`splash-retrieve-unsubscribe`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| unsub_tag | This is the unsub_tag found on the GroupContacts object. | Required | 
| unsub_type | This parameter specifies the types of unsubscribe to retrieve: "all", "event", or "any". Possible values are: all, event, any. | Required | 
| event_id | The ID of the event with which the unsub_tag is associated. | Required | 


#### Context Output

There is no context output for this command.
### splash-create-an-unsubscribe
***
You can send a POST to the /unsubscribe endpoint to create new unsubscribes at both the organization and event levels. 

**Note**: Unsubscribing a contact means they will no longer receive any communications from Splash to the level that you specify.


#### Base Command

`splash-create-an-unsubscribe`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| unsub_tag | This is the unsub_tag found on the GroupContacts object. | Required | 
| unsub_type | This parameter specifies the types of unsubscribe to create: "all", "event", or "any". Possible values are: all, event, any. | Required | 
| event_id | The ID of the event with which the unsub_tag is associated. | Required | 


#### Context Output

There is no context output for this command.
### splash-resubscribe
***
Unsubscribed contacts, whether from an event or an organization, can be resubscribed. Sending a DELETE call to this endpoint and specifying the unsub_tag originally used for the unsubscribe "deletes" the unsubscribe, essentially resubscribing the contact to communication from your Splash organization.


#### Base Command

`splash-resubscribe`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| unsub_tag | . | Optional | 
| unsub_type | . | Optional | 
| event_id | . | Optional | 


#### Context Output

There is no context output for this command.
### splash-create-event
***
Creating an event.


#### Base Command

`splash-create-event`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| title | The title of the event to create. | Required | 
| splash_theme_id | The numerical ID of the theme the new event will use. Find this in any GET /events API call response. When an ID is not entered, it defaults to the most recently updated theme to which you have access. | Optional | 
| event_start | The event start date and time, in the format YYYY-mm-dd H:M:S. Splash copies it from the theme itself when none is entered. | Optional | 
| event_end | The event end date and time in the same format as event_start. | Optional | 
| time_zone_identifier | Indicate the time zone for your event in this field. | Optional | 
| domain | Choose a particular domain for your event if you do not want to use the one automatically generated from the events title. | Optional | 
| venue_name | The event venue. | Optional | 
| address | The venue address. | Optional | 
| city | The city of the venue. | Optional | 
| state | The state, province, or territory of the venue. | Optional | 
| zip_code | The postal code of the venue. | Optional | 
| country | The country of the event venue. | Optional | 
| event_tags | Tags can be applied to the created event. Delimit each tag with a comma. | Optional | 
| event_type | Use this field to identify which event type to use. | Optional | 
| salesforce_campaign_id | The new event can be associated with a Salesforce Campaign by its SFDC object ID. When placed in this field, your Salesforce integration automatically starts synchronizing the guest list. | Optional | 
| owner_email | If you are an org admin, you can pick a use to set as the owner of the event if you would like to override the default. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Splash.CreateEvent.status | String |  | 
| Splash.CreateEvent.message | String |  | 
| Splash.CreateEvent.data.domain | String |  | 
| Splash.CreateEvent.data.event_id | String |  | 
