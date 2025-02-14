Use the Zoom integration manage your Zoom users and meetings
This integration was integrated and tested with version 2.0.0 of Zoom

## Configure Zoom in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| `Server URL` (e.g., '<https://api.zoom.us/v2/>') |  | True |
| `Account ID (OAuth)` |  | True |
| `Client ID (OAuth)` |  | True |
| `Client Secret (OAuth)` |  | True |
| `Use system proxy settings` |  | False |
| `Trust any certificate (not secure)` |  | False |
| `Long running instance`| Enable in order to use zoom-ask and for mirroring. |False |
| `Listen Port`|Listener port number. Required when choosing long running instance with an external engine for using the Zoom Bot.  |False|
| `Bot JID`| Zoom Bot app JID. | False|
| `Bot Client ID (OAuth)`| Zoom Bot app client ID. | False|
| `Bot Client Secret (OAuth)`|  Zoom Bot app secret ID. | False|
| `Secret Token`| For mirroring, see [Configuring Secret Token](#secret-token). |False|
| `Verification Token`| For verify the mirror in. |False|
| `Mirroring` | Enable Incident Mirroring. See [how to configure the app](#secret-token). | False |
| `Certificate (Required for HTTPS)`| (For Cortex XSOAR 6.x) For use with HTTPS - the certificate that the service should use. (For Cortex XSOAR 8 and Cortex XSIAM) Custom certificates are supported only using engine.|False|
|`Private Key (Required for HTTPS)`|(For Cortex XSOAR 6.x) For use with HTTPS - the private key that the service should use. (For Cortex XSOAR 8 and Cortex XSIAM) When using an engine, configure a private API key|False|
 
  





### Server configuration (XSOAR 6.x)

In the Server Configuration section, verify that the value for the instance.execute.external.`INTEGRATION-INSTANCE-NAME` key is set to true. If this key does not exist:

1. Click **+ Add Server Configuration**.
2. Add **instance.execute.external.`INTEGRATION-INSTANCE-NAME`** and set the value to **true**. 

XSOAR endpoint URL-

- **For Cortex XSOAR 6.x**: `<CORTEX-XSOAR-URL>/instance/execute/<INTEGRATION-INSTANCE-NAME>`. For example, `https://my.demisto.live/instance/execute/zoom`. Note that the string `instance` does not refer to the name of your XSOAR instance, but rather is part of the URL.
- **For Cortex XSOAR 8.x / XSIAM**: you need to run using external engine: `https://<Engine URL>:<port>`. For example, <https://my-engine-url:7001>. 


## Create Zoom ChatBOT app

1. Log onto the Zoom App Marketplace: <https://marketplace.zoom.us/>.
2. Click **Develop** > **Build App**.
3. Choose **General App**.
4. Click **Create**.

![enter image description here](https://github.com/demisto/content-assets/raw/master/Assets/Zoom/create-team-chat-app.gif)

### Configure App Settings

1. Update your app’s name. By default, the build flow generates a generic name for your app. To change your app's name, select the edit icon (pencil) and update the name. To save your changes, click anywhere outside of the app name field.
2. Under the section "Select how the app is managed", select "Admin-managed", and click "Save".
3. Enter your Cortex XSOAR endpoint URL in the **OAuth Redirect URL**.
4. Click **Features** > **Surface** > **Team Chat**.
Toggle on the "Team Chat Subscription" section. Under "Bot Endpoint URL", add:
   - For Cortex XSOAR 6.x: `<CORTEX-XSOAR-URL>/instance/execute/<INTEGRATION-INSTANCE-NAME>`. For example, `https://my.demisto.live/instance/execute/zoom`. Note that the string `instance` does not refer to the name of your Cortex XSOAR instance, but rather is part of the URL.
   - For Cortex XSOAR 8.x / XSIAM you need to run using external engine: `https://<Engine Url>:<port>`. For example, <https://my-engine-url:7001>. 

![enter image description here](https://github.com/demisto/content-assets/raw/master/Assets/Zoom/bot_endpoint_url.gif)

5. Click **Scopes** > **+ Add Scopes** to add the following scope permissions.

   | Scope Type | Scope Name | 
   | --- |  --- | 
   | Team Chat | /imchat:bot |
   | Team Chat | /team_chat:read:user_message:admin |
   | Team Chat | /team_chat:read:list_user_sessions:admin |
   | Team Chat | /team_chat:read:list_user_messages:admin |
   | Team Chat | /team_chat:write:user_channel:admin |
   | Team Chat | /team_chat:write:members:admin |
   | Team Chat | /team_chat:update:user_channel:admin |
   | User | /user:read:user:admin |

![enter image description here](../../doc_files/scope-premissions.png)

6. Click **Local Test** > **Add App Now** to test your app and authorize your Cortex XSOAR app.
   
7. If mirroring is enabled in the integration configuration or using `ZoomAsk`:
   - **Endpoint URL Requirements:**
   According to the [Zoom requirements](https://developers.zoom.us/docs/api/webhooks/#webhook-endpoint-requirements) in order to receive webhooks, the Event notification endpoint URL that you specify for each event subscription must:
       - Be a publicly accessible https endpoint url that supports TLSv1.2+ with a valid certificate chain issued by a Certificate Authority (CA).
       - Employ the `https://` scheme.
       - Be able to accept HTTP POST requests containing JSON payloads.
       - Be a fully qualified domain name (FQDN).
       -  be able to respond with an HTTP Status Code.

   - **Zoom Configurations:**
     
     1. Copy the **Secret Token** from the "Features" > "Access" page under the "Token" section and add it to the instance configuration. ![enter image description here](../../doc_files/zoom-token.png)
     2. Configure Event Subscriptions.
     3. In the "Features" section, under "Access", in the "General Features" section, enable "Event Subscription".
     4. Click **+Add New Event Subscription**.
     5.  Enter the following information:
         - Subscription name: Enter a name for this Event Subscription (e.g., "Send Message Sent")
         - Add Events: Click **+Add Events**. Under Event Types, select **Chat Message**, and then select **Chat Message Sent**.
         - Event notification endpoint URL: Enter the Cortex XSOAR URL of your server (`CORTEX-XSOAR-URL`/instance/execute/`INTEGRATION-INSTANCE-NAME`) where you want to receive event notifications. This URL should handle incoming event data from Zoom. Make sure it's publicly accessible.
         - Authentication Header Option - 
           1. **Default Header Provided by Zoom option** - This option allows you to use a verification token provided by Zoom. Copy the **Verification Token** under the "Token" section and add it to the instance configuration.
          ![enter image description here](../../doc_files/verification.png)

           2. **Basic Authentication option** - You can use Basic Authentication by providing your Zoom Client ID (OAuth) and Secret ID (OAuth) as configured in the instance configuration.
          ![enter image description here](../../doc_files/authentication_header.png)

        ![enter image description here](https://github.com/demisto/content-assets/raw/master/Assets/Zoom/add-event.gif)


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### zoom-create-user

***
Create a new user in zoom account


#### Base Command

`zoom-create-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| first_name | First name of the new user. | Required | 
| last_name | Last name of the new user. | Required | 
| email | The email of the new user. | Required | 
| user_type | The type of the newly created user.  Note: the old type "pro" in now called "Licensed", and the type "Corporate" is not sopprted in Zoom v2 and above.. Possible values are: Basic, Licensed, pro, Corporate. Default is Basic. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zoom.User.id | string | The ID of the created user | 
| Zoom.User.first_name | string | First name of the created user | 
| Zoom.User.last_name | string | Last name for the created user | 
| Zoom.User.email | string | Email of the created user | 
| Zoom.User.created_at | date | Created date of the user. Note that this field does not appear in zoom v2 and above. | 
| Zoom.User.type | number | The type of the user | 

#### Command example

```!zoom-create-user email=example@example.com first_name=john last_name=smith user_type=Basic```

#### Context Example

```json
{
    "Zoom": {
        "User": {
            "email": "example@example.com",
            "first_name": "john",
            "id": "wSQafNLNSJWq_oBzmT7XOw",
            "last_name": "smith",
            "type": 1
        }
    }
}
```

#### Human Readable Output

>User created successfully with ID: wSQafNLNSJWq_oBzmT7XOw

### zoom-create-meeting

***
Create a new zoom meeting (scheduled ,instant, or recurring)


#### Base Command

`zoom-create-meeting`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The type of the meeting. Possible values are: Instant, Scheduled, Recurring meeting with fixed time. Default is Instant. | Required | 
| end_date_time | For recurring meetings only. Select the final date on which the meeting will recur before it is canceled. For example: 2017-11-25T12:00:00Z. | Optional | 
| end_times | For recurring meetings only.Select how many times the meeting should recur before it is canceled. max = 365. Default = 1.. | Optional | 
| monthly_day | For recurring meetings with Monthly recurrence_type only. State the day in a month the meeting should recur. The value range is from 1 to 31. Default = 1.. | Optional | 
| monthly_week | For recurring meetings with Monthly recurrence_type only.State the week of the month when the meeting should recur. If you use this field, you must also use the monthly_week_day field to state the day of the week when the meeting should recur. Allowed: -1 (for last week of the month) ┃1┃2┃3┃4. | Optional | 
| monthly_week_day | For recurring meetings with Monthly recurrence_type only. State a specific day in a week when the monthly meeting should recur. Allowed: 1┃2┃3┃4┃5┃6┃7To use this field, you must also use the monthly_week field.. | Optional | 
| repeat_interval | For recurring meeting with fixed time only. Define the interval at which the meeting should recur. For instance, if you would like to schedule a meeting that recurs every two months, you must set the value of this field as 2 and the value of the type parameter as Monthly. For a daily meeting, the maximum is 90 days. For a weekly meeting the maximum is of 12 weeks. For a monthly meeting, there is a maximum of 3 months. | Optional | 
| recurrence_type | For recurring meetings only. Set the recurrence meeting types.. Possible values are: Daily, Weekly, Monthly. | Optional | 
| weekly_days | For recurring meetings with a Weekly recurrence_type only. State a specific day in a week when the weekly meeting should recur. Allowed: 1┃2┃3┃4┃5┃6┃7  Default = 1.. | Optional | 
| auto-record-meeting | The automatic recording settings. Note that the Cloud option is available for Zoom paid customers only. Possible values are: local, cloud, none. Default is none. | Optional | 
| encryption_type | The type of end-to-end (E2EE) encryption, enhanced_encryption or e2ee. Possible values are: enhanced_encryption, e2ee. Default is enhanced_encryption. | Optional | 
| host_video | start meetings with the host video on. Possible values are: true, false. Default is True. | Optional | 
| join_before_host_time | If the value of the join_before_host field is true, this field sets the time that a participant can join before the meeting's host. You can choose: 5 or 10 (minutes), or 0 for any time. Possible values are: 0, 5, 10. | Optional | 
| join_before_host | Whether participants can join the meeting before its host. For scheduled or recurring meetings only. The default value is False. Possible values are: false, true. | Optional | 
| meeting_authentication | If true, only authenticated users can join the meeting. Possible values are: false, true. Default is false. | Optional | 
| user | email address or id of user for meeting. | Required | 
| topic | The topic of the meeting. | Required | 
| waiting_room | This allows the host to control when a participant joins the meeting. The default is False. Possible values are: false, true. | Optional | 
| start-time | Meeting start time. When using a format like “yyyy-MM-ddTHH:mm:ssZ”, always use GMT time. When using a format like “yyyy-MM-ddTHH:mm:ss”, you should use local time and you will need to specify the time zone. Only used for scheduled meetings and recurring meetings with fixed time. | Optional | 
| timezone | Timezone to format start_time. For example, “America/Los_Angeles”. For scheduled meetings only. . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zoom.Meeting.join_url | string | Join url for the meeting | 
| Zoom.Meeting.id | string | Meeting id of the new meeting that is created | 
| Zoom.Meeting.start_url | string | The URL to start the meeting | 
| Zoom.Meeting.uuid | string | Unique meeting ID of the new meeting that is created | 
| Zoom.Meeting.status | string | The status of the meeting | 
| Zoom.Meeting.start_time | Date | The time that the meeting will start at | 
| Zoom.Meeting.host email | string | The email of the host of this meeting | 
| Zoom.Meeting.topic | string | The topic of the meeting | 
| Zoom.Meeting.duration | number | The duratian of the meeting | 
| Zoom.Meeting.created_at | Date | The time that this meeting was created | 
| Zoom.Meeting.type | number | The type of the new meeting, Instant = 1, Scheduled =2,Recurring with fixed time = 8 | 

#### Command example

```!zoom-create-meeting topic=test type=scheduled user=example@example.com start-time=2023-01-29T12:12:12Z```

#### Context Example

```json
{
    "Zoom": {
        "Meeting": {
            "created_at": "2023-01-15T12:44:30Z",
            "duration": 60,
            "host_email": "example@example.com",
            "host_id": "uJiZN-O7Rp6Jp_995FpZGg",
            "id": 88454393857,
            "join_url": "https://us06web.zoom.us/j/8845?pwd=WkI1WUdvbHhnMlJuaXU1WDNPdz09",
            "pre_schedule": false,
            "settings": {
                "allow_multiple_devices": false,
                "alternative_host_update_polls": false,
                "alternative_hosts": "",
                "alternative_hosts_email_notification": true,
                "approval_type": 2,
                "approved_or_denied_countries_or_regions": {
                    "enable": false
                },
                "audio": "both",
                "auto_recording": "none",
                "breakout_room": {
                    "enable": false
                },
                "close_registration": false,
                "cn_meeting": false,
                "device_testing": false,
                "email_notification": true,
                "enable_dedicated_group_chat": false,
                "encryption_type": "enhanced_encryption",
                "enforce_login": false,
                "enforce_login_domains": "",
                "focus_mode": false,
                "global_dial_in_countries": [
                    "US"
                ],
                "global_dial_in_numbers": [
                    {
                        "city": "Houston",
                        "country": "US",
                        "country_name": "US",
                        "number": "+1 3462487799",
                        "type": "toll"
                    },
                    {
                        "country": "US",
                        "country_name": "US",
                        "number": "+1 3602095623",
                        "type": "toll"
                    },
                    {
                        "country": "US",
                        "country_name": "US",
                        "number": "+1 3863475053",
                        "type": "toll"
                    },
                    {
                        "country": "US",
                        "country_name": "US",
                        "number": "+1 5074734847",
                        "type": "toll"
                    },
                    {
                        "country": "US",
                        "country_name": "US",
                        "number": "+1 5642172000",
                        "type": "toll"
                    },
                    {
                        "city": "New York",
                        "country": "US",
                        "country_name": "US",
                        "number": "+1 6465588656",
                        "type": "toll"
                    },
                    {
                        "country": "US",
                        "country_name": "US",
                        "number": "+1 6469313860",
                        "type": "toll"
                    },
                    {
                        "country": "US",
                        "country_name": "US",
                        "number": "+1 6694449171",
                        "type": "toll"
                    },
                    {
                        "country": "US",
                        "country_name": "US",
                        "number": "+1 6892781000",
                        "type": "toll"
                    },
                    {
                        "country": "US",
                        "country_name": "US",
                        "number": "+1 7193594580",
                        "type": "toll"
                    },
                    {
                        "city": "Denver",
                        "country": "US",
                        "country_name": "US",
                        "number": "+1 7207072699",
                        "type": "toll"
                    },
                    {
                        "country": "US",
                        "country_name": "US",
                        "number": "+1 2532050468",
                        "type": "toll"
                    },
                    {
                        "city": "Tacoma",
                        "country": "US",
                        "country_name": "US",
                        "number": "+1 2532158782",
                        "type": "toll"
                    },
                    {
                        "city": "Washington DC",
                        "country": "US",
                        "country_name": "US",
                        "number": "+1 3017158592",
                        "type": "toll"
                    },
                    {
                        "country": "US",
                        "country_name": "US",
                        "number": "+1 3052241968",
                        "type": "toll"
                    },
                    {
                        "country": "US",
                        "country_name": "US",
                        "number": "+1 3092053325",
                        "type": "toll"
                    },
                    {
                        "city": "US",
                        "country": "US",
                        "country_name": "US",
                        "number": "+1 3126266799",
                        "type": "toll"
                    }
                ],
                "host_save_video_order": false,
                "host_video": true,
                "in_meeting": false,
                "jbh_time": 0,
                "join_before_host": false,
                "meeting_authentication": false,
                "mute_upon_entry": false,
                "participant_video": false,
                "private_meeting": false,
                "registrants_confirmation_email": true,
                "registrants_email_notification": true,
                "request_permission_to_unmute_participants": false,
                "show_share_button": false,
                "use_pmi": false,
                "waiting_room": false,
                "watermark": false
            },
            "start_time": "2023-01-29T12:12:12Z",
            "start_url": "https://us06web.zoom.us/s/883857?zIjAwMDAwMSIsInptX3NrbSI6InptX28ybSIsImFsZyI6IkhTMjU2In0.eyJhdWQiOiJjbGllbnRzbSIsInVpZCI6InVKaVpOLU83UnA2SnBfOTk1RnBaR2ciLCJpc3MiOiJ3ZWIiLCJzayI6IjczMjU5NTExMTgxNDYyODc0NjciLCJzdHkiOjEwMCwid2NkIjoidXMwNiIsImNsdCI6MCwibW51bSI6Ijg4NDU0MzkzODU3IiwiZXhwIjoxNjczNzkzODcwLCJpYXQiOjE2NzM3ODY2NzAsImFpZCI6ImFlS0QyQkZKUkFTdDFRVlVSV285Q0EiLCJjaWQiOiIifQ.5vRJBkMbmODUD_7H3bkS7OjR-MuuLUzNMJ_KeCzWc_U",
            "status": "waiting",
            "timezone": "Asia/Jerusalem",
            "topic": "test",
            "type": 2,
            "uuid": "4gbib+fjTFmz1wH1LoE7EQ=="
        }
    }
}
```

#### Human Readable Output

>### Meeting details
>
>|uuid|id|host_id|host_email|topic|type|status|start_time|duration|timezone|created_at|start_url|join_url|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 4gbib+fjTFmz1wH1LoE7EQ== | 88454393857 | uJiZN-O7Rp6Jp_995FpZGg | <example@example.com> | test | 2 | waiting | 2023-01-29T12:12:12Z | 60 | Asia/Jerusalem | 2023-01-15T12:44:30Z | <https://us06web.zoom.us/s/88454393857?zak=eyJ0eXAiOiJKV1QiLCJzdiI6IjAwMDAwMSIsInptX3NrbSI6InptX28ybSIsImFsZyI6IkhTMjU2In0.eyJhdWQiOiJjbGllbnRzbSIsInVpZCI6InVKaVpOLU83UnA2SnBfOTk1RnBaR2ciLCJpc3MiOiJ3ZWIiLCJzayI6IjczMjU5NTExMTgxNDYyODc0NjciLCJzdHkiOjEwMCwid2NkIjoidXMwNiIsImNsdCI6MCwibW51bSI6Ijg4NDU0MzkzODU3IiwiZXhwIjoxNjczNzkzODcwLCJpYXQiOjE2NzM3ODY2NzAsImFpZCI6ImFlS0QyQkZKUkFTdDFRVlVSV285Q0EiLCJjaWQiOiIifQ.5vRJBkMbmODUD_7H3bkS7OjR-MuuLUzNMJ_KeCzWc_U> | <https://us06web.zoom.us/j/88454393857?pwd=WkI1WnVEWUdvbHhnMlJuaXU1WDNPdz09> |


### zoom-fetch-recording

***
Get meeting record and save as file in the warroom


#### Base Command

`zoom-fetch-recording`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| meeting_id | Meeting ID of the recorded meeting. | Required | 
| delete_after | Whether to delete the recording from the cloud after downloading. Possible values are: false, true. Default is true. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.SHA256 | Unknown | Attachment's SHA256 | 
| File.SHA1 | Unknown | Attachment's SHA1 | 
| File.MD5 | Unknown | Attachment's MD5 | 
| File.Name | Unknown | Attachment's Name | 
| File.Info | Unknown | Attachment's Info | 
| File.Size | Unknown | Attachment's Size \(In Bytes\) | 
| File.Extension | Unknown | Attachment's Extension | 
| File.Type | Unknown | Attachment's Type | 
| File.EntryID | Unknown | Attachment's EntryID | 
| File.SSDeep | Unknown | Attachment's SSDeep hash | 

#### Command example

```!zoom-fetch-recording meeting_id=83622325727 delete_after=false```

#### Context Example

```json
{
    "File": [
        {
            "EntryID": "446@37e93103-1bd6-4776-8021-0f7023b1bb79",
            "Extension": "MP4",
            "Info": "video/mp4",
            "MD5": "0de01f8f6d037e9ebecde2f91ad9b7a3",
            "Name": "recording_83622325727_d831fbd5-3938-44d0-b30b-962bf76e2916.MP4",
            "SHA1": "c81f9abb6dcf9be42dae99bc5e1501c43496d66e",
            "SHA256": "8b252b01c8e6af62b88de64abf80d360467da1598dcd6b50ac9a252ffafb2eb5",
            "SHA512": "b273e90a9cd0589eaba1c5e647fedab7b46e198193a54bec70a18def9ada57575833ea89b6eabf7f5852c3dc98b862780793d3e87e32a238ec2a7acffdba2495",
            "SSDeep": "1536:TDWnSNbM8oEWzjSn7anYBcoGdee32hfUunvSHx8:T6t8JWzjSWnYBcoG9325UunvSHq",
            "Size": 320333,
            "Type": "ISO Media, MP4 v2 [ISO 14496-14]"
        },
        {
            "EntryID": "447@37e93103-1bd6-4776-8021-0f7023b1bb79",
            "Extension": "M4A",
            "Info": "video/mp4",
            "MD5": "e826111564499ca8021d0ddfcfde064b",
            "Name": "recording_83622325727_19bf5f8a-e77c-4b75-b09e-13983521703c.M4A",
            "SHA1": "50d3386dc5b74935b8f8d541f319df34a49f90a0",
            "SHA256": "2719528cf61358ccbee861fb8e42d9d5fb37390baa22d0dc7dad1aa7e3935146",
            "SHA512": "74bfb40ade824e6e36329b3e2335b2028fac648d3ecef1a02e9be93d4a455e3acf4c1f9c844d1c2ebcc661d4c84d66c1da4f0ca0462eabc12bf2dff84006d460",
            "SSDeep": "24:fctSXvr4S+08n11/TlllZltk2B0tDilduxEJvCXyxrApd4dEcpXuFxnZQ4r:uYr41Xnf/T/vX/8OvqyrjiCuFhZQK",
            "Size": 243652,
            "Type": "ISO Media, MP4 v2 [ISO 14496-14]"
        }
    ]
}
```

#### Human Readable Output

>The Audio file recording_83622325727_19bf5f8a-e77c-4b75-b09e-13983521703c.M4A was downloaded successfully

### zoom-list-users

***
List the existing users


#### Base Command

`zoom-list-users`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | Which status of users to list. Possible values are: active, inactive, pending. Default is active. | Optional | 
| page-size | Number of users to return. Max 300. The default is 30. | Optional | 
| next_page_token | The next page token is used to get the next page. IMPORTANT: You must pass the same page size that you passed in the first call. | Optional | 
| page-number | Which page of results to return. The default = 1. Note: This argument is in a deprecate process by the API. As an alternative use "next_page_token" or "limit".. | Optional | 
| limit | The total amunt of results to show. | Optional | 
| user_id | A user ID. this is for a singel user. | Optional | 
| role_id | Filter the response by a specific role. For example: role_id=0 (Owner), role_id=2 (Member). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zoom.Metadata.Count | number | Total page count available | 
| Zoom.Metadata.Number | number | Current page number | 
| Zoom.Metadata.Size | number | Number of results in current page | 
| Zoom.Metadata.Total | number | Total number of records | 
| Zoom.User.id | string | ID of the user | 
| Zoom.User.first_name | string | First name of user | 
| Zoom.User.last_name | string | Last name of user | 
| Zoom.User.email | string | Email of user | 
| Zoom.User.type | number | Type of user | 
| Zoom.User.created_at | date | Date when user was created | 
| Zoom.User.dept | string | Department for user | 
| Zoom.User.verified | number | Is the user verified | 
| Zoom.User.last_login_time | date | Last login time of the user | 
| Zoom.User.timezone | string | Default timezone for the user | 
| Zoom.User.pmi | string | PMI of user | 
| Zoom.User.group_ids | string | Groups user belongs to | 

#### Command example

```!zoom-list-users status=pending limit=10```

#### Context Example

```json
{
    "Zoom": {
        "Metadata": {
            "Count": 6,
            "Number": 1,
            "Size": 10,
            "Total": 59
        },
        "User": [
            {
                "created_at": "2023-01-15T12:44:34Z",
                "email": "example@example.com",
                "id": "",
                "pmi": 0,
                "role_id": "0",
                "status": "pending",
                "type": 1,
                "user_created_at": "2023-01-02T12:55:33Z",
                "verified": 0
            },
            {
                "created_at": "2023-01-15T12:44:34Z",
                "email": "example@example.com",
                "id": "",
                "pmi": 0,
                "role_id": "0",
                "status": "pending",
                "type": 1,
                "user_created_at": "2023-01-02T13:09:28Z",
                "verified": 0
            },
            {
                "created_at": "2023-01-15T12:44:34Z",
                "email": "example@example.com",
                "id": "",
                "pmi": 0,
                "role_id": "0",
                "status": "pending",
                "type": 1,
                "user_created_at": "2022-12-22T10:19:47Z",
                "verified": 0
            },
            {
                "created_at": "2023-01-15T12:44:34Z",
                "email": "example@example.com",
                "id": "",
                "pmi": 0,
                "role_id": "0",
                "status": "pending",
                "type": 1,
                "user_created_at": "2023-01-02T13:12:46Z",
                "verified": 0
            },
            {
                "created_at": "2023-01-15T12:44:34Z",
                "email": "example@example.com",
                "id": "",
                "pmi": 0,
                "role_id": "0",
                "status": "pending",
                "type": 1,
                "user_created_at": "2023-01-02T12:04:08Z",
                "verified": 0
            },
            {
                "created_at": "2023-01-15T12:44:34Z",
                "email": "example@example.com",
                "id": "",
                "pmi": 0,
                "role_id": "0",
                "status": "pending",
                "type": 1,
                "user_created_at": "2023-01-02T12:56:08Z",
                "verified": 0
            },
            {
                "created_at": "2023-01-15T12:44:34Z",
                "email": "example@example.com",
                "id": "",
                "pmi": 0,
                "role_id": "0",
                "status": "pending",
                "type": 1,
                "user_created_at": "2023-01-02T12:58:16Z",
                "verified": 0
            },
            {
                "created_at": "2023-01-15T12:44:34Z",
                "email": "example@example.com",
                "id": "",
                "pmi": 0,
                "role_id": "0",
                "status": "pending",
                "type": 1,
                "user_created_at": "2023-01-02T13:15:04Z",
                "verified": 0
            },
            {
                "created_at": "2023-01-15T12:44:34Z",
                "email": "example@example.com",
                "id": "",
                "pmi": 0,
                "role_id": "0",
                "status": "pending",
                "type": 1,
                "user_created_at": "2023-01-02T11:58:04Z",
                "verified": 0
            },
            {
                "created_at": "2023-01-15T12:44:34Z",
                "email": "example@example.com",
                "id": "",
                "pmi": 0,
                "role_id": "0",
                "status": "pending",
                "type": 1,
                "user_created_at": "2023-01-02T13:09:52Z",
                "verified": 0
            }
        ]
    }
}
```

#### Human Readable Output

>### Users
>
>|id|email|type|pmi|verified|created_at|status|role_id|
>|---|---|---|---|---|---|---|---|
>|  | <example@example.com> | 1 | 0 | 0 | 2023-01-15T12:44:34Z | pending | 0 |
>|  | <example@example.com> | 1 | 0 | 0 | 2023-01-15T12:44:34Z | pending | 0 |
>|  | <example@example.com> | 1 | 0 | 0 | 2023-01-15T12:44:34Z | pending | 0 |
>|  | <example@example.com> | 1 | 0 | 0 | 2023-01-15T12:44:34Z | pending | 0 |
>|  | <example@example.com> | 1 | 0 | 0 | 2023-01-15T12:44:34Z | pending | 0 |
>|  | <example@example.com> | 1 | 0 | 0 | 2023-01-15T12:44:34Z | pending | 0 |
>|  | <example@example.com> | 1 | 0 | 0 | 2023-01-15T12:44:34Z | pending | 0 |
>|  | <example@example.com> | 1 | 0 | 0 | 2023-01-15T12:44:34Z | pending | 0 |
>|  | <example@example.com> | 1 | 0 | 0 | 2023-01-15T12:44:34Z | pending | 0 |
>|  | <example@example.com> | 1 | 0 | 0 | 2023-01-15T12:44:34Z | pending | 0 |
>
>### Metadata
>
>|total_records|
>|---|
>| 59 |


### zoom-delete-user

***
Delete a user from Zoom


#### Base Command

`zoom-delete-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | The user ID or email to delete. | Required | 
| action | The action to take. Possible values are: disassociate, delete. Default is disassociate. | Optional | 


#### Context Output

There is no context output for this command.

### zoom-meeting-get

***
Get the information of an existing zoom meeting


#### Base Command

`zoom-meeting-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| meeting_id | The id of the existing meeting. | Required | 
| occurrence_id | Provide this field to view meeting details of a particular occurrence of the recurring meeting. | Optional | 
| show_previous_occurrences | Set the value of this field to true if you would like to view meeting details of all previous occurrences of a recurring meeting. Possible values are: false, true. Default is True. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zoom.Meeting.join_url | string | Join url for the meeting | 
| Zoom.Meeting.id | string | Meeting id of the new meeting that is created | 
| Zoom.Meeting.start_url | string | The URL to start the meeting | 
| Zoom.Meeting.uuid | string | Unique meeting ID of the new meeting that is created | 
| Zoom.Meeting.status | string | The status of the meeting | 
| Zoom.Meeting.start_time | Date | The time that the meeting will start at | 
| Zoom.Meeting.host email | string | The email of the host of this meeting | 
| Zoom.Meeting.topic | string | The topic of the meeting | 
| Zoom.Meeting.duration | number | The duratian of the meeting | 
| Zoom.Meeting.created_at | Date | The time that this meeting was created | 
| Zoom.Meeting.type | number | The type of the new meeting, Instant = 1, Scheduled =2,Recurring with fixed time = 8 | 

#### Command example

```!zoom-meeting-get meeting_id=88949894296```

#### Context Example

```json
{
    "Zoom": {
        "Meeting": {
            "agenda": "",
            "assistant_id": "",
            "created_at": "2022-12-29T08:10:13Z",
            "duration": 60,
            "host_email": "example@example.com",
            "host_id": "uJiZN-O7Rp6Jp_995FpZGg",
            "id": 88949894296,
            "join_url": "https://us06web.zoom.us/94296?pwd=b3GdrSDBBNU1FYTVRVmdadz09",
            "pre_schedule": false,
            "settings": {
                "allow_multiple_devices": false,
                "alternative_host_update_polls": false,
                "alternative_hosts": "",
                "alternative_hosts_email_notification": true,
                "approval_type": 2,
                "approved_or_denied_countries_or_regions": {
                    "enable": false
                },
                "audio": "both",
                "auto_recording": "none",
                "breakout_room": {
                    "enable": false
                },
                "close_registration": false,
                "cn_meeting": false,
                "device_testing": false,
                "email_notification": true,
                "enable_dedicated_group_chat": false,
                "encryption_type": "enhanced_encryption",
                "enforce_login": false,
                "enforce_login_domains": "",
                "focus_mode": false,
                "global_dial_in_countries": [
                    "US"
                ],
                "global_dial_in_numbers": [
                    {
                        "country": "US",
                        "country_name": "US",
                        "number": "+1 6469313860",
                        "type": "toll"
                    },
                    {
                        "country": "US",
                        "country_name": "US",
                        "number": "+1 6694449171",
                        "type": "toll"
                    },
                    {
                        "country": "US",
                        "country_name": "US",
                        "number": "+1 6892781000",
                        "type": "toll"
                    },
                    {
                        "country": "US",
                        "country_name": "US",
                        "number": "+1 7193594580",
                        "type": "toll"
                    },
                    {
                        "city": "Denver",
                        "country": "US",
                        "country_name": "US",
                        "number": "+1 7207072699",
                        "type": "toll"
                    },
                    {
                        "country": "US",
                        "country_name": "US",
                        "number": "+1 2532050468",
                        "type": "toll"
                    },
                    {
                        "city": "Tacoma",
                        "country": "US",
                        "country_name": "US",
                        "number": "+1 2532158782",
                        "type": "toll"
                    },
                    {
                        "city": "Washington DC",
                        "country": "US",
                        "country_name": "US",
                        "number": "+1 3017158592",
                        "type": "toll"
                    },
                    {
                        "country": "US",
                        "country_name": "US",
                        "number": "+1 3052241968",
                        "type": "toll"
                    },
                    {
                        "country": "US",
                        "country_name": "US",
                        "number": "+1 3092053325",
                        "type": "toll"
                    },
                    {
                        "city": "US",
                        "country": "US",
                        "country_name": "US",
                        "number": "+1 3126266799",
                        "type": "toll"
                    },
                    {
                        "city": "Houston",
                        "country": "US",
                        "country_name": "US",
                        "number": "+1 3462487799",
                        "type": "toll"
                    },
                    {
                        "country": "US",
                        "country_name": "US",
                        "number": "+1 3602095623",
                        "type": "toll"
                    },
                    {
                        "country": "US",
                        "country_name": "US",
                        "number": "+1 3863475053",
                        "type": "toll"
                    },
                    {
                        "country": "US",
                        "country_name": "US",
                        "number": "+1 5074734847",
                        "type": "toll"
                    },
                    {
                        "country": "US",
                        "country_name": "US",
                        "number": "+1 5642172000",
                        "type": "toll"
                    },
                    {
                        "city": "New York",
                        "country": "US",
                        "country_name": "US",
                        "number": "+1 6465588656",
                        "type": "toll"
                    }
                ],
                "host_save_video_order": false,
                "host_video": true,
                "in_meeting": false,
                "jbh_time": 0,
                "join_before_host": false,
                "meeting_authentication": false,
                "mute_upon_entry": false,
                "participant_video": false,
                "private_meeting": false,
                "registrants_confirmation_email": true,
                "registrants_email_notification": true,
                "request_permission_to_unmute_participants": false,
                "show_share_button": false,
                "use_pmi": false,
                "waiting_room": false,
                "watermark": false
            },
            "start_time": "2022-12-29T12:12:12Z",
            "start_url": "https://us06web.zoom.us/s/88949?zak=eyJ0eXAiOiJKV1QiLCJzdiI6IjAwMDAwMSIsInptX3NrbSI6InVKaVpOLU83UnA2SnBfOTk1RnBaR2ciLCJpc3MiOiJ3ZWIiLCJzayI6IjczMjU5NTExMTgxNDYyODc0NjciLCJzdHkiOjEwMCwid2NkIjoidXMwNiIsImNsdCI6MCwibW51bSI6Ijg4OTQ5ODk0Mjk2IiwiZXhwIjoxNjczNzkzODc2LCJpYXQiOjE2NzM3ODY2NzYsImFpZCI6ImFlS0QyQkZKUkFTdDFRVlVSV285Q0EiLCJjaWQiOiIifQ.BTOeH_-MZRm7A5sACnDJrP_zKbzaDCWZ5orvtH4rVb0",
            "status": "waiting",
            "timezone": "Asia/Jerusalem",
            "topic": "test",
            "type": 2,
            "uuid": "anhEx2x6QWG7TREn71MmoA=="
        }
    }
}
```

#### Human Readable Output

>### Meeting details
>
>|uuid|id|host_id|host_email|topic|type|status|start_time|duration|timezone|agenda|created_at|start_url|join_url|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| anhEx2x6QWG7TREn71MmoA== | 88949894296 | uJiZN-O7Rp6Jp_995FpZGg | <example@example.com> | test | 2 | waiting | 2022-12-29T12:12:12Z | 60 | Asia/Jerusalem |  | 2022-12-29T08:10:13Z | <https://us06web.zoom.us/s/88949894296?zak=eyJ0eXAiOiJKV1QiLCJzdiI6IjAwMDAwMSIsInptX3NrbSI6InptX28ybSIsImFsZyI6IkhTMjU2In0.eyJhdWQiOiJjbGllbnRzbSIsInVpZCI6InVKaVpOLU83UnA2SnBfOTk1RnBaR2ciLCJpc3MiOiJ3ZWIiLCJzayI6IjczMjU5NTExMTgxNDYyODc0NjciLCJzdHkiOjEwMCwid2NkIjoidXMwNiIsImNsdCI6MCwibW51bSI6Ijg4OTQ5ODk0Mjk2IiwiZXhwIjoxNjczNzkzODc2LCJpYXQiOjE2NzM3ODY2NzYsImFpZCI6ImFlS0QyQkZKUkFTdDFRVlVSV285Q0EiLCJjaWQiOiIifQ.BTOeH_-MZRm7A5sACnDJrP_zKbzaDCWZ5orvtH4rVb0> | <https://us06web.zoom.us/j/88949894296?pwd=b3dzT1pzWGdrSDBBNU1FYTVRVmdadz09> |


### zoom-meeting-list

***
Show all the meetings of a given user. Note: only scheduled and unexpired meetings will appear.



#### Base Command

`zoom-meeting-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user ID of the meetings owner. | Required | 
| page_size | Number of users to return. Default = 30. Max = 300. | Optional | 
| page_number | Which page of results to return. The default = 1. Note: This argument is in a deprecate process by the API. As an alternative use "next_page_token" or "limit". | Optional | 
| next_page_token | The next page token is used to paginate te the next page. IMPORTENT: You must pass the same page size that you pased at the first call.. | Optional | 
| limit | The total amunt of results to show. | Optional | 
| type | Filter the results by searching specific types. Possible values are: all, scheduled, live, upcoming, upcoming_meetings, previous_meetings. Default is "scheduled". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zoom.Metadata.Total | number | Total number of records | 
| Zoom.Meeting.page_size | number | The size of the page returned from the API | 
| Zoom.Meeting.total_records | number | The total records in the API for this request. | 
| Zoom.Meeting.join_url | string | Join url for the meeting | 
| Zoom.Meeting.id | string | Meeting id of the new meeting that is created | 
| Zoom.Meeting.start_url | string | The URL to start the meeting | 
| Zoom.Meeting.uuid | string | Unique meeting ID of the new meeting that is created | 
| Zoom.Meeting.status | string | The status of the meeting | 
| Zoom.Meeting.start_time | Date | The time that the meeting will start at | 
| Zoom.Meeting.host email | string | The email of the host of this meeting | 
| Zoom.Meeting.topic | string | The topic of the meeting | 
| Zoom.Meeting.duration | number | The duratian of the meeting | 
| Zoom.Meeting.created_at | Date | The time that this meeting was created | 
| Zoom.Meeting.type | unknown | The ty pe of this meeting | 

#### Command example

```!zoom-meeting-list user_id=example@example.com type=scheduled limit=7```

#### Context Example

```json
{
    "Zoom": {
        "Meeting": {
            "meetings": [
                {
                    "created_at": "2022-12-04T10:41:27Z",
                    "duration": 60,
                    "host_id": "uJiZN-O7Rp6Jp_995FpZGg",
                    "id": 83810397585,
                    "join_url": "https://us06web.zoom.us/j/83810397585?pwd=OGFiZjVvMWZzdDBoaXlLdz09",
                    "start_time": "2022-12-10T11:00:00Z",
                    "timezone": "Asia/Jerusalem",
                    "topic": "2",
                    "type": 8,
                    "uuid": "z93Dc6Kj3jx+zaYg=="
                },
                {
                    "created_at": "2022-12-06T07:59:02Z",
                    "duration": 60,
                    "host_id": "uJiZN-O7Rp6Jp_995FpZGg",
                    "id": 84540166459,
                    "join_url": "https://us06web.zoom.us/j/84540166459?pwd=ZzZaaVpFYlBVYnFoUT09",
                    "start_time": "2022-12-12T08:00:00Z",
                    "timezone": "Asia/Jerusalem",
                    "topic": "My recurring Meeting -Dima",
                    "type": 8,
                    "uuid": "4kZQ+HlFOAz0VBPHoCYg=="
                },
                {
                    "created_at": "2022-12-27T21:05:41Z",
                    "duration": 60,
                    "host_id": "uJiZN-O7Rp6Jp_995FpZGg",
                    "id": 89824497327,
                    "join_url": "https://us06web.zoom.us/j/89824497327?pwd=SWp3b3VDRVhmQT09",
                    "start_time": "2022-12-27T21:05:00Z",
                    "timezone": "Asia/Jerusalem",
                    "topic": "efe",
                    "type": 8,
                    "uuid": "RABXy2D4hA1rgpDgQ=="
                },
                {
                    "created_at": "2022-12-27T21:11:01Z",
                    "duration": 60,
                    "host_id": "uJiZN-O7Rp6Jp_995FpZGg",
                    "id": 83245658341,
                    "join_url": "https://us06web.zoom.us/j/83245658341?pwd=SmNGMHI0RDNkZ2Yms3Zz09",
                    "start_time": "2022-12-27T21:11:00Z",
                    "timezone": "Asia/Jerusalem",
                    "topic": "efe",
                    "type": 8,
                    "uuid": "qOXvloSamJjjFaFgniTA=="
                },
                {
                    "created_at": "2022-12-27T21:25:54Z",
                    "duration": 60,
                    "host_id": "uJiZN-O7Rp6Jp_995FpZGg",
                    "id": 88468901206,
                    "join_url": "https://us06web.zoom.us/j/88468901206?pwd=RXZYQlWCtpS3l1MHUxZz09",
                    "start_time": "2022-12-27T21:25:00Z",
                    "timezone": "Asia/Jerusalem",
                    "topic": "efe",
                    "type": 8,
                    "uuid": "yHzCvl4Sry+C9LnCwdnwQ=="
                },
                {
                    "created_at": "2022-12-28T06:39:48Z",
                    "duration": 60,
                    "host_id": "uJiZN-O7Rp6Jp_995FpZGg",
                    "id": 87525048161,
                    "join_url": "https://us06web.zoom.us/j/87525048161?pwd=ZXlV3U0OUxxSlBkdz09",
                    "start_time": "2022-12-28T06:39:00Z",
                    "timezone": "Asia/Jerusalem",
                    "topic": "efe",
                    "type": 8,
                    "uuid": "Sblh/S1W+rTKUcojJjw=="
                },
                {
                    "created_at": "2022-12-28T06:42:25Z",
                    "duration": 60,
                    "host_id": "uJiZN-O7Rp6Jp_995FpZGg",
                    "id": 83877839723,
                    "join_url": "https://us06web.zoom.us/j/83877839723?pwd=WySkY4Zkc4Zz09",
                    "start_time": "2022-12-28T06:42:00Z",
                    "timezone": "Asia/Jerusalem",
                    "topic": "efe",
                    "type": 8,
                    "uuid": "iLXDe4HsR6uMb+x8GyybTA=="
                }
            ],
            "next_page_token": "N58N4bhqiBFapzndJocx6cc8NKr2",
            "page_size": 7,
            "total_records": 60
        },
        "Metadata": {
            "Size": 7,
            "Total": 60
        }
    }
}
```

#### Human Readable Output

>### Meeting list
>
>|uuid|id|host_id|topic|type|start time|duration|timezone|created_at|join_url|
>|---|---|---|---|---|---|---|---|---|---|
>| z93Dc6KjSo20Wr3jx+zaYg== | 83810397585 | uJiZN-O7Rp6Jp_995FpZGg | 2 | 8 |  | 60 | Asia/Jerusalem | 2022-12-04T10:41:27Z | <https://us06web.zoom.us/j/83810397585?pwd=OGFiZjRYNGhwWkVvMWZzdDBoaXlLdz09> |
>| 4kZQ+Hl2RFOAz0VBPHoCYg== | 84540166459 | uJiZN-O7Rp6Jp_995FpZGg | My recurring Meeting -Dima | 8 |  | 60 | Asia/Jerusalem | 2022-12-06T07:59:02Z | <https://us06web.zoom.us/j/84540166459?pwd=ZzdmUEJ5QkZaaUZaaVpFYlBVYnFoUT09> |
>| RABXyk81T02D4hA1rgpDgQ== | 89824497327 | uJiZN-O7Rp6Jp_995FpZGg | efe | 8 |  | 60 | Asia/Jerusalem | 2022-12-27T21:05:41Z | <https://us06web.zoom.us/j/89824497327?pwd=SWpvK0I0L3pQcTNnWlF3b3VDRVhmQT09> |
>| qOXvlLOoSamJjjFaFgniTA== | 83245658341 | uJiZN-O7Rp6Jp_995FpZGg | efe | 8 |  | 60 | Asia/Jerusalem | 2022-12-27T21:11:01Z | <https://us06web.zoom.us/j/83245658341?pwd=SmNGMHI0R1hndnNlRXRDNkZ2Yms3Zz09> |
>| yHzCvl4USry+C9LnCwdnwQ== | 88468901206 | uJiZN-O7Rp6Jp_995FpZGg | efe | 8 |  | 60 | Asia/Jerusalem | 2022-12-27T21:25:54Z | <https://us06web.zoom.us/j/88468901206?pwd=RXZYQlhVbWJKZ1pLWCtpS3l1MHUxZz09> |
>| Sblh/I34S1W+rTKUcojJjw== | 87525048161 | uJiZN-O7Rp6Jp_995FpZGg | efe | 8 |  | 60 | Asia/Jerusalem | 2022-12-28T06:39:48Z | <https://us06web.zoom.us/j/87525048161?pwd=ZXlXdXl0QWlLOFVyV3U0OUxxSlBkdz09> |
>| iLXDe4HsR6uMb+x8GyybTA== | 83877839723 | uJiZN-O7Rp6Jp_995FpZGg | efe | 8 |  | 60 | Asia/Jerusalem | 2022-12-28T06:42:25Z | <https://us06web.zoom.us/j/83877839723?pwd=WU9xNmp5RW5KRDhsZ1RySkY4Zkc4Zz09> |
>
>### Metadata
>
>|total_records|
>|---|
>| 60 |

#### Command example

```!zoom-list-account-public-channels```

#### Context Example

```json
{
    "Zoom": {
        "Channel": {
            "channels": [
                {
                    "channel_settings": {
                        "add_member_permissions": 1,
                        "allow_to_add_external_users": 0,
                        "mention_all_permissions": 1,
                        "new_members_can_see_previous_messages_files": true,
                        "posting_permissions": 1
                    },
                    "id": "f7ce414a24634240ae0a7894823d8707",
                    "jid": "f7ce414a24634240ae0a7894823d8707@conference.xmpp.zoom.us",
                    "name": "Channel1",
                    "type": 3
                },
                {
                    "channel_settings": {
                        "add_member_permissions": 1,
                        "allow_to_add_external_users": 0,
                        "mention_all_permissions": 1,
                        "new_members_can_see_previous_messages_files": true,
                        "posting_permissions": 1
                    },
                    "id": "e82e99ac9b0c40b08449c76766cf398d",
                    "jid": "e82e99ac9b0c40b08449c76766cf398d@conference.xmpp.zoom.us",
                    "name": "Channel2",
                    "type": 3
                },
                {
                    "channel_settings": {
                        "add_member_permissions": 1,
                        "allow_to_add_external_users": 0,
                        "mention_all_permissions": 1,
                        "new_members_can_see_previous_messages_files": false,
                        "posting_permissions": 1
                    },
                    "id": "e7e2c5e1ba854056906af1c9dc36148f",
                    "jid": "e7e2c5e1ba854056906af1c9dc36148f@conference.xmpp.zoom.us",
                    "name": "Channel3",
                    "type": 3
                },
                {
                    "channel_settings": {
                        "add_member_permissions": 2,
                        "allow_to_add_external_users": 0,
                        "mention_all_permissions": 1,
                        "new_members_can_see_previous_messages_files": true,
                        "posting_permissions": 1
                    },
                    "id": "e6388c9667c245c3844009ae995664d5",
                    "jid": "e6388c9667c245c3844009ae995664d5@conference.xmpp.zoom.us",
                    "name": "Channel4",
                    "type": 3
                }
            ],
            "next_page_token": "",
            "page_size": 20,
            "total_records": 4
        },
        "ChannelsNextToken": ""
    }
}
```

#### Human Readable Output

>### Channels
>
>|Channel ID|Channel JID|Channel name|Channel type|
>|---|---|---|---|
>| f7ce414a24634240ae0a7894823d8707 | <f7ce414a24634240ae0a7894823d8707@conference.xmpp.zoom.us> | Channel1 | 3 |
>| e82e99ac9b0c40b08449c76766cf398d | <e82e99ac9b0c40b08449c76766cf398d@conference.xmpp.zoom.us> | Channel2 | 3 |
>| e7e2c5e1ba854056906af1c9dc36148f | <e7e2c5e1ba854056906af1c9dc36148f@conference.xmpp.zoom.us> | channel3 | 3 |
>| e6388c9667c245c3844009ae995664d5 | <e6388c9667c245c3844009ae995664d5@conference.xmpp.zoom.us> | Channel4 | 3 |


### zoom-list-user-channels

***
List the existing channels

#### Base Command

`zoom-list-user-channels`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page-size | Number of channels to return. Max 300. The default is 50. | Optional | 
| next_page_token | The next page token is used to get the next page. IMPORTANT: You must pass the same page size that you passed in the first call. | Optional | 
| page-number | Which page of results to return. The default = 1. Note: This argument is in a deprecate process by the API. As an alternative use "next_page_token" or "limit". | Optional | 
| limit | The total amunt of results to show. | Optional | 
| channel_id | A channel ID. This is for a single channel. | Optional | 
| user_id | A user ID. This is for a single user. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zoom.Channel.id | string | The ID of the created channel. | 
| Zoom.Channel.name | string | The name of the created channel. | 
| Zoom.Channel.type | string | The created channel type. | 
| Zoom.Channel.url | string | The created channel URL. | 

#### Command example

```!zoom-list-user-channels user_id=uJiZN-O7Rp6Jp_995FpZGg channel_id=88f2f20f4abd415cba2429538be58025```

#### Context Example

```json
{
    "Zoom": {
        "Channel": {
            "channel_settings": {
                "add_member_permissions": 1,
                "allow_to_add_external_users": 0,
                "mention_all_permissions": 1,
                "new_members_can_see_previous_messages_files": true,
                "posting_permissions": 1
            },
            "channel_url": "https://us06web.zoom.us/launch/chat/v2/eyJzaWQiOiI4OGYyZjIwZjRhYmQ0MTVjYmEyNDI5NTM4YmU1ODAyNUBjb25mZXJlbmNlLnhtcHAuem9vbS51cyJ9",
            "id": "88f2f20f4abd415cba2429538be58025",
            "jid": "88f2f20f4abd415cba2429538be58025@conference.xmpp.zoom.us",
            "name": "Channel-Updated5",
            "type": 3
        },
        "UserChannelsNextToken": null
    }
}
```

#### Human Readable Output

>### Channels
>
>|Channel ID|Channel name|Channel type|Channel url|User id|channel JID|
>|---|---|---|---|---|---|
>| 88f2f20f4abd415cba2429538be58025 | Channel-Updated5 | 3 | <https://us06web.zoom.us/launch/chat/v2/eyJzaWQiOiI4OGYyZjIwZjRhYmQ0MTVjYmEyNDI5NTM4YmU1ODAyNUBjb25mZXJlbmNlLnhtcHAuem9vbS51cyJ9> | uJiZN-O7Rp6Jp_995FpZGg | <88f2f20f4abd415cba2429538be58025@conference.xmpp.zoom.us> |


#### Command example

```!zoom-list-user-channels user_id=uJiZN-O7Rp6Jp_995FpZGg```

#### Context Example

```json
{
    "Zoom": {
        "Channel": {
            "channels": [
                {
                    "channel_settings": {
                        "add_member_permissions": 1,
                        "allow_to_add_external_users": 0,
                        "mention_all_permissions": 1,
                        "new_members_can_see_previous_messages_files": false,
                        "posting_permissions": 1
                    },
                    "channel_url": "https://us06web.zoom.us/launch/chat/v2/eyJzaWQiOiJlN2UyYzVlMWJhODU0MDU2OTA2YWYxYzlkYzM2MTQ4ZkBjb25mZXJlbmNlLnhtcHAuem9vbS51cyJ9",
                    "id": "e7e2c5e1ba854056906af1c9dc36148f",
                    "jid": "e7e2c5e1ba854056906af1c9dc36148f@conference.xmpp.zoom.us",
                    "name": "TestChannel1",
                    "type": 3
                },
                {
                    "channel_settings": {
                        "add_member_permissions": 1,
                        "allow_to_add_external_users": 0,
                        "mention_all_permissions": 1,
                        "new_members_can_see_previous_messages_files": true,
                        "posting_permissions": 1
                    },
                    "channel_url": "https://us06web.zoom.us/launch/chat/v2/eyJzaWQiOiI3ODI4YTFiMjgzYmQ0MjYxOTkwOTRlNWVhMGFhOTM1M0Bjb25mZXJlbmNlLnhtcHAuem9vbS51cyJ9",
                    "id": "7828a1b283bd426199094e5ea0aa9353",
                    "jid": "7828a1b283bd426199094e5ea0aa9353@conference.xmpp.zoom.us",
                    "name": "Channel",
                    "type": 3
                },
                {
                    "channel_settings": {
                        "add_member_permissions": 1,
                        "allow_to_add_external_users": 0,
                        "mention_all_permissions": 1,
                        "new_members_can_see_previous_messages_files": true,
                        "posting_permissions": 1
                    },
                    "channel_url": "https://us06web.zoom.us/launch/chat/v2/eyJzaWQiOiIwOGE0OWVmY2I5YTA0N2MzYmU5NWMwNDc4NzI1NjJjZkBjb25mZXJlbmNlLnhtcHAuem9vbS51cyJ9",
                    "id": "08a49efcb9a047c3be95c047872562cf",
                    "jid": "08a49efcb9a047c3be95c047872562cf@conference.xmpp.zoom.us",
                    "name": "DemoChannel-Updated",
                    "type": 3
                },
                {
                    "channel_settings": {
                        "add_member_permissions": 1,
                        "allow_to_add_external_users": 0,
                        "mention_all_permissions": 1,
                        "new_members_can_see_previous_messages_files": false,
                        "posting_permissions": 1
                    },
                    "channel_url": "https://us06web.zoom.us/launch/chat/v2/eyJzaWQiOiI5MmIwMjY4YWFmOGQ0MDM5OTQ4YjE3ZDc4M2IwODE5OEBjb25mZXJlbmNlLnhtcHAuem9vbS51cyJ9",
                    "id": "92b0268aaf8d4039948b17d783b08198",
                    "jid": "92b0268aaf8d4039948b17d783b08198@conference.xmpp.zoom.us",
                    "name": "TestGroupChannel1",
                    "type": 3
                },
                {
                    "channel_settings": {
                        "add_member_permissions": 1,
                        "allow_to_add_external_users": 0,
                        "mention_all_permissions": 1,
                        "new_members_can_see_previous_messages_files": true,
                        "posting_permissions": 1
                    },
                    "channel_url": "https://us06web.zoom.us/launch/chat/v2/eyJzaWQiOiIzZDRjZjFiNDkzNDk0NGFkODM5YzEwOWJhYWM5MzEyNkBjb25mZXJlbmNlLnhtcHAuem9vbS51cyJ9",
                    "id": "3d4cf1b4934944ad839c109baac93126",
                    "jid": "3d4cf1b4934944ad839c109baac93126@conference.xmpp.zoom.us",
                    "name": "Admins1",
                    "type": 2
                },
                {
                    "channel_settings": {
                        "add_member_permissions": 1,
                        "allow_to_add_external_users": 0,
                        "mention_all_permissions": 1,
                        "new_members_can_see_previous_messages_files": true,
                        "posting_permissions": 1
                    },
                    "channel_url": "https://us06web.zoom.us/launch/chat/v2/eyJzaWQiOiJlODJlOTlhYzliMGM0MGIwODQ0OWM3Njc2NmNmMzk4ZEBjb25mZXJlbmNlLnhtcHAuem9vbS51cyJ9",
                    "id": "e82e99ac9b0c40b08449c76766cf398d",
                    "jid": "e82e99ac9b0c40b08449c76766cf398d@conference.xmpp.zoom.us",
                    "name": "Admins_to_delete_2",
                    "type": 3
                },
                {
                    "channel_settings": {
                        "add_member_permissions": 1,
                        "allow_to_add_external_users": 0,
                        "mention_all_permissions": 1,
                        "new_members_can_see_previous_messages_files": true,
                        "posting_permissions": 1
                    },
                    "channel_url": "https://us06web.zoom.us/launch/chat/v2/eyJzaWQiOiIwZWJlNzEwMDNlYjI0ZjVmODU3N2U1YTEyNGYwNjQyOEBjb25mZXJlbmNlLnhtcHAuem9vbS51cyJ9",
                    "id": "0ebe71003eb24f5f8577e5a124f06428",
                    "jid": "0ebe71003eb24f5f8577e5a124f06428@conference.xmpp.zoom.us",
                    "name": "Admins_to_delete_2_updated",
                    "type": 3
                },
                {
                    "channel_settings": {
                        "add_member_permissions": 1,
                        "allow_to_add_external_users": 1,
                        "mention_all_permissions": 1,
                        "new_members_can_see_previous_messages_files": true,
                        "posting_permissions": 1
                    },
                    "channel_url": "https://us06web.zoom.us/launch/chat/v2/eyJzaWQiOiIyZTk5YTdlMDdkZTA0ZjUyYmYyYzQ0OGNkMmIxNTFmY0Bjb25mZXJlbmNlLnhtcHAuem9vbS51cyJ9",
                    "id": "2e99a7e07de04f52bf2c448cd2b151fc",
                    "jid": "2e99a7e07de04f52bf2c448cd2b151fc@conference.xmpp.zoom.us",
                    "name": "BotChannel",
                    "type": 5
                },
                {
                    "channel_settings": {
                        "add_member_permissions": 1,
                        "allow_to_add_external_users": 0,
                        "mention_all_permissions": 1,
                        "new_members_can_see_previous_messages_files": true,
                        "posting_permissions": 1
                    },
                    "channel_url": "https://us06web.zoom.us/launch/chat/v2/eyJzaWQiOiJiMThkMTUxNDBjMjU0NTQ5YTgwYWY2NTcyYjNiNTUyZUBjb25mZXJlbmNlLnhtcHAuem9vbS51cyJ9",
                    "id": "b18d15140c254549a80af6572b3b552e",
                    "jid": "b18d15140c254549a80af6572b3b552e@conference.xmpp.zoom.us",
                    "name": "ChannelName",
                    "type": 3
                },
                {
                    "channel_settings": {
                        "add_member_permissions": 1,
                        "allow_to_add_external_users": 0,
                        "mention_all_permissions": 1,
                        "new_members_can_see_previous_messages_files": true,
                        "posting_permissions": 1
                    },
                    "channel_url": "https://us06web.zoom.us/launch/chat/v2/eyJzaWQiOiIzNjQxYzNmZGMxZGM0Zjc4OGU4ZWIzNDA3YTQwYzQ3MkBjb25mZXJlbmNlLnhtcHAuem9vbS51cyJ9",
                    "id": "3641c3fdc1dc4f788e8eb3407a40c472",
                    "jid": "3641c3fdc1dc4f788e8eb3407a40c472@conference.xmpp.zoom.us",
                    "name": "Admins",
                    "type": 2
                },
                {
                    "channel_settings": {
                        "add_member_permissions": 1,
                        "allow_to_add_external_users": 0,
                        "mention_all_permissions": 1,
                        "new_members_can_see_previous_messages_files": true,
                        "posting_permissions": 1
                    },
                    "channel_url": "https://us06web.zoom.us/launch/chat/v2/eyJzaWQiOiJmN2NlNDE0YTI0NjM0MjQwYWUwYTc4OTQ4MjNkODcwN0Bjb25mZXJlbmNlLnhtcHAuem9vbS51cyJ9",
                    "id": "f7ce414a24634240ae0a7894823d8707",
                    "jid": "f7ce414a24634240ae0a7894823d8707@conference.xmpp.zoom.us",
                    "name": "TestChannel3",
                    "type": 3
                }
            ],
            "next_page_token": "",
            "page_size": 50,
            "total_records": 11
        },
        "UserChannelsNextToken": ""
    }
}
```

#### Human Readable Output

>### Channels
>
>|Channel ID|Channel name|Channel type|Channel url|User id|channel JID|
>|---|---|---|---|---|---|
>| e7e2c5e1ba854056906af1c9dc36148f | TestChannel1 | 3 | <https://us06web.zoom.us/launch/chat/v2/eyJzaWQiOiJlN2UyYzVlMWJhODU0MDU2OTA2YWYxYzlkYzM2MTQ4ZkBjb25mZXJlbmNlLnhtcHAuem9vbS51cyJ9> | uJiZN-O7Rp6Jp_995FpZGg | <e7e2c5e1ba854056906af1c9dc36148f@conference.xmpp.zoom.us> |
>| 7828a1b283bd426199094e5ea0aa9353 | Channel | 3 | <https://us06web.zoom.us/launch/chat/v2/eyJzaWQiOiI3ODI4YTFiMjgzYmQ0MjYxOTkwOTRlNWVhMGFhOTM1M0Bjb25mZXJlbmNlLnhtcHAuem9vbS51cyJ9> | uJiZN-O7Rp6Jp_995FpZGg | <7828a1b283bd426199094e5ea0aa9353@conference.xmpp.zoom.us> |
>| 08a49efcb9a047c3be95c047872562cf | DemoChannel-Updated | 3 | <https://us06web.zoom.us/launch/chat/v2/eyJzaWQiOiIwOGE0OWVmY2I5YTA0N2MzYmU5NWMwNDc4NzI1NjJjZkBjb25mZXJlbmNlLnhtcHAuem9vbS51cyJ9> | uJiZN-O7Rp6Jp_995FpZGg | <08a49efcb9a047c3be95c047872562cf@conference.xmpp.zoom.us> |
>| 92b0268aaf8d4039948b17d783b08198 | TestGroupChannel1 | 3 | <https://us06web.zoom.us/launch/chat/v2/eyJzaWQiOiI5MmIwMjY4YWFmOGQ0MDM5OTQ4YjE3ZDc4M2IwODE5OEBjb25mZXJlbmNlLnhtcHAuem9vbS51cyJ9> | uJiZN-O7Rp6Jp_995FpZGg | <92b0268aaf8d4039948b17d783b08198@conference.xmpp.zoom.us> |
>| 3d4cf1b4934944ad839c109baac93126 | Admins1 | 2 | <https://us06web.zoom.us/launch/chat/v2/eyJzaWQiOiIzZDRjZjFiNDkzNDk0NGFkODM5YzEwOWJhYWM5MzEyNkBjb25mZXJlbmNlLnhtcHAuem9vbS51cyJ9> | uJiZN-O7Rp6Jp_995FpZGg | <3d4cf1b4934944ad839c109baac93126@conference.xmpp.zoom.us> |
>| e82e99ac9b0c40b08449c76766cf398d | Admins_to_delete_2 | 3 | <https://us06web.zoom.us/launch/chat/v2/eyJzaWQiOiJlODJlOTlhYzliMGM0MGIwODQ0OWM3Njc2NmNmMzk4ZEBjb25mZXJlbmNlLnhtcHAuem9vbS51cyJ9> | uJiZN-O7Rp6Jp_995FpZGg | <e82e99ac9b0c40b08449c76766cf398d@conference.xmpp.zoom.us> |
>| 0ebe71003eb24f5f8577e5a124f06428 | Admins_to_delete_2_updated | 3 | <https://us06web.zoom.us/launch/chat/v2/eyJzaWQiOiIwZWJlNzEwMDNlYjI0ZjVmODU3N2U1YTEyNGYwNjQyOEBjb25mZXJlbmNlLnhtcHAuem9vbS51cyJ9> | uJiZN-O7Rp6Jp_995FpZGg | <0ebe71003eb24f5f8577e5a124f06428@conference.xmpp.zoom.us> |
>| 2e99a7e07de04f52bf2c448cd2b151fc | BotChannel | 5 | <https://us06web.zoom.us/launch/chat/v2/eyJzaWQiOiIyZTk5YTdlMDdkZTA0ZjUyYmYyYzQ0OGNkMmIxNTFmY0Bjb25mZXJlbmNlLnhtcHAuem9vbS51cyJ9> | uJiZN-O7Rp6Jp_995FpZGg | <2e99a7e07de04f52bf2c448cd2b151fc@conference.xmpp.zoom.us> |
>| b18d15140c254549a80af6572b3b552e | ChannelName | 3 | <https://us06web.zoom.us/launch/chat/v2/eyJzaWQiOiJiMThkMTUxNDBjMjU0NTQ5YTgwYWY2NTcyYjNiNTUyZUBjb25mZXJlbmNlLnhtcHAuem9vbS51cyJ9> | uJiZN-O7Rp6Jp_995FpZGg | <b18d15140c254549a80af6572b3b552e@conference.xmpp.zoom.us> |
>| 3641c3fdc1dc4f788e8eb3407a40c472 | Admins | 2 | <https://us06web.zoom.us/launch/chat/v2/eyJzaWQiOiIzNjQxYzNmZGMxZGM0Zjc4OGU4ZWIzNDA3YTQwYzQ3MkBjb25mZXJlbmNlLnhtcHAuem9vbS51cyJ9> | uJiZN-O7Rp6Jp_995FpZGg | <3641c3fdc1dc4f788e8eb3407a40c472@conference.xmpp.zoom.us> |
>| f7ce414a24634240ae0a7894823d8707 | TestChannel3 | 3 | <https://us06web.zoom.us/launch/chat/v2/eyJzaWQiOiJmN2NlNDE0YTI0NjM0MjQwYWUwYTc4OTQ4MjNkODcwN0Bjb25mZXJlbmNlLnhtcHAuem9vbS51cyJ9> | uJiZN-O7Rp6Jp_995FpZGg | <f7ce414a24634240ae0a7894823d8707@conference.xmpp.zoom.us> |


### zoom-create-channel

***
Creates a channel for a user

#### Base Command

`zoom-create-channel`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user's unique identifier. | Required | 
| member_emails | The member(s) to include in the channel. A maximum of 20 members can be added to the channel at once with this API. | Required | 
| add_member_permissions | Who can add new channel members: * 1 - All channel members can add new members. * 2 - Only channel owner and administrators can add new members. Note: This setting can only be modified by the channel owner. Default: 1. 
| posting_permissions | The channel members' posting permissions: * 1 — All chat channel members can post to the channel. * 2 — Only the channel owner and administrators can post to the channel. * 3 — Only the channel owner, administrators and certain members can post to the channel. Default: 1. | Optional | 
| new_members_can_see_prev_msgs | Whether new channel members can view messages and files previously posted in the channel. Possible values are: true, false. Default is True. | Optional | 
| channel_name | The name of the channel. Maximum of 128 characters. | Required | 
| channel_type | The type of the channel. The value can be one of the following: 1: Private channel. In this type of channel, members must be invited to join a channel. 2: Private channel with members that belong to one Zoom account. Members in this channel should be invited and the members should be from the same organization. 3: Public channel. Anyone can search for this channel and join the channel. 4: New chat. This is an instant channel which can be created by adding members to a new chat. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zoom.Channel.id | string | the channel's unique identifier. | 
| Zoom.Channel.jid | string | The channel JID. | 
| Zoom.Channel.name | string | The channel name. | 
| Zoom.Channel.type | string | The type of the channel. The value can be one of the following: 1: Private channel. In this type of channel, members must be invited to join a channel. 2: Private channel with members that belong to one Zoom account. Members in this channel should be invited and the members should be from the same organization. 3: Public channel. Anyone can search for this channel and join the channel. 4: Group chat. This is an instant channel which can be created by adding members to a new chat. 
 | 
| Zoom.Channel.url | string | The URL of the Zoom chat channel. | 

#### Command example

```!zoom-create-channel user_id=uJiZN-O7Rp6Jp_995FpZGg member_emails=example@example.com channel_name=ChannelName channel_type="Public channel"```

#### Context Example

```json
{
    "Zoom": {
        "Channel": {
            "channel_url": "https://us06web.zoom.us/launch/chat/v2/eyJzaWQiOiJiMThkMTUxNDBjMjU0NTQ5YTgwYWY2NTcyYjNiNTUyZUBjb25mZXJlbmNlLnhtcHAuem9vbS51cyJ9",
            "id": "b18d15140c254549a80af6572b3b552e",
            "jid": "b18d15140c254549a80af6572b3b552e@conference.xmpp.zoom.us",
            "name": "ChannelName",
            "type": 3
        }
    }
}
```

#### Human Readable Output

>### Channel details
>
>|Channel ID|Channel name|Channel type|Channel url|User id|
>|---|---|---|---|---|
>| b18d15140c254549a80af6572b3b552e | ChannelName | 3 | <https://us06web.zoom.us/launch/chat/v2/eyJzaWQiOiJiMThkMTUxNDBjMjU0NTQ5YTgwYWY2NTcyYjNiNTUyZUBjb25mZXJlbmNlLnhtcHAuem9vbS51cyJ9> | uJiZN-O7Rp6Jp_995FpZGg |


### zoom-delete-channel

***
Deletes a specific Zoom channel

#### Base Command

`zoom-delete-channel`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| channel_id | Unique identifier of a channel. | Required | 
| user_id | User unique identifier. | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!zoom-delete-channel user_id=uJiZN-O7Rp6Jp_995FpZGg channel_id=88f2f20f4abd415cba2429538be58025```

#### Human Readable Output

>Channel 88f2f20f4abd415cba2429538be58025 was deleted successfully

### zoom-update-channel

***
Update an existing channel in a Zoom account.

#### Base Command

`zoom-update-channel`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| channel_id | The channel ID. | Required | 
| user_id | User unique identifier. | Required | 
| add_member_permissions | Who can add new channel members: * 1 - All channel members can add new members. * 2 - Only channel owner and administrators can add new members. Note: This setting can only be modified by the channel owner. | Optional | 
| posting_permissions | The channel members' posting permissions: * 1 — All chat channel members can post to the channel. * 2 — Only the channel owner and administrators can post to the channel. * 3 — Only the channel owner, administrators and certain members can post to the channel. | Optional | 
| new_members_can_see_prev_msgs | Whether new channel members can view messages and files previously posted in the channel. Possible values are: true, false. Default is True. | Optional | 
| channel_name | A new name for the channel. | Optional | 

#### Context Output

There is no context output for this command.

#### Command example

```!zoom-update-channel user_id=uJiZN-O7Rp6Jp_995FpZGg channel_name=Channel-Updated5 channel_id=88f2f20f4abd415cba2429538be58025```

#### Human Readable Output

>Channel 88f2f20f4abd415cba2429538be58025 was updated successfully

### zoom-invite-to-channel

***
Invites members that are in a user's contact list to a channel. A channel can have one or multiple members. The maximum number of members that can be added at once with this API is 5.


#### Base Command

`zoom-invite-to-channel`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| channel_id | The channel's unique identifier. | Required | 
| user_id | User unique identifier. | Required | 
| members | The member's email address. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zoom.Channel.ids | string | A comma-separated list of user IDs of the members added to the channel.  User IDs of those who are not from the same account will be omitted from the list.
 | 
| Zoom.Channel.added_at | string | The date and time when the members are added to the channel. | 
| Zoom.Channel.member_ids | string | A comma-separated list of member IDs of the members added to the channel. | 

#### Command example

```!zoom-invite-to-channel user_id=uJiZN-O7Rp6Jp_995FpZGg members=example@example.com channel_id=88f2f20f4abd415cba2429538be58025```

#### Context Example

```json
{
    "Zoom": {
        "Channel": {
            "added_at": "2023-05-22T08:36:57Z",
            "ids": "pq0t1uvlrqmi_p_-cg2ugq",
            "member_ids": "1vqMC-BQdfok1tpAnSw8OT6FtcMiXBaUPNoRhTIzcvJjtbxgPXQRLmDm-10C2Ggg"
        }
    }
}
```

#### Human Readable Output

>### Channel details
>
>|Added at date and time|Channel ID|User id|
>|---|---|---|
>| 2023-05-22T08:36:57Z | 88f2f20f4abd415cba2429538be58025 | pq0t1uvlrqmi_p_-cg2ugq |


### zoom-remove-from-channel

***
Removes a member from a chat channel. A channel can have one or more members.

#### Base Command

`zoom-remove-from-channel`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| channel_id | The unique identifier of the channel from where you would like to remove a member. | Required | 
| user_id | User unique identifier. | Required | 
| member_id | The email address or user ID or member ID of the member to remove from the channel. | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!zoom-remove-from-channel user_id=uJiZN-O7Rp6Jp_995FpZGg member_id=example@example.com channel_id=88f2f20f4abd415cba2429538be58025```

#### Human Readable Output

>Member <example@example.com> was successfully removed from channel 88f2f20f4abd415cba2429538be58025

### zoom-send-file

***
Sends a file on Zoom to either an individual user in your contact list or a channel of which you are a member.

#### Base Command

`zoom-send-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| to_channel | The channel ID of the channel to which to send the chat file. | Optional | 
| user_id | The user's ID. | Required | 
| to_contact | The user ID or member ID of the contact to send the chat file. | Optional | 
| entry_id | Cortex XSOAR internal file ID. | Required | 

#### Context Output

There is no context output for this command.

### zoom-send-message

***
Sends chat messages on Zoom to either an individual user who is in your contact list or to a channel of which you are a member.

#### Base Command

`zoom-send-message`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | Unique identifier of the user. | Required | 
| at_contact |  Email address of the mention contact. | Optional | 
| is_markdown | if a markdown message provide in the message argument| Optional
| message | The message to be sent. Maximum of 1024 characters. | Required | 
| entry_ids | A list of the file IDs to send. This field only accepts a maximum of six file IDs.  | Optional | 
| reply_main_message_id | The reply message's ID. This field only returns if the message is a reply message. | Optional | 
| to_channel | The channel ID of the channel to send a message. | Optional | 
| to_contact | The email address or user ID or member ID of the person to send a message. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zoom.ChatMessage.id | number | Unique identifier of the message. | 

#### Command example

```!zoom-send-message user_id=uJiZN-O7Rp6Jp_995FpZGg message="message" to_contact=example@example.com```

#### Context Example

```json
{
    "Zoom": {
        "ChatMessage": {
            "id": "7df8cc5b-efc4-4e08-9083-9823b8871c82"
        }
    }
}
```

#### Human Readable Output

>### Message
>
>|Contact|Message ID|
>|---|---|
>| <example@example.com> | 7df8cc5b-efc4-4e08-9083-9823b8871c82 |


### zoom-delete-message

***
Deletes a chat message previously sent to a contact or a channel.

#### Base Command

`zoom-delete-message`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | Unique identifier of the user. | Required | 
| message_id | Unique identifier of the message. | Required | 
| to_channel | The channel ID where the message was sent. You must provide this parameter or the to_contact parameter. | Optional | 
| to_contact | The member ID or user ID or email address of a chat contact to whom the message was sent.  You must provide this parameter or the to_channel parameter. | Optional | 

#### Context Output

There is no context output for this command.

#### Command example

```!zoom-delete-message user_id=uJiZN-O7Rp6Jp_995FpZGg to_contact=example@example.com message_id=4a59df4a-9668-46bd-bff2-3e1f3462ecc3```

#### Human Readable Output

>Message 4a59df4a-9668-46bd-bff2-3e1f3462ecc3 was deleted successfully

### zoom-update-message

***
Edits a chat message that you previously sent to either a contact or a channel in Zoom by providing the ID of the message as the value of the messageId parameter.  As a query parameter, you must provide either the contact's email address or the Channel ID of the channel where the message was sent.


#### Base Command

`zoom-update-message`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | Unique identifier of the user. | Required | 
| message_id | Unique identifier of the message. | Required | 
| message | The edited message. | Required | 
| to_channel | The channel ID of the channel where you sent the message. You must provide either to_contact or to_channel parameter in the API request. Channel ID can be retrieved from List User's Channels API. | Optional | 
| to_contact | The email address or user ID or member ID of the contact to whom the message was sent.  You must provide either this parameter or the to_channel parameter in the API request. | Optional | 
| entry_ids | A list of Cortex XSOAR file entry IDs to send. | Optional | 

#### Context Output

There is no context output for this command.

#### Command example

```!zoom-update-message user_id=uJiZN-O7Rp6Jp_995FpZGg message="message2" to_contact=example@example.com message_id=4a59df4a-9668-46bd-bff2-3e1f3462ecc3```

#### Human Readable Output

>Message 4a59df4a-9668-46bd-bff2-3e1f3462ecc3 was successfully updated

### zoom-list-messages

***
Searches chat messages or shared files between a user and an individual contact or a chat channel. 


#### Base Command

`zoom-list-messages`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | Unique identifier of the user. | Required | 
| to_contact | This field allows you to query by the email address or user ID or member ID of a chat contact with whom the user communicated. The API only returns messages sent and/or received between the user and the queried contact. | Optional | 
| to_channel | This field queries by the channel ID of a channel in which the user had chat conversations. The API only returns messages sent and/or received by the user in the queried channel. | Optional | 
| date | The query date from which to retrieve the chat messages. This value defaults to the current date. Format %Y-%m-%dT%H:%M:%S.. | Optional | 
| from | Start date. Format %Y-%m-%dT%H:%M:%S. | Optional | 
| to | End date. Format %Y-%m-%dT%H:%M:%S. | Optional | 
| include_deleted_and_edited_message | Whether to include deleted and edited messages. Default false. | Optional | 
| search_type | The type of search: message — Search messages. file — Search files.. Possible values are: message, file. | Optional | 
| search_key | Key for search in messages. | Optional | 
| exclude_child_message |  Whether to exclude returning all child messages in a chat, leaving only the parent messages.  Default: false. | Optional | 
| next_page_token | The next page token paginates through a large set of results. A next page token is returned whenever the set of available results exceeds the current page size. This token's expiration period is 15 minutes. | Optional | 
| page_size | Number of records returned from a single API call. Default 50. | Optional | 
| page_number | The page of results to return. Default 1. | Optional | 
| limit | Total amount of results to show. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zoom.ChatMessage.date | date | The queried date value. | 
| Zoom.ChatMessage.id | string | The channel's unique identifier. | 
| Zoom.Channel.jid | string | The channel JID. | 
| Zoom.Channel.name | string | The channel name. | 
| Zoom.Channel.type | string | The type of the channel. The value can be one of the following: 1: Private channel. In this type of channel, members must be invited to join a channel. 2: Private channel with members that belong to one Zoom account. Members in this channel should be invited and the members should be from the same organization. 3: Public channel. Anyone can search for this channel and join the channel. 4: Group chat. This is an instant channel which can be created by adding members to a new chat. 
 | 
| Zoom.ChatMessage.date | date | The queried date value. | 
| Zoom.ChatMessage.from | date-time | The queried from value. \(Returned only if the from query parameter is used\) | 
| Zoom.ChatMessage.messages | array of object | Information about received messages and files. | 
| Zoom.ChatMessage.messages.bot_message | object | The chatbot's message in JSON format. | 
| Zoom.ChatMessage.messages.bot_message.date_time | date-time | The date and time when the message was sent. | 
| Zoom.ChatMessage.messages.files | array of object | Information about chat files \(if multiple files exist\). | 
| Zoom.ChatMessage.messages.files.download_url | string | The download URL of the chat file. | 
| Zoom.ChatMessage.messages.files.file_id | string | The unique ID of the chat file. | 
| Zoom.ChatMessage.messages.files.file_name | string | The name and file extension of the chat file. | 
| Zoom.ChatMessage.messages.files.file_size | integer | The size of the chat file in bytes. | 
| Zoom.ChatMessage.messages.rich_text | array of object | Rich text formatting information. | 
| Zoom.ChatMessage.messages.rich_text.start_position | integer | The start position of the rich text in the message string. | 
| Zoom.ChatMessage.messages.rich_text.end_position | integer | The end position of the rich text. | 
| Zoom.ChatMessage.messages.rich_text.format_type | enum | The type of rich text format. | 
| Zoom.ChatMessage.messages.rich_text.format_attr | string | The attribute values of a specific format_type. | 
| Zoom.ChatMessage.messages.rich_text.download_url | string | The download URL of the first file. | 
| Zoom.ChatMessage.messages.rich_text.file_id | string | The unique ID of the first file. | 
| Zoom.ChatMessage.messages.rich_text.file_name | string | The name of the first file. | 
| Zoom.ChatMessage.messages.rich_text.file_size | integer | The size of the first file in bytes. | 
| Zoom.ChatMessage.messages.id | string | Unique identifier of the message. | 
| Zoom.ChatMessage.messages.message | string | The message content. | 
| Zoom.ChatMessage.messages.reply_main_message_id | string | The unique identifier of a reply message. \(Returned only for reply messages\) | 
| Zoom.ChatMessage.messages.reply_main_message_timestamp | integer | The timestamp of when the reply message was sent. \(Returned only for reply messages\) | 
| Zoom.ChatMessage.messages.sender | string | The email address of the message sender. Empty if the sender does not belong to the same account as the current user or is not a contact. | 
| Zoom.ChatMessage.messages.sender_member_id | string | The member ID of the message sender. | 
| Zoom.ChatMessage.messages.sender_display_name | string | The display name of the message sender. | 
| Zoom.ChatMessage.messages.status | enum | Indicates the status of the message. Allowed values Deleted, Edited, Normal. \(Returned only when include_deleted_and_edited_message query parameter is set to true\) | 
| Zoom.ChatMessage.messages.timestamp | integer | The timestamp of the message in microseconds. | 
| Zoom.ChatMessage.at_items | array of object | Information about mentions. | 
| Zoom.ChatMessage.at_items.at_contact | string | The user ID of the mentioned contact. Empty if the contact does not belong to the same account as the current user. | 
| Zoom.ChatMessage.at_items.at_contact_member_id | string | The member ID of the mentioned contact. | 
| Zoom.ChatMessage.at_items.at_type | integer | The type of mention. Allowed values 1 \(Contact\), 2 \(Channel\). | 
| Zoom.ChatMessage.at_items.end_position | integer | The end position of the mention. | 
| Zoom.ChatMessage.at_items.start_position | integer | The start position of the mention. | 
| Zoom.ChatMessageNextToken.user_id|	string	|The user ID associated with the next page token.|
| Zoom.ChatMessageNextToken.to_channel|	string	|The channel ID associated with the next page token.|
| Zoom.ChatMessageNextToken.include_deleted_and_edited_message| boolean	|Indicates whether deleted and edited messages are included in the next page token request.|
| Zoom.ChatMessageNextToken.search_type|	string|	The search type associated with the next page token.|
| Zoom.ChatMessageNextToken.to|	string|	The recipient associated with the next page token.|
| Zoom.ChatMessageNextToken.date|	string|	The date associated with the next page token.|
| Zoom.ChatMessageNextToken.page_size|	integer|	The page size associated with the next page token.|
| Zoom.ChatMessageNextToken.next_page_token|	string|	The next page token for pagination.|
| Zoom.ChatMessageNextToken.from|	string|	The sender associated with the next page token.|
| Zoom.ChatMessageNextToken.search_key|	string	|The search key associated with the next page token.|
| Zoom.ChatMessageNextToken.exclude_child_message|	boolean	|Indicates whether child messages are excluded in the next page token request.|
| Zoom.ChatMessageNextToken.to_contact|	string	|The contact ID associated with the next page token.|

#### Command example

```!zoom-list-messages user_id=uJiZN-O7Rp6Jp_995FpZGg to_contact=example@example.com date=today```

#### Context Example

```json
{
    "Zoom": {
        "ChatMessage": {
            "ChatMessage": [
                {
                    "date_time": "2023-05-22T08:24:14Z",
                    "id": "a62636c8-b6c1-4135-9352-88ac61eafc31",
                    "message": "message",
                    "send_member_id": "1vrdvnC1gHuxZtpVLR7Oz1_A1dcCrBf0PNoRhTIzcvJjtbxgPXQRLmDm-10C2Ggg",
                    "sender": "example@example.com",
                    "sender_display_name": "admin zoom",
                    "timestamp": 1684743854543
                },
                {
                    "date_time": "2023-05-22T08:20:22Z",
                    "id": "4a59df4a-9668-46bd-bff2-3e1f3462ecc3",
                    "message": "my message",
                    "send_member_id": "1vrdvnC1gHuxZtpVLR7Oz1_A1dcCrBf0PNoRhTIzcvJjtbxgPXQRLmDm-10C2Ggg",
                    "sender": "example@example.com",
                    "sender_display_name": "admin zoom",
                    "timestamp": 1684743622899
                }
            ],
            "ChatMessageNextToken": ""
        }
    }
}
```

#### Human Readable Output

>### Messages
>
>|Date Time|From|Message Id|Message sender|Message text|Sender display name|To|User id|
>|---|---|---|---|---|---|---|---|
>| 2023-05-22T08:24:14Z | None | a62636c8-b6c1-4135-9352-88ac61eafc31 | <example@example.com> | message | admin zoom | None | uJiZN-O7Rp6Jp_995FpZGg |
>| 2023-05-22T08:20:22Z | None | 4a59df4a-9668-46bd-bff2-3e1f3462ecc3 | <example@example.com> | my message | admin zoom | None | uJiZN-O7Rp6Jp_995FpZGg |

### zoom-delete-user-token

***
Revoke a user's Zoom SSO session.
To list all available users use the `zoom-list-users` command.


#### Base Command

`zoom-delete-user-token`

#### Input

| **Argument Name** | **Description**                                                                         | **Required** |
|-------------------|-----------------------------------------------------------------------------------------| --- |
| user_id           | The user ID or email to be revoked.                                                     | Required | 

#### Command example

```!zoom-delete-user-token user_id=useremail@myself.com```

#### Context Output

There is no context output for this command.

#### Human Readable Output

>### Message
>
>User SSO token for user <useremail@myself.com> is deleted

### send-notification

***
Sends messages from your Marketplace Chatbot app on Zoom to either an individual user or to a channel.

#### Base Command

`send-notification`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| to |  The email address or user ID or member ID of the person to send a message.  | Required | 
| channel_id |  The channel ID of the channel to send a message. | Optional | 
| message | The message to be sent. Maximum of 1024 characters. | Required | 
| visible_to_user | The UserID that allows a Chatbot to send a message to a group channel when it has only one designated person in that group channel to see the message. | Optional |

#### Context Output

There is no context output for this command.

#### Command example

```!send-notification message=hi to=example@example.com```

#### Context Output

There is no context output for this command.

#### Human Readable Output

>### Message
>
>Message sent to Zoom successfully. Message ID is: 20230815153245201_BPK3S3S_aw1


## mirror-investigation

***
Mirrors the investigation between Zoom and the Cortex XSOAR War Room.

#### Base Command

`mirror-investigation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The mirroring type. Can be "all", which mirrors everything, "chat", which mirrors only chats (not commands), or "none", which stops all mirroring. Possible values are: all, chat, none. Default is all. | Optional | 
| autoclose | Whether the channel is auto-closed when an investigation is closed. Can be "true" or "false". Default is "true". | Optional | 
| direction | The mirroring direction. Can be "FromDemisto", "ToDemisto", or "Both". Default value is "Both". | Optional | 
| channelName | The name of the channel. The default is "incident-&lt;incidentID&gt;". | Optional | 

#### Context Output

There is no context output for this command.

#### Command Example

```!mirror-investigation direction="FromDemisto" channelName="example"```

#### Human Readable Output

> Investigation mirrored successfully, channel:example

### close-channel

***
Delete a mirrored Zoom channel.

#### Base Command

`close-channel`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| channel | The name of the channel to delete. If not provided, the mirrored investigation channel is deleted (if the channel exists). | Optional | 
| channel_id | The ID of the channel to delete. If not provided, the mirrored investigation channel is deleted (if the channel exists). | Optional | 

#### Context Output

There is no context output for this command.

#### Command Example

```
!close-channel channel=new-zoom-channel
```

#### Human Readable Output

> Channel successfully deleted.
