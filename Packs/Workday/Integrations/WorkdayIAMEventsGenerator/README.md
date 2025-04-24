Generates mock reports and events for Workday IAM. Use these for testing and development.

## Configure Workday_IAM_Event_Generator in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Long running instance | True |
| Port mapping (&lt;port&gt; or &lt;host port&gt;:&lt;docker port&gt;) | True |
| Incident type | False |


## Create an instance

To configure a long running integration to be accessed via Cortex XSOAR Server's https endpoint perform the following:

1. Configure the long running integration to listen on a unique port
2. Add the following advanced Server parameter:
    - Name: instance.execute.external.<instance_name>
    - Value: true

    For example for an instance named edl set the following:
    Name: instance.execute.external.workday_iam_event_generator_instance_1
    Value: true
    
    **Note**: The instance name is configured via the Name parameter of the integration. 
    
You will then be able to access the long running integration via the Cortex XSOAR Server's HTTPS endpoint. The route to the integration will be available at:
https://<server_hostname>/instance/execute/<instance_name>

Use this URL to configure `Workday_IAM` integration and invoke *Fetch_incidents*

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### workday-generate-hire-event
***
Generate workday new hire event.

After running this command, a new incident will be created of type: ``IAM - New Hire``



#### Base Command

`workday-generate-hire-event`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_email | The user email for the event. | Required | 
| first_name | The new user first name. | Optional | 
| last_name | The new user last name. | Optional | 


#### Command Example
```!workday-generate-hire-event user_email=testing@test.com first_name=John last_name=Smith```

#### Human Readable Output

>Successfully generated the new hire event.

### workday-generate-update-event
***
Generate workday update event.

After running this command, a new incident will be created of type: ``IAM - Update User``


#### Base Command

`workday-generate-update-event`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_email | The user email for the event. | Required | 
| title | The user updated title. | Optional | 
| city | The user city. | Optional | 
| street_address | The updated street address. | Optional | 
| last_day_of_work | The last hire date for the user.  For example: "06/15/2020". This will trigger "terminate" event. | Optional | 


#### Command Example
```!workday-generate-update-event user_email=panw@test.com city="Tel Aviv" title="Software Engineer"```

#### Human Readable Output

>Successfully generated the Update user event.

### workday-generate-rehire-event
***
Generate workday rehire event.

After running this command, a new incident will be created of type: ``IAM - Rehire User``


#### Base Command

`workday-generate-rehire-event`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_email | The user email for the event. | Required | 


#### Command Example
```!workday-generate-rehire-event user_email=panw@testing.com```

#### Human Readable Output

>Successfully generated the rehire user event.

### workday-generate-terminate-event
***
Generate workday terminate event.

After running this command, a new incident will be created of type: ``IAM - Terminate User``


#### Base Command

`workday-generate-terminate-event`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| last_day_of_work | The last hire date of the user. For example: "06/15/2020". The default is today. | Optional | 
| user_email | The user email to termniate. | Required | 
| termination_date | The user termination date. For example: "06/15/2020". The default is today. | Optional | 


#### Command Example
```!workday-generate-terminate-event user_email=panw@testing.com```

#### Human Readable Output

>Successfully generated the Terminate user event.

### initialize-context
***
Reset the integration context to fetch the first run reports.


#### Base Command

`initialize-context`
#### Input

There are no input arguments for this command.

#### Command Example
```!initialize-context ```

#### Human Readable Output
>The integration context has been initialized.
