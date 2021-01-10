This integration allows interacting with XSOAR server, mostly for internal use.

## Configure XsoarServerPowershell on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for XsoarServerPowershell.
3. Click **Add instance** to create and configure a new integration instance.
4. Click **Test** to validate the URLs, token, and connection.

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### xsoar-get-integration-context
***
Get integration context.

#### Base Command

`xsoar-get-integration-context`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| XSOAR.IntegrationContext.Value | String | Integration context value. | 


#### Command Example
```!xsoar-get-integration-context```

#### Context Example
```json
{
    "XSOAR": {
        "IntegrationContext": {
            "Value": "test_value"
        }
    }
}
```

#### Human Readable Output

>Integration context value is **test_value**

### xsoar-set-integration-context
***
Set integration context.

#### Base Command

`xsoar-set-integration-context`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| value | Value to set in integration context. | Required | 

#### Context Output

There is no context output for this command.

#### Command Example
```!xsoar-set-integration-context value="test_value"```

#### Context Example
```json
{}
```

#### Human Readable Output

>Integration context value set to **test_value** 
