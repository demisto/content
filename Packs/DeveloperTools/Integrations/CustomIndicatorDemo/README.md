Custom Indicator Demo is a demo integration which demonstrates usage of CustomIndicator helper class.
This integration was integrated and tested with version xx of CustomIndicatorDemo

## Configure CustomIndicatorDemo on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for CustomIndicatorDemo.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Your server URL |  | True |
    | API Key | The API Key to use for connection | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### test-custom-indicator
***
This command demonstrates the usage of CustomIndicator.


#### Base Command

`test-custom-indicator`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Demo.Result.Output | String | Dummy output. | 

#### Context Example

```
DBotScore
[
	{
		"Indicator": "custom_value",
		"Score": 1,
		"Type": "MyCustomIndicator",
		"Vendor": "CustomIndicatorDemo"
	}
]
Demo.Result
{
	"dummy": "test"
}
custom
[
	{
		"Value": "custom_value",
		"param1": "value1",
		"param2": "value2"
	}
]
```

#### Command Example
``` !test-custom-indicator```

#### Human Readable Output
>custom_value

